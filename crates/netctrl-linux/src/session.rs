//! Transactional Linux forwarding/shaping. The journal is written before every mutation.
use crate::{discovery, system::*};
use netctrl_core::*;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub namespace: u64,
    pub owner_pid: u32,
    pub token: String,
    pub plan: SessionPlan,
    pub up: String,
    pub down: String,
    pub forward_chain: String,
    pub output_chain: String,
    pub original_forwarding: String,
    pub forwarding_touched: bool,
    pub clsact_created: bool,
    pub ifbs: Vec<String>,
    pub filters: Vec<u32>,
    pub firewall_created: Vec<String>,
    pub hooks: Vec<(String, String)>,
    #[serde(default)]
    pub firewall_readback: std::collections::BTreeMap<String, String>,
}
pub struct Session {
    pub journal: Journal,
    pub path: PathBuf,
    _lock: fs::File,
}
pub fn namespace() -> Result<u64> {
    Ok(fs::metadata("/proc/self/ns/net")?.ino())
}
pub fn journal_path() -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("session-{}.json", namespace()?)))
}
fn lock() -> Result<fs::File> {
    let p = state_dir()?.join(format!("lock-{}", namespace()?));
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    // SAFETY: f owns a valid fd, flock does not retain a pointer.
    if unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } != 0
    {
        return Err(Error::Conflict(
            "another session or recovery owns this network namespace".into(),
        ));
    }
    Ok(f)
}
pub fn capture_binary() -> Result<PathBuf> {
    let p = std::env::current_exe()?
        .parent()
        .ok_or_else(|| Error::Dependency("helper parent missing".into()))?
        .join("netctrl-capture");
    trusted(&p)?;
    Ok(p)
}
fn json(name: &str, args_: &[String]) -> Result<serde_json::Value> {
    let output = run(name, args_)?;
    serde_json::from_str(&output).map_err(|e| {
        Error::Backend(format!(
            "{name} {}: JSON readback {e}; output {output:?}",
            args_.join(" ")
        ))
    })
}
fn filter_list(iface: &str, direction: &str) -> Result<serde_json::Value> {
    json(
        "tc",
        &args(&["-j", "filter", "show", "dev", iface, direction]),
    )
}
fn values(v: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    v.as_array().into_iter().flatten()
}
fn ipt(a: &[&str]) -> Result<String> {
    let mut v = args(&["-w", "3"]);
    v.extend(args(a));
    run("iptables", &v)
}
fn validate_routing_rules() -> Result<()> {
    let rules = json("ip", &args(&["-j", "-4", "rule", "show"]))?;
    for r in values(&rules) {
        let ordinary = matches!(
            (r["priority"].as_u64(), r["table"].as_str()),
            (Some(0), Some("local")) | (Some(32766), Some("main")) | (Some(32767), Some("default"))
        );
        if !ordinary
            || r["src"] != "all"
            || r.as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !["priority", "src", "table", "protocol"].contains(&k.as_str()))
            })
        {
            return Err(Error::Unsupported(
                "custom IPv4 policy-routing rules require manual integration".into(),
            ));
        }
    }
    Ok(())
}

pub async fn preflight(plan: &SessionPlan) -> Result<Vec<String>> {
    if !root() {
        return Err(Error::Permission("privileged helper required".into()));
    }
    discovery::revalidate(plan).await?;
    validate_routing_rules()?;
    capture_binary()?;
    if !ipt(&["--version"])?.contains("nf_tables") {
        return Err(Error::Unsupported(
            "first release supports iptables-nft only".into(),
        ));
    }
    let nft = json("nft", &args(&["-j", "list", "ruleset"]))?;
    if let Some(rules) = nft.get("nftables").and_then(|v| v.as_array()) {
        for r in rules {
            if let Some(c) = r.get("chain")
                && c.get("hook").and_then(|s| s.as_str()) == Some("forward")
                && !(c.get("family").and_then(|s| s.as_str()) == Some("ip")
                    && c.get("table").and_then(|s| s.as_str()) == Some("filter")
                    && c.get("name").and_then(|s| s.as_str()) == Some("FORWARD"))
            {
                return Err(Error::Unsupported(
                    "competing native nftables forwarding base chain; configure manually".into(),
                ));
            }
        }
    }
    if values(&filter_list(&plan.interface.name, "ingress")?)
        .next()
        .is_some()
    {
        return Err(Error::Conflict(
            "existing ingress filters; NetCtrl will not override them".into(),
        ));
    }
    let qs = json(
        "tc",
        &args(&["-j", "qdisc", "show", "dev", &plan.interface.name]),
    )?;
    if values(&qs).any(|q| q["kind"] == "ingress") {
        return Err(Error::Conflict(
            "existing ingress qdisc is not clsact".into(),
        ));
    }
    if journal_path()?.exists() {
        return Err(Error::Conflict(
            "unfinished session journal; run netctrl recover".into(),
        ));
    }
    let changes=vec![format!("Interface {} ({}), controller {}",plan.interface.name,plan.controller.mac,plan.controller.ip),format!("Redirect IPv4 gateway {} ({}) for {} selected client(s)",plan.gateway.ip,plan.gateway.mac,plan.targets.len()),"Enable forwarding on this interface; add scoped firewall exceptions and suppress client ICMP redirects".into(),"Create two owned IFBs and per-device queues; preserve the physical root qdisc".into(),"IPv6 and direct same-subnet traffic remain outside enforcement; exit/watchdog restores owned changes".into()];
    Ok(changes)
}
impl Session {
    pub fn create(plan: SessionPlan) -> Result<Self> {
        plan.validate()?;
        let guard = lock()?;
        let path = journal_path()?;
        if path.exists() {
            return Err(Error::Conflict("recovery is required".into()));
        }
        let mut random = [0u8; 16];
        fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let short = &token[..10];
        let original = fs::read_to_string(sysctl_path(&plan.interface.name)?)?
            .trim()
            .to_string();
        if original != "0" && original != "1" {
            return Err(Error::Backend("unexpected forwarding state".into()));
        }
        let j = Journal {
            version: 1,
            namespace: namespace()?,
            owner_pid: std::process::id(),
            up: format!("ncu{short}"),
            down: format!("ncd{short}"),
            forward_chain: format!("NC{short}F"),
            output_chain: format!("NC{short}O"),
            token,
            plan,
            original_forwarding: original,
            forwarding_touched: false,
            clsact_created: false,
            ifbs: vec![],
            filters: vec![],
            firewall_created: vec![],
            hooks: vec![],
            firewall_readback: Default::default(),
        };
        atomic_json(&path, &j)?;
        Ok(Self {
            journal: j,
            path,
            _lock: guard,
        })
    }
    fn save(&self) -> Result<()> {
        atomic_json(&self.path, &self.journal)
    }
    pub fn install(&mut self) -> Result<()> {
        // Install forwarding exceptions before enabling reception of redirected traffic.
        let f = self.journal.forward_chain.clone();
        let o = self.journal.output_chain.clone();
        let iface = self.journal.plan.interface.name.clone();
        let token = self.journal.token.clone();
        for chain in [&f, &o] {
            self.journal.firewall_created.push(chain.clone());
            self.save()?;
            ipt(&["-N", chain])?;
        }
        let subnet = self.journal.plan.subnet.trunc().to_string();
        for t in &self.journal.plan.targets {
            let ip = t.peer.ip.to_string();
            let mac = t.peer.mac.to_string();
            let gw = self.journal.plan.gateway.mac.to_string();
            ipt(&[
                "-A",
                &f,
                "-i",
                &iface,
                "-o",
                &iface,
                "-s",
                &ip,
                "!",
                "-d",
                &subnet,
                "-m",
                "mac",
                "--mac-source",
                &mac,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "ACCEPT",
            ])?;
            ipt(&[
                "-A",
                &f,
                "-i",
                &iface,
                "-o",
                &iface,
                "-d",
                &ip,
                "!",
                "-s",
                &subnet,
                "-m",
                "mac",
                "--mac-source",
                &gw,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "ACCEPT",
            ])?;
            // Preserve router-local services intercepted by the client gateway mapping.
            let gateway_ip = self.journal.plan.gateway.ip.to_string();
            ipt(&[
                "-A",
                &f,
                "-i",
                &iface,
                "-o",
                &iface,
                "-s",
                &ip,
                "-d",
                &gateway_ip,
                "-m",
                "mac",
                "--mac-source",
                &mac,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "ACCEPT",
            ])?;
            ipt(&[
                "-A",
                &f,
                "-i",
                &iface,
                "-o",
                &iface,
                "-d",
                &ip,
                "-s",
                &gateway_ip,
                "-m",
                "mac",
                "--mac-source",
                &gw,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "ACCEPT",
            ])?;
            // Locally generated ICMP errors (including PMTU) are allowed; only redirects are suppressed.
            ipt(&[
                "-A",
                &o,
                "-d",
                &ip,
                "-p",
                "icmp",
                "--icmp-type",
                "redirect",
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "DROP",
            ])?;
        }
        // A previously non-routing interface must not begin routing unselected traffic.
        if self.journal.original_forwarding == "0" {
            ipt(&[
                "-A",
                &f,
                "-i",
                &iface,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                "DROP",
            ])?;
        }
        for (hook, chain, selector) in [("FORWARD", f.as_str(), "-i"), ("OUTPUT", o.as_str(), "-o")]
        {
            self.journal.hooks.push((hook.into(), chain.into()));
            self.save()?;
            ipt(&[
                "-I",
                hook,
                "1",
                selector,
                &iface,
                "-m",
                "comment",
                "--comment",
                &token,
                "-j",
                chain,
            ])?;
        }
        let qs = json("tc", &args(&["-j", "qdisc", "show", "dev", &iface]))?;
        if !values(&qs).any(|q| q["kind"] == "clsact") {
            self.journal.clsact_created = true;
            self.save()?;
            run("tc", &args(&["qdisc", "add", "dev", &iface, "clsact"]))?;
        }
        for ifb in [self.journal.up.clone(), self.journal.down.clone()] {
            self.journal.ifbs.push(ifb.clone());
            self.save()?;
            run(
                "ip",
                &args(&[
                    "link",
                    "add",
                    "name",
                    &ifb,
                    "alias",
                    &format!("netctrl:{token}"),
                    "type",
                    "ifb",
                ]),
            )?;
            run(
                "ip",
                &args(&[
                    "link",
                    "set",
                    "dev",
                    &ifb,
                    "alias",
                    &format!("netctrl:{token}"),
                    "mtu",
                    // Accept oversized ingress until IPv4 routing can fragment it
                    // or generate ICMP fragmentation-needed on the physical egress.
                    "65535",
                    "up",
                ]),
            )?;
            run(
                "tc",
                &args(&["qdisc", "add", "dev", &ifb, "root", "handle", "1:", "htb"]),
            )?;
        }
        // Skip direct LAN traffic before target filters. Existing ingress filters were rejected.
        self.add_filter(
            40000,
            &[
                "src_ip", &subnet, "dst_ip", &subnet, "action", "pass", "cookie", &token,
            ],
        )?;
        self.add_filter(
            40001,
            &[
                "src_ip",
                &subnet,
                "dst_mac",
                &self.journal.plan.controller.mac.to_string(),
                "src_mac",
                &self.journal.plan.gateway.mac.to_string(),
                "action",
                "pass",
                "cookie",
                &token,
            ],
        )?;
        let targets = self.journal.plan.targets.clone();
        for (idx, t) in targets.iter().enumerate() {
            let minor = format!("{:x}", idx + 1);
            for (upload, rate) in [(true, t.policy.upload_bps), (false, t.policy.download_bps)] {
                if let Some(rate) = rate {
                    let ifb = if upload {
                        self.journal.up.clone()
                    } else {
                        self.journal.down.clone()
                    };
                    let class = format!("1:{minor}");
                    let rate_s = format!("{rate}bit");
                    let burst = (rate / 8 / 20)
                        .max(u64::from(self.journal.plan.interface.mtu) * 2)
                        .to_string();
                    run(
                        "tc",
                        &args(&[
                            "class", "add", "dev", &ifb, "parent", "1:", "classid", &class, "htb",
                            "rate", &rate_s, "ceil", &rate_s, "burst", &burst, "cburst", &burst,
                        ]),
                    )?;
                    run(
                        "tc",
                        &args(&[
                            "qdisc",
                            "add",
                            "dev",
                            &ifb,
                            "parent",
                            &class,
                            "fq_codel",
                            "limit",
                            "256",
                            "memory_limit",
                            "1048576",
                        ]),
                    )?;
                    let ip = t.peer.ip.to_string();
                    let key = if upload { "src_ip" } else { "dst_ip" };
                    run(
                        "tc",
                        &args(&[
                            "filter",
                            "add",
                            "dev",
                            &ifb,
                            "parent",
                            "1:",
                            "protocol",
                            "ip",
                            "pref",
                            &(idx + 1).to_string(),
                            "flower",
                            key,
                            &ip,
                            "classid",
                            &class,
                        ]),
                    )?;
                    let src_mac = if upload {
                        t.peer.mac
                    } else {
                        self.journal.plan.gateway.mac
                    }
                    .to_string();
                    let own = self.journal.plan.controller.mac.to_string();
                    self.add_filter(
                        40100 + (idx as u32) * 2 + u32::from(!upload),
                        &[
                            key, &ip, "src_mac", &src_mac, "dst_mac", &own, "action", "mirred",
                            "egress", "redirect", "dev", &ifb, "cookie", &token,
                        ],
                    )?;
                }
            }
        }
        for c in [&self.journal.forward_chain, &self.journal.output_chain] {
            self.journal
                .firewall_readback
                .insert(c.clone(), ipt(&["-S", c])?);
        }
        self.journal.forwarding_touched = true;
        self.save()?;
        fs::write(sysctl_path(&iface)?, "1\n")?;
        self.verify()?;
        Ok(())
    }
    fn add_filter(&mut self, pref: u32, tail: &[&str]) -> Result<()> {
        self.journal.filters.push(pref);
        self.save()?;
        let mut a = args(&[
            "filter",
            "add",
            "dev",
            &self.journal.plan.interface.name,
            "ingress",
            "protocol",
            "ip",
            "pref",
            &pref.to_string(),
            "flower",
            "skip_hw",
        ]);
        a.extend(args(tail));
        run("tc", &a)?;
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        if !interface_matches(&self.journal)? {
            return Err(Error::Conflict("interface identity changed".into()));
        }
        if fs::read_to_string(sysctl_path(&self.journal.plan.interface.name)?)?.trim() != "1" {
            return Err(Error::Backend("forwarding readback failed".into()));
        }
        let filters = filter_list(&self.journal.plan.interface.name, "ingress")?;
        if values(&filters)
            .filter(|v| v.get("options").is_some())
            .any(|v| {
                !v["pref"].as_u64().is_some_and(|p| {
                    self.journal
                        .filters
                        .iter()
                        .any(|owned| u64::from(*owned) == p)
                }) || !v.to_string().contains(&self.journal.token)
            })
        {
            return Err(Error::Conflict(
                "foreign ingress policy appeared during enforcement".into(),
            ));
        }
        for pref in &self.journal.filters {
            if !values(&filters).any(|v| {
                v["pref"].as_u64() == Some(u64::from(*pref))
                    && v.to_string().contains(&self.journal.token)
            }) {
                return Err(Error::Backend(format!("filter {pref} readback failed")));
            }
        }
        for c in [&self.journal.forward_chain, &self.journal.output_chain] {
            let actual = ipt(&["-S", c])?;
            if self.journal.firewall_readback.get(c) != Some(&actual) {
                return Err(Error::Conflict("owned firewall rules changed".into()));
            }
        }
        for (hook, chain) in &self.journal.hooks {
            let selector = if hook == "FORWARD" { "-i" } else { "-o" };
            ipt(&[
                "-C",
                hook,
                selector,
                &self.journal.plan.interface.name,
                "-m",
                "comment",
                "--comment",
                &self.journal.token,
                "-j",
                chain,
            ])?;
        }
        for ifb in [&self.journal.up, &self.journal.down] {
            let link = json("ip", &args(&["-j", "link", "show", "dev", ifb]))?;
            if !values(&link)
                .any(|v| v["ifalias"].as_str() == Some(&format!("netctrl:{}", self.journal.token)))
            {
                return Err(Error::Conflict("IFB ownership changed".into()));
            }
            let q = json("tc", &args(&["-j", "qdisc", "show", "dev", ifb]))?;
            if !values(&q).any(|v| v["kind"] == "htb") {
                return Err(Error::Backend("HTB readback failed".into()));
            }
        }
        Ok(())
    }
    pub async fn counters(&self) -> Result<Vec<(std::net::Ipv4Addr, EnforcementCounters)>> {
        discovery::revalidate(&self.journal.plan).await?;
        validate_routing_rules()?;
        self.verify()?;
        let ups = crate::classes::read(&self.journal.up).await?;
        let downs = crate::classes::read(&self.journal.down).await?;
        for (classes, upload) in [(&ups, true), (&downs, false)] {
            let expected = self
                .journal
                .plan
                .targets
                .iter()
                .filter(|t| {
                    if upload {
                        t.policy.upload_bps.is_some()
                    } else {
                        t.policy.download_bps.is_some()
                    }
                })
                .count();
            if classes.len() != expected {
                return Err(Error::Conflict("unexpected HTB class inventory".into()));
            }
        }
        let mut output = vec![];
        for (idx, t) in self.journal.plan.targets.iter().enumerate() {
            let mut c = EnforcementCounters {
                upload: EnforcementStatus::AppliedUnverified,
                download: EnforcementStatus::AppliedUnverified,
                ..Default::default()
            };
            for upload in [true, false] {
                let stats = if upload { &ups } else { &downs };
                let rate = if upload {
                    t.policy.upload_bps
                } else {
                    t.policy.download_bps
                };
                if let Some(rate) = rate {
                    let class = stats
                        .iter()
                        .find(|s| s.minor as usize == idx + 1)
                        .ok_or_else(|| Error::Backend("HTB class missing".into()))?;
                    if class.rate_bps != rate / 8 * 8 || class.ceil_bps != rate / 8 * 8 {
                        return Err(Error::Conflict("HTB rate was externally changed".into()));
                    }
                    c.dropped = c.dropped.saturating_add(class.dropped);
                    if upload {
                        c.uploaded = class.bytes;
                    } else {
                        c.downloaded = class.bytes;
                    }
                }
            }
            // Forward-chain counters confirm packets actually traversed the allowed IPv4 path.
            let rules = ipt(&["-L", &self.journal.forward_chain, "-v", "-x", "-n"])?;
            for l in rules.lines() {
                let cols: Vec<_> = l.split_whitespace().collect();
                if cols.len() < 9 || cols[2] != "ACCEPT" {
                    continue;
                }
                let packets = cols[0].parse::<u64>().unwrap_or(0);
                let bytes = cols[1].parse::<u64>().unwrap_or(0);
                if packets == 0 {
                    continue;
                }
                let off_subnet = format!("!{}", self.journal.plan.subnet.trunc());
                if cols[7] == t.peer.ip.to_string()
                    && cols[8] == off_subnet
                    && (t.policy.upload_bps.is_none() || c.uploaded > 0)
                {
                    c.upload = EnforcementStatus::TrafficVerified;
                    if t.policy.upload_bps.is_none() {
                        c.uploaded = bytes;
                    }
                }
                if cols[8] == t.peer.ip.to_string()
                    && cols[7] == off_subnet
                    && (t.policy.download_bps.is_none() || c.downloaded > 0)
                {
                    c.download = EnforcementStatus::TrafficVerified;
                    if t.policy.download_bps.is_none() {
                        c.downloaded = bytes;
                    }
                }
            }
            output.push((t.peer.ip, c));
        }
        Ok(output)
    }
    pub fn recover(&mut self) -> Result<()> {
        recover_journal(&self.journal, &self.path)
    }
}
fn interface_matches(j: &Journal) -> Result<bool> {
    let v = json(
        "ip",
        &args(&["-j", "link", "show", "dev", &j.plan.interface.name]),
    )?;
    Ok(values(&v).any(|i| {
        i["ifindex"].as_u64() == Some(u64::from(j.plan.interface.index))
            && i["address"].as_str() == Some(&j.plan.controller.mac.to_string())
    }))
}
pub fn repair(plan: &SessionPlan) -> Result<()> {
    let mut c = std::process::Command::new(capture_binary()?)
        .arg("--repair")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let stdin = c
        .stdin
        .take()
        .ok_or_else(|| Error::Backend("repair stdin missing".into()))?;
    netctrl_engine::write_frame(&mut std::io::BufWriter::new(stdin), plan)?;
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = c.try_wait()? {
            if s.success() {
                return Ok(());
            }
            return Err(Error::Backend("corrective ARP worker failed".into()));
        }
        if start.elapsed() > std::time::Duration::from_secs(5) {
            let _ = c.kill();
            let _ = c.wait();
            return Err(Error::Backend("corrective ARP worker timed out".into()));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
pub fn recover_journal(j: &Journal, path: &Path) -> Result<()> {
    if j.version != 1 || j.namespace != namespace()? {
        return Err(Error::Conflict(
            "journal belongs to another version or network namespace".into(),
        ));
    }
    j.plan.validate()?;
    let mut errors = vec![];
    let same = interface_matches(j).unwrap_or(false);
    let iface = &j.plan.interface.name;
    if same {
        match filter_list(iface, "ingress") {
            Ok(v) => {
                for pref in j.filters.iter().rev() {
                    let matching: Vec<_> = values(&v)
                        .filter(|v| {
                            v["pref"].as_u64() == Some(u64::from(*pref))
                                && v.get("options").is_some()
                        })
                        .collect();
                    if matching.is_empty() {
                        continue;
                    }
                    if matching.iter().all(|v| v.to_string().contains(&j.token)) {
                        if let Err(e) = run(
                            "tc",
                            &args(&[
                                "filter",
                                "del",
                                "dev",
                                iface,
                                "ingress",
                                "pref",
                                &pref.to_string(),
                                "protocol",
                                "ip",
                            ]),
                        ) {
                            errors.push(e.to_string());
                        }
                    } else {
                        errors.push(format!("filter {pref} ownership changed"));
                    }
                }
            }
            Err(e) => errors.push(e.to_string()),
        }
        if j.forwarding_touched
            && let Err(e) = repair(&j.plan)
        {
            errors.push(e.to_string());
        }
    }
    for ifb in &j.ifbs {
        if let Ok(v) = json("ip", &args(&["-j", "link", "show", "dev", ifb])) {
            if values(&v).any(|x| x["ifalias"].as_str() == Some(&format!("netctrl:{}", j.token))) {
                if let Err(e) = run("ip", &args(&["link", "del", "dev", ifb])) {
                    errors.push(e.to_string());
                }
            } else {
                errors.push(format!("IFB {ifb} ownership changed"));
            }
        }
    }
    if same && j.clsact_created {
        let ingress = filter_list(iface, "ingress");
        let egress = filter_list(iface, "egress");
        if let (Ok(i), Ok(e)) = (ingress, egress)
            && values(&i).next().is_none()
            && values(&e).next().is_none()
        {
            let q = json("tc", &args(&["-j", "qdisc", "show", "dev", iface]))?;
            if values(&q).any(|q| q["kind"] == "clsact")
                && let Err(e) = run("tc", &args(&["qdisc", "del", "dev", iface, "clsact"]))
            {
                errors.push(e.to_string());
            }
        }
    }
    for chain in j.firewall_created.iter().rev() {
        if let Ok(rules) = ipt(&["-S", chain]) {
            if rules
                .lines()
                .filter(|l| l.starts_with("-A "))
                .any(|l| !l.contains(&j.token))
            {
                errors.push(format!("firewall chain {chain} has foreign rules"));
                continue;
            }
            for (hook, c) in j.hooks.iter().filter(|(_, c)| c == chain) {
                let selector = if hook == "FORWARD" { "-i" } else { "-o" };
                let rule = [
                    "-D",
                    hook,
                    selector,
                    iface,
                    "-m",
                    "comment",
                    "--comment",
                    &j.token,
                    "-j",
                    c,
                ];
                let exists = ipt(&[
                    "-C",
                    hook,
                    selector,
                    iface,
                    "-m",
                    "comment",
                    "--comment",
                    &j.token,
                    "-j",
                    c,
                ])
                .is_ok();
                if exists && let Err(e) = ipt(&rule) {
                    errors.push(e.to_string());
                }
            }
            if let Err(e) = ipt(&["-F", chain]).and_then(|_| ipt(&["-X", chain])) {
                errors.push(e.to_string());
            }
        }
    }
    if same && j.forwarding_touched {
        let p = sysctl_path(iface)?;
        let current = fs::read_to_string(&p)?;
        if current.trim() == "1" {
            fs::write(p, format!("{}\n", j.original_forwarding))?;
        } else if current.trim() != j.original_forwarding {
            errors.push("forwarding setting was externally changed".into());
        }
    }
    if !same {
        errors.push("interface identity changed; its settings were preserved".into());
    }
    if errors.is_empty() {
        if path.exists() {
            fs::remove_file(path)?;
            fs::File::open(
                path.parent()
                    .ok_or_else(|| Error::Invalid("journal path".into()))?,
            )?
            .sync_all()?;
        }
        Ok(())
    } else {
        Err(Error::Conflict(errors.join("; ")))
    }
}
pub fn recover_saved() -> Result<()> {
    let _guard = lock()?;
    let path = journal_path()?;
    if !path.exists() {
        return Ok(());
    }
    let m = fs::symlink_metadata(&path)?;
    if m.uid() != 0 || m.mode() & 0o077 != 0 || !m.is_file() {
        return Err(Error::Permission("unsafe journal".into()));
    }
    let j: Journal = serde_json::from_reader(fs::File::open(&path)?)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    recover_journal(&j, &path)
}
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
