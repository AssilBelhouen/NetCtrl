//! Privileged integration harness. All links live in newly created test namespaces.
use netctrl_core::*;
use netctrl_engine::*;
use netctrl_linux::{
    discovery, session,
    system::{self, args, run as command},
};
use std::{
    io::{BufReader, BufWriter},
    net::Ipv4Addr,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
fn ip(a: &[&str]) -> Result<String> {
    command("ip", &args(a))
}
fn net(ns: &str, tool: &str, a: &[&str]) -> Result<String> {
    let mut v = args(&["netns", "exec", ns, tool]);
    v.extend(args(a));
    command("ip", &v)
}
fn check(ok: bool, s: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Backend(s.into()))
    }
}
struct Lab {
    names: Vec<String>,
    children: Vec<Child>,
}
impl Drop for Lab {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        for n in self.names.iter().rev() {
            let _ = ip(&["netns", "del", n]);
        }
    }
}
pub fn run() -> Result<()> {
    if !system::root() {
        return Err(Error::Permission(
            "run the integration harness with sudo".into(),
        ));
    }
    if std::env::args().nth(1).as_deref() == Some("--udp-receive") {
        return udp_receive();
    }
    if std::env::args().nth(1).as_deref() == Some("--udp-send") {
        return udp_send();
    }
    if std::env::args().nth(1).as_deref() == Some("--controller") {
        let prefix = std::env::args()
            .nth(2)
            .ok_or_else(|| Error::Invalid("lab prefix".into()))?;
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(controller(&prefix));
    }
    // SAFETY: creating a new network namespace affects only this test process and descendants.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for module in ["ifb", "sch_htb", "cls_flower", "act_mirred", "sch_fq_codel"] {
        if module == "ifb" {
            command("modprobe", &args(&[module, "numifbs=0"]))?;
        } else {
            command("modprobe", &args(&[module]))?;
        }
    }
    let prefix = format!("ncl{}", std::process::id());
    let mut lab = Lab {
        names: vec![],
        children: vec![],
    };
    ip(&["link", "add", "name", "br-lab", "type", "bridge"])?;
    ip(&["link", "set", "br-lab", "up"])?;
    for (label, octet) in [("r", 1), ("c", 2), ("a", 10), ("b", 11), ("u", 12)] {
        let ns = format!("{prefix}-{label}");
        ip(&["netns", "add", &ns])?;
        lab.names.push(ns.clone());
        let host = format!("v{label}");
        ip(&["link", "add", &host, "type", "veth", "peer", "name", "nc0"])?;
        ip(&["link", "set", "nc0", "netns", &ns])?;
        ip(&["link", "set", &host, "master", "br-lab"])?;
        ip(&["link", "set", &host, "up"])?;
        net(&ns, "ip", &["link", "set", "lo", "up"])?;
        net(&ns, "ip", &["link", "set", "nc0", "mtu", "1400", "up"])?;
        net(
            &ns,
            "ip",
            &["addr", "add", &format!("10.77.0.{octet}/24"), "dev", "nc0"],
        )?;
        if label != "r" {
            net(&ns, "ip", &["route", "add", "default", "via", "10.77.0.1"])?;
        }
        if label == "c" {
            // New namespaces can inherit forwarding defaults from the runner.
            net(&ns, "sysctl", &["-w", "net.ipv4.conf.nc0.forwarding=0"])?;
        }
    }
    let router = format!("{prefix}-r");
    net(&router, "ip", &["link", "add", "wan0", "type", "dummy"])?;
    net(&router, "ip", &["link", "set", "wan0", "up"])?;
    net(
        &router,
        "ip",
        &["addr", "add", "198.18.0.1/24", "dev", "wan0"],
    )?;
    // Default-deny is deliberate: the backend must install only scoped exceptions.
    net(
        &format!("{prefix}-c"),
        "iptables",
        &["-P", "FORWARD", "DROP"],
    )?;
    for label in ["r", "a", "b"] {
        net(
            &format!("{prefix}-{label}"),
            "ping",
            &["-c", "1", "-W", "2", "10.77.0.2"],
        )?;
    }
    let server = Command::new(system::tool("ip")?)
        .args([
            "netns",
            "exec",
            &router,
            "iperf3",
            "-s",
            "-J",
            "-B",
            "198.18.0.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    lab.children.push(server);
    std::thread::sleep(Duration::from_millis(200));
    let status = Command::new(system::tool("ip")?)
        .args(["netns", "exec", &format!("{prefix}-c")])
        .arg(std::env::current_exe()?)
        .args(["--controller", &prefix])
        .status()?;
    check(status.success(), "controller integration scenarios failed")?;
    println!(
        "PASS: isolated forwarding, bidirectional shaping, independent clients, unlimited mode, MTU, conflict rejection, rollback, mapping change and watchdog recovery"
    );
    Ok(())
}
struct Harness {
    child: Child,
    input: Arc<Mutex<BufWriter<std::process::ChildStdin>>>,
    events: mpsc::Receiver<Event>,
    alive: Arc<AtomicBool>,
    pub counters: Arc<Mutex<Vec<(Ipv4Addr, EnforcementCounters)>>>,
}
impl Harness {
    fn start() -> Result<Self> {
        let path = std::env::current_exe()?.with_file_name("netctrl-helper");
        system::trusted(&path)?;
        let mut child = Command::new(path)
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = Arc::new(Mutex::new(BufWriter::new(
            child
                .stdin
                .take()
                .ok_or_else(|| Error::Backend("helper input".into()))?,
        )));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Backend("helper output".into()))?;
        let (tx, events) = mpsc::sync_channel(64);
        let counters = Arc::new(Mutex::new(vec![]));
        let c = counters.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                match read_frame::<_, Event>(&mut r) {
                    Ok(Some(Event::Counters(v))) => {
                        if let Ok(mut c) = c.lock() {
                            *c = v;
                        }
                    }
                    Ok(Some(
                        Event::Packet(_) | Event::Neighbor(_) | Event::CaptureStats { .. },
                    )) => {}
                    Ok(Some(e)) => {
                        if matches!(e, Event::Error(_)) {
                            eprintln!("helper event: {e:?}");
                        }
                        if tx.send(e).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
        let alive = Arc::new(AtomicBool::new(true));
        let a = alive.clone();
        let i = input.clone();
        std::thread::spawn(move || {
            while a.load(Ordering::Relaxed) {
                if let Ok(mut w) = i.lock()
                    && write_frame(&mut *w, &Request::Heartbeat).is_err()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        Ok(Self {
            child,
            input,
            events,
            alive,
            counters,
        })
    }
    fn send(&self, r: Request) -> Result<()> {
        write_frame(
            &mut *self
                .input
                .lock()
                .map_err(|_| Error::Backend("input lock".into()))?,
            &r,
        )
    }
    fn wait(&self, predicate: impl Fn(&Event) -> bool) -> Result<Event> {
        let start = Instant::now();
        loop {
            let e = self
                .events
                .recv_timeout(Duration::from_secs(15))
                .map_err(|e| Error::Backend(format!("helper response: {e}")))?;
            if let Event::Error(e) = &e {
                return Err(Error::Backend(format!("helper: {e}")));
            }
            if predicate(&e) {
                return Ok(e);
            }
            if start.elapsed() > Duration::from_secs(15) {
                return Err(Error::Backend("helper response deadline".into()));
            }
        }
    }
    fn apply(&self, plan: SessionPlan) -> Result<()> {
        self.send(Request::Prepare { plan })?;
        let revision = match self.wait(|e| matches!(e, Event::Prepared { .. }))? {
            Event::Prepared { revision, .. } => revision,
            _ => return Err(Error::Backend("missing preview".into())),
        };
        self.send(Request::Apply { revision })?;
        self.wait(|e| matches!(e, Event::Applied))?;
        std::thread::sleep(Duration::from_secs(1));
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        self.send(Request::Quit)?;
        self.wait(|e| matches!(e, Event::Recovered))?;
        let start = Instant::now();
        while self.child.try_wait()?.is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                return Err(Error::Backend("helper failed to exit".into()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.alive.store(false, Ordering::Relaxed);
        Ok(())
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
        let _ = self.child.kill();
        let _ = self.child.wait();
        let deadline = Instant::now() + Duration::from_secs(12);
        while session::journal_path().is_ok_and(|p| p.exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
fn udp_receive() -> Result<()> {
    let bind = std::env::args()
        .nth(2)
        .ok_or_else(|| Error::Invalid("receiver bind".into()))?;
    let socket = std::net::UdpSocket::bind(&bind)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let timeout = Instant::now() + Duration::from_secs(15);
    let mut first: Option<Instant> = None;
    let mut bytes = 0u64;
    let mut buffer = [0u8; 2048];
    loop {
        let now = Instant::now();
        if let Some(first) = first
            && now.duration_since(first) >= Duration::from_secs(7)
        {
            println!("{}", bytes * 8 / 6);
            return Ok(());
        }
        if now >= timeout {
            return Err(Error::Backend("UDP receiver saw no usable traffic".into()));
        }
        match socket.recv_from(&mut buffer) {
            Ok((n, _)) => {
                let first = *first.get_or_insert_with(Instant::now);
                let elapsed = first.elapsed();
                if elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(7) {
                    bytes += n as u64;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
}
fn udp_send() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let destination = a
        .get(2)
        .ok_or_else(|| Error::Invalid("sender destination".into()))?;
    let bind = a
        .get(3)
        .ok_or_else(|| Error::Invalid("sender bind".into()))?;
    let bps: u64 = a
        .get(4)
        .ok_or_else(|| Error::Invalid("sender rate".into()))?
        .parse()
        .map_err(|_| Error::Invalid("sender rate".into()))?;
    if !(1_000_000..=100_000_000).contains(&bps) {
        return Err(Error::Invalid("test sender rate".into()));
    }
    let socket = std::net::UdpSocket::bind(format!("{bind}:0"))?;
    let packet = [42u8; 1000];
    let period = Duration::from_nanos(8_000_000_000_000 / bps);
    let start = Instant::now();
    let mut next = start;
    while start.elapsed() < Duration::from_secs(8) {
        match socket.send_to(&packet, destination) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(e) => return Err(e.into()),
        }
        next += period;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else if now.duration_since(next) > Duration::from_millis(20) {
            next = now;
        }
    }
    Ok(())
}
fn throughput(prefix: &str, label: &str, reverse: bool, cap: Option<u64>) -> Result<()> {
    let ns = format!("{prefix}-{label}");
    let router = format!("{prefix}-r");
    let client_ip = if label == "a" {
        "10.77.0.10"
    } else {
        "10.77.0.11"
    };
    let server_ip = "198.18.0.1";
    let (receiver_ns, receiver_ip, sender_ns, sender_ip) = if reverse {
        (ns.as_str(), client_ip, router.as_str(), server_ip)
    } else {
        (router.as_str(), server_ip, ns.as_str(), client_ip)
    };
    let endpoint = format!("{receiver_ip}:5521");
    let executable = std::env::current_exe()?;
    let receiver = Command::new(system::tool("ip")?)
        .args(["netns", "exec", receiver_ns])
        .arg(&executable)
        .args(["--udp-receive", &endpoint])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    std::thread::sleep(Duration::from_millis(100));
    let offered = cap
        .map(|c| c * 3)
        .unwrap_or(10_000_000)
        .max(3_000_000)
        .to_string();
    let sender = Command::new(system::tool("ip")?)
        .args(["netns", "exec", sender_ns])
        .arg(&executable)
        .args(["--udp-send", &endpoint, sender_ip, &offered])
        .status()?;
    let output = receiver.wait_with_output()?;
    check(
        sender.success() && output.status.success(),
        "Rust UDP measurement processes failed",
    )?;
    let bps: f64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| Error::Backend("invalid measured throughput".into()))?;
    println!(
        "{label} {}: {:.3} Mbps (cap {cap:?})",
        if reverse { "download" } else { "upload" },
        bps / 1e6
    );
    if let Some(cap) = cap {
        check(
            bps >= cap as f64 * 0.75 && bps <= cap as f64 * 1.10,
            "measured receive throughput outside 75–110% cap",
        )?;
    } else {
        check(
            bps >= 6_000_000.0,
            "unlimited path remained unexpectedly limited",
        )?;
    }
    Ok(())
}
async fn controller(prefix: &str) -> Result<()> {
    let iface = discovery::interfaces()
        .await?
        .into_iter()
        .find(|i| i.name == "nc0")
        .ok_or_else(|| Error::Backend("controller interface missing".into()))?;
    let peers = discovery::neighbors(iface.index).await?;
    let peer = |octet| {
        peers
            .iter()
            .find(|p| p.ip == Ipv4Addr::new(10, 77, 0, octet))
            .copied()
            .ok_or_else(|| Error::Backend(format!("neighbor .{octet} missing: {peers:?}")))
    };
    let plan = SessionPlan {
        controller: Peer {
            ip: Ipv4Addr::new(10, 77, 0, 2),
            mac: iface
                .mac
                .ok_or_else(|| Error::Backend("controller MAC".into()))?,
        },
        gateway: peer(1)?,
        subnet: iface.addresses[0].trunc(),
        interface: iface.clone(),
        targets: vec![
            TargetPolicy {
                peer: peer(10)?,
                policy: BandwidthPolicy {
                    upload_bps: Some(2_000_000),
                    download_bps: Some(4_000_000),
                },
            },
            TargetPolicy {
                peer: peer(11)?,
                policy: BandwidthPolicy {
                    upload_bps: Some(1_000_000),
                    download_bps: Some(3_000_000),
                },
            },
        ],
    };
    let baseline = command("tc", &args(&["-j", "qdisc", "show", "dev", "nc0"]))?;
    // Competing native firewall hooks cannot be integrated automatically.
    command("nft", &args(&["add", "table", "inet", "lab_conflict"]))?;
    command(
        "nft",
        &args(&[
            "add",
            "chain",
            "inet",
            "lab_conflict",
            "forward",
            "{ type filter hook forward priority 1; policy accept; }",
        ]),
    )?;
    check(
        session::preflight(&plan).await.is_err(),
        "foreign firewall accepted",
    )?;
    command("nft", &args(&["delete", "table", "inet", "lab_conflict"]))?;
    // A conflicting ingress policy must be rejected before any network modification.
    command("tc", &args(&["qdisc", "add", "dev", "nc0", "clsact"]))?;
    command(
        "tc",
        &args(&[
            "filter", "add", "dev", "nc0", "ingress", "pref", "123", "matchall", "action", "pass",
        ]),
    )?;
    check(
        session::preflight(&plan).await.is_err(),
        "foreign ingress filter was accepted",
    )?;
    command("tc", &args(&["qdisc", "del", "dev", "nc0", "clsact"]))?;
    // A partial install with an externally pre-created IFB triggers rollback; foreign link survives.
    let mut partial = session::Session::create(plan.clone())?;
    let collision = partial.journal.up.clone();
    command(
        "ip",
        &args(&["link", "add", "name", &collision, "type", "dummy"]),
    )?;
    check(partial.install().is_err(), "expected setup collision")?;
    check(
        partial.recover().is_err(),
        "foreign link ownership should retain a recovery conflict",
    )?;
    command("ip", &args(&["link", "del", "dev", &collision]))?;
    partial.recover()?;
    drop(partial);
    let mut h = Harness::start()?;
    h.send(Request::Observe {
        interface: iface.clone(),
        config: Config::default(),
    })?;
    h.apply(plan.clone())?;
    net(
        &format!("{prefix}-u"),
        "ping",
        &["-c", "1", "-W", "2", "198.18.0.1"],
    )?;
    let tcp = net(
        &format!("{prefix}-a"),
        "iperf3",
        &["-c", "198.18.0.1", "-t", "2", "-J"],
    )?;
    let tcp: serde_json::Value =
        serde_json::from_str(&tcp).map_err(|e| Error::Backend(e.to_string()))?;
    check(
        tcp.get("error").is_none()
            && tcp["end"]["sum_received"]["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "TCP forwarding failed",
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "2", "-W", "2", "198.18.0.1"],
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "1", "-W", "2", "10.77.0.1"],
    )?;
    // Receive a datagram larger than the controller egress MTU. The kernel must
    // fragment when allowed and report failure for DF without breaking small traffic.
    command(
        "ip",
        &args(&[
            "route",
            "add",
            "198.18.0.1/32",
            "via",
            "10.77.0.1",
            "dev",
            "nc0",
            "mtu",
            "1200",
        ]),
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &[
            "-c",
            "1",
            "-W",
            "2",
            "-s",
            "1300",
            "-M",
            "dont",
            "198.18.0.1",
        ],
    )?;
    check(
        net(
            &format!("{prefix}-a"),
            "ping",
            &["-c", "1", "-W", "2", "-s", "1300", "-M", "do", "198.18.0.1"],
        )
        .is_err(),
        "oversized DF packet unexpectedly passed",
    )?;
    command("ip", &args(&["route", "del", "198.18.0.1/32"]))?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "1", "-W", "2", "198.18.0.1"],
    )?;
    for (label, up, down) in [("a", 2_000_000, 4_000_000), ("b", 1_000_000, 3_000_000)] {
        throughput(prefix, label, false, Some(up))?;
        throughput(prefix, label, true, Some(down))?;
    }
    let counters = h
        .counters
        .lock()
        .map_err(|_| Error::Backend("counter lock".into()))?
        .clone();
    check(
        counters.iter().all(|(_, c)| {
            c.upload == EnforcementStatus::TrafficVerified
                && c.download == EnforcementStatus::TrafficVerified
        }),
        "forwarding traffic was not verified in both directions",
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &[
            "-c",
            "1",
            "-W",
            "2",
            "-s",
            "2000",
            "-M",
            "dont",
            "198.18.0.1",
        ],
    )?;
    // Changing a selected identity must suspend management and trigger repair.
    let changed = Peer {
        ip: plan.targets[0].peer.ip,
        mac: Mac([2, 99, 0, 0, 0, 10]),
    };
    // Generate the mapping update from the actual client using an isolated address change.
    net(
        &format!("{prefix}-a"),
        "ip",
        &["link", "set", "nc0", "address", &changed.mac.to_string()],
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "1", "-W", "2", "10.77.0.2"],
    )?;
    let e = h
        .events
        .recv_timeout(Duration::from_secs(8))
        .map_err(|e| Error::Backend(e.to_string()))?;
    // Some queued control events may precede the mapping notification.
    let mut mapping =
        matches!(&e,Event::Error(s) if (s.contains("mapping") && s.contains("changed")));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !mapping && Instant::now() < deadline {
        if let Ok(Event::Error(s)) = h.events.recv_timeout(Duration::from_secs(1)) {
            mapping = s.contains("mapping") && s.contains("changed");
        }
    }
    check(mapping, "IP/MAC change did not suspend enforcement")?;
    net(
        &format!("{prefix}-a"),
        "ip",
        &[
            "link",
            "set",
            "nc0",
            "address",
            &plan.targets[0].peer.mac.to_string(),
        ],
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "1", "-W", "2", "10.77.0.2"],
    )?;
    // Re-observe after suspension and explicitly apply unlimited policies.
    h.send(Request::Observe {
        interface: iface.clone(),
        config: Config::default(),
    })?;
    let mut unlimited = plan.clone();
    for t in &mut unlimited.targets {
        t.policy = BandwidthPolicy::default();
    }
    h.apply(unlimited)?;
    throughput(prefix, "a", false, None)?;
    throughput(prefix, "a", true, None)?;
    h.stop()?;
    check(
        !session::journal_path()?.exists(),
        "normal exit left a journal",
    )?;
    check(
        command("tc", &args(&["-j", "qdisc", "show", "dev", "nc0"]))? == baseline,
        "physical root qdisc changed",
    )?;
    // Independent guardian must recover after SIGKILL (no Rust destructors run).
    let mut crashed = Harness::start()?;
    crashed.send(Request::Observe {
        interface: iface.clone(),
        config: Config::default(),
    })?;
    crashed.apply(plan.clone())?;
    crashed.child.kill()?;
    crashed.child.wait()?;
    let deadline = Instant::now() + Duration::from_secs(12);
    while session::journal_path()?.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    check(
        !session::journal_path()?.exists(),
        "watchdog did not recover after SIGKILL",
    )?;
    check(
        std::fs::read_to_string(system::sysctl_path("nc0")?)?.trim() == "0",
        "forwarding was not restored",
    )?;
    net(
        &format!("{prefix}-a"),
        "ping",
        &["-c", "2", "-W", "2", "198.18.0.1"],
    )?;
    drop(crashed);
    // Stop UI heartbeats while keeping its pipe open: independent timeout cleanup.
    let mut lost_ui = Harness::start()?;
    lost_ui.send(Request::Observe {
        interface: iface,
        config: Config::default(),
    })?;
    lost_ui.apply(plan)?;
    lost_ui.alive.store(false, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(15);
    while (lost_ui.child.try_wait()?.is_none() || session::journal_path()?.exists())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    check(
        lost_ui.child.try_wait()?.is_some() && !session::journal_path()?.exists(),
        "UI heartbeat loss did not restore state",
    )?;
    Ok(())
}
