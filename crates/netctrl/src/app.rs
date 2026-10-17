use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use netctrl_core::*;
use netctrl_engine::*;
use netctrl_sim::Simulator;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Clone, Debug)]
pub enum Modal {
    None,
    Help,
    Details,
    Interfaces {
        cursor: usize,
    },
    Limits {
        device: DeviceId,
        field: bool,
        up: String,
        down: String,
    },
    Confirm {
        revision: u64,
        plan: SessionPlan,
        changes: Vec<String>,
    },
    EnableScan,
}
pub struct App {
    pub config: Config,
    pub config_path: PathBuf,
    pub interfaces: Vec<Interface>,
    pub interface_index: usize,
    pub registry: Registry,
    pub traffic: TrafficBook,
    pub enforcement: BTreeMap<Ipv4Addr, EnforcementCounters>,
    pub selected: usize,
    pub panel: usize,
    pub modal: Modal,
    pub message: String,
    pub active: bool,
    pub scan_running: bool,
    pub capture_dropped: u32,
    pub capture_received: u32,
    pub started: Instant,
    pub last_sample: Instant,
    pub last_scan: Instant,
    pub sim: Option<Simulator>,
    pub quitting: bool,
    pub needs_observe: bool,
    pub dns_queued: BTreeSet<DeviceId>,
}
impl App {
    pub fn new(
        config: Config,
        path: PathBuf,
        interfaces: Vec<Interface>,
        demo: bool,
    ) -> Result<Self> {
        let index = config
            .interface
            .as_ref()
            .and_then(|n| interfaces.iter().position(|i| &i.name == n))
            .or_else(|| {
                interfaces
                    .iter()
                    .position(|i| i.active && i.gateway.is_some())
            })
            .unwrap_or(0);
        let mut a = Self {
            config,
            config_path: path,
            interfaces,
            interface_index: index,
            registry: Registry::default(),
            traffic: TrafficBook::default(),
            enforcement: BTreeMap::new(),
            selected: 0,
            panel: 0,
            modal: Modal::None,
            message: "Observation shows only traffic visible on this interface".into(),
            active: false,
            scan_running: false,
            capture_dropped: 0,
            capture_received: 0,
            started: Instant::now(),
            last_sample: Instant::now(),
            last_scan: Instant::now(),
            sim: None,
            quitting: false,
            needs_observe: !demo,
            dns_queued: BTreeSet::new(),
        };
        if demo {
            let mut sim = Simulator::new();
            a.interfaces = vec![sim.interface.clone()];
            a.interface_index = 0;
            a.config.mode = Mode::Simulation;
            let p = sim.plan(BandwidthPolicy {
                upload_bps: Some(2_000_000),
                download_bps: Some(4_000_000),
            });
            sim.apply(&p)?;
            a.config.policies = p
                .targets
                .iter()
                .map(|t| SavedPolicy {
                    device: DeviceId {
                        interface: 1,
                        mac: t.peer.mac,
                    },
                    policy: t.policy.clone(),
                })
                .collect();
            a.active = true;
            for peer in sim.neighbors(1)? {
                let id = a.registry.observe(1, peer, 0);
                if let Some(d) = a.registry.get_mut(id) {
                    d.hostname = Some(if peer == sim.router {
                        "router.sim".into()
                    } else {
                        format!("device-{}.sim", peer.ip.octets()[3])
                    });
                }
            }
            a.registry.observe(1, sim.controller, 0);
            a.sim = Some(sim);
            a.needs_observe = false;
        }
        Ok(a)
    }
    pub fn interface(&self) -> Option<&Interface> {
        self.interfaces.get(self.interface_index)
    }
    pub fn devices(&self) -> Vec<&Device> {
        let idx = self.interface().map(|i| i.index);
        let mut d: Vec<_> = self
            .registry
            .devices()
            .filter(|d| Some(d.id.interface) == idx)
            .collect();
        d.sort_by_key(|d| d.addresses.first().copied());
        d
    }
    pub fn selected_device(&self) -> Option<Device> {
        self.devices().get(self.selected).map(|d| (*d).clone())
    }
    pub fn policy(&self, id: DeviceId) -> BandwidthPolicy {
        self.config
            .policies
            .iter()
            .find(|p| p.device == id)
            .map(|p| p.policy.clone())
            .unwrap_or_default()
    }
    pub fn save(&mut self) {
        if self.sim.is_none()
            && let Err(e) = self.config.save(&self.config_path)
        {
            self.message = e.to_string();
        }
    }
    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
    pub fn observe_peer(&mut self, peer: Peer) {
        if let Some(i) = self.interface()
            && i.addresses.iter().any(|a| a.contains(&peer.ip))
            && peer.mac.is_unicast()
        {
            self.registry.observe(i.index, peer, self.now_ms());
        }
    }
    pub fn packet(&mut self, p: netctrl_core::packet::PacketSummary) {
        let Some(i) = self.interface().cloned() else {
            return;
        };
        // Forwarded IPv4 is already counted on ingress. Defense in depth for
        // mock/alternative workers in addition to the live outbound BPF filter.
        if p.outbound
            && let IpAddr::V4(source) = p.source
            && !i.addresses.iter().any(|a| a.addr() == source)
        {
            return;
        }
        let local = |ip: &Ipv4Addr| i.addresses.iter().any(|a| a.contains(ip));
        for (ip, mac, upload) in [
            (p.source, p.source_mac, true),
            (p.destination, p.destination_mac, false),
        ] {
            let id = match ip {
                IpAddr::V4(ip) if local(&ip) => {
                    if upload
                        && !p.outbound
                        && let Some(mac) = mac
                        && Some(mac) != i.mac
                        && Some(ip) != i.gateway
                    {
                        self.observe_peer(Peer { ip, mac });
                    }
                    self.registry
                        .devices()
                        .find(|d| d.id.interface == i.index && d.addresses.contains(&ip))
                        .map(|d| d.id)
                }
                IpAddr::V6(_) => mac.and_then(|mac| {
                    self.registry
                        .devices()
                        .find(|d| {
                            d.id.interface == i.index
                                && d.id.mac == mac
                                && !d.addresses.iter().any(|a| Some(*a) == i.gateway)
                        })
                        .map(|d| d.id)
                }),
                _ => None,
            };
            if let Some(id) = id {
                if let Some(d) = self.registry.get_mut(id)
                    && ip.is_ipv6()
                {
                    d.ipv6_seen = true;
                }
                self.traffic.record(id, upload, p.bytes);
            }
        }
    }
    pub fn event(&mut self, e: Event) {
        match e {
            Event::Ready => {
                self.message =
                    "Capture/helper ready; traffic visibility is interface-dependent".into();
            }
            Event::Error(s) => {
                self.scan_running = false;
                tracing::warn!(message=%s,"backend error");
                self.message = sanitize(&s);
            }
            Event::Message(s) => self.message = sanitize(&s),
            Event::Packet(p) => self.packet(p),
            Event::Neighbor(p) => self.observe_peer(p),
            Event::ScanComplete { scope, peers } => {
                if let Some(i) = self.interface() {
                    let idx = i.index;
                    self.registry.complete_scan(idx, scope, &peers);
                }
                for p in peers {
                    self.observe_peer(p);
                }
                self.scan_running = false;
                self.last_scan = Instant::now();
                self.message =
                    "ARP scan complete; silence may mean isolation, sleep or filtering".into();
            }
            Event::CaptureStats { received, dropped } => {
                self.capture_received = received;
                self.capture_dropped = dropped;
            }
            Event::Prepared {
                revision,
                plan,
                changes,
            } => {
                self.modal = Modal::Confirm {
                    revision,
                    plan,
                    changes,
                }
            }
            Event::Applied => {
                self.active = true;
                self.enforcement.clear();
                self.message="Policies applied; awaiting per-direction traffic verification. IPv6 can bypass.".into();
            }
            Event::Counters(c) => self.enforcement = c.into_iter().collect(),
            Event::Recovered => {
                self.active = false;
                self.scan_running = false;
                self.enforcement.clear();
                self.message =
                    "Owned network state restored; remote ARP correction is best effort".into();
            }
        }
    }
    pub fn scan(&mut self) -> Result<Option<Request>> {
        if self.scan_running {
            return Err(Error::Conflict("scan is already running".into()));
        }
        if let Some(s) = &mut self.sim {
            let peers = s.neighbors(1)?;
            for p in peers {
                self.observe_peer(p);
            }
            self.last_scan = Instant::now();
            return Ok(None);
        }
        let i = self
            .interface()
            .ok_or_else(|| Error::Invalid("select an interface".into()))?;
        let subnet = *i
            .addresses
            .first()
            .ok_or_else(|| Error::Invalid("interface has no IPv4".into()))?;
        let scope = self.config.scan_subnet.unwrap_or(subnet.trunc());
        scan_hosts(subnet, scope, self.config.max_scan_hosts)?;
        self.scan_running = true;
        self.last_scan = Instant::now();
        self.message = "Bounded local ARP scan in progress".into();
        Ok(Some(Request::Scan { scope }))
    }
    pub fn plan(&self) -> Result<SessionPlan> {
        let i = self
            .interface()
            .ok_or_else(|| Error::Invalid("select an interface".into()))?
            .clone();
        let subnet = *i
            .addresses
            .first()
            .ok_or_else(|| Error::Invalid("interface has no IPv4".into()))?;
        let gateway_ip = i.gateway.ok_or_else(|| {
            Error::Unsupported("selected interface has no default gateway".into())
        })?;
        let gateway = self
            .devices()
            .into_iter()
            .find(|d| d.addresses.contains(&gateway_ip) && d.presence != Presence::Conflict)
            .map(|d| Peer {
                ip: gateway_ip,
                mac: d.id.mac,
            })
            .ok_or_else(|| Error::Invalid("gateway MAC unresolved; scan first".into()))?;
        let mut targets = vec![];
        for saved in &self.config.policies {
            if saved.device.interface != i.index {
                continue;
            }
            let d = self.registry.get(saved.device).ok_or_else(|| {
                Error::Conflict("saved device is not currently discovered".into())
            })?;
            if d.presence != Presence::Online || d.addresses.len() != 1 {
                return Err(Error::Conflict(
                    "target identity is stale, conflicting, or has multiple IPv4 addresses".into(),
                ));
            }
            targets.push(TargetPolicy {
                peer: Peer {
                    ip: d.addresses[0],
                    mac: d.id.mac,
                },
                policy: saved.policy.clone(),
            });
        }
        let p = SessionPlan {
            interface: i.clone(),
            subnet: subnet.trunc(),
            controller: Peer {
                ip: subnet.addr(),
                mac: i
                    .mac
                    .ok_or_else(|| Error::Invalid("interface MAC missing".into()))?,
            },
            gateway,
            targets,
        };
        p.validate()?;
        Ok(p)
    }
    pub fn tick(&mut self) -> Result<()> {
        if let Some(s) = &mut self.sim {
            s.advance(100_000_000);
            let peers = s.clients.clone();
            for c in peers {
                for _ in 0..20 {
                    s.transfer(c, true, 1500);
                    s.transfer(c, false, 1500);
                }
            }
            let mut packets = vec![];
            while let Some(p) = s.next_packet()? {
                packets.push(p);
            }
            let counters = s.counters()?;
            for p in packets {
                self.packet(p);
            }
            self.enforcement = counters.into_iter().collect();
        }
        let elapsed = self.last_sample.elapsed();
        if elapsed >= Duration::from_millis(self.config.sample_interval_ms) {
            let limit =
                (self.config.history_secs * 1000 / self.config.sample_interval_ms).max(1) as usize;
            self.traffic.sample(elapsed, limit);
            self.last_sample = Instant::now();
            self.registry
                .age(self.now_ms(), self.config.scan_interval_secs * 3000);
        }
        Ok(())
    }
    pub fn key(&mut self, key: KeyEvent) -> Result<Vec<Request>> {
        if key.kind == KeyEventKind::Release {
            return Ok(vec![]);
        }
        let mut requests = vec![];
        match self.modal.clone() {
            Modal::Help | Modal::Details => {
                self.modal = Modal::None;
                return Ok(requests);
            }
            Modal::Confirm { revision, plan, .. } => {
                match key.code {
                    KeyCode::Char('y' | 'Y') => {
                        self.modal = Modal::None;
                        if let Some(s) = &mut self.sim {
                            s.apply(&plan)?;
                            self.active = true;
                        } else {
                            requests.push(Request::Apply { revision });
                        }
                    }
                    KeyCode::Char('n' | 'N') | KeyCode::Esc => self.modal = Modal::None,
                    _ => {}
                }
                return Ok(requests);
            }
            Modal::EnableScan => {
                match key.code {
                    KeyCode::Char('y' | 'Y') => {
                        self.config.active_discovery = true;
                        self.save();
                        self.modal = Modal::None;
                        if let Some(r) = self.scan()? {
                            requests.push(r);
                        }
                    }
                    KeyCode::Char('n' | 'N') | KeyCode::Esc => self.modal = Modal::None,
                    _ => {}
                }
                return Ok(requests);
            }
            Modal::Limits {
                device,
                mut field,
                mut up,
                mut down,
            } => {
                match key.code {
                    KeyCode::Esc => self.modal = Modal::None,
                    KeyCode::Tab => {
                        field = !field;
                        self.modal = Modal::Limits {
                            device,
                            field,
                            up,
                            down,
                        };
                    }
                    KeyCode::Backspace => {
                        if field {
                            down.pop();
                        } else {
                            up.pop();
                        }
                        self.modal = Modal::Limits {
                            device,
                            field,
                            up,
                            down,
                        };
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() || c == '.' || c == 'u' => {
                        let s = if field { &mut down } else { &mut up };
                        if s.len() < 16 {
                            s.push(c);
                        }
                        self.modal = Modal::Limits {
                            device,
                            field,
                            up,
                            down,
                        };
                    }
                    KeyCode::Enter => {
                        let policy = BandwidthPolicy {
                            upload_bps: parse_rate(&up)?,
                            download_bps: parse_rate(&down)?,
                        };
                        policy.validate()?;
                        self.config.policies.retain(|p| p.device != device);
                        self.config.policies.push(SavedPolicy { device, policy });
                        self.save();
                        self.modal = Modal::None;
                        if self.active {
                            let plan = self.plan()?;
                            if self.sim.is_some() {
                                self.modal = Modal::Confirm {
                                    revision: 0,
                                    plan,
                                    changes: vec!["Replace simulated limits".into()],
                                };
                            } else {
                                requests.push(Request::Prepare { plan });
                            }
                        } else {
                            self.message="Desired limits saved. M prepares live Manage mode with confirmation.".into();
                        }
                    }
                    _ => {}
                }
                return Ok(requests);
            }
            Modal::Interfaces { mut cursor } => {
                match key.code {
                    KeyCode::Esc => self.modal = Modal::None,
                    KeyCode::Up => {
                        cursor = cursor.saturating_sub(1);
                        self.modal = Modal::Interfaces { cursor };
                    }
                    KeyCode::Down => {
                        if !self.interfaces.is_empty() {
                            cursor = (cursor + 1).min(self.interfaces.len() - 1);
                            self.modal = Modal::Interfaces { cursor };
                        }
                    }
                    KeyCode::Enter => {
                        if self.active {
                            return Err(Error::Conflict(
                                "stop enforcement with M before changing interface".into(),
                            ));
                        }
                        self.modal = Modal::None;
                        self.interface_index = cursor;
                        self.selected = 0;
                        self.scan_running = false;
                        self.enforcement.clear();
                        self.config.interface = self.interface().map(|i| i.name.clone());
                        self.save();
                        self.needs_observe = true;
                    }
                    _ => {}
                }
                return Ok(requests);
            }
            Modal::None => {}
        }
        match key.code {
            KeyCode::Char('q' | 'Q') => self.quitting = true,
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.devices().len().saturating_sub(1))
            }
            KeyCode::Enter => self.modal = Modal::Details,
            KeyCode::Tab => self.panel = (self.panel + 1) % 3,
            KeyCode::Char('h' | 'H') => self.modal = Modal::Help,
            KeyCode::Char('i' | 'I') => {
                if self.active {
                    return Err(Error::Conflict(
                        "stop enforcement before choosing an interface".into(),
                    ));
                }
                self.modal = Modal::Interfaces {
                    cursor: self.interface_index,
                };
            }
            KeyCode::Char('s' | 'S') => {
                if !self.config.active_discovery && self.sim.is_none() {
                    self.modal = Modal::EnableScan;
                } else if let Some(r) = self.scan()? {
                    requests.push(r);
                }
            }
            KeyCode::Char('r' | 'R') => {
                self.traffic.sample(
                    self.last_sample.elapsed(),
                    (self.config.history_secs * 1000 / self.config.sample_interval_ms).max(1)
                        as usize,
                );
                self.last_sample = Instant::now();
                self.message = "Statistics sampled; totals preserved".into();
            }
            KeyCode::Char('x' | 'X') => {
                requests.push(Request::Recover);
                self.message = "Recovery requested".into();
            }
            KeyCode::Char('l' | 'L') => {
                let d = self
                    .selected_device()
                    .ok_or_else(|| Error::Invalid("select a device".into()))?;
                let i = self
                    .interface()
                    .ok_or_else(|| Error::Invalid("interface missing".into()))?;
                if Some(d.id.mac) == i.mac || d.addresses.iter().any(|ip| Some(*ip) == i.gateway) {
                    return Err(Error::Invalid(
                        "controller and gateway are protected".into(),
                    ));
                }
                let p = self.policy(d.id);
                self.modal = Modal::Limits {
                    device: d.id,
                    field: false,
                    up: format_rate_input(p.upload_bps),
                    down: format_rate_input(p.download_bps),
                };
            }
            KeyCode::Char('m' | 'M') => {
                if self.active {
                    if let Some(s) = &mut self.sim {
                        s.restore()?;
                        self.active = false;
                        self.enforcement.clear();
                    } else {
                        requests.push(Request::Stop);
                    }
                    self.config.mode = Mode::Monitor;
                    self.save();
                } else {
                    let plan = self.plan()?;
                    self.config.mode = if self.sim.is_some() {
                        Mode::Simulation
                    } else {
                        Mode::Manage
                    };
                    self.save();
                    if self.sim.is_some() {
                        self.modal = Modal::Confirm {
                            revision: 0,
                            plan,
                            changes: vec![
                                "Apply simulated ARP redirection and token buckets".into(),
                            ],
                        };
                    } else {
                        requests.push(Request::Prepare { plan });
                    }
                }
            }
            _ => {}
        }
        Ok(requests)
    }
}
pub fn parse_rate(s: &str) -> Result<Option<u64>> {
    if s.trim().is_empty() || s.trim() == "u" {
        return Ok(None);
    }
    let n: f64 = s
        .parse()
        .map_err(|_| Error::Invalid("enter Mbps, or u for unlimited".into()))?;
    if !n.is_finite() || n <= 0.0 || n > 1_000_000.0 {
        return Err(Error::Invalid("Mbps must be positive".into()));
    }
    let b = (n * 1_000_000.0).round() as u64;
    BandwidthPolicy {
        upload_bps: Some(b),
        download_bps: None,
    }
    .validate()?;
    Ok(Some(b))
}
pub fn format_rate_input(n: Option<u64>) -> String {
    n.map(|n| format!("{}", n as f64 / 1_000_000.0))
        .unwrap_or("u".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_and_protection() -> Result<()> {
        let mut a = App::new(Config::default(), PathBuf::from("unused"), vec![], true)?;
        a.selected = 0;
        assert!(
            a.key(KeyEvent::new(
                KeyCode::Char('l'),
                crossterm::event::KeyModifiers::NONE
            ))
            .is_err()
        );
        assert_eq!(parse_rate("1.5")?, Some(1_500_000));
        assert!(parse_rate("0").is_err());
        assert!(parse_rate("NaN").is_err());
        assert_eq!(parse_rate("u")?, None);
        Ok(())
    }
    #[test]
    fn cancel_interface_preview_and_manage_confirmation() -> Result<()> {
        let mut a = App::new(Config::default(), PathBuf::from("unused"), vec![], true)?;
        a.active = false;
        let mut other = a.interfaces[0].clone();
        other.index = 2;
        other.name = "sim1".into();
        a.interfaces.push(other);
        let key = |code| KeyEvent::new(code, crossterm::event::KeyModifiers::NONE);
        a.key(key(KeyCode::Char('i')))?;
        a.key(key(KeyCode::Down))?;
        a.key(key(KeyCode::Esc))?;
        assert_eq!(a.interface_index, 0);
        a.key(key(KeyCode::Char('m')))?;
        assert!(matches!(a.modal, Modal::Confirm { .. }));
        a.key(key(KeyCode::Char('n')))?;
        assert!(!a.active);
        Ok(())
    }
    #[test]
    fn forwarded_capture_is_counted_once() -> Result<()> {
        let mut a = App::new(Config::default(), PathBuf::from("unused"), vec![], true)?;
        let c = a
            .sim
            .as_ref()
            .ok_or_else(|| Error::Backend("sim missing".into()))?
            .clients[0];
        let mut p = netctrl_core::packet::PacketSummary {
            source: c.ip.into(),
            destination: Ipv4Addr::new(203, 0, 113, 1).into(),
            source_mac: Some(c.mac),
            destination_mac: a.interface().and_then(|i| i.mac),
            bytes: 1000,
            outbound: false,
        };
        a.packet(p.clone());
        p.outbound = true;
        a.packet(p);
        let id = DeviceId {
            interface: 1,
            mac: c.mac,
        };
        assert_eq!(a.traffic.entries.get(&id).map(|t| t.uploaded), Some(1000));
        Ok(())
    }
}
