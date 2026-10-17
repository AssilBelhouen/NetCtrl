use netctrl_core::arp::ArpFrame;
use netctrl_core::*;
use netctrl_engine::*;
use std::{
    collections::BTreeMap,
    io::{BufReader, BufWriter},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
struct ScanState {
    targets: Vec<std::net::Ipv4Addr>,
    index: usize,
    round: u8,
    next: Instant,
    scope: config_subnet::Ipv4Net,
    peers: BTreeMap<(std::net::Ipv4Addr, Mac), Peer>,
    pps: u32,
}
fn err(e: impl std::fmt::Display) -> Error {
    Error::Backend(format!("libpcap: {e}"))
}
fn open(
    name: &str,
    config: &Config,
    direction: pcap::Direction,
    filter: &str,
) -> Result<pcap::Capture<pcap::Active>> {
    let mut c = pcap::Capture::from_device(name)
        .map_err(err)?
        .promisc(config.promiscuous)
        .snaplen(config.capture_snaplen)
        .buffer_size(config.capture_buffer_bytes)
        .immediate_mode(true)
        .timeout(10)
        .open()
        .map_err(err)?;
    if c.get_datalink() != pcap::Linktype::ETHERNET {
        return Err(Error::Unsupported(
            "live capture requires Ethernet framing; cooked/tunnel interfaces are unavailable"
                .into(),
        ));
    }
    c.direction(direction).map_err(err)?;
    c.filter(filter, true).map_err(err)?;
    c.setnonblock().map_err(err)
}
fn send(cap: &mut pcap::Capture<pcap::Active>, frame: ArpFrame) -> Result<()> {
    cap.sendpacket(frame.encode()?.as_slice()).map_err(err)
}
fn redirect(cap: &mut pcap::Capture<pcap::Active>, p: &SessionPlan, restore: bool) -> Result<()> {
    for t in &p.targets {
        let gateway = if restore {
            p.gateway
        } else {
            Peer {
                ip: p.gateway.ip,
                mac: p.controller.mac,
            }
        };
        let client = if restore {
            t.peer
        } else {
            Peer {
                ip: t.peer.ip,
                mac: p.controller.mac,
            }
        };
        let mut to_client = ArpFrame::reply(gateway, t.peer);
        let mut to_gateway = ArpFrame::reply(client, p.gateway);
        // Keep Ethernet source as the controller during repair to avoid moving switch FDB entries.
        to_client.source = p.controller.mac;
        to_gateway.source = p.controller.mac;
        send(cap, to_client.clone())?;
        send(cap, to_gateway.clone())?;
        // Directed requests also initialize an empty ARP cache without broadcasting a forged mapping.
        to_client.operation = 1;
        to_gateway.operation = 1;
        send(cap, to_client)?;
        send(cap, to_gateway)?;
    }
    Ok(())
}
pub fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--check") {
        println!(
            "libpcap loaded; {} adapters",
            pcap::Device::list().map_err(err)?.len()
        );
        return Ok(());
    }
    // SAFETY: geteuid has no pointer arguments or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Permission(
            "capture must be launched by the privileged helper".into(),
        ));
    }
    let mut stdin = BufReader::new(std::io::stdin());
    if std::env::args().nth(1).as_deref() == Some("--repair") {
        let p: SessionPlan =
            read_frame(&mut stdin)?.ok_or_else(|| Error::Invalid("repair plan missing".into()))?;
        p.validate()?;
        let mut cap = open(
            &p.interface.name,
            &Config::default(),
            pcap::Direction::In,
            "arp",
        )?;
        for _ in 0..5 {
            redirect(&mut cap, &p, true)?;
            std::thread::sleep(Duration::from_millis(200));
        }
        return Ok(());
    }
    let init: WorkerInit = read_frame(&mut stdin)?
        .ok_or_else(|| Error::Invalid("worker configuration missing".into()))?;
    init.config.validate()?;
    validate_interface_name(&init.interface.name)?;
    let addr = *init
        .interface
        .addresses
        .first()
        .ok_or_else(|| Error::Invalid("interface has no IPv4".into()))?;
    let controller = Peer {
        ip: addr.addr(),
        mac: init
            .interface
            .mac
            .ok_or_else(|| Error::Invalid("interface has no MAC".into()))?,
    };
    let mut cap = open(
        &init.interface.name,
        &init.config,
        pcap::Direction::In,
        "arp or ip or ip6",
    )?;
    let mut outgoing = open(
        &init.interface.name,
        &init.config,
        pcap::Direction::Out,
        &format!("(ip and src host {}) or ip6", controller.ip),
    )?;
    let (commands_tx, commands_rx) = mpsc::sync_channel(64);
    std::thread::spawn(move || {
        loop {
            match read_frame::<_, WorkerRequest>(&mut stdin) {
                Ok(Some(r)) => {
                    if commands_tx.send(r).is_err() {
                        break;
                    }
                }
                _ => {
                    let _ = commands_tx.send(WorkerRequest::Stop);
                    break;
                }
            }
        }
    });
    let (events_tx, events_rx) = mpsc::sync_channel(4096);
    let dropped = Arc::new(AtomicU32::new(0));
    std::thread::spawn(move || {
        let mut out = BufWriter::new(std::io::stdout());
        for e in events_rx {
            if write_frame(&mut out, &e).is_err() {
                break;
            }
        }
    });
    let emit = |event| {
        if events_tx.try_send(event).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    };
    emit(Event::Ready);
    let mut scan: Option<ScanState> = None;
    let mut plan = None;
    let mut next_redirect = Instant::now();
    let mut stats = Instant::now();
    let mut known = BTreeMap::new();
    loop {
        while let Ok(r) = commands_rx.try_recv() {
            match r {
                WorkerRequest::Stop => return Ok(()),
                WorkerRequest::Redirect(p) => {
                    p.validate()?;
                    if p.interface != init.interface {
                        return Err(Error::Conflict("worker interface differs".into()));
                    }
                    plan = Some(p);
                    next_redirect = Instant::now();
                }
                WorkerRequest::Repair(p) => {
                    p.validate()?;
                    plan = None;
                    for _ in 0..3 {
                        redirect(&mut cap, &p, true)?;
                    }
                }
                WorkerRequest::Scan {
                    targets,
                    scope,
                    probes_per_sec,
                } => {
                    if scan.is_some() {
                        emit(Event::Error("scan already in progress".into()));
                        continue;
                    }
                    let allowed = scan_hosts(addr, scope, 4096)?;
                    if targets.len() > 4096
                        || targets.iter().any(|ip| !allowed.contains(ip))
                        || !(1..=500).contains(&probes_per_sec)
                    {
                        return Err(Error::Invalid("worker scan scope/rate".into()));
                    }
                    scan = Some(ScanState {
                        targets,
                        index: 0,
                        round: 0,
                        next: Instant::now(),
                        scope,
                        peers: BTreeMap::new(),
                        pps: probes_per_sec,
                    });
                }
            }
        }
        if let Some(p) = &plan
            && Instant::now() >= next_redirect
        {
            redirect(&mut cap, p, false)?;
            next_redirect = Instant::now() + Duration::from_secs(2);
        }
        let mut finished = false;
        if let Some(ScanState {
            targets,
            index,
            round,
            next,
            pps,
            ..
        }) = &mut scan
            && Instant::now() >= *next
        {
            if *index < targets.len() {
                if targets[*index] != controller.ip {
                    send(&mut cap, ArpFrame::request(controller, targets[*index]))?;
                }
                *index += 1;
                *next = Instant::now() + Duration::from_micros(1_000_000 / u64::from(*pps));
            } else if *round == 0 {
                *round = 1;
                *index = 0;
                *next = Instant::now() + Duration::from_secs(1);
            } else {
                finished = true;
            }
        }
        if finished && let Some(ScanState { scope, peers, .. }) = scan.take() {
            emit(Event::ScanComplete {
                scope,
                peers: peers.into_values().collect(),
            });
        }
        for (capture, outbound) in [(&mut cap, false), (&mut outgoing, true)] {
            for _ in 0..512 {
                match capture.next_packet() {
                    Ok(packet) => {
                        if !outbound
                            && let Ok(a) = ArpFrame::decode(packet.data)
                            && a.source == a.sender.mac
                            && addr.contains(&a.sender.ip)
                            && a.sender.mac != controller.mac
                        {
                            if let Some(ScanState { scope, peers, .. }) = &mut scan
                                && scope.contains(&a.sender.ip)
                            {
                                peers.insert((a.sender.ip, a.sender.mac), a.sender);
                            }
                            emit(Event::Neighbor(a.sender));
                        }
                        if let Ok(Some(mut p)) =
                            netctrl_core::packet::parse_ethernet(packet.data, packet.header.len)
                        {
                            p.outbound = outbound;
                            if !outbound
                                && let (std::net::IpAddr::V4(ip), Some(mac)) =
                                    (p.source, p.source_mac)
                                && addr.contains(&ip)
                                && mac != controller.mac
                                && mac.is_unicast()
                                && known.insert(ip, mac) != Some(mac)
                            {
                                emit(Event::Neighbor(Peer { ip, mac }));
                            }
                            emit(Event::Packet(p));
                        }
                    }
                    Err(pcap::Error::NoMorePackets) | Err(pcap::Error::TimeoutExpired) => break,
                    Err(e) => return Err(err(e)),
                }
            }
        }
        if stats.elapsed() >= Duration::from_secs(1) {
            let s = cap.stats().map_err(err)?;
            let o = outgoing.stats().map_err(err)?;
            emit(Event::CaptureStats {
                received: s.received.saturating_add(o.received),
                dropped: s
                    .dropped
                    .saturating_add(o.dropped)
                    .saturating_add(dropped.load(Ordering::Relaxed)),
            });
            stats = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
