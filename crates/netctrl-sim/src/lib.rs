//! Deterministic router/controller/client simulation with ARP expiry and token buckets.
use netctrl_core::*;
use netctrl_core::{arp::ArpFrame, packet::PacketSummary};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
};
#[derive(Clone, Debug)]
struct CacheEntry {
    mac: Mac,
    expires: u64,
}
pub struct Simulator {
    pub interface: Interface,
    pub router: Peer,
    pub controller: Peer,
    pub clients: Vec<Peer>,
    pub now_ns: u64,
    caches: BTreeMap<(Ipv4Addr, Ipv4Addr), CacheEntry>,
    buckets: BTreeMap<(Ipv4Addr, bool), TokenBucket>,
    packets: VecDeque<PacketSummary>,
    pub forwarded: BTreeMap<Ipv4Addr, EnforcementCounters>,
    pub forwarding: bool,
    pub isolated: bool,
    pub fail_forwarding: bool,
}
impl Default for Simulator {
    fn default() -> Self {
        Self::new()
    }
}
impl Simulator {
    pub fn new() -> Self {
        let peer = |n| Peer {
            ip: Ipv4Addr::new(192, 0, 2, n),
            mac: Mac([2, 0, 0, 0, 0, n]),
        };
        let controller = peer(2);
        let router = peer(1);
        let interface = Interface {
            index: 1,
            name: "sim0".into(),
            active: true,
            ethernet: true,
            mac: Some(controller.mac),
            addresses: vec![
                config_subnet::Ipv4Net::new(controller.ip, 24)
                    .unwrap_or_else(|_| unreachable!("constant /24")),
            ],
            gateway: Some(router.ip),
            mtu: 1500,
        };
        let mut s = Self {
            interface,
            router,
            controller,
            clients: vec![peer(10), peer(11), peer(12)],
            now_ns: 0,
            caches: BTreeMap::new(),
            buckets: BTreeMap::new(),
            packets: VecDeque::new(),
            forwarded: BTreeMap::new(),
            forwarding: false,
            isolated: false,
            fail_forwarding: false,
        };
        s.restore_caches();
        s
    }
    fn restore_caches(&mut self) {
        for c in &self.clients {
            self.caches.insert(
                (c.ip, self.router.ip),
                CacheEntry {
                    mac: self.router.mac,
                    expires: u64::MAX,
                },
            );
            self.caches.insert(
                (self.router.ip, c.ip),
                CacheEntry {
                    mac: c.mac,
                    expires: u64::MAX,
                },
            );
        }
    }
    pub fn plan(&self, policy: BandwidthPolicy) -> SessionPlan {
        SessionPlan {
            interface: self.interface.clone(),
            subnet: self.interface.addresses[0].trunc(),
            controller: self.controller,
            gateway: self.router,
            targets: self
                .clients
                .iter()
                .map(|p| TargetPolicy {
                    peer: *p,
                    policy: policy.clone(),
                })
                .collect(),
        }
    }
    pub fn cache(&self, owner: Ipv4Addr, ip: Ipv4Addr) -> Option<Mac> {
        self.caches
            .get(&(owner, ip))
            .filter(|e| e.expires > self.now_ns)
            .map(|e| e.mac)
    }
    pub fn advance(&mut self, ns: u64) {
        self.now_ns = self.now_ns.saturating_add(ns);
        self.caches.retain(|_, v| v.expires > self.now_ns);
    }
    pub fn transfer(&mut self, client: Peer, upload: bool, bytes: u64) -> bool {
        let (owner, ip) = if upload {
            (client.ip, self.router.ip)
        } else {
            (self.router.ip, client.ip)
        };
        let redirected = self.cache(owner, ip) == Some(self.controller.mac);
        if !redirected {
            return !self.isolated;
        }
        if !self.forwarding || self.fail_forwarding {
            return false;
        }
        let c = self.forwarded.entry(client.ip).or_default();
        if let Some(b) = self.buckets.get_mut(&(client.ip, upload))
            && !b.allow(bytes, self.now_ns)
        {
            c.dropped += 1;
            return false;
        }
        if upload {
            c.uploaded += bytes;
            c.upload = EnforcementStatus::TrafficVerified;
        } else {
            c.downloaded += bytes;
            c.download = EnforcementStatus::TrafficVerified;
        }
        let external = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        self.packets.push_back(PacketSummary {
            source_mac: Some(if upload { client.mac } else { self.router.mac }),
            destination_mac: Some(self.controller.mac),
            source: if upload { client.ip.into() } else { external },
            destination: if upload { external } else { client.ip.into() },
            bytes,
            outbound: false,
        });
        true
    }
}
impl DiscoveryBackend for Simulator {
    fn interfaces(&mut self) -> Result<Vec<Interface>> {
        Ok(vec![self.interface.clone()])
    }
    fn neighbors(&mut self, index: u32) -> Result<Vec<Peer>> {
        if index != 1 {
            return Err(Error::Invalid("unknown simulator interface".into()));
        }
        if self.isolated {
            return Ok(vec![self.router]);
        }
        Ok(std::iter::once(self.router)
            .chain(self.clients.iter().copied())
            .collect())
    }
}
impl CaptureBackend for Simulator {
    fn next_packet(&mut self) -> Result<Option<PacketSummary>> {
        Ok(self.packets.pop_front())
    }
}
impl ArpTransport for Simulator {
    fn send_arp(&mut self, frame: &ArpFrame) -> Result<()> {
        frame.encode()?;
        if self.isolated {
            return Err(Error::Unsupported("simulated client isolation".into()));
        }
        if frame.operation == 2 {
            self.caches.insert(
                (frame.target.ip, frame.sender.ip),
                CacheEntry {
                    mac: frame.sender.mac,
                    expires: self.now_ns + 60_000_000_000,
                },
            );
        }
        Ok(())
    }
}
impl ForwardingBackend for Simulator {
    fn capabilities(&self) -> Capabilities {
        let c = if self.isolated {
            Capability::Unsupported("client isolation".into())
        } else {
            Capability::Available
        };
        Capabilities {
            discovery: Capability::Available,
            capture: Capability::Available,
            redirection: c.clone(),
            forwarding: c.clone(),
            shaping: c,
            recovery: Capability::Available,
        }
    }
    fn prepare(&mut self, p: &SessionPlan) -> Result<TopologyAssessment> {
        p.validate()?;
        Ok(TopologyAssessment {
            supported: !self.isolated,
            reasons: if self.isolated {
                vec!["simulated client isolation".into()]
            } else {
                vec![]
            },
        })
    }
    fn apply(&mut self, p: &SessionPlan) -> Result<()> {
        if !self.prepare(p)?.supported {
            return Err(Error::Unsupported("simulated isolation".into()));
        }
        if self.fail_forwarding {
            return Err(Error::Backend(
                "simulated forwarding initialization failure".into(),
            ));
        }
        self.buckets.clear();
        self.forwarded.clear();
        for t in &p.targets {
            for (upload, bps) in [(true, t.policy.upload_bps), (false, t.policy.download_bps)] {
                if let Some(bps) = bps {
                    self.buckets.insert(
                        (t.peer.ip, upload),
                        TokenBucket::new(bps / 8, (bps / 8 / 10).max(3000), self.now_ns)?,
                    );
                }
            }
            self.forwarded.insert(
                t.peer.ip,
                EnforcementCounters {
                    upload: EnforcementStatus::AppliedUnverified,
                    download: EnforcementStatus::AppliedUnverified,
                    ..Default::default()
                },
            );
            self.send_arp(&ArpFrame::reply(
                Peer {
                    ip: self.router.ip,
                    mac: self.controller.mac,
                },
                t.peer,
            ))?;
            self.send_arp(&ArpFrame::reply(
                Peer {
                    ip: t.peer.ip,
                    mac: self.controller.mac,
                },
                self.router,
            ))?;
        }
        self.forwarding = true;
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        self.forwarding = false;
        self.buckets.clear();
        self.restore_caches();
        Ok(())
    }
}
impl ShapingBackend for Simulator {
    fn counters(&mut self) -> Result<Vec<(Ipv4Addr, EnforcementCounters)>> {
        Ok(self
            .forwarded
            .iter()
            .map(|(ip, c)| (*ip, c.clone()))
            .collect())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_limits_expiry_and_recovery() -> Result<()> {
        let mut s = Simulator::new();
        let p = s.plan(BandwidthPolicy {
            upload_bps: Some(80_000),
            download_bps: None,
        });
        s.apply(&p)?;
        let c = s.clients[0];
        assert_eq!(s.cache(c.ip, s.router.ip), Some(s.controller.mac));
        assert!(s.transfer(c, true, 3000));
        assert!(!s.transfer(c, true, 1));
        s.advance(1_000_000_000);
        assert!(s.transfer(c, true, 3000));
        assert!(s.transfer(c, false, 1_000_000));
        s.advance(61_000_000_000);
        assert_eq!(s.cache(c.ip, s.router.ip), None);
        s.restore()?;
        assert_eq!(s.cache(c.ip, s.router.ip), Some(s.router.mac));
        Ok(())
    }
    #[test]
    fn unsupported_never_succeeds() -> Result<()> {
        let mut s = Simulator::new();
        s.isolated = true;
        let p = s.plan(BandwidthPolicy::default());
        assert!(!s.prepare(&p)?.supported);
        assert!(s.apply(&p).is_err());
        assert!(!s.capabilities().forwarding.available());
        Ok(())
    }
    #[test]
    fn independent_clients_and_failure() -> Result<()> {
        let mut s = Simulator::new();
        let p = s.plan(BandwidthPolicy {
            upload_bps: Some(80_000),
            download_bps: None,
        });
        s.apply(&p)?;
        assert!(s.transfer(s.clients[0], true, 3000));
        assert!(s.transfer(s.clients[1], true, 3000));
        s.fail_forwarding = true;
        assert!(!s.transfer(s.clients[1], false, 1500));
        s.restore()?;
        assert!(s.transfer(s.clients[1], false, 1500));
        Ok(())
    }
}
