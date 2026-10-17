//! Portable domain model, validation, packet accounting and backend contracts.
pub mod arp;
pub mod config;
pub mod packet;
pub mod registry;
pub mod traffic;
pub use config::*;
use ipnet::Ipv4Net;
pub use registry::*;
use serde::{Deserialize, Serialize};
use std::{fmt, net::Ipv4Addr, str::FromStr};
pub use traffic::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("missing dependency: {0}")]
    Dependency(String),
    #[error("conflicting state: {0}")]
    Conflict(String),
    #[error("backend failure: {0}")]
    Backend(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Mac(pub [u8; 6]);
impl Mac {
    pub fn is_unicast(self) -> bool {
        self.0 != [0; 6] && self.0[0] & 1 == 0
    }
}
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            a[0], a[1], a[2], a[3], a[4], a[5]
        )
    }
}
impl FromStr for Mac {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut a = [0; 6];
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(Error::Invalid("MAC must have six octets".into()));
        }
        for (i, p) in parts.iter().enumerate() {
            if p.len() != 2 {
                return Err(Error::Invalid("invalid MAC octet".into()));
            }
            a[i] = u8::from_str_radix(p, 16).map_err(|_| Error::Invalid("invalid MAC".into()))?;
        }
        Ok(Self(a))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub active: bool,
    pub ethernet: bool,
    pub mac: Option<Mac>,
    pub addresses: Vec<Ipv4Net>,
    pub gateway: Option<Ipv4Addr>,
    pub mtu: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId {
    pub interface: u32,
    pub mac: Mac,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub mac: Mac,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPlan {
    pub interface: Interface,
    pub subnet: Ipv4Net,
    pub controller: Peer,
    pub gateway: Peer,
    pub targets: Vec<TargetPolicy>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPolicy {
    pub peer: Peer,
    pub policy: BandwidthPolicy,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthPolicy {
    /// None means unlimited. Zero is invalid, never an implicit block.
    pub upload_bps: Option<u64>,
    pub download_bps: Option<u64>,
}
impl BandwidthPolicy {
    pub fn validate(&self) -> Result<()> {
        for n in [self.upload_bps, self.download_bps].into_iter().flatten() {
            if !(1_000..=1_000_000_000_000).contains(&n) {
                return Err(Error::Invalid(
                    "rate must be 1000..=10^12 bps, or unlimited".into(),
                ));
            }
        }
        Ok(())
    }
}
impl SessionPlan {
    pub fn validate(&self) -> Result<()> {
        validate_interface_name(&self.interface.name)?;
        if !self.interface.active || !self.interface.ethernet {
            return Err(Error::Unsupported(
                "requires an active Ethernet-compatible interface".into(),
            ));
        }
        if self.interface.mac != Some(self.controller.mac)
            || !self
                .interface
                .addresses
                .iter()
                .any(|a| a.addr() == self.controller.ip && a.trunc() == self.subnet.trunc())
        {
            return Err(Error::Conflict("controller identity/subnet changed".into()));
        }
        if self.interface.gateway != Some(self.gateway.ip)
            || self.gateway.mac == self.controller.mac
        {
            return Err(Error::Conflict(
                "gateway identity is unavailable or invalid".into(),
            ));
        }
        if self.targets.is_empty() || self.targets.len() > 128 {
            return Err(Error::Invalid("select 1..=128 devices".into()));
        }
        let mut ips = std::collections::BTreeSet::new();
        let mut macs = std::collections::BTreeSet::new();
        for p in std::iter::once(&self.controller)
            .chain(std::iter::once(&self.gateway))
            .chain(self.targets.iter().map(|t| &t.peer))
        {
            if !self.subnet.contains(&p.ip)
                || p.ip.is_multicast()
                || p.ip.is_unspecified()
                || p.ip.is_loopback()
                || p.ip.is_broadcast()
                || p.ip == self.subnet.network()
                || p.ip == self.subnet.broadcast()
                || !p.mac.is_unicast()
                || !ips.insert(p.ip)
                || !macs.insert(p.mac)
            {
                return Err(Error::Invalid(
                    "peers must have unique unicast IP/MAC identities in the selected subnet"
                        .into(),
                ));
            }
        }
        for t in &self.targets {
            if self
                .interface
                .addresses
                .iter()
                .any(|a| a.addr() == t.peer.ip)
            {
                return Err(Error::Invalid(
                    "all controller addresses are protected".into(),
                ));
            }
            t.policy.validate()?;
        }
        Ok(())
    }
}
pub fn validate_interface_name(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 15
        || s.starts_with('-')
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
    {
        return Err(Error::Invalid("unsupported interface name".into()));
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    Available,
    PermissionDenied(String),
    MissingDependency(String),
    Unsupported(String),
    Conflict(String),
}
impl Capability {
    pub fn available(&self) -> bool {
        matches!(self, Self::Available)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub discovery: Capability,
    pub capture: Capability,
    pub redirection: Capability,
    pub forwarding: Capability,
    pub shaping: Capability,
    pub recovery: Capability,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyAssessment {
    pub supported: bool,
    pub reasons: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnforcementStatus {
    #[default]
    Inactive,
    Desired,
    AppliedUnverified,
    TrafficVerified,
    Failed(String),
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnforcementCounters {
    pub upload: EnforcementStatus,
    pub download: EnforcementStatus,
    pub uploaded: u64,
    pub downloaded: u64,
    pub dropped: u64,
}
/// Remove terminal control characters from all network-derived labels.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '\u{202e}' && *c != '\u{202d}')
        .take(128)
        .collect()
}

pub trait DiscoveryBackend {
    fn interfaces(&mut self) -> Result<Vec<Interface>>;
    fn neighbors(&mut self, index: u32) -> Result<Vec<Peer>>;
}
pub trait CaptureBackend {
    fn next_packet(&mut self) -> Result<Option<packet::PacketSummary>>;
}
pub trait ArpTransport {
    fn send_arp(&mut self, frame: &arp::ArpFrame) -> Result<()>;
}
pub trait ForwardingBackend {
    fn capabilities(&self) -> Capabilities;
    fn prepare(&mut self, plan: &SessionPlan) -> Result<TopologyAssessment>;
    fn apply(&mut self, plan: &SessionPlan) -> Result<()>;
    fn restore(&mut self) -> Result<()>;
}
pub trait ShapingBackend {
    fn counters(&mut self) -> Result<Vec<(Ipv4Addr, EnforcementCounters)>>;
}
pub mod config_subnet {
    pub use ipnet::Ipv4Net;
}
impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Self {
        match e {}
    }
}
#[cfg(test)]
mod validation_tests {
    use super::*;
    fn plan() -> Result<SessionPlan> {
        let mac = |n| Mac([2, 0, 0, 0, 0, n]);
        let address = Ipv4Net::new(Ipv4Addr::new(10, 1, 0, 2), 24)
            .map_err(|e| Error::Invalid(e.to_string()))?;
        Ok(SessionPlan {
            interface: Interface {
                index: 2,
                name: "eth0".into(),
                active: true,
                ethernet: true,
                mac: Some(mac(2)),
                addresses: vec![address],
                gateway: Some(Ipv4Addr::new(10, 1, 0, 1)),
                mtu: 1500,
            },
            subnet: address.trunc(),
            controller: Peer {
                ip: address.addr(),
                mac: mac(2),
            },
            gateway: Peer {
                ip: Ipv4Addr::new(10, 1, 0, 1),
                mac: mac(1),
            },
            targets: vec![TargetPolicy {
                peer: Peer {
                    ip: Ipv4Addr::new(10, 1, 0, 10),
                    mac: mac(10),
                },
                policy: BandwidthPolicy::default(),
            }],
        })
    }
    #[test]
    fn protected_identities_and_subnet() -> Result<()> {
        let p = plan()?;
        p.validate()?;
        for peer in [
            p.controller,
            p.gateway,
            Peer {
                ip: Ipv4Addr::new(10, 2, 0, 4),
                mac: Mac([2, 0, 0, 0, 0, 4]),
            },
        ] {
            let mut bad = p.clone();
            bad.targets[0].peer = peer;
            assert!(bad.validate().is_err());
        }
        let mut bad = p;
        bad.interface.name = "eth0; touch /tmp/pwn".into();
        assert!(bad.validate().is_err());
        Ok(())
    }
    #[test]
    fn hostile_labels_and_mac() {
        assert_eq!(sanitize("host\x1b[2J\nname"), "host[2Jname");
        assert!(
            "ff:ff:ff:ff:ff:ff"
                .parse::<Mac>()
                .is_ok_and(|m| !m.is_unicast())
        );
        assert!("00:00:00:00:00".parse::<Mac>().is_err());
    }
}
