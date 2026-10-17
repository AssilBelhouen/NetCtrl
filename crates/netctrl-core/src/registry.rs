use crate::{DeviceId, Mac, Peer};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Presence {
    Online,
    Stale,
    Unreachable,
    Conflict,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub addresses: Vec<Ipv4Addr>,
    pub hostname: Option<String>,
    pub last_seen_ms: u64,
    pub presence: Presence,
    pub ipv6_seen: bool,
    pub missed_scans: u32,
}
#[derive(Default, Clone, Debug)]
pub struct Registry {
    devices: BTreeMap<DeviceId, Device>,
    claims: BTreeMap<(u32, Ipv4Addr), Mac>,
}
impl Registry {
    pub fn observe(&mut self, interface: u32, peer: Peer, now_ms: u64) -> DeviceId {
        let id = DeviceId {
            interface,
            mac: peer.mac,
        };
        let previous = self.claims.insert((interface, peer.ip), peer.mac);
        let conflict = previous.is_some_and(|m| m != peer.mac);
        if let Some(mac) = previous.filter(|m| *m != peer.mac)
            && let Some(old) = self.devices.get_mut(&DeviceId { interface, mac })
        {
            old.presence = Presence::Conflict;
        }
        let d = self.devices.entry(id).or_insert(Device {
            id,
            addresses: vec![],
            hostname: None,
            last_seen_ms: now_ms,
            presence: Presence::Online,
            ipv6_seen: false,
            missed_scans: 0,
        });
        if !d.addresses.contains(&peer.ip) {
            d.addresses.push(peer.ip);
        }
        d.last_seen_ms = now_ms;
        d.missed_scans = 0;
        if conflict || d.presence == Presence::Conflict {
            d.presence = Presence::Conflict;
        } else {
            d.presence = Presence::Online;
        }
        id
    }
    pub fn get(&self, id: DeviceId) -> Option<&Device> {
        self.devices.get(&id)
    }
    pub fn get_mut(&mut self, id: DeviceId) -> Option<&mut Device> {
        self.devices.get_mut(&id)
    }
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }
    pub fn age(&mut self, now_ms: u64, stale_ms: u64) {
        for d in self.devices.values_mut() {
            if d.presence != Presence::Conflict && now_ms.saturating_sub(d.last_seen_ms) > stale_ms
            {
                d.presence = Presence::Stale;
            }
        }
    }
    /// Only call after a successful completed scan; silence is not proof of power-off.
    pub fn complete_scan(&mut self, interface: u32, scope: ipnet::Ipv4Net, seen: &[Peer]) {
        let mut claims = BTreeMap::<Ipv4Addr, std::collections::BTreeSet<Mac>>::new();
        for p in seen
            .iter()
            .filter(|p| scope.contains(&p.ip) && p.mac.is_unicast())
        {
            claims.entry(p.ip).or_default().insert(p.mac);
        }
        // A completed fresh scan can retire obsolete DHCP mappings. Multiple
        // responders retain ambiguity; passive observations alone never clear it.
        for d in self
            .devices
            .values_mut()
            .filter(|d| d.id.interface == interface)
        {
            let fresh: Vec<_> = seen
                .iter()
                .filter(|p| p.mac == d.id.mac && scope.contains(&p.ip))
                .map(|p| p.ip)
                .collect();
            d.addresses.retain(|ip| {
                if !scope.contains(ip) {
                    return true;
                }
                if let Some(macs) = claims.get(ip)
                    && !macs.contains(&d.id.mac)
                {
                    return false;
                }
                fresh.is_empty() || fresh.contains(ip)
            });
            for ip in &fresh {
                if !d.addresses.contains(ip) {
                    d.addresses.push(*ip);
                }
            }
            if !fresh.is_empty() {
                d.presence = if fresh
                    .iter()
                    .any(|ip| claims.get(ip).is_some_and(|m| m.len() > 1))
                {
                    Presence::Conflict
                } else {
                    Presence::Online
                };
            } else if d.addresses.is_empty() {
                d.presence = Presence::Stale;
            }
        }
        self.claims
            .retain(|(idx, ip), _| *idx != interface || !scope.contains(ip));
        for (ip, macs) in &claims {
            if let Some(mac) = macs.first() {
                self.claims.insert((interface, *ip), *mac);
            }
        }
        for d in self.devices.values_mut().filter(|d| {
            d.id.interface == interface && d.addresses.iter().any(|ip| scope.contains(ip))
        }) {
            if seen.iter().any(|p| p.mac == d.id.mac) {
                d.missed_scans = 0;
            } else if d.presence != Presence::Conflict {
                d.missed_scans += 1;
                d.presence = if d.missed_scans >= 3 {
                    Presence::Unreachable
                } else {
                    Presence::Stale
                };
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedup_and_conflicts() {
        let mut r = Registry::default();
        let p = Peer {
            ip: [10, 0, 0, 2].into(),
            mac: Mac([2, 0, 0, 0, 0, 2]),
        };
        let id = r.observe(2, p, 1);
        r.observe(2, p, 2);
        assert_eq!(r.devices().count(), 1);
        r.observe(
            2,
            Peer {
                ip: p.ip,
                mac: Mac([2, 0, 0, 0, 0, 3]),
            },
            3,
        );
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Conflict));
    }
}
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn failed_scan_does_not_mean_offline() -> crate::Result<()> {
        let mut r = Registry::default();
        let p = Peer {
            ip: [10, 0, 0, 3].into(),
            mac: Mac([2, 0, 0, 0, 0, 3]),
        };
        let id = r.observe(1, p, 1);
        let n = "10.0.0.0/24"
            .parse()
            .map_err(|e: ipnet::AddrParseError| crate::Error::Invalid(e.to_string()))?;
        r.complete_scan(1, n, &[]);
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Stale));
        r.complete_scan(1, n, &[]);
        r.complete_scan(1, n, &[]);
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Unreachable));
        r.observe(1, p, 100);
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Online));
        Ok(())
    }
    #[test]
    fn fresh_scan_reconciles_dhcp_without_hiding_duplicate_claims() -> crate::Result<()> {
        let scope = "10.0.0.0/24"
            .parse()
            .map_err(|e: ipnet::AddrParseError| crate::Error::Invalid(e.to_string()))?;
        let mut r = Registry::default();
        let old = Peer {
            ip: [10, 0, 0, 3].into(),
            mac: Mac([2, 0, 0, 0, 0, 3]),
        };
        let id = r.observe(1, old, 0);
        let changed = Peer {
            ip: [10, 0, 0, 4].into(),
            ..old
        };
        r.observe(1, changed, 1);
        r.complete_scan(1, scope, &[changed]);
        assert_eq!(
            r.get(id).map(|d| d.addresses.as_slice()),
            Some([changed.ip].as_slice())
        );
        let duplicate = Peer {
            mac: Mac([2, 0, 0, 0, 0, 9]),
            ..changed
        };
        r.observe(1, duplicate, 2);
        r.complete_scan(1, scope, &[changed, duplicate]);
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Conflict));
        r.complete_scan(1, scope, &[changed]);
        assert_eq!(r.get(id).map(|d| &d.presence), Some(&Presence::Online));
        Ok(())
    }
}
