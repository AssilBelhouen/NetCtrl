//! Strict Ethernet/IPv4 ARP codec used by both the simulator and live worker.
use crate::{Error, Mac, Peer, Result};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArpFrame {
    pub destination: Mac,
    pub source: Mac,
    pub operation: u16,
    pub sender: Peer,
    pub target: Peer,
}
impl ArpFrame {
    pub fn encode(&self) -> Result<[u8; 42]> {
        self.validate()?;
        let mut b = [0u8; 42];
        b[..6].copy_from_slice(&self.destination.0);
        b[6..12].copy_from_slice(&self.source.0);
        b[12..22].copy_from_slice(&[
            8,
            6,
            0,
            1,
            8,
            0,
            6,
            4,
            (self.operation >> 8) as u8,
            self.operation as u8,
        ]);
        b[22..28].copy_from_slice(&self.sender.mac.0);
        b[28..32].copy_from_slice(&self.sender.ip.octets());
        b[32..38].copy_from_slice(&self.target.mac.0);
        b[38..42].copy_from_slice(&self.target.ip.octets());
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 42 || b[12..20] != [8, 6, 0, 1, 8, 0, 6, 4] {
            return Err(Error::Invalid("not Ethernet IPv4 ARP".into()));
        }
        let mac = |start: usize| {
            let mut a = [0; 6];
            a.copy_from_slice(&b[start..start + 6]);
            Mac(a)
        };
        let a = Self {
            destination: mac(0),
            source: mac(6),
            operation: u16::from_be_bytes([b[20], b[21]]),
            sender: Peer {
                mac: mac(22),
                ip: [b[28], b[29], b[30], b[31]].into(),
            },
            target: Peer {
                mac: mac(32),
                ip: [b[38], b[39], b[40], b[41]].into(),
            },
        };
        a.validate()?;
        Ok(a)
    }
    fn validate(&self) -> Result<()> {
        if ![1, 2].contains(&self.operation)
            || !self.source.is_unicast()
            || !self.sender.mac.is_unicast()
            || self.sender.ip.is_unspecified()
            || self.sender.ip.is_multicast()
        {
            return Err(Error::Invalid("invalid ARP sender/operation".into()));
        }
        Ok(())
    }
    pub fn request(sender: Peer, ip: std::net::Ipv4Addr) -> Self {
        Self {
            destination: Mac([255; 6]),
            source: sender.mac,
            operation: 1,
            sender,
            target: Peer {
                ip,
                mac: Mac::default(),
            },
        }
    }
    pub fn reply(sender: Peer, target: Peer) -> Self {
        Self {
            destination: target.mac,
            source: sender.mac,
            operation: 2,
            sender,
            target,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_reject_malformed() -> Result<()> {
        let a = ArpFrame::request(
            Peer {
                ip: [10, 0, 0, 2].into(),
                mac: Mac([2, 0, 0, 0, 0, 2]),
            },
            [10, 0, 0, 1].into(),
        );
        let b = a.encode()?;
        assert_eq!(ArpFrame::decode(&b)?, a);
        for len in 0..42 {
            assert!(ArpFrame::decode(&b[..len]).is_err());
        }
        let mut b = b;
        b[20] = 255;
        assert!(ArpFrame::decode(&b).is_err());
        Ok(())
    }
}
