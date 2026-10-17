use crate::{Error, Mac, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketSummary {
    pub source_mac: Option<Mac>,
    pub destination_mac: Option<Mac>,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub bytes: u64,
    pub outbound: bool,
}
/// Count IP datagram bytes, independently of snapshot length. Unknown link types are rejected.
pub fn parse_ethernet(data: &[u8], wire_len: u32) -> Result<Option<PacketSummary>> {
    if data.len() < 14 {
        return Err(Error::Invalid("truncated Ethernet header".into()));
    }
    let mut s = [0; 6];
    s.copy_from_slice(&data[6..12]);
    let mut d = [0; 6];
    d.copy_from_slice(&data[..6]);
    let mut offset = 14;
    let mut ether = u16::from_be_bytes([data[12], data[13]]);
    for _ in 0..2 {
        if ether == 0x8100 || ether == 0x88a8 {
            if data.len() < offset + 4 {
                return Err(Error::Invalid("truncated VLAN".into()));
            }
            ether = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }
    }
    let data = data
        .get(offset..)
        .ok_or_else(|| Error::Invalid("truncated frame".into()))?;
    let (source, destination, bytes) = match ether {
        0x0800 => {
            let ip = etherparse::Ipv4HeaderSlice::from_slice(data)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            (
                IpAddr::V4(ip.source_addr()),
                IpAddr::V4(ip.destination_addr()),
                u64::from(ip.total_len()),
            )
        }
        0x86dd => {
            let ip = etherparse::Ipv6HeaderSlice::from_slice(data)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            (
                IpAddr::V6(ip.source_addr()),
                IpAddr::V6(ip.destination_addr()),
                40 + u64::from(ip.payload_length()),
            )
        }
        _ => return Ok(None),
    };
    if bytes > u64::from(wire_len.saturating_sub(offset as u32)) {
        return Err(Error::Invalid("IP length exceeds wire packet".into()));
    }
    Ok(Some(PacketSummary {
        source_mac: Some(Mac(s)),
        destination_mac: Some(Mac(d)),
        source,
        destination,
        bytes,
        outbound: false,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_and_short_frames() -> Result<()> {
        let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv6([0; 16], [1; 16], 64)
            .udp(1, 2);
        let mut b = vec![];
        builder
            .write(&mut b, &[1; 12])
            .map_err(|e| Error::Backend(e.to_string()))?;
        let p = parse_ethernet(&b, b.len() as u32)?
            .ok_or_else(|| Error::Backend("missing IP".into()))?;
        assert_eq!(p.bytes, 60);
        assert!(p.source.is_ipv6());
        assert!(parse_ethernet(&b[..12], 72).is_err());
        Ok(())
    }
}
