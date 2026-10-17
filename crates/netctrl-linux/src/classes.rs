//! Exact HTB policy and statistics readback through Netlink, independent of tc's text/JSON support.
use futures_util::TryStreamExt;
use netctrl_core::*;
use netlink_packet_core::Nla;
use netlink_packet_route::tc::{TcAttribute, TcOption, TcStats2};
#[derive(Clone, Debug)]
pub struct ClassStats {
    pub minor: u16,
    pub bytes: u64,
    pub dropped: u64,
    pub rate_bps: u64,
    pub ceil_bps: u64,
}
fn fail(e: impl std::fmt::Display) -> Error {
    Error::Backend(format!("HTB netlink readback: {e}"))
}
fn u32_at(b: &[u8], offset: usize) -> Result<u32> {
    let a: [u8; 4] = b
        .get(offset..offset + 4)
        .ok_or_else(|| fail("truncated rate"))?
        .try_into()
        .map_err(fail)?;
    Ok(u32::from_ne_bytes(a))
}
/// Decode the stable Linux UAPI TCA_HTB_PARMS / RATE64 / CEIL64 attributes.
fn rates(mut b: &[u8]) -> Result<(u64, u64)> {
    let (mut rate, mut ceil, mut rate64, mut ceil64) = (None, None, None, None);
    while !b.is_empty() {
        if b.len() < 4 {
            return Err(fail("truncated HTB attribute header"));
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let kind = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            return Err(fail("invalid HTB attribute length"));
        }
        let payload = &b[4..len];
        match kind {
            1 => {
                if payload.len() < 44 {
                    return Err(fail("truncated tc_htb_opt"));
                }
                rate = Some(u64::from(u32_at(payload, 8)?));
                ceil = Some(u64::from(u32_at(payload, 20)?));
            }
            6 | 7 => {
                let a: [u8; 8] = payload.try_into().map_err(fail)?;
                if kind == 6 {
                    rate64 = Some(u64::from_ne_bytes(a));
                } else {
                    ceil64 = Some(u64::from_ne_bytes(a));
                }
            }
            _ => {}
        }
        let aligned = (len + 3) & !3;
        if aligned > b.len() {
            return Err(fail("truncated HTB alignment"));
        }
        b = &b[aligned..];
    }
    let rate = rate64.or(rate).ok_or_else(|| fail("missing rate"))?;
    let ceil = ceil64.or(ceil).ok_or_else(|| fail("missing ceiling"))?;
    Ok((rate.saturating_mul(8), ceil.saturating_mul(8)))
}
pub async fn read(name: &str) -> Result<Vec<ClassStats>> {
    let (c, h, _) = rtnetlink::new_connection().map_err(fail)?;
    tokio::spawn(c);
    let link = h
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("IFB missing"))?;
    let mut classes = h.traffic_class(link.header.index as i32).get().execute();
    let mut output = vec![];
    while let Some(c) = classes.try_next().await.map_err(fail)? {
        if !c
            .attributes
            .iter()
            .any(|a| matches!(a,TcAttribute::Kind(k) if k=="htb"))
        {
            continue;
        }
        let (mut bytes, mut dropped, mut policy) = (None, None, None);
        for attr in c.attributes {
            match attr {
                TcAttribute::Stats(s) => {
                    bytes = Some(s.bytes);
                    dropped = Some(u64::from(s.drops));
                }
                TcAttribute::Stats2(s) => {
                    for a in s {
                        match a {
                            TcStats2::Basic(b) => bytes = Some(b.bytes),
                            TcStats2::Queue(q) => dropped = Some(u64::from(q.drops)),
                            _ => {}
                        }
                    }
                }
                TcAttribute::Options(opts) => {
                    for o in opts {
                        if let TcOption::Other(n) = o {
                            let mut b = vec![0; n.value_len()];
                            n.emit_value(&mut b);
                            policy = Some(rates(&b)?);
                        }
                    }
                }
                _ => {}
            }
        }
        let (rate_bps, ceil_bps) = policy.ok_or_else(|| fail("HTB policy missing"))?;
        output.push(ClassStats {
            minor: c.header.handle.minor,
            bytes: bytes.ok_or_else(|| fail("byte counter missing"))?,
            dropped: dropped.ok_or_else(|| fail("drop counter missing"))?,
            rate_bps,
            ceil_bps,
        });
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uapi_rates_and_truncation() -> Result<()> {
        let mut b = vec![0; 48];
        b[..2].copy_from_slice(&48u16.to_ne_bytes());
        b[2..4].copy_from_slice(&1u16.to_ne_bytes());
        b[12..16].copy_from_slice(&250_000u32.to_ne_bytes());
        b[24..28].copy_from_slice(&250_000u32.to_ne_bytes());
        assert_eq!(rates(&b)?, (2_000_000, 2_000_000));
        for n in 1..48 {
            assert!(rates(&b[..n]).is_err());
        }
        Ok(())
    }
}
