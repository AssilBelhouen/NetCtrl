use crate::{DeviceId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Sample {
    pub upload_bps: f64,
    pub download_bps: f64,
}
impl Sample {
    pub fn upload_mbps(self) -> f64 {
        self.upload_bps / 1_000_000.0
    }
    pub fn download_mbps(self) -> f64 {
        self.download_bps / 1_000_000.0
    }
    pub fn download_kb_s(self) -> f64 {
        self.download_bps / 8000.0
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Traffic {
    pub uploaded: u64,
    pub downloaded: u64,
    pub packets: u64,
    pub observable: bool,
    pub current: Sample,
    pub history: VecDeque<Sample>,
    #[serde(skip)]
    previous: (u64, u64),
}
#[derive(Default)]
pub struct TrafficBook {
    pub entries: BTreeMap<DeviceId, Traffic>,
}
impl TrafficBook {
    pub fn record(&mut self, id: DeviceId, upload: bool, bytes: u64) {
        let e = self.entries.entry(id).or_default();
        e.observable = true;
        e.packets = e.packets.saturating_add(1);
        if upload {
            e.uploaded = e.uploaded.saturating_add(bytes)
        } else {
            e.downloaded = e.downloaded.saturating_add(bytes)
        }
    }
    pub fn sample(&mut self, elapsed: std::time::Duration, history_limit: usize) {
        if elapsed.is_zero() {
            return;
        }
        for e in self.entries.values_mut() {
            e.current = Sample {
                upload_bps: e.uploaded.saturating_sub(e.previous.0) as f64 * 8.0
                    / elapsed.as_secs_f64(),
                download_bps: e.downloaded.saturating_sub(e.previous.1) as f64 * 8.0
                    / elapsed.as_secs_f64(),
            };
            e.previous = (e.uploaded, e.downloaded);
            e.history.push_back(e.current);
            while e.history.len() > history_limit {
                e.history.pop_front();
            }
        }
    }
}
/// Deterministic integer token bucket. Time is supplied by the caller (nanoseconds).
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: u64,
    capacity: u64,
    tokens: u64,
    last: u64,
    remainder: u128,
}
impl TokenBucket {
    pub fn new(bytes_per_sec: u64, capacity: u64, now: u64) -> Result<Self> {
        if bytes_per_sec == 0 || capacity == 0 {
            return Err(Error::Invalid(
                "bucket rate and capacity must be positive".into(),
            ));
        }
        Ok(Self {
            rate: bytes_per_sec,
            capacity,
            tokens: capacity,
            last: now,
            remainder: 0,
        })
    }
    pub fn allow(&mut self, bytes: u64, now: u64) -> bool {
        if now >= self.last {
            let elapsed = now - self.last;
            let value = u128::from(elapsed) * u128::from(self.rate) + self.remainder;
            let refill = value / 1_000_000_000;
            self.remainder = value % 1_000_000_000;
            self.tokens = (u128::from(self.tokens) + refill).min(u128::from(self.capacity)) as u64;
            self.last = now;
        }
        if bytes > self.tokens {
            false
        } else {
            self.tokens -= bytes;
            true
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bucket_refill_and_clock() -> Result<()> {
        let mut b = TokenBucket::new(1000, 1000, 0)?;
        assert!(b.allow(1000, 0));
        assert!(!b.allow(1, 0));
        assert!(b.allow(500, 500_000_000));
        assert!(!b.allow(1, 1));
        assert!(b.allow(1000, 2_000_000_000));
        assert!(!b.allow(1001, u64::MAX));
        Ok(())
    }
    #[test]
    fn aggregation_and_units() {
        let mut b = TrafficBook::default();
        let id = DeviceId {
            interface: 1,
            mac: crate::Mac([2, 0, 0, 0, 0, 1]),
        };
        b.record(id, false, 125000);
        b.sample(std::time::Duration::from_secs(1), 1);
        assert_eq!(b.entries[&id].current.download_mbps(), 1.0);
        assert_eq!(b.entries[&id].current.download_kb_s(), 125.0);
        b.sample(std::time::Duration::from_secs(1), 1);
        assert_eq!(b.entries[&id].history.len(), 1);
        assert_eq!(b.entries[&id].current.download_bps, 0.0);
    }
}
