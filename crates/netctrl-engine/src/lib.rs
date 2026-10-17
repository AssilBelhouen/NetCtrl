//! Versioned bounded IPC shared by the UI, helper and capture worker.
use netctrl_core::*;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u32,
    pub body: T,
}
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, body: &T) -> Result<()> {
    let data = serde_json::to_vec(&Envelope {
        version: VERSION,
        body,
    })
    .map_err(|e| Error::Invalid(e.to_string()))?;
    if data.len() > MAX_FRAME {
        return Err(Error::Invalid("IPC frame too large".into()));
    }
    w.write_all(&data)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}
pub fn read_frame<R: BufRead, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    let mut data = Vec::new();
    let n = std::io::Read::take(&mut *r, (MAX_FRAME + 2) as u64).read_until(b'\n', &mut data)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_FRAME + 1 || data.last() != Some(&b'\n') {
        return Err(Error::Invalid("oversized or unterminated IPC frame".into()));
    }
    let e: Envelope<T> =
        serde_json::from_slice(&data).map_err(|e| Error::Invalid(e.to_string()))?;
    if e.version != VERSION {
        return Err(Error::Unsupported(format!("IPC version {}", e.version)));
    }
    Ok(Some(e.body))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Heartbeat,
    Observe {
        interface: Interface,
        config: Config,
    },
    Scan {
        scope: ipnet_export::Ipv4Net,
    },
    Prepare {
        plan: SessionPlan,
    },
    Apply {
        revision: u64,
    },
    Stop,
    Recover,
    Quit,
}
// A re-export avoids a second wire representation of CIDRs.
pub mod ipnet_export {
    pub use netctrl_core::config_subnet::Ipv4Net;
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Ready,
    Message(String),
    Error(String),
    Packet(netctrl_core::packet::PacketSummary),
    Neighbor(Peer),
    ScanComplete {
        scope: ipnet_export::Ipv4Net,
        peers: Vec<Peer>,
    },
    CaptureStats {
        received: u32,
        dropped: u32,
    },
    Prepared {
        revision: u64,
        plan: SessionPlan,
        changes: Vec<String>,
    },
    Applied,
    Counters(Vec<(std::net::Ipv4Addr, EnforcementCounters)>),
    Recovered,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Scan {
        targets: Vec<std::net::Ipv4Addr>,
        scope: ipnet_export::Ipv4Net,
        probes_per_sec: u32,
    },
    Redirect(SessionPlan),
    Repair(SessionPlan),
    Stop,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing() -> Result<()> {
        let mut b = vec![];
        write_frame(&mut b, &Request::Heartbeat)?;
        let mut r = std::io::Cursor::new(b);
        assert!(matches!(read_frame(&mut r)?, Some(Request::Heartbeat)));
        assert!(
            read_frame::<_, Request>(&mut std::io::Cursor::new(
                b"{\"version\":2,\"body\":\"Heartbeat\"}\n"
            ))
            .is_err()
        );
        assert!(
            read_frame::<_, Request>(&mut std::io::Cursor::new(vec![b'a'; MAX_FRAME + 2])).is_err()
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerInit {
    pub interface: Interface,
    pub config: Config,
}
