use crate::{BandwidthPolicy, DeviceId, Error, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Monitor,
    Simulation,
    Manage,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub interface: Option<String>,
    pub scan_subnet: Option<Ipv4Net>,
    pub active_discovery: bool,
    pub scan_interval_secs: u64,
    pub max_scan_hosts: usize,
    pub scan_probes_per_sec: u32,
    pub sample_interval_ms: u64,
    pub ui_fps: u16,
    pub history_secs: u64,
    pub capture_snaplen: i32,
    pub capture_buffer_bytes: i32,
    pub promiscuous: bool,
    pub log_level: String,
    pub mode: Mode,
    pub policies: Vec<SavedPolicy>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedPolicy {
    pub device: DeviceId,
    pub policy: BandwidthPolicy,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            interface: None,
            scan_subnet: None,
            active_discovery: false,
            scan_interval_secs: 60,
            max_scan_hosts: 1024,
            scan_probes_per_sec: 100,
            sample_interval_ms: 1000,
            ui_fps: 10,
            history_secs: 600,
            capture_snaplen: 256,
            capture_buffer_bytes: 4 * 1024 * 1024,
            promiscuous: false,
            log_level: "info".into(),
            mode: Mode::Monitor,
            policies: vec![],
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !(5..=3600).contains(&self.scan_interval_secs)
            || !(1..=4096).contains(&self.max_scan_hosts)
            || !(1..=500).contains(&self.scan_probes_per_sec)
            || !(100..=60_000).contains(&self.sample_interval_ms)
            || !(1..=60).contains(&self.ui_fps)
            || !(1..=3600).contains(&self.history_secs)
            || !(128..=65535).contains(&self.capture_snaplen)
            || !(65536..=64 * 1024 * 1024).contains(&self.capture_buffer_bytes)
        {
            return Err(Error::Invalid(
                "configuration values are outside supported bounds".into(),
            ));
        }
        if let Some(n) = &self.interface {
            crate::validate_interface_name(n)?;
        }
        if !["error", "warn", "info", "debug", "trace"].contains(&self.log_level.as_str()) {
            return Err(Error::Invalid("invalid log level".into()));
        }
        for p in &self.policies {
            p.policy.validate()?;
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let c = match fs::read_to_string(path) {
            Ok(s) => toml::from_str::<Self>(&s).map_err(|e| Error::Invalid(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e.into()),
        };
        c.validate()?;
        Ok(c)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let data = toml::to_string_pretty(self).map_err(|e| Error::Invalid(e.to_string()))?;
        let tmp = parent.join(format!(
            ".netctrl-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| Error::Backend(e.to_string()))?
                .as_nanos()
        ));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| {
            let mut f = opts.open(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}
pub fn scan_hosts(
    interface: Ipv4Net,
    scope: Ipv4Net,
    limit: usize,
) -> Result<Vec<std::net::Ipv4Addr>> {
    if limit == 0
        || limit > 4096
        || !interface.contains(&scope.network())
        || !interface.contains(&scope.broadcast())
    {
        return Err(Error::Invalid(
            "scan must be bounded inside the selected subnet".into(),
        ));
    }
    let count = if scope.prefix_len() >= 31 {
        1u64 << (32 - scope.prefix_len())
    } else {
        (1u64 << (32 - scope.prefix_len())) - 2
    };
    if count > limit as u64 {
        return Err(Error::Invalid(format!(
            "subnet has {count} hosts; choose a narrower local range (cap {limit})"
        )));
    }
    Ok(scope
        .hosts()
        .filter(|ip| *ip != interface.network() && *ip != interface.broadcast())
        .collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds() -> Result<()> {
        let n =
            Ipv4Net::new([192, 168, 1, 2].into(), 24).map_err(|e| Error::Invalid(e.to_string()))?;
        assert_eq!(scan_hosts(n, n, 1024)?.len(), 254);
        assert!(
            scan_hosts(
                n,
                "192.168.2.0/24"
                    .parse()
                    .map_err(|e: ipnet::AddrParseError| Error::Invalid(e.to_string()))?,
                1024
            )
            .is_err()
        );
        assert!(
            scan_hosts(
                "10.0.0.1/8"
                    .parse()
                    .map_err(|e: ipnet::AddrParseError| Error::Invalid(e.to_string()))?,
                "10.0.0.0/8"
                    .parse()
                    .map_err(|e: ipnet::AddrParseError| Error::Invalid(e.to_string()))?,
                1024
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn config_roundtrip() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("config.toml");
        let c = Config::default();
        c.save(&p)?;
        assert_eq!(c, Config::load(&p)?);
        assert!(
            BandwidthPolicy {
                upload_bps: Some(0),
                download_bps: None
            }
            .validate()
            .is_err()
        );
        Ok(())
    }
}
#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn policies_roundtrip_and_bounded_large_scope() -> Result<()> {
        let mut c = Config::default();
        c.policies.push(SavedPolicy {
            device: DeviceId {
                interface: 2,
                mac: crate::Mac([2, 0, 0, 0, 0, 1]),
            },
            policy: BandwidthPolicy {
                upload_bps: Some(1_000_000),
                download_bps: None,
            },
        });
        let d = tempfile::tempdir()?;
        let p = d.path().join("config.toml");
        c.save(&p)?;
        assert_eq!(c, Config::load(&p)?);
        let n = "0.0.0.0/0"
            .parse()
            .map_err(|e: ipnet::AddrParseError| Error::Invalid(e.to_string()))?;
        assert!(scan_hosts(n, n, 4096).is_err());
        Ok(())
    }
}
