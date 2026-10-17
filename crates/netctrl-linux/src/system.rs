//! Restricted system-tool execution and root-owned filesystem operations.
use netctrl_core::*;
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub fn root() -> bool {
    // SAFETY: getuid/geteuid have no pointers or preconditions.
    unsafe { libc::geteuid() == 0 }
}
pub fn tool(name: &str) -> Result<PathBuf> {
    if !["ip", "tc", "iptables", "iptables-save", "nft", "modprobe"].contains(&name) {
        return Err(Error::Invalid("unknown system tool".into()));
    }
    for d in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let p = Path::new(d).join(name);
        if p.is_file() {
            trusted(&p)?;
            return Ok(p);
        }
    }
    Err(Error::Dependency(name.into()))
}
pub fn trusted(path: &Path) -> Result<()> {
    let canonical = path.canonicalize()?;
    for p in canonical.ancestors() {
        let m = p.metadata()?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error::Permission(format!(
                "{} must be root-owned and not group/world-writable",
                p.display()
            )));
        }
    }
    Ok(())
}
pub fn run(name: &str, args: &[String]) -> Result<String> {
    let p = tool(name)?;
    let mut child = Command::new(p)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child
        .stdout
        .take()
        .ok_or_else(|| Error::Backend("no stdout".into()))?;
    let err = child
        .stderr
        .take()
        .ok_or_else(|| Error::Backend("no stderr".into()))?;
    let read = |mut r: Box<dyn Read + Send>| -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut b = vec![];
            r.by_ref().take(4 * 1024 * 1024).read_to_end(&mut b)?;
            Ok(b)
        })
    };
    let stdout = read(Box::new(out));
    let stderr = read(Box::new(err));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Backend(format!("{name} timed out")));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = stdout
        .join()
        .map_err(|_| Error::Backend("stdout reader panicked".into()))??;
    let err = stderr
        .join()
        .map_err(|_| Error::Backend("stderr reader panicked".into()))??;
    if !status.success() {
        return Err(Error::Backend(format!(
            "{name} {}: {}; {}",
            args.join(" "),
            String::from_utf8_lossy(&err),
            String::from_utf8_lossy(&out)
                .chars()
                .take(2048)
                .collect::<String>()
        )));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}
pub fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}
pub fn sysctl_path(iface: &str) -> Result<PathBuf> {
    validate_interface_name(iface)?;
    Ok(Path::new("/proc/sys/net/ipv4/conf")
        .join(iface)
        .join("forwarding"))
}
pub fn atomic_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("journal parent missing".into()))?;
    let tmp = path.with_extension("new");
    // Caller holds the namespace transaction lock. A killed writer may leave its
    // uncommitted file; never follow or remove an untrusted replacement.
    if let Ok(m) = std::fs::symlink_metadata(&tmp) {
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Err(Error::Permission("unsafe journal temporary file".into()));
        }
        std::fs::remove_file(&tmp)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut f = options.open(&tmp)?;
    let bytes = serde_json::to_vec(value).map_err(|e| Error::Invalid(e.to_string()))?;
    let result = (|| {
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}
pub fn state_dir() -> Result<PathBuf> {
    let p = PathBuf::from("/var/lib/netctrl");
    match std::fs::create_dir(&p) {
        Ok(()) => std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = std::fs::symlink_metadata(&p)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(Error::Permission(
            "unsafe /var/lib/netctrl permissions".into(),
        ));
    }
    Ok(p)
}
pub fn capabilities() -> Capabilities {
    let privcap = if root() {
        Capability::Available
    } else {
        Capability::PermissionDenied("use the installed sudo helper".into())
    };
    let dependency = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| tool(n).err())
            .map_or(privcap.clone(), |e| {
                Capability::MissingDependency(e.to_string())
            })
    };
    let capture = if Path::new("/usr/local/libexec/netctrl/netctrl-capture").is_file() {
        privcap.clone()
    } else {
        Capability::MissingDependency("installed netctrl-capture and libpcap runtime".into())
    };
    Capabilities {
        discovery: Capability::Available,
        capture,
        redirection: privcap.clone(),
        forwarding: dependency(&["ip", "iptables", "nft"]),
        shaping: dependency(&["tc", "ip"]),
        recovery: privcap,
    }
}
