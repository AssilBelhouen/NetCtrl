use netctrl_core::*;
use netctrl_engine::*;
use std::{
    io::{BufReader, BufWriter},
    process::{Child, Command, Stdio},
    sync::mpsc,
};
pub const HELPER: &str = "/usr/local/libexec/netctrl/netctrl-helper";
pub struct Client {
    pub events: tokio::sync::mpsc::Receiver<Event>,
    input: mpsc::SyncSender<Request>,
    child: Child,
}
impl Client {
    pub fn start() -> Result<Self> {
        #[cfg(target_os = "linux")]
        netctrl_linux::system::trusted(std::path::Path::new(HELPER))?;
        let mut cmd = if is_root() {
            Command::new(HELPER)
        } else {
            let mut c = Command::new("/usr/bin/sudo");
            c.args(["-n", "--", HELPER]);
            c
        };
        let mut child = cmd
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| Error::Backend("helper stdin missing".into()))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| Error::Backend("helper stdout missing".into()))?;
        let (tx, rx) = mpsc::sync_channel(64);
        std::thread::spawn(move || {
            let mut w = BufWriter::new(input);
            for r in rx {
                if write_frame(&mut w, &r).is_err() {
                    break;
                }
            }
        });
        let (events_tx, events) = tokio::sync::mpsc::channel(4096);
        let errors = events_tx.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(output);
            loop {
                match read_frame::<_, Event>(&mut r) {
                    Ok(Some(e)) => {
                        if events_tx.blocking_send(e).is_err() {
                            break;
                        }
                    }
                    x => {
                        let msg = match x {
                            Err(e) => e.to_string(),
                            _ => "privileged helper disconnected".into(),
                        };
                        let _ = events_tx.blocking_send(Event::Error(msg));
                        break;
                    }
                }
            }
        });
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in BufReader::new(stderr).lines().take(100) {
                    if let Ok(s) = line {
                        let _ = errors.blocking_send(Event::Error(sanitize(&s)));
                    } else {
                        break;
                    }
                }
            });
        }
        Ok(Self {
            events,
            input: tx,
            child,
        })
    }
    pub fn send(&self, r: Request) -> Result<()> {
        self.input
            .try_send(r)
            .map_err(|e| Error::Backend(format!("helper request queue: {e}")))
    }
    pub async fn close(&mut self) -> Result<()> {
        self.send(Request::Quit)?;
        let until = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(s) = self.child.try_wait()? {
                return if s.success() {
                    Ok(())
                } else {
                    Err(Error::Backend(format!(
                        "helper exited {s}; inspect recovery journal"
                    )))
                };
            }
            while self.events.try_recv().is_ok() {}
            if std::time::Instant::now() > until {
                return Err(Error::Backend(
                    "helper cleanup still pending; watchdog/recover will handle it".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
pub fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        netctrl_linux::system::root()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
