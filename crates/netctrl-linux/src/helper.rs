//! Privileged stdio service and independent crash watchdog.
use crate::{
    discovery,
    session::{self, Session},
    system::*,
};
use netctrl_core::*;
use netctrl_engine::*;
use std::{
    io::{BufRead, BufReader, BufWriter, Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
enum Incoming {
    Request(Request),
    Worker(u64, Event),
    WorkerExit(u64, String),
    Eof,
}
type Output = Arc<Mutex<BufWriter<std::io::Stdout>>>;
fn emit(out: &Output, e: Event) -> Result<()> {
    let mut o = out
        .lock()
        .map_err(|_| Error::Backend("output lock poisoned".into()))?;
    write_frame(&mut *o, &e)
}
struct Worker {
    child: Child,
    input: BufWriter<ChildStdin>,
}
impl Worker {
    fn start(init: &WorkerInit, generation: u64, tx: mpsc::Sender<Incoming>) -> Result<Self> {
        let mut child = Command::new(session::capture_binary()?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut input = BufWriter::new(
            child
                .stdin
                .take()
                .ok_or_else(|| Error::Backend("capture stdin missing".into()))?,
        );
        write_frame(&mut input, init)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Backend("capture stdout missing".into()))?;
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                match read_frame::<_, Event>(&mut r) {
                    Ok(Some(e)) => {
                        if tx.blocking_send(Incoming::Worker(generation, e)).is_err() {
                            break;
                        }
                    }
                    result => {
                        let msg = match result {
                            Err(e) => e.to_string(),
                            _ => "capture worker exited; check libpcap dependency and permissions"
                                .into(),
                        };
                        let _ = tx.blocking_send(Incoming::WorkerExit(generation, msg));
                        break;
                    }
                }
            }
        });
        Ok(Self { child, input })
    }
    fn send(&mut self, r: WorkerRequest) -> Result<()> {
        write_frame(&mut self.input, &r)
    }
    fn stop(mut self) {
        let _ = self.send(WorkerRequest::Stop);
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Err(_) => break,
                _ => {
                    if start.elapsed() > Duration::from_secs(2) {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn start_time(pid: u32) -> Result<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    text.rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .map(str::to_string)
        .ok_or_else(|| Error::Backend("process identity missing".into()))
}
fn watchdog(pid: u32, identity: String) -> Result<()> {
    // The internal entry point must never become an arbitrary privileged kill API.
    // SAFETY: getppid has no arguments or preconditions.
    if pid != unsafe { libc::getppid() } as u32
        || std::fs::read_link(format!("/proc/{pid}/exe"))? != std::env::current_exe()?
        || start_time(pid)? != identity
    {
        return Err(Error::Permission(
            "watchdog must be a direct child of this helper".into(),
        ));
    }
    std::io::stdout().write_all(b"NETCTRL_WATCHDOG_1\n")?;
    std::io::stdout().flush()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut input = std::io::stdin();
        let mut b = [0; 1];
        while input.read_exact(&mut b).is_ok() {
            if tx.send(b[0]).is_err() {
                return;
            }
        }
    });
    loop {
        match rx.recv_timeout(Duration::from_secs(6)) {
            Ok(2) => return Ok(()), // Explicit disarm after successful local recovery.
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if start_time(pid).is_ok_and(|s| s == identity) {
        // SAFETY: positive verified process id; SIGKILL cannot execute user code.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    session::recover_saved()
}
pub fn main() -> Result<()> {
    if !root() {
        return Err(Error::Permission(
            "launch the installed helper through sudo".into(),
        ));
    }
    let argv: Vec<_> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("--watchdog") {
        let pid = argv
            .get(2)
            .ok_or_else(|| Error::Invalid("watchdog pid".into()))?
            .parse()
            .map_err(|_| Error::Invalid("watchdog pid".into()))?;
        return watchdog(
            pid,
            argv.get(3)
                .ok_or_else(|| Error::Invalid("watchdog process identity".into()))?
                .clone(),
        );
    }
    if argv.get(1).map(String::as_str) == Some("--recover") {
        return session::recover_saved();
    }
    if argv.get(1).map(String::as_str) != Some("--stdio") {
        return Err(Error::Invalid("expected --stdio or --recover".into()));
    }
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(service())
}
async fn service() -> Result<()> {
    let out: Output = Arc::new(Mutex::new(BufWriter::new(std::io::stdout())));
    let (tx, mut rx) = mpsc::channel(4096);
    let input_tx = tx.clone();
    let heartbeat = Arc::new(AtomicU64::new(session::now_millis()));
    let h = heartbeat.clone();
    std::thread::spawn(move || {
        let mut input = BufReader::new(std::io::stdin());
        loop {
            match read_frame::<_, Request>(&mut input) {
                Ok(Some(r)) => {
                    h.store(session::now_millis(), Ordering::Relaxed);
                    if input_tx.blocking_send(Incoming::Request(r)).is_err() {
                        break;
                    }
                }
                _ => {
                    h.store(0, Ordering::Relaxed);
                    let _ = input_tx.blocking_send(Incoming::Eof);
                    break;
                }
            }
        }
    });
    let mut guard = Command::new(std::env::current_exe()?)
        .args([
            "--watchdog",
            &std::process::id().to_string(),
            &start_time(std::process::id())?,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ready = guard
        .stdout
        .take()
        .ok_or_else(|| Error::Backend("watchdog handshake pipe missing".into()))?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(ready)
            .take(64)
            .read_line(&mut line)
            .map(|_| line);
        let _ = ready_tx.send(result);
    });
    if !matches!(ready_rx.recv_timeout(Duration::from_secs(3)), Ok(Ok(line)) if line == "NETCTRL_WATCHDOG_1\n")
    {
        let _ = guard.kill();
        let _ = guard.wait();
        return Err(Error::Backend(
            "watchdog did not complete its parent authentication handshake".into(),
        ));
    }
    let mut guard_input = guard
        .stdin
        .take()
        .ok_or_else(|| Error::Backend("watchdog pipe missing".into()))?;
    let running = Arc::new(AtomicBool::new(true));
    let cleaned = Arc::new(AtomicBool::new(false));
    let clean = cleaned.clone();
    let r = running.clone();
    let h = heartbeat.clone();
    let pulse = std::thread::spawn(move || {
        while r.load(Ordering::Relaxed)
            && session::now_millis().saturating_sub(h.load(Ordering::Relaxed)) < 5000
        {
            if guard_input.write_all(&[1]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if clean.load(Ordering::Acquire) {
            let _ = guard_input.write_all(&[2]);
        }
    });
    let mut worker: Option<Worker> = None;
    let mut current: Option<Session> = None;
    let mut init: Option<WorkerInit> = None;
    let mut prepared: Option<(u64, SessionPlan, Instant)> = None;
    let mut generation = 0;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut quitting = false;
    emit(&out, Event::Ready)?;
    let result:Result<()> = async {
 while !quitting {
  tokio::select! {
   item=rx.recv()=> {match item {
    Some(Incoming::Request(req))=>{
     let result:Result<()> = async {match req {
      Request::Heartbeat=>{},
      Request::Observe{interface,config}=>{
       if current.is_some(){return Err(Error::Conflict("stop enforcement before changing interface".into()));}config.validate()?;
       let actual=discovery::interfaces().await?.into_iter().find(|i|i.index==interface.index).ok_or_else(||Error::Invalid("interface missing".into()))?;
       if actual!=interface{return Err(Error::Conflict("interface changed".into()));}
       if let Some(w)=worker.take(){w.stop();}generation+=1;
       let i=WorkerInit{interface,config};worker=Some(Worker::start(&i,generation,tx.clone())?);init=Some(i);
      },
      Request::Scan{scope}=>{let i=init.as_ref().ok_or_else(||Error::Invalid("select an interface first".into()))?;let subnet=*i.interface.addresses.first().ok_or_else(||Error::Invalid("IPv4 address missing".into()))?;let targets=scan_hosts(subnet,scope,i.config.max_scan_hosts)?;worker.as_mut().ok_or_else(||Error::Dependency("capture worker unavailable".into()))?.send(WorkerRequest::Scan{targets,scope,probes_per_sec:i.config.scan_probes_per_sec})?;},
      Request::Prepare{plan}=>{
       let i=init.as_ref().ok_or_else(||Error::Invalid("capture is not running".into()))?;if i.interface!=plan.interface{return Err(Error::Conflict("plan interface differs from observation interface".into()));}
       let changes=if current.is_some(){discovery::revalidate(&plan).await?;vec!["Restore the current session, then replace it with the displayed policies".into(),"Revalidate the topology, firewall and shaping capabilities before replacement".into()]}else{session::preflight(&plan).await?};
       let revision=session::now_millis();prepared=Some((revision,plan.clone(),Instant::now()));emit(&out,Event::Prepared{revision,plan,changes})?;
      },
      Request::Apply{revision}=>{
       let (expected,plan,when)=prepared.take().ok_or_else(||Error::Invalid("prepare a change preview first".into()))?;
       if revision!=expected || when.elapsed()>Duration::from_secs(60){return Err(Error::Conflict("confirmation expired; prepare again".into()));}
       if let Some(w)=worker.take(){w.stop();}generation+=1;
       if let Some(mut s)=current.take(){s.recover()?;}
       session::preflight(&plan).await?;
       let mut session=Session::create(plan.clone())?;
       if let Err(e)=session.install(){let recovery=session.recover();return Err(Error::Backend(format!("setup failed: {e}; rollback: {recovery:?}")));}
       let startup:Result<Worker>=async {
        session.counters().await?;
        let i=init.as_ref().ok_or_else(||Error::Invalid("worker initialization missing".into()))?;
        let mut w=Worker::start(i,generation,tx.clone())?;
        w.send(WorkerRequest::Redirect(plan))?;Ok(w)
       }.await;
       match startup {Ok(w)=>{worker=Some(w);current=Some(session);emit(&out,Event::Applied)?;},Err(e)=>{let recovery=session.recover();return Err(Error::Backend(format!("startup failed: {e}; rollback: {recovery:?}")));}}
      },
      Request::Stop=>{
       if let Some(w)=worker.take(){w.stop();}generation+=1;prepared=None;
       if let Some(mut s)=current.take(){s.recover()?;}emit(&out,Event::Recovered)?;
       if let Some(i)=&init {worker=Some(Worker::start(i,generation,tx.clone())?);}
      },
      Request::Recover=>{if let Some(w)=worker.take(){w.stop();}generation+=1;if let Some(mut s)=current.take(){s.recover()?;}else{session::recover_saved()?;}emit(&out,Event::Recovered)?;},
      Request::Quit=>quitting=true,
     }Ok(()) }.await;
     if let Err(e)=result {emit(&out,Event::Error(e.to_string()))?;}
    },
    Some(Incoming::Worker(g,e)) if g==generation=>{
     if let Event::Neighbor(p)=&e&& let Some(s)=&current&& std::iter::once(&s.journal.plan.gateway).chain(s.journal.plan.targets.iter().map(|t|&t.peer)).any(|old|old.ip==p.ip&&old.mac!=p.mac){if let Some(w)=worker.take(){w.stop();}generation+=1;if let Some(mut s)=current.take(){s.recover()?;}emit(&out,Event::Recovered)?;emit(&out,Event::Error("IP/MAC mapping changed; enforcement stopped; rescan and confirm".into()))?;}
     emit(&out,e)?;
    },
    Some(Incoming::WorkerExit(g,message)) if g==generation=>{worker.take();if let Some(mut s)=current.take(){s.recover()?;}emit(&out,Event::Recovered)?;emit(&out,Event::Error(message))?;},
    Some(Incoming::Eof)|None=>quitting=true,
    _=>{},
   }},
   _=tick.tick()=>{
    if session::now_millis().saturating_sub(heartbeat.load(Ordering::Relaxed))>5000 || guard.try_wait()?.is_some(){quitting=true;}
    if let Some(s)=&current {match s.counters().await{Ok(c)=>emit(&out,Event::Counters(c))?,Err(e)=>{if let Some(w)=worker.take(){w.stop();}generation+=1;if let Some(mut s)=current.take(){s.recover()?;}emit(&out,Event::Recovered)?;emit(&out,Event::Error(e.to_string()))?;}}}
   }
  }
 }
 Ok(()) }.await;
    if let Some(w) = worker.take() {
        w.stop();
    }
    let recovery = if let Some(mut s) = current.take() {
        s.recover()
    } else {
        Ok(())
    };
    let _ = emit(
        &out,
        match &recovery {
            Ok(()) => Event::Recovered,
            Err(e) => Event::Error(e.to_string()),
        },
    );
    cleaned.store(recovery.is_ok(), Ordering::Release);
    running.store(false, Ordering::Relaxed);
    let _ = pulse.join();
    let _ = guard.wait();
    result.and(recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internal_watchdog_rejects_an_unrelated_process() -> Result<()> {
        let pid = std::process::id();
        assert!(matches!(
            watchdog(pid, start_time(pid)?),
            Err(Error::Permission(_))
        ));
        Ok(())
    }
}
