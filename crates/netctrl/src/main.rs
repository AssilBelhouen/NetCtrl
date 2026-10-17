mod app;
mod client;
mod view;
use clap::{Parser, Subcommand};
use crossterm::event::{Event as TerminalEvent, EventStream};
use futures_util::StreamExt;
use netctrl_core::*;
use netctrl_engine::*;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Parser)]
#[command(
    version,
    about = "Linux LAN visibility and explicitly authorized IPv4 bandwidth management"
)]
struct Cli {
    #[arg(long)]
    demo: bool,
    #[arg(long)]
    no_helper: bool,
    #[arg(long)]
    config: Option<PathBuf>,
    /// Render one deterministic frame as plain text (use with --demo).
    #[arg(long)]
    snapshot: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
enum Commands {
    Doctor,
    Recover,
}
fn config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("netctrl/config.toml")
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        if matches!(&e, Error::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe) {
            return;
        }
        eprintln!("netctrl: {e}");
        std::process::exit(1);
    }
}
async fn interfaces() -> Result<Vec<Interface>> {
    #[cfg(target_os = "linux")]
    {
        netctrl_linux::discovery::interfaces().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Unsupported(
            "live networking is currently Linux-only; use --demo".into(),
        ))
    }
}
async fn neighbors(index: u32) -> Result<Vec<Peer>> {
    #[cfg(target_os = "linux")]
    {
        netctrl_linux::discovery::neighbors(index).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = index;
        Err(Error::Unsupported("Linux only".into()))
    }
}
async fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.config.unwrap_or_else(config_path);
    let config = if cli.demo {
        Config::default()
    } else {
        Config::load(&path)?
    };
    if let Some(command) = cli.command {
        return match command {
            Commands::Doctor => {
                let ifaces = interfaces().await?;
                #[cfg(target_os = "linux")]
                {
                    let capture =
                        std::process::Command::new("/usr/local/libexec/netctrl/netctrl-capture")
                            .arg("--check")
                            .output();
                    let data = serde_json::json!({"interfaces":ifaces,"capabilities":netctrl_linux::system::capabilities(),"helper_installed":std::path::Path::new(client::HELPER).is_file(),"libpcap":capture.map(|o|String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(|e|e.to_string()),"note":"Privilege-dependent capabilities are evaluated again by the installed helper; live support also requires topology and firewall preflight."});
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&data)
                            .map_err(|e| Error::Backend(e.to_string()))?
                    );
                }
                #[cfg(not(target_os = "linux"))]
                println!("{ifaces:?}");
                Ok(())
            }
            Commands::Recover => {
                #[cfg(target_os = "linux")]
                netctrl_linux::system::trusted(std::path::Path::new(client::HELPER))?;
                let status = if client::is_root() {
                    std::process::Command::new(client::HELPER)
                        .arg("--recover")
                        .status()?
                } else {
                    std::process::Command::new("/usr/bin/sudo")
                        .args(["--", client::HELPER, "--recover"])
                        .status()?
                };
                if !status.success() {
                    return Err(Error::Backend(
                        "recovery failed; inspect helper diagnostics and retained journal".into(),
                    ));
                }
                println!("Owned local state restored. Remote ARP repair is best effort.");
                Ok(())
            }
        };
    }
    let log_parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("config path has no parent".into()))?;
    std::fs::create_dir_all(log_parent)?;
    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_parent.join("netctrl.log"))?;
    let _ = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_env_filter(config.log_level.clone())
        .with_writer(std::sync::Mutex::new(log))
        .try_init();
    let ifaces = if cli.demo {
        vec![]
    } else {
        interfaces().await?
    };
    let mut a = app::App::new(config, path, ifaces, cli.demo)?;
    if cli.snapshot {
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(136, 35))?;
        a.tick()?;
        a.traffic.sample(Duration::from_millis(100), 600);
        terminal.draw(|f| view::render(f, &a))?;
        use std::io::Write;
        let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
        for line in terminal.backend().buffer().content.chunks(136) {
            writeln!(
                stdout,
                "{}",
                line.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
            )?;
        }
        stdout.flush()?;
        return Ok(());
    }
    if let Some(i) = a.interface().cloned() {
        for n in neighbors(i.index).await.unwrap_or_default() {
            a.observe_peer(n);
        }
        seed_host(&mut a);
    }
    let mut helper = None;
    if !cli.demo && !cli.no_helper && std::path::Path::new(client::HELPER).is_file() {
        let authorized = client::is_root()
            || std::process::Command::new("/usr/bin/sudo")
                .arg("-v")
                .status()?
                .success();
        if authorized {
            match client::Client::start() {
                Ok(c) => helper = Some(c),
                Err(e) => a.message = e.to_string(),
            }
        }
    } else if !cli.demo {
        a.message="Read-only discovery. Install the root-owned helper for capture and Manage; see README.".into();
    }
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut a, &mut terminal, &mut helper).await;
    ratatui::restore();
    let cleanup = if let Some(c) = &mut helper {
        c.close().await
    } else {
        Ok(())
    };
    result.and(cleanup)
}
fn seed_host(a: &mut app::App) {
    if let Some(i) = a.interface().cloned()
        && let Some(mac) = i.mac
    {
        for addr in i.addresses {
            a.observe_peer(Peer {
                ip: addr.addr(),
                mac,
            });
        }
    }
}
async fn event_loop(
    a: &mut app::App,
    terminal: &mut ratatui::DefaultTerminal,
    helper: &mut Option<client::Client>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut ticker =
        tokio::time::interval(Duration::from_millis(1000 / u64::from(a.config.ui_fps)));
    let mut neighbor_tick = tokio::time::interval(Duration::from_secs(5));
    let mut heartbeat = Instant::now() - Duration::from_secs(2);
    let (resolved_tx, mut resolved_rx) =
        tokio::sync::mpsc::channel::<(DeviceId, Option<String>)>(64);
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .ok()
        .and_then(|b| b.build().ok())
        .map(std::sync::Arc::new);
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        if a.quitting {
            break;
        }
        if a.needs_observe {
            a.needs_observe = false;
            a.scan_running = false;
            a.selected = 0;
            seed_host(a);
            if let (Some(c), Some(i)) = (helper.as_ref(), a.interface())
                && let Err(e) = c.send(Request::Observe {
                    interface: i.clone(),
                    config: a.config.clone(),
                })
            {
                a.message = e.to_string();
            }
        }
        tokio::select! {
         _=ticker.tick()=>{
          if let Err(e)=a.tick(){a.message=e.to_string();}
          if heartbeat.elapsed()>=Duration::from_secs(1){if let Some(c)=helper.as_ref()&& let Err(e)=c.send(Request::Heartbeat){a.message=e.to_string();}heartbeat=Instant::now();}
          if a.config.active_discovery&&!a.scan_running&&a.last_scan.elapsed()>=Duration::from_secs(a.config.scan_interval_secs){match a.scan(){Ok(Some(r))=>{if let Some(c)=helper.as_ref(){if let Err(e)=c.send(r){a.scan_running=false;a.message=e.to_string();}}else{a.scan_running=false;}},Err(e)=>{a.message=e.to_string();a.last_scan=Instant::now();},_=>{}}}
          terminal.draw(|f|view::render(f,a))?;
          if let Some(resolver)=&resolver&& a.sim.is_none(){let candidates:Vec<_>=a.devices().iter().filter(|d|d.hostname.is_none()&&!a.dns_queued.contains(&d.id)).take(8).map(|d|(d.id,d.addresses.first().copied())).collect();for(id,ip)in candidates {if let Some(ip)=ip {a.dns_queued.insert(id);let resolver=resolver.clone();let tx=resolved_tx.clone();let semaphore=permits.clone();tokio::spawn(async move{let Ok(_permit)=semaphore.acquire_owned().await else{return;};let name=tokio::time::timeout(Duration::from_secs(2),resolver.reverse_lookup(ip)).await.ok().and_then(|r|r.ok()).and_then(|r|r.answers().first().map(|r|r.data.to_string()));let _=tx.send((id,name)).await;});}}}
         },
         event=events.next()=>{match event{Some(Ok(TerminalEvent::Key(k)))=>{match a.key(k){Ok(requests)=>{for r in requests{if let Some(c)=helper.as_ref(){if let Err(e)=c.send(r){a.scan_running=false;a.message=e.to_string();}}else{a.scan_running=false;a.message="Privileged helper unavailable; run doctor and follow installation instructions".into();}}},Err(e)=>a.message=e.to_string()}},Some(Err(e))=>return Err(e.into()),None=>break,_=>{}}},
         e=async {if let Some(c)=helper.as_mut(){c.events.recv().await}else{std::future::pending::<Option<Event>>().await}}=>{if let Some(e)=e{a.event(e);}},
         _=neighbor_tick.tick()=>{if a.sim.is_none()&& let Some(i)=a.interface(){let index=i.index;match neighbors(index).await{Ok(ns)=>for p in ns{a.observe_peer(p)},Err(e)=>a.message=e.to_string()}}},
         Some((id,name))=resolved_rx.recv()=>{if let Some(d)=a.registry.get_mut(id){d.hostname=name.map(|s|sanitize(&s));}},
         _=tokio::signal::ctrl_c()=>break,
        }
    }
    Ok(())
}
