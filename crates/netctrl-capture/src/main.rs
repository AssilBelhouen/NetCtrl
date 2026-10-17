#[cfg(target_os = "linux")]
mod worker;
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(e) = worker::run() {
        eprintln!("netctrl-capture: {e}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("capture backend is currently Linux-only");
        std::process::exit(1);
    }
}
