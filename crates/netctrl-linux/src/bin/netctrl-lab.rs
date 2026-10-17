#[cfg(target_os = "linux")]
#[path = "../lab/mod.rs"]
mod lab;
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(e) = lab::run() {
        eprintln!("LAB FAILED: {e}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Linux-only integration harness");
        std::process::exit(1);
    }
}
