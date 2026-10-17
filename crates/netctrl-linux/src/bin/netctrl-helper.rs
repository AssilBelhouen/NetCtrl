fn main() {
    #[cfg(target_os = "linux")]
    if let Err(e) = netctrl_linux::helper::main() {
        eprintln!("netctrl-helper: {e}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Linux helper unavailable on this platform");
        std::process::exit(1);
    }
}
