#![cfg(target_os = "linux")]
//! Exercise the real terminal lifecycle without an elevated helper.
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn keys_and_terminal_restoration() -> std::io::Result<()> {
    let (mut master, mut slave) = (-1, -1);
    let size = libc::winsize {
        ws_row: 35,
        ws_col: 136,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: all output pointers and the input window size remain valid for this call.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two unique owned file descriptors.
    let (mut master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    let settings = |fd| -> std::io::Result<libc::termios> {
        let mut value = std::mem::MaybeUninit::uninit();
        // SAFETY: value points to enough writable memory; assume_init follows success only.
        if unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { value.assume_init() })
    };
    let original = settings(slave.as_raw_fd())?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netctrl"));
    cmd.args(["--demo", "--no-helper"])
        .env("TERM", "xterm-256color")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));
    // SAFETY: only async-signal-safe libc calls run between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop(cmd);
    let mut output = master.try_clone()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = output.read_to_end(&mut bytes);
        bytes
    });
    std::thread::sleep(Duration::from_millis(500));
    for keys in [
        b"h".as_slice(),
        b"\x1b",
        b"\x1b[B",
        b"\r",
        b"\x1b",
        b"\t",
        b"r",
        b"m",
        b"m",
        b"n",
        b"q",
    ] {
        master.write_all(keys)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(std::io::Error::other("TUI failed to exit after Q"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let restored = settings(slave.as_raw_fd())?;
    drop(slave);
    drop(master);
    let bytes = reader
        .join()
        .map_err(|_| std::io::Error::other("PTY reader panicked"))?;
    assert!(status.success(), "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(
        original.c_lflag, restored.c_lflag,
        "terminal local flags changed"
    );
    assert_eq!(
        original.c_iflag, restored.c_iflag,
        "terminal input flags changed"
    );
    assert_eq!(
        original.c_oflag, restored.c_oflag,
        "terminal output flags changed"
    );
    assert!(String::from_utf8_lossy(&bytes).contains("SIMULATION"));
    Ok(())
}
