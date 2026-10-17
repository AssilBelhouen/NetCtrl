# Conventions and commands

Rust 2024; explicit Error/Result, Serde DTOs, structured tracing; Clippy denies unwrap_used and expect_used. Unsafe is limited to documented libc OS calls. Treat packet fields, hostnames, config, IPC and paths as untrusted; sanitize terminal labels. Invoke tools with validated argument arrays, never a shell.

Checks: cargo fmt --all -- --check; cargo clippy --workspace --all-targets --locked -- -D warnings; cargo test --workspace --locked; RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked; cargo build --workspace --release --locked.

On shared mounts lacking Unix chmod support, use a native-filesystem CARGO_TARGET_DIR. Root helper installation and isolated integration commands are in README. Build as the normal user; install executables root-owned under /usr/local/libexec/netctrl.
