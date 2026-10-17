# Codex Entry Point — NetCtrl

This repository contains `NetCtrl`, a cross-platform, SelfishNet-inspired network monitoring and bandwidth management application written in Rust, with a terminal user interface (TUI).



This repository uses `AGENTS.md` and `.agents/` as source of truth. Do not treat outdated guidance in other directories as authoritative.

# Read First

Before non-trivial edits, read:

- `.agents/memory/architecture.md` — System architecture, Rust workspace structure, networking pipeline, and platform abstractions.

- `.agents/memory/conventions.md` — Rust coding standards, naming conventions, error handling, concurrency, and testing practices.

- `.agents/memory/networking-index.md` — Device discovery, ARP, packet capture, forwarding, and network interfaces.

- `.agents/memory/tui-index.md` — Ratatui architecture, rendering, keyboard events, application state, and UI components.

- `.agents/memory/shaping-index.md` — Bandwidth policies, token-bucket algorithms, traffic shaping, and platform-specific enforcement.

- `.agents/memory/platform-index.md` — Windows/Linux networking differences, native dependencies, permissions, and limitations.

- `.agents/TASKS.md` — Running list of completed and pending tasks, bugs, features, and technical debt.

Additional references:

`.agents/docs/` — Detailed implementation specifications, protocol documentation, network diagrams, and design decisions.

`.agents/skills/` — Repository-local Codex skills.

`.agents/agents/` — Specialized agent instructions and workflow prompts.

If a referenced file does not exist, do not invent its contents. Create it when its absence blocks useful documentation or when implementing the corresponding subsystem.

Use these files for efficient codebase lookup before performing broad repository searches.

## Essential Commands

See README for installation and isolated integration commands. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, and `cargo build --workspace --release --locked`.

Use a native-filesystem `CARGO_TARGET_DIR` on shared mounts. Build without sudo; install only finished helper/worker binaries into root-owned locations.

---
## Core Rules

Follow `.agents/AGENTS.md`. Never test forwarding on physical interfaces during implementation. Only `netctrl-lab` may create privileged test networks. Manage requires a fresh explicit application confirmation.

---
## Memory Maintenance

Whenever future project changes modify architecture, workflows, commands, conventions, dependencies, environment assumptions, or important implementation decisions, Codex must update the relevant files in `.agents/memory/`.

Memory files should stay concise, factual, and durable. Do not store temporary notes, speculation, secrets, credentials, or one-off debugging details.
