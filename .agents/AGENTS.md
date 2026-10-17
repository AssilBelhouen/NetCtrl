# NetCtrl working instructions

Read the repository `AGENTS.md` and the subsystem indexes in `.agents/memory/`. Those files describe implemented behavior, not promises.

- Rust workspace, edition 2024. Stable toolchain; commit Cargo.lock.
- Run format, Clippy with warnings denied, workspace tests, docs and release build before delivery.
- Privileged network tests use `netctrl-lab` only; it creates isolated namespaces. Never enable Manage on a physical network without the application's explicit change confirmation.
- Keep root-owned installed helper/capture executables separate from the unprivileged UI. Do not execute elevated binaries from a writable checkout.
- Update the relevant memory indexes and TASKS whenever architecture, commands, dependencies or operational behavior changes.
- Preserve explicit errors for unsupported or failed operations. Never simulate success in a live backend.
