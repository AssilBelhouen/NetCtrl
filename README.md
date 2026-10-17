# NetCtrl

Linux LAN discovery, visible-traffic monitoring, and explicitly authorized IPv4 bandwidth management in a Rust/Ratatui terminal application. Windows networking is future work.

**Discovery, observation, and enforcement are distinct.** On a switched home network, a normal PC cannot see every client's unicast traffic. NetCtrl reports unseen traffic as `unseen`. Manage mode can redirect selected IPv4 clients through the controller using ARP, Linux forwarding, and `tc` queues. IPv6 and direct same-subnet traffic can bypass these limits.

## Build and install

Ubuntu 22.04/24.04, stable Rust, and an Ethernet-compatible adapter are the initial targets:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcap-dev iproute2 iptables nftables iputils-ping iperf3
cargo build --workspace --release --locked
sudo install -d -o root -g root -m 0755 /usr/local/libexec/netctrl
sudo install -o root -g root -m 0755 target/release/netctrl-helper target/release/netctrl-capture /usr/local/libexec/netctrl/
install -D -m 0755 target/release/netctrl "$HOME/.local/bin/netctrl"
```

Build as your normal user. The installed helper and capture worker, including their parent directories, must be root-owned and not group/world-writable. Never give the TUI setuid privileges. The helper uses `sudo` and narrow typed IPC. Kernel IFB/HTB/flower/mirred/fq_codel support is required; `netctrl-lab` loads these modules for integration tests. An unavailable kernel feature is an explicit setup error with rollback.

On shared filesystems that cannot apply Unix permissions, keep `CARGO_TARGET_DIR` on a native Linux filesystem. For example: `export CARGO_TARGET_DIR="$HOME/.cache/netctrl/target"`; adjust installation paths accordingly.

```sh
netctrl --demo                # simulated network, no root or network changes
netctrl --demo --snapshot     # plain-text rendering
netctrl doctor                # interfaces, dependency and privilege diagnostics
netctrl --no-helper           # read-only interface/neighbor discovery
netctrl                       # unprivileged TUI; sudo helper provides capture
netctrl recover               # repair an unfinished session in this namespace
```

## Workflow

1. Select the adapter with `I`. Interfaces without a valid IPv4 default gateway can still be inspected, but cannot enter Manage.
2. Press `S` and confirm bounded ARP discovery. This also enables periodic scans. Large subnets require a narrower `scan_subnet` in configuration.
3. Select a client and press `L`. Enter upload/download **Mbps**, use `Tab` between fields, `u` for unlimited, and `Enter` to save desired limits. Controller and gateway identities are protected.
4. Press `M`. Review the exact targets, limits and network changes. `Y` explicitly applies the preview; `N` cancels. Editing an active limit produces another preview.
5. Inspect per-direction verification with `Tab`. `AppliedUnverified` means kernel objects exist; `TrafficVerified` also requires observed forwarding counters. An idle device is not proof of enforcement.
6. `M` stops management; `X` requests recovery; `Q` quits and restores owned state.

Other keys: ↑/↓ navigate, `Enter` details, `R` sample statistics, `H` help, `Tab` dashboard/topology/recovery.

## Behavior and boundaries

- Monitor mode refreshes Netlink interface/neighbor data and, with the helper, captures visible Ethernet IPv4/IPv6 traffic through libpcap. Capture uses separate inbound and controller-outbound handles to avoid counting forwarded frames twice.
- Counters use IP datagram bytes; Mbps and KB/s use decimal units. Kernel shaping accounting includes protocol overhead, so application payload throughput can be slightly below the configured rate. Capture totals and forwarding/shaping counters describe different stages.
- ARP scans stay inside the selected local subnet: default 1,024 addresses, maximum 4,096, 100 probes/sec, one retry, and no overlaps. Silence can indicate sleep, filtering or isolation; it does not prove a device is off.
- Manage supports a single LAN adapter and gateway with resolvable, distinct client IP/MAC identities. Wi-Fi isolation, static ARP, ARP inspection, VM anti-spoofing, tunnels, competing ingress filters, policy routing and complex native nftables forwarding chains can prevent operation. Unsupported cases fail explicitly.
- The first firewall adapter is **iptables-nft**. Scoped exceptions are inserted ahead of its FORWARD policy after confirmation. Unrelated rules remain in place. Native competing nftables forwarding base chains are refused.
- Two owned IFBs hold per-client HTB/fq_codel queues. The physical root qdisc is preserved. Unlimited directions do not enter the shaping queues. A selected client can still exchange router-local traffic, including DNS.
- Discovery is not an authentication protocol. Conflicting or changed selected IP/MAC mappings suspend enforcement and require renewed discovery/confirmation.
- Hostnames are best-effort reverse DNS using the configured system DNS servers. Traffic history is bounded and in memory; packet payloads are not persisted.

## Configuration

Settings live at `$XDG_CONFIG_HOME/netctrl/config.toml`, or `~/.config/netctrl/config.toml`. Use `--config PATH` to override. Settings are saved atomically; preferred Manage mode and saved policies never auto-enable forwarding.

```toml
version = 1
interface = "eth0"
active_discovery = false
scan_interval_secs = 60
max_scan_hosts = 1024
scan_probes_per_sec = 100
sample_interval_ms = 1000
ui_fps = 10
history_secs = 600
capture_snaplen = 256
capture_buffer_bytes = 4194304
promiscuous = false
log_level = "info"
mode = "monitor"
policies = []
# scan_subnet = "192.168.1.0/24"
```

The TUI writes device policies with integer `upload_bps`/`download_bps`; omitted fields mean unlimited. Rates below 1,000 bps, zero, excessive bounds, unknown settings and invalid subnets are rejected. Kernel rates round down to whole bytes/second (at most 7 bps). Structured logs are adjacent to the configuration in `netctrl.log`.

## Recovery

A root-owned write-ahead journal under `/var/lib/netctrl` records owned changes per network namespace. An independent watchdog survives helper termination. UI heartbeat loss or pipe closure stops management. Recovery removes owned classifiers/queues, sends repeated corrective ARP replies, restores owned firewall and forwarding changes, and retains a journal when ownership conflicts require investigation.

```sh
netctrl recover
sudo ls -l /var/lib/netctrl
```

Recovery preserves foreign objects and externally changed state. Run recovery inside the original network namespace if a session ran in one. Root administrative intervention may be necessary when the interface identity changes or foreign rules are inserted into an owned chain. A hard power loss prevents immediate ARP repair; devices may need to expire or refresh their neighbor caches. Corrective replies preserve the controller Ethernet source to avoid moving switch forwarding entries for other devices.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo build --workspace --release --locked
sudo install -o root -g root -m 0755 target/release/netctrl-lab /usr/local/libexec/netctrl/
sudo /usr/local/libexec/netctrl/netctrl-lab
```

The Rust lab creates an isolated bridge plus router, controller, two selected clients and an unselected client namespace. It tests real helper IPC, ARP forwarding, independent upload/download limits, measured throughput, unlimited policies, default-deny firewall integration, fragments, mapping changes, conflicting ingress rules, partial-setup rollback, normal exit, SIGKILL recovery and UI heartbeat loss. Rust UDP senders offer three times each cap; receivers discard one second of warm-up and measure six seconds of payload throughput, requiring 75–110% of the configured cap. Prerequisite failures fail the lab rather than silently skipping tests. CI executes these checks on Ubuntu 22.04 and 24.04.

## Architecture

- `netctrl-core`: domain model, validation, ARP codec, packet parsing, counters, configuration and backend traits.
- `netctrl-engine`: bounded, versioned request/event protocol.
- `netctrl-linux`: Netlink discovery, firewall/tc transactions, recovery, helper and isolated lab.
- `netctrl-capture`: libpcap worker; raw frame injection stays here.
- `netctrl-sim`: deterministic ARP-cache and token-bucket simulator implementing backend traits.
- `netctrl`: CLI, unprivileged UI, history, reverse DNS and helper client.

Detailed process, transaction and verification notes are in [.agents/docs/architecture.md](.agents/docs/architecture.md).

Application code is Rust; the Linux backend invokes validated iproute2/netfilter tools directly without a shell. No forwarding or shaping path silently reports success when unsupported.
