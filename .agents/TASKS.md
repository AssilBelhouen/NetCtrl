# Tasks

Implemented: Rust workspace; core model/validation; ARP codec; simulator; Netlink discovery and route validation; libpcap worker; token buckets/counters; bounded helper IPC; Linux forwarding/tc/firewall transactions; authenticated watchdog; Ratatui CLI/TUI; configuration; isolated Rust lab; private GitHub repository and Ubuntu CI.

Verification: 23 unprivileged tests include real pseudo-terminal restoration. Formatting, warnings-denied Clippy, docs and release builds pass locally. The isolated lab verifies real forwarding, independent client caps, TCP/UDP, unlimited policies, route MTU/DF/fragments, firewall/ingress conflicts, partial rollback, mapping changes, normal exit, helper SIGKILL and UI heartbeat loss. Measured finite payload rates are approximately 96% of configured caps; acceptance is 75–110%. Live home-network management has not been activated.

Repository: private AssilBelhouen/NetCtrl. CI runs the complete checks and privileged lab on Ubuntu 22.04 and 24.04; inspect the Actions run for the current commit when changing code.

Deferred: Windows/Npcap implementation; IPv6 enforcement; native nftables firewall integration; unsupported capture datalinks and custom policy-routing topologies; package-manager distribution.
