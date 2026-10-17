# Architecture

Six crates: core (portable types, config, ARP, parsing, counters, traits); engine (bounded versioned IPC); linux (discovery, transactional session backend, helper/watchdog, lab); capture (libpcap worker); sim (deterministic mock backends); netctrl (CLI/TUI).

UI exchanges typed requests/events with the installed helper via inherited pipes. Helper independently validates interface identities and plans, invokes root-owned capture worker, and owns network transactions. Capture worker alone links libpcap. Live enforcement is Linux/IPv4 only; Windows is deferred.

Session states distinguish desired settings, confirmed installation, and traffic verification. Configuration never auto-authorizes privileged changes. Pure Rust simulation uses the same domain model and backend traits.
