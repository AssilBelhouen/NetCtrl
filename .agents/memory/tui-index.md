# TUI

CLI/TUI crate modules: app (state/actions/accounting), view (Ratatui rendering), client (helper transport), main (event loop, CLI, reverse DNS).

Keys: Up/Down, Enter details, S scan with opt-in, L limit editor, M preview/start/stop Manage, R sample, Tab panels, I interface, X recovery, H help, Q cleanup/quit. Y/N confirms a concrete backend preview. Demo is a separate simulated session and does not save real settings.

Rates are decimal Mbps/KB/s; unavailable observation is shown as unseen. Details include totals and IPv6 observation. Reverse DNS is best effort, bounded to eight jobs with two-second timeouts. History is bounded in memory. Ratatui restoration is called on normal error/exit and its initialization installs panic restoration.

Recovery clears enforcement and restores observation without automatically reapplying policies. A closed helper channel exits cleanly through terminal restoration; interface previews commit only on Enter. IPv6 bypass remains visible while management is active or IPv6 has been observed.
