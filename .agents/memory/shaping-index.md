# Shaping and recovery

Live policies are per selected IPv4 peer: optional positive upload_bps/download_bps, None unlimited. Rates 1000..=10^12 bps. Max 128 targets; controller, gateway, conflicting and ambiguous identities are excluded.

tc ingress flower classifiers redirect selected off-subnet directions to two owned IFBs. HTB classes cap each device independently; fq_codel bounds queues. Direct LAN/router-local traffic bypasses shaping. Existing physical root qdisc is preserved; existing ingress filters are refused.

iptables-nft owned chains provide scoped forwarding exceptions and suppress client ICMP redirects. If forwarding was originally disabled, unselected forwarded ingress stays blocked. Per-interface IPv4 forwarding is restored on exit. Competing native nftables forwarding base chains are unsupported.

Write-ahead journals are root-owned in /var/lib/netctrl and keyed by network namespace inode. Owned links have aliases, classifiers have cookies, firewall rules have comments. Cleanup preserves foreign objects and retains conflicts. Helper stdout/heartbeat loss and an independent watchdog trigger recovery. Remote ARP correction after power loss cannot be guaranteed.

Runtime readback uses Netlink for exact HTB rates/ceilings and counters, and rejects changed class/filter inventories. Per-second interface, neighbor and routing validation suspends management on change; custom IPv4 rules are unsupported. IFBs use MTU 65535 so kernel routing handles route/egress fragmentation. The watchdog authenticates its direct helper parent before setup proceeds.
