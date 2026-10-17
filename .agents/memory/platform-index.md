# Platforms and dependencies

Linux is implemented; Ubuntu 22.04/24.04 are CI targets. Windows/Npcap are deferred; no live Windows success stubs.

Native build dependency: libpcap-dev, pkg-config and C toolchain. Runtime: libpcap, iproute2 (ip/tc), iptables-nft, nftables. Live shaping needs IFB, HTB, flower, mirred, fq_codel support. Lab additionally uses iperf3, ping, modprobe, namespace capabilities and sudo/root.

UI is unprivileged. Installed helper/capture worker and parent directories must be root-owned and not group/world-writable. No file capabilities or setuid UI are installed. Missing dependencies and permissions are explicit errors; read-only discovery and --demo remain useful.

VM anti-spoofing, client isolation, static ARP, tunnels, policy routing and firewall/ingress conflicts can prevent redirection. IPv6 remains observable where captured but is not enforced.
