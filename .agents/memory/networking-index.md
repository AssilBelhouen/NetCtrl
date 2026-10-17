# Networking

Linux discovery uses rtnetlink dumps of links, local IPv4 addresses, main-table default routes and neighbor entries. UI refreshes neighbors every five seconds and updates interface enumeration while monitoring. Selected-interface identity is rechecked before privileged operations. Route lookup rejects a default path on another interface.

Capture worker uses libpcap inbound plus controller-outbound handles on Ethernet framing. ARP observations and local packet sources update device mappings. Packet parser supports Ethernet/VLAN IPv4/IPv6; other datalinks are explicitly unsupported. No payloads are persisted.

Active scanning requires opt-in, stays within the selected interface subnet, and is capped at 4096 addresses. Default 1024, 100 probes/sec, one retry. Completed scans reconcile obsolete DHCP addresses while preserving duplicate claims and drive suspected-unreachable state; silence does not prove isolation/offline.

ARP redirection uses only selected client/gateway mappings. Directed requests initialize empty caches; replies refresh them. Corrective frames retain the controller Ethernet source while restoring genuine ARP sender hardware addresses to avoid switch FDB migration.
