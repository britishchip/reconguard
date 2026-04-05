# ReconGuard

An XDP-based network intrusion detecton and prevention tool focused on reconnaisance detection. Utilizing eBPF, ReconGuard runs directly in the Linux kernel, inspecting packets at wire speed before they reach the network stack.

---

## Overview

ReconGuard attaches an XDP program to a network interface and inspects every incoming TCP and UDP packet. It maintains per-IP (IPv4 only) state to detect port scanning behavior, and drops offending traffic in-kernel without any userspace round-trip.

```
Incoming packet
      ↓
   XDP hook (kernel)
      ↓
  ┌─────────────────────────────┐
  │  Blocked IP?   → XDP_DROP  │
  │  Blocked port? → XDP_DROP  │
  │  Port scan?    → XDP_DROP  │
  │  Otherwise     → XDP_PASS  │
  └─────────────────────────────┘
      ↓
  Ring buffer event → userspace
      ↓
  Terminal output + blocklist update
```
TODO: insert architcture diagram here

### Port Scan Detection

ReconGuard tracks the number of unique destination ports contacted by each source IP within a configurable time window. A source IP that exceeds the port threshold within the window is classified as a scanner, immediately added to the blocklist, and all further packets from that IP are dropped. False positives are handled via a whitelist for trusted IPs.

Port state is tracked using a bitmap; each source IP maintains a 2048-element __u32 array in the Port_Scan_Tracker map, giving 65,535 bits, one per possible port. When a packet arrives, the destination port is tested against the bitmap. If the bit is unset(the port is new), the bit is set and the unique port counter incremented. If already set, the packet is ignored for counting purposes.

### Port Blocking

ReconGuard maintains a static port blocklist loaded from blocked_ports.txt at startup. Incoming packets destined for a blocked port are dropped immediately, before any further inspection occurs.
The blocklist is also implemented as a bitmap; a 2048-element __u32 array stored in the Blocked_Ports BPF map, giving one bit per possible port number. Checking whether a port is blocked is a single bitwise AND operation, making lookups O(1) with no iteration overhead regardless of how many ports are blocked.

---

## Features

- **XDP packet filtering** — monitors traffic at the earliest possible point
- **Port scan detection** — bitmap-based unique port tracking per source IP with a sliding time window
- **IP blocklist** — persistent blocklist loaded at startup and updated at runtime
- **IP whitelist** — trusted IPs are exempt from port scan detection
- **Port blocklist** — block specific destination ports entirely
- **Ring buffer events** — all traffic events streamed to userspace for logging
- **Persistence** — blocklist and whitelist are loaded from disk at startup and updated at runtime, so state survives across restarts.

---

## Requirements

- Linux kernel 5.10+ (XDP and BPF ring buffer support)
- `clang` and `gcc` (for BPF compilation)
- `libbpf` and `libxdp`
- `bpftool`

---

## Building

```bash
make
```

This compiles the BPF program, generates the skeleton header, and builds the userspace binary.

---

## Usage

```bash
sudo ./reconguard <interface>
```

Example:

```bash
sudo ./reconguard eth0
```

ReconGuard will load your blocklist and port rules, attach to the interface, and begin monitoring.

Press `Ctrl+C` to stop.

---

## Configuration Files

ReconGuard reads three plain text files from the working directory at startup:

| File | Description |
|---|---|
| `blocked_ports.txt` | One port number per line. Packets headed to these ports are dropped. |
| `blocklist.txt` | One IPv4 address per line. These IPs are blocked immediately. Updated at runtime when scanners are detected. |
| `whitelist.txt` | One IPv4 address per line. These IPs are exempt from port scan detection. For NAT gateways, load balancers, monitoring agents, or any legitimately noisy host. Any IP generating false positives can be added here to exempt it entirely. |

All three files are created automatically if they don't exist.

---

## Tuning

Two constants in `reconguard.bpf.c` control scan detection sensitivity:

```c
#define SCAN_WINDOW_NS  90ULL * 1000000000ULL  // 90 second window
#define PORT_THRESHOLD  90                      // unique ports before flagging
```

The detection parameters: time window, threshold values, and scan classification logic, are informed by [Cisco's port scan inspector documentation for Firewall Threat Defense.](https://www.cisco.com/c/en/us/td/docs/security/cdo/cloud-delivered-firewall-management-center-in-cdo/managing-firewall-threat-defense-services-with-cisco-defense-orchestrator/advanced-access-threat-detection.html)

---

## Maps

| Map | Type | Purpose |
|---|---|---|
| `Network_RB` | Ring buffer | Streams packet events to userspace |
| `Blocked_Ports` | Array (bitmap) | O(1) port blocklist lookup |
| `Blocked_IPs` | LRU hash | IP blocklist, updated at runtime |
| `Whitelist` | LRU hash | Trusted IPs exempt from scan detection |
| `Port_Scan_Tracker` | LRU hash | Per-IP scan state (port bitmap + window) |
| `Scratch_Space` | Per-CPU array | Stack-safe scratch buffer for scan entry init |

---

## License

GPL
