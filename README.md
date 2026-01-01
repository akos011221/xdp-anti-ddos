# xdp-syn-filter

Protect against TCP SYN exhaustion in the NIC driver path by dropping malicious IPv4 sources using XDP/eBPF.

![Architecture](./images/architecture.drawio.svg)

## Why?

xdp-syn-filter does SYN flood detection and mitigation in the Linux kernel dataplane, before skb allocation, conntrack, netfilter and sockets. This way expensive allocations can be avoided, SYN flooding can be mitigated with very low resource consumption.

## Features

- All drops happen in XDP without involving the network stack
- Quarantine is time-bounded, expires after TTL
- Stateless program, no external dependencies required
- Minimal telemetry, per-CPU counters are used
- Attacker-controlled maps are LRU-bounded
- Perfect for anycast nodes

## Data Flow

1. NIC receives packet
2. XDP program executed before networking stack
3. If IPv4+TCP+SYN:
   - Check quarantine TTL map
   - Drop if quarantined
   - Otherwise update rate window
4. If rate threshold exceeded:
   - Insert IP into quarantine with TTL
   - Emit a ring buffer event
   - Drop packet
5. Per-CPU counters updated for observability

## Build

```bash
make
make caps
```

## Run

```bash
sudo ./xdp-syn-filter <iface>
```
