# xdp-syn-filter

Protect against TCP SYN exhaustion in the NIC driver path by dropping malicious IPv4 sources using XDP/eBPF.

![Architecture](./images/architecture.drawio.svg)

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
