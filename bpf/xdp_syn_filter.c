#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

#define REASON_QUARANTINE 1

/*
    STATS
    ~ counters are incremented in the kernel and are pulled
      from the user space.
*/

struct stats
{
    __u64 pkts_total;         // all packets coming to XDP
    __u64 pkts_ipv4;          // IPv4 packets
    __u64 pkts_tcp;           // TCP packets
    __u64 pkts_syn;           // SYN=1, ACK=0
    __u64 dropped_quarantine; // dropped because src is currently quarantined
    __u64 dropped_rate;       // dropped because just been quarantined
    __u64 quarantine_actions; // how many times it was quarantined
};

// Per-CPU array map with only one element.
// Value is per-CPU replicated.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

// Helper: get pointer to stats struct.
static __always_inline struct stats *get_stats(void)
{
    __u32 key = 0;
    // Since it's per-CPU map, the lookup returns a pointer
    // to the current CPU's value.
    return bpf_map_lookup_elem(&stats_map, &key);
}

/*
    QUARANTINE EVENT
    ~ events are only sent to ring buffer when a new source
      address is quarantined.
*/

struct quarantine_event
{
    __u64 ts_ns;       // timestamp
    __u32 src_ip;      // quarantined src in host order
    __u32 ttl_seconds; // how many seconds the quarantine lasts
};
_Static_assert(sizeof(struct quarantine_event) == 16, "quarantine_event ABI must be 16 bytes");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

static __always_inline void emit_quarantine_event(__u32 src_ip, __u32 ttl_seconds)
{
    struct quarantine_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        // If ringbuf is full, reserve returns NULL (0).
        // Don't write to NULL, skip it instead.
        return;
    }

    e->ts_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip;
    e->ttl_seconds = ttl_seconds;

    bpf_ringbuf_submit(e, 0); // Submits to user space
}

/*
    QUARANTINE MAP
    ~ LRU to prevent exhaustion under large attacks.
      Fast checks using absolute paths without storing insertion times.
*/
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);   // src in host order
    __type(value, __u64); // expiry time in ns
} quarantine_ipv4 SEC(".maps");

/*
    RATE DETECTION
    ~ How many SYNs received per second. Mapped by source IP.
*/
struct syn_state
{
    __u64 window_start_ns;
    __u32 count;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, struct syn_state);
} syn_rate SEC(".maps");

/*
    XDP entry point.
*/
SEC("xdp")
int xdp_syn_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct stats *st = get_stats();
    if (st)
        st->pkts_total++;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_PASS;
    }

    __u16 h_proto = bpf_ntohs(eth->h_proto); // Convert from big-endian to host order for the CPU.
    if (h_proto != ETH_P_IP)
    {
        return XDP_PASS;
    }
    if (st)
        st->pkts_ipv4++;

    /* IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return XDP_PASS;
    }

    // There may be optional header options.
    // IHL field stores the actual header length (32 bit words, multiply by 4 to get in bytes)
    __u32 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
    {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }
    if (st)
        st->pkts_tcp++;

    __u32 src_ip = bpf_ntohl(ip->saddr); // Convert from big-endian to host order for the CPU.

    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
    {
        return XDP_PASS;
    }

    // There may be optional header options.
    // doff encodes number of 32-bit words in the TCP header.
    __u32 tcp_header_len = tcp->doff * 4;
    if ((void *)tcp + tcp_header_len > data_end)
    {
        return XDP_PASS;
    }

    // Check if it's an inital handshake.
    __u8 is_syn = tcp->syn;
    __u8 is_ack = tcp->ack;
    if (!(is_syn && !is_ack))
    {
        return XDP_PASS;
    }
    if (st)
        st->pkts_syn++;

    __u64 now = bpf_ktime_get_ns();

    /* QUARANTINE CHECK */
    __u64 *expiry_ns = bpf_map_lookup_elem(&quarantine_ipv4, &src_ip);
    if (expiry_ns)
    {
        if (now < *expiry_ns)
        {
            if (st)
                st->dropped_quarantine++;
            return XDP_DROP;
        }
        else
        {
            // Expired, can be removed from quarantine.
            bpf_map_delete_elem(&quarantine_ipv4, &src_ip);
        }
    }

    /* RATE DETECTION */
    struct syn_state *rs = bpf_map_lookup_elem(&syn_rate, &src_ip);

    const __u64 WINDOW_NS = 1000000000ULL; // 1s
    const __u32 THRESHOLD = 200;           // max SYN per 1s
    const __u32 TTL_SEC = 60;              // quarantine duration

    if (!rs) {
        // Source is not yet in the map
        struct syn_state init = {
            .window_start_ns = now,
            .count = 1,
        };
        bpf_map_update_elem(&syn_rate, &src_ip, &init, BPF_ANY);
        return XDP_PASS;
    }

    // If window expired, reset.
    if (now - rs->window_start_ns > WINDOW_NS) {
        rs->window_start_ns = now;
        rs->count = 1;
        return XDP_PASS;
    }

    // Still in the 1s window, increment counter.
    rs->count++;

    if (rs->count <= THRESHOLD) {
        return XDP_PASS;
    }

    /* QUARANTINE ACTION */
    __u64 expiry = now + ((__u64)TTL_SEC * 1000000000ULL); // TTL sec is __u32, we multiply
                                                           // by 1e9, so need to cast to __u64
    bpf_map_update_elem(&quarantine_ipv4, &src_ip, &expiry, BPF_ANY);

    if (st) {
        st->dropped_rate++;
        st->quarantine_actions++;
    }

    // Emit one ringbuf event to user-space, as it's a new quarantine.
    emit_quarantine_event(src_ip, TTL_SEC);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
