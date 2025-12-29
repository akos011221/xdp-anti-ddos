#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

// BPF map for Blocklist
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, __u32); // IP address
    __type(value, __u8); // 1 means blocked
} blocked_ipv4 SEC(".maps");

// BPF map for Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

// Even structure. This will be copied over to user space to the Go code.
struct drop_event {
    __u64 ts_ns; // timestamp in nanoseconds
    __u32 src_ip;
    __u16 dst_port;
    __u8 reason;
    __u8 tcp_flags;
};
// 16 bytes total.

#define REASON_BLOCKLIST  1

static __always_inline void emit_event(__u32 src_ip, __u16 dst_port, __u8 reason, __u8 tcp_flags)
{
    struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e) {
        // If ringbuf is full, reserve returns NULL (0).
        // Don't write to NULL, skip it instead.
        return;
    }

    e->ts_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip;
    e->dst_port = dst_port;
    e->reason = reason;
    e->tcp_flags = tcp_flags;

    // Done writing, submit it to user space.
    bpf_ringbuf_submit(e, 0);
}

// XDP entry point.
SEC("xdp")
int xdp_anti_ddos(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header.
    struct ethhdr *eth = data;

    // Must stay inside [data, data_end]. If the pointer is
    // beyond data_end, we must pass.
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Convert 16-bit big-endian to host order.
    __u16 h_proto = bpf_ntohs(eth->h_proto);

    // Is it IPv4 type?
    if (h_proto != ETH_P_IP) {
        return XDP_PASS;
    }

    // IP header is right after Ethernet header.
    struct iphdr *ip = (void *)(eth + 1);

    // Check minimum IP header size.
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Internet Header Length (ihl) in 32-bit words.
    // Multiplying by 4, gives it in bytes.
    __u32 ip_header_len = ip->ihl * 4;

    // Verify full IP header is present (including options).
    if ((void *)ip + ip_header_len > data_end) {
        return XDP_PASS;
    }

    // Only care about TCP.
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Convert SRC IP from network byte order to host order.
    __u32 src_ip = bpf_ntohl(ip->saddr);

    // TCP header.
    struct tcphdr *tcp = (void*)ip + ip_header_len;

    // Check minimum TCP header size.
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // tcp->doff is the TCP header length.
    // It's inside the TCP header, thus we couldn't read it safely
    // until we know that at least the minimum header exists.
    __u32 tcp_header_len = tcp->doff * 4; // Multiply by 4 for bytes.
    
    // If TCP header does not fit into the received frame, stop XDP processing.
    if ((void *)tcp + tcp_header_len > data_end) {
        return XDP_PASS;
    }

    // Convert dport to host order.
    __u16 dst_port = bpf_ntohs(tcp->dest);

    __u8 is_syn = tcp->syn;
    __u8 is_ack = tcp->ack;

    if (!(is_syn && !is_ack)) {
        return XDP_PASS;
    }

    __u8 *blocked = bpf_map_lookup_elem(&blocked_ipv4, &src_ip);

    if (blocked && *blocked == 1) {
        __u8 flags = (tcp->syn ? 0x02 : 0) |
                     (tcp->ack ? 0x10 : 0) |
                     (tcp->fin ? 0x01 : 0) |
                     (tcp->rst ? 0x04 : 0);
        emit_event(src_ip, dst_port, REASON_BLOCKLIST, flags);

        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
