// SPDX-License-Identifier: GPL-2.0
//
// XDP-based DDoS mitigation firewall for FastNetMon
// Drops packets from blocked source IPs at the earliest possible point in the network stack
//
// Compile on Ubuntu 22.04 x86_64:
//   sudo apt install -y clang libbpf-dev gcc-multilib
//   clang -c -g -O2 -target bpf xdp_firewall_kernel.c -o xdp_firewall_kernel.o
//
// To unload:
//   sudo xdp-loader unload <interface> --all
//

#define KBUILD_MODNAME "fastnetmon_xdp_firewall"

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum number of blocked IPs
#define MAX_BLOCKED_IPS 65536

// Rate limit map entry
struct rate_limit_entry {
    __u64 last_seen_ns;     // Last packet timestamp in nanoseconds
    __u64 packet_count;     // Packets in current window
    __u64 byte_count;       // Bytes in current window
    __u64 window_start_ns;  // Start of current rate limit window
};

// Rate limit configuration
struct rate_limit_config {
    __u64 window_ns;        // Rate limit window in nanoseconds (e.g., 1 second = 1000000000)
    __u64 max_pps;          // Maximum packets per second (0 = no limit)
    __u64 max_bps;          // Maximum bytes per second (0 = no limit)
};

// Statistics counters
struct fw_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 dropped_blocked;
    __u64 dropped_ratelimit;
    __u64 passed;
};

// IPv4 blocked source IPs map (key: __be32 source IP, value: ban timestamp)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __be32);
    __type(value, __u64);
} blocked_ipv4_map SEC(".maps");

// IPv6 blocked source IPs map (key: struct in6_addr, value: ban timestamp)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, struct in6_addr);
    __type(value, __u64);
} blocked_ipv6_map SEC(".maps");

// Per-IP rate limiting state (key: __be32 source IP)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __be32);
    __type(value, struct rate_limit_entry);
} ratelimit_ipv4_map SEC(".maps");

// Global rate limit configuration (key: 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_config);
} ratelimit_config_map SEC(".maps");

// Per-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_stats);
} stats_map SEC(".maps");

static __always_inline struct fw_stats* get_stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline struct rate_limit_config* get_ratelimit_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&ratelimit_config_map, &key);
}

// Check if IPv4 source IP should be rate limited
// Returns XDP_DROP if rate exceeded, XDP_PASS otherwise
static __always_inline int check_ratelimit_ipv4(__be32 src_ip, __u32 pkt_len) {
    struct rate_limit_config *config = get_ratelimit_config();
    if (!config)
        return XDP_PASS;

    // If no rate limit configured, pass all
    if (config->max_pps == 0 && config->max_bps == 0)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&ratelimit_ipv4_map, &src_ip);

    if (!entry) {
        // First packet from this IP, create entry
        struct rate_limit_entry new_entry = {
            .last_seen_ns = now,
            .packet_count = 1,
            .byte_count = pkt_len,
            .window_start_ns = now,
        };
        bpf_map_update_elem(&ratelimit_ipv4_map, &src_ip, &new_entry, BPF_ANY);
        return XDP_PASS;
    }

    // Check if we're in a new window
    if (config->window_ns > 0 && (now - entry->window_start_ns) > config->window_ns) {
        // Reset counters for new window
        entry->window_start_ns = now;
        entry->packet_count = 1;
        entry->byte_count = pkt_len;
        entry->last_seen_ns = now;
        return XDP_PASS;
    }

    // Increment counters
    entry->packet_count++;
    entry->byte_count += pkt_len;
    entry->last_seen_ns = now;

    // Check PPS limit
    if (config->max_pps > 0 && entry->packet_count > config->max_pps) {
        return XDP_DROP;
    }

    // Check BPS limit
    if (config->max_bps > 0 && entry->byte_count > config->max_bps) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp_firewall")
int xdp_firewall_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct fw_stats *stats = get_stats();

    if (!stats)
        return XDP_PASS;

    stats->total_packets++;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u32 pkt_len = data_end - data;

    stats->total_bytes += pkt_len;

    if (eth_proto == ETH_P_IP) {
        // IPv4
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __be32 src_ip = iph->saddr;

        // Check blocklist first (fastest path for known bad IPs)
        __u64 *blocked = bpf_map_lookup_elem(&blocked_ipv4_map, &src_ip);
        if (blocked) {
            stats->dropped_blocked++;
            return XDP_DROP;
        }

        // Check rate limit
        int rl_action = check_ratelimit_ipv4(src_ip, pkt_len);
        if (rl_action == XDP_DROP) {
            stats->dropped_ratelimit++;
            return XDP_DROP;
        }

    } else if (eth_proto == ETH_P_IPV6) {
        // IPv6
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct in6_addr src_ip6 = ip6h->saddr;

        // Check blocklist
        __u64 *blocked = bpf_map_lookup_elem(&blocked_ipv6_map, &src_ip6);
        if (blocked) {
            stats->dropped_blocked++;
            return XDP_DROP;
        }
    }

    stats->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
