#pragma once

#include <string>
#include <cstdint>

// Initialize XDP firewall - load BPF program and attach to interface
bool xdp_firewall_init(const std::string& interface_name, const std::string& xdp_firewall_microcode_path);

// Shutdown XDP firewall - detach and cleanup
void xdp_firewall_shutdown();

// Block an IPv4 address via XDP BPF map
bool xdp_firewall_block_ipv4(uint32_t ip_address);

// Unblock an IPv4 address via XDP BPF map
bool xdp_firewall_unblock_ipv4(uint32_t ip_address);

// Block an IPv6 address via XDP BPF map
bool xdp_firewall_block_ipv6(const struct in6_addr& ip6_address);

// Unblock an IPv6 address via XDP BPF map
bool xdp_firewall_unblock_ipv6(const struct in6_addr& ip6_address);

// Configure per-IP rate limiting in XDP
// window_ns: rate limit window in nanoseconds
// max_pps: max packets per window (0 = disabled)
// max_bps: max bytes per window (0 = disabled)
bool xdp_firewall_set_ratelimit(uint64_t window_ns, uint64_t max_pps, uint64_t max_bps);

// Get XDP firewall statistics
struct xdp_fw_stats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dropped_blocked;
    uint64_t dropped_ratelimit;
    uint64_t passed;
};

bool xdp_firewall_get_stats(xdp_fw_stats& stats);
