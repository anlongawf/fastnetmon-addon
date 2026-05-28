#include "xdp_firewall_action.hpp"

#include <string>
#include <cstring>
#include <cerrno>
#include <netinet/in.h>

#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>

#ifdef ENABLE_XDP_FIREWALL
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#endif

extern log4cpp::Category& logger;

#ifdef ENABLE_XDP_FIREWALL

static int blocked_ipv4_map_fd = -1;
static int blocked_ipv6_map_fd = -1;
static int ratelimit_ipv4_map_fd = -1;
static int ratelimit_config_map_fd = -1;
static int stats_map_fd = -1;
static struct bpf_object* bpf_obj = nullptr;
static int xdp_prog_fd = -1;
static int attached_ifindex = -1;

bool xdp_firewall_init(const std::string& interface_name, const std::string& xdp_firewall_microcode_path) {
    logger << log4cpp::Priority::INFO << "XDP Firewall: Initializing on interface " << interface_name;

    int ifindex = if_nametoindex(interface_name.c_str());
    if (ifindex == 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Cannot find interface " << interface_name
               << ": " << strerror(errno);
        return false;
    }

    // Load BPF object file
    bpf_obj = bpf_object__open_file(xdp_firewall_microcode_path.c_str(), nullptr);
    if (libbpf_get_error(bpf_obj)) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to open BPF object: "
               << xdp_firewall_microcode_path;
        bpf_obj = nullptr;
        return false;
    }

    if (bpf_object__load(bpf_obj)) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to load BPF object";
        bpf_object__close(bpf_obj);
        bpf_obj = nullptr;
        return false;
    }

    // Find the XDP program
    struct bpf_program* prog = bpf_object__find_program_by_name(bpf_obj, "xdp_firewall_prog");
    if (!prog) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Cannot find xdp_firewall_prog in BPF object";
        bpf_object__close(bpf_obj);
        bpf_obj = nullptr;
        return false;
    }

    xdp_prog_fd = bpf_program__fd(prog);

    // Get map file descriptors
    blocked_ipv4_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "blocked_ipv4_map");
    blocked_ipv6_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "blocked_ipv6_map");
    ratelimit_ipv4_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "ratelimit_ipv4_map");
    ratelimit_config_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "ratelimit_config_map");
    stats_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "stats_map");

    if (blocked_ipv4_map_fd < 0 || blocked_ipv6_map_fd < 0 ||
        ratelimit_config_map_fd < 0 || stats_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to find required BPF maps";
        bpf_object__close(bpf_obj);
        bpf_obj = nullptr;
        return false;
    }

    // Attach XDP program to interface using SKB mode (generic, works on all drivers)
    // For production with supported NIC, use XDP_FLAGS_DRV_MODE for native performance
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;

    if (bpf_xdp_attach(ifindex, xdp_prog_fd, xdp_flags, nullptr) < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to attach XDP program to interface "
               << interface_name << ": " << strerror(errno);
        bpf_object__close(bpf_obj);
        bpf_obj = nullptr;
        return false;
    }

    attached_ifindex = ifindex;

    logger << log4cpp::Priority::INFO << "XDP Firewall: Successfully attached to interface "
           << interface_name << " (ifindex=" << ifindex << ")";
    return true;
}

void xdp_firewall_shutdown() {
    if (attached_ifindex > 0) {
        bpf_xdp_detach(attached_ifindex, XDP_FLAGS_SKB_MODE, nullptr);
        logger << log4cpp::Priority::INFO << "XDP Firewall: Detached from interface ifindex=" << attached_ifindex;
        attached_ifindex = -1;
    }

    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = nullptr;
    }

    blocked_ipv4_map_fd = -1;
    blocked_ipv6_map_fd = -1;
    ratelimit_ipv4_map_fd = -1;
    ratelimit_config_map_fd = -1;
    stats_map_fd = -1;
    xdp_prog_fd = -1;
}

bool xdp_firewall_block_ipv4(uint32_t ip_address) {
    if (blocked_ipv4_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Not initialized, cannot block IPv4";
        return false;
    }

    __be32 key = htonl(ip_address);
    uint64_t timestamp = time(nullptr);

    if (bpf_map_update_elem(blocked_ipv4_map_fd, &key, &timestamp, BPF_ANY) != 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to add IPv4 to blocklist: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "XDP Firewall: Blocked IPv4 address";
    return true;
}

bool xdp_firewall_unblock_ipv4(uint32_t ip_address) {
    if (blocked_ipv4_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Not initialized, cannot unblock IPv4";
        return false;
    }

    __be32 key = htonl(ip_address);

    if (bpf_map_delete_elem(blocked_ipv4_map_fd, &key) != 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to remove IPv4 from blocklist: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "XDP Firewall: Unblocked IPv4 address";
    return true;
}

bool xdp_firewall_block_ipv6(const struct in6_addr& ip6_address) {
    if (blocked_ipv6_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Not initialized, cannot block IPv6";
        return false;
    }

    uint64_t timestamp = time(nullptr);

    if (bpf_map_update_elem(blocked_ipv6_map_fd, &ip6_address, &timestamp, BPF_ANY) != 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to add IPv6 to blocklist: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "XDP Firewall: Blocked IPv6 address";
    return true;
}

bool xdp_firewall_unblock_ipv6(const struct in6_addr& ip6_address) {
    if (blocked_ipv6_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Not initialized, cannot unblock IPv6";
        return false;
    }

    if (bpf_map_delete_elem(blocked_ipv6_map_fd, &ip6_address) != 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to remove IPv6 from blocklist: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "XDP Firewall: Unblocked IPv6 address";
    return true;
}

bool xdp_firewall_set_ratelimit(uint64_t window_ns, uint64_t max_pps, uint64_t max_bps) {
    if (ratelimit_config_map_fd < 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Not initialized, cannot set rate limit";
        return false;
    }

    struct {
        uint64_t window_ns;
        uint64_t max_pps;
        uint64_t max_bps;
    } config = { window_ns, max_pps, max_bps };

    uint32_t key = 0;
    if (bpf_map_update_elem(ratelimit_config_map_fd, &key, &config, BPF_ANY) != 0) {
        logger << log4cpp::Priority::ERROR << "XDP Firewall: Failed to set rate limit config: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "XDP Firewall: Rate limit set - window: " << window_ns
           << "ns, max_pps: " << max_pps << ", max_bps: " << max_bps;
    return true;
}

bool xdp_firewall_get_stats(xdp_fw_stats& stats) {
    if (stats_map_fd < 0) {
        return false;
    }

    uint32_t key = 0;
    struct {
        uint64_t total_packets;
        uint64_t total_bytes;
        uint64_t dropped_blocked;
        uint64_t dropped_ratelimit;
        uint64_t passed;
    } raw_stats;

    if (bpf_map_lookup_elem(stats_map_fd, &key, &raw_stats) != 0) {
        return false;
    }

    stats.total_packets = raw_stats.total_packets;
    stats.total_bytes = raw_stats.total_bytes;
    stats.dropped_blocked = raw_stats.dropped_blocked;
    stats.dropped_ratelimit = raw_stats.dropped_ratelimit;
    stats.passed = raw_stats.passed;

    return true;
}

#else // !ENABLE_XDP_FIREWALL

bool xdp_firewall_init(const std::string& interface_name, const std::string& xdp_firewall_microcode_path) {
    logger << log4cpp::Priority::WARN << "XDP Firewall: Not compiled with ENABLE_XDP_FIREWALL support";
    return false;
}

void xdp_firewall_shutdown() {}

bool xdp_firewall_block_ipv4(uint32_t ip_address) { return false; }
bool xdp_firewall_unblock_ipv4(uint32_t ip_address) { return false; }
bool xdp_firewall_block_ipv6(const struct in6_addr& ip6_address) { return false; }
bool xdp_firewall_unblock_ipv6(const struct in6_addr& ip6_address) { return false; }
bool xdp_firewall_set_ratelimit(uint64_t window_ns, uint64_t max_pps, uint64_t max_bps) { return false; }
bool xdp_firewall_get_stats(xdp_fw_stats& stats) { return false; }

#endif
