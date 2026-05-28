#include "nftables_action.hpp"

#include <cstdlib>
#include <sstream>
#include <vector>
#include <mutex>

#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>

extern log4cpp::Category& logger;

static firewall_backend_t active_backend = firewall_backend_t::nftables;
static std::mutex firewall_mutex;
static bool initialized = false;

// Table and chain names for nftables
static const char* NFT_TABLE_NAME = "fastnetmon";
static const char* NFT_CHAIN_BLOCK = "ddos_block";
static const char* NFT_CHAIN_RATELIMIT = "ddos_ratelimit";

// Chain name for iptables
static const char* IPT_CHAIN_NAME = "FASTNETMON_BLOCK";
static const char* IPT_CHAIN_RATELIMIT = "FASTNETMON_RATELIMIT";

static int exec_command(const std::string& cmd) {
    logger << log4cpp::Priority::DEBUG << "Firewall action exec: " << cmd;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        logger << log4cpp::Priority::WARN << "Firewall action command failed (ret=" << ret << "): " << cmd;
    }
    return ret;
}

static bool init_nftables() {
    // Create fastnetmon table with inet family (handles both IPv4 and IPv6)
    std::ostringstream setup;
    setup << "nft add table inet " << NFT_TABLE_NAME << " && "
          << "nft add chain inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK
          << " '{ type filter hook input priority -200; policy accept; }' && "
          << "nft add chain inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_RATELIMIT
          << " '{ type filter hook input priority -150; policy accept; }'";

    if (exec_command(setup.str()) != 0) {
        logger << log4cpp::Priority::ERROR << "Firewall: Failed to create nftables table/chains";
        return false;
    }

    logger << log4cpp::Priority::INFO << "Firewall: nftables table '" << NFT_TABLE_NAME << "' initialized";
    return true;
}

static bool init_iptables() {
    // Create custom chains for IPv4 and IPv6
    std::ostringstream setup;
    setup << "iptables -N " << IPT_CHAIN_NAME << " 2>/dev/null; "
          << "iptables -N " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
          << "ip6tables -N " << IPT_CHAIN_NAME << " 2>/dev/null; "
          << "ip6tables -N " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
          << "iptables -C INPUT -j " << IPT_CHAIN_NAME << " 2>/dev/null || "
          << "iptables -I INPUT 1 -j " << IPT_CHAIN_NAME << "; "
          << "iptables -C INPUT -j " << IPT_CHAIN_RATELIMIT << " 2>/dev/null || "
          << "iptables -I INPUT 2 -j " << IPT_CHAIN_RATELIMIT << "; "
          << "ip6tables -C INPUT -j " << IPT_CHAIN_NAME << " 2>/dev/null || "
          << "ip6tables -I INPUT 1 -j " << IPT_CHAIN_NAME << "; "
          << "ip6tables -C INPUT -j " << IPT_CHAIN_RATELIMIT << " 2>/dev/null || "
          << "ip6tables -I INPUT 2 -j " << IPT_CHAIN_RATELIMIT;

    if (exec_command(setup.str()) != 0) {
        logger << log4cpp::Priority::WARN << "Firewall: Some iptables chain setup commands failed (may already exist)";
    }

    logger << log4cpp::Priority::INFO << "Firewall: iptables chains initialized";
    return true;
}

bool firewall_action_init(firewall_backend_t backend) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    active_backend = backend;

    bool result = false;
    if (backend == firewall_backend_t::nftables) {
        result = init_nftables();
    } else {
        result = init_iptables();
    }

    initialized = result;
    return result;
}

void firewall_action_shutdown() {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return;

    if (active_backend == firewall_backend_t::nftables) {
        std::ostringstream cmd;
        cmd << "nft delete table inet " << NFT_TABLE_NAME << " 2>/dev/null";
        exec_command(cmd.str());
        logger << log4cpp::Priority::INFO << "Firewall: nftables table cleaned up";
    } else {
        std::ostringstream cmd;
        cmd << "iptables -D INPUT -j " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "iptables -D INPUT -j " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
            << "iptables -F " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "iptables -X " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "iptables -F " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
            << "iptables -X " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
            << "ip6tables -D INPUT -j " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "ip6tables -D INPUT -j " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
            << "ip6tables -F " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "ip6tables -X " << IPT_CHAIN_NAME << " 2>/dev/null; "
            << "ip6tables -F " << IPT_CHAIN_RATELIMIT << " 2>/dev/null; "
            << "ip6tables -X " << IPT_CHAIN_RATELIMIT << " 2>/dev/null";
        exec_command(cmd.str());
        logger << log4cpp::Priority::INFO << "Firewall: iptables chains cleaned up";
    }

    initialized = false;
}

bool firewall_action_block_ipv4(uint32_t ip_address, const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) {
        logger << log4cpp::Priority::ERROR << "Firewall: Not initialized, cannot block " << ip_as_string;
        return false;
    }

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        cmd << "nft add rule inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK
            << " ip saddr " << ip_as_string << " counter drop "
            << "comment \\\"fastnetmon_block_" << ip_as_string << "\\\"";
    } else {
        cmd << "iptables -A " << IPT_CHAIN_NAME << " -s " << ip_as_string
            << " -j DROP -m comment --comment \"fastnetmon_block_" << ip_as_string << "\"";
    }

    if (exec_command(cmd.str()) != 0) {
        logger << log4cpp::Priority::ERROR << "Firewall: Failed to block " << ip_as_string;
        return false;
    }

    logger << log4cpp::Priority::INFO << "Firewall: Blocked IPv4 " << ip_as_string;
    return true;
}

bool firewall_action_unblock_ipv4(uint32_t ip_address, const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return false;

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        // Delete rule by finding handle with comment
        cmd << "nft -a list chain inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK
            << " 2>/dev/null | grep 'fastnetmon_block_" << ip_as_string
            << "' | awk '{print $NF}' | xargs -I{} nft delete rule inet "
            << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK << " handle {}";
    } else {
        cmd << "iptables -D " << IPT_CHAIN_NAME << " -s " << ip_as_string
            << " -j DROP -m comment --comment \"fastnetmon_block_" << ip_as_string << "\" 2>/dev/null";
    }

    if (exec_command(cmd.str()) != 0) {
        logger << log4cpp::Priority::WARN << "Firewall: Failed to unblock " << ip_as_string << " (may not exist)";
        return false;
    }

    logger << log4cpp::Priority::INFO << "Firewall: Unblocked IPv4 " << ip_as_string;
    return true;
}

bool firewall_action_block_ipv6(const std::string& ipv6_as_string) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return false;

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        cmd << "nft add rule inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK
            << " ip6 saddr " << ipv6_as_string << " counter drop "
            << "comment \\\"fastnetmon_block_" << ipv6_as_string << "\\\"";
    } else {
        cmd << "ip6tables -A " << IPT_CHAIN_NAME << " -s " << ipv6_as_string
            << " -j DROP -m comment --comment \"fastnetmon_block_" << ipv6_as_string << "\"";
    }

    if (exec_command(cmd.str()) != 0) {
        logger << log4cpp::Priority::ERROR << "Firewall: Failed to block IPv6 " << ipv6_as_string;
        return false;
    }

    logger << log4cpp::Priority::INFO << "Firewall: Blocked IPv6 " << ipv6_as_string;
    return true;
}

bool firewall_action_unblock_ipv6(const std::string& ipv6_as_string) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return false;

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        cmd << "nft -a list chain inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK
            << " 2>/dev/null | grep 'fastnetmon_block_" << ipv6_as_string
            << "' | awk '{print $NF}' | xargs -I{} nft delete rule inet "
            << NFT_TABLE_NAME << " " << NFT_CHAIN_BLOCK << " handle {}";
    } else {
        cmd << "ip6tables -D " << IPT_CHAIN_NAME << " -s " << ipv6_as_string
            << " -j DROP -m comment --comment \"fastnetmon_block_" << ipv6_as_string << "\" 2>/dev/null";
    }

    exec_command(cmd.str());
    logger << log4cpp::Priority::INFO << "Firewall: Unblocked IPv6 " << ipv6_as_string;
    return true;
}

bool firewall_action_ratelimit_ipv4(const std::string& ip_as_string, uint64_t pps_limit, uint64_t mbps_limit) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return false;

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        // nftables rate limiting using limit statement
        // Rate is specified in packets/second
        cmd << "nft add rule inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_RATELIMIT
            << " ip saddr " << ip_as_string
            << " limit rate over " << pps_limit << "/second counter drop "
            << "comment \\\"fastnetmon_ratelimit_" << ip_as_string << "\\\"";
    } else {
        // iptables hashlimit for per-IP rate limiting
        cmd << "iptables -A " << IPT_CHAIN_RATELIMIT << " -s " << ip_as_string
            << " -m limit --limit " << pps_limit << "/sec --limit-burst " << (pps_limit * 2)
            << " -j ACCEPT && "
            << "iptables -A " << IPT_CHAIN_RATELIMIT << " -s " << ip_as_string
            << " -j DROP -m comment --comment \"fastnetmon_ratelimit_" << ip_as_string << "\"";
    }

    if (exec_command(cmd.str()) != 0) {
        logger << log4cpp::Priority::ERROR << "Firewall: Failed to apply rate limit for " << ip_as_string;
        return false;
    }

    logger << log4cpp::Priority::INFO << "Firewall: Rate limit applied for " << ip_as_string
           << " (pps=" << pps_limit << ", mbps=" << mbps_limit << ")";
    return true;
}

bool firewall_action_remove_ratelimit_ipv4(const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(firewall_mutex);

    if (!initialized) return false;

    std::ostringstream cmd;
    if (active_backend == firewall_backend_t::nftables) {
        cmd << "nft -a list chain inet " << NFT_TABLE_NAME << " " << NFT_CHAIN_RATELIMIT
            << " 2>/dev/null | grep 'fastnetmon_ratelimit_" << ip_as_string
            << "' | awk '{print $NF}' | xargs -I{} nft delete rule inet "
            << NFT_TABLE_NAME << " " << NFT_CHAIN_RATELIMIT << " handle {}";
    } else {
        // Remove all rules for this IP from ratelimit chain
        cmd << "while iptables -D " << IPT_CHAIN_RATELIMIT << " -s " << ip_as_string
            << " -j DROP 2>/dev/null; do true; done; "
            << "while iptables -D " << IPT_CHAIN_RATELIMIT << " -s " << ip_as_string
            << " -j ACCEPT 2>/dev/null; do true; done";
    }

    exec_command(cmd.str());
    logger << log4cpp::Priority::INFO << "Firewall: Rate limit removed for " << ip_as_string;
    return true;
}
