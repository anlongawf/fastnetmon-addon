#pragma once

#include <string>
#include <cstdint>

// Firewall backend type
enum class firewall_backend_t {
    nftables,
    iptables
};

// Initialize the firewall action module
// Creates the necessary nftables table/chain or iptables chain
bool firewall_action_init(firewall_backend_t backend);

// Shutdown and cleanup all rules
void firewall_action_shutdown();

// Block an IPv4 address using nftables/iptables
bool firewall_action_block_ipv4(uint32_t ip_address, const std::string& ip_as_string);

// Unblock an IPv4 address
bool firewall_action_unblock_ipv4(uint32_t ip_address, const std::string& ip_as_string);

// Block an IPv6 address
bool firewall_action_block_ipv6(const std::string& ipv6_as_string);

// Unblock an IPv6 address
bool firewall_action_unblock_ipv6(const std::string& ipv6_as_string);

// Apply rate limit to an IPv4 address (packets per second)
bool firewall_action_ratelimit_ipv4(const std::string& ip_as_string, uint64_t pps_limit, uint64_t mbps_limit);

// Remove rate limit for an IPv4 address
bool firewall_action_remove_ratelimit_ipv4(const std::string& ip_as_string);
