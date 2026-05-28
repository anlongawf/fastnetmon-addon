#pragma once

#include <string>
#include <cstdint>

#include "../attack_details.hpp"
#include "../fastnetmon_actions.hpp"

// DDoS mitigation mode
enum class ddos_mitigation_mode_t {
    disabled,       // No active mitigation
    block_only,     // Only block source IP (XDP + firewall)
    ratelimit_only, // Only rate limit (don't fully block)
    block_and_ratelimit // Block + rate limit for partial attacks
};

// Configuration for DDoS mitigation
struct ddos_mitigation_config_t {
    // Master switch
    bool enabled = false;

    // XDP firewall
    bool xdp_firewall_enabled = false;
    std::string xdp_firewall_interface;
    std::string xdp_firewall_microcode_path;

    // nftables/iptables firewall
    bool firewall_enabled = false;
    bool use_nftables = true; // true = nftables, false = iptables

    // Rate limiting
    bool ratelimit_enabled = false;
    uint64_t ratelimit_pps = 10000;  // Default rate limit in PPS when attack detected
    uint64_t ratelimit_mbps = 500;   // Default rate limit in Mbps

    // XDP rate limiting (applied globally in kernel)
    bool xdp_ratelimit_enabled = false;
    uint64_t xdp_ratelimit_pps = 50000;
    uint64_t xdp_ratelimit_bps = 0; // 0 = disabled

    // Mitigation mode
    ddos_mitigation_mode_t mode = ddos_mitigation_mode_t::block_only;
};

// Initialize all DDoS mitigation subsystems based on configuration
bool ddos_mitigation_init(const ddos_mitigation_config_t& config);

// Shutdown all mitigation subsystems
void ddos_mitigation_shutdown();

// Called when an attack is detected and IP should be banned
void ddos_mitigation_ban(attack_action_t action,
                         uint32_t client_ip,
                         const std::string& client_ip_as_string,
                         bool ipv6,
                         const std::string& ipv6_as_string,
                         const attack_details_t& attack_details);

// Called when ban should be lifted
void ddos_mitigation_unban(uint32_t client_ip,
                           const std::string& client_ip_as_string,
                           bool ipv6,
                           const std::string& ipv6_as_string);

// Get current mitigation configuration (for API/monitoring)
const ddos_mitigation_config_t& ddos_mitigation_get_config();
