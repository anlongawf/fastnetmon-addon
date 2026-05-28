#include "ddos_mitigation_action.hpp"
#include "xdp_firewall_action.hpp"
#include "nftables_action.hpp"

#include <log4cpp/Category.hh>
#include <log4cpp/Priority.hh>

extern log4cpp::Category& logger;

static ddos_mitigation_config_t current_config;

bool ddos_mitigation_init(const ddos_mitigation_config_t& config) {
    current_config = config;

    if (!config.enabled) {
        logger << log4cpp::Priority::INFO << "DDoS Mitigation: Disabled by configuration";
        return true;
    }

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Initializing active mitigation subsystems";

    bool all_ok = true;

    // Initialize XDP firewall if enabled
    if (config.xdp_firewall_enabled) {
        if (!xdp_firewall_init(config.xdp_firewall_interface, config.xdp_firewall_microcode_path)) {
            logger << log4cpp::Priority::ERROR << "DDoS Mitigation: XDP firewall initialization failed";
            all_ok = false;
        } else {
            logger << log4cpp::Priority::INFO << "DDoS Mitigation: XDP firewall initialized on "
                   << config.xdp_firewall_interface;

            // Configure XDP rate limiting if enabled
            if (config.xdp_ratelimit_enabled) {
                uint64_t window_ns = 1000000000ULL; // 1 second window
                xdp_firewall_set_ratelimit(window_ns, config.xdp_ratelimit_pps, config.xdp_ratelimit_bps);
            }
        }
    }

    // Initialize firewall (nftables/iptables) if enabled
    if (config.firewall_enabled) {
        firewall_backend_t backend = config.use_nftables ?
            firewall_backend_t::nftables : firewall_backend_t::iptables;

        if (!firewall_action_init(backend)) {
            logger << log4cpp::Priority::ERROR << "DDoS Mitigation: Firewall initialization failed";
            all_ok = false;
        } else {
            std::string backend_name = config.use_nftables ? "nftables" : "iptables";
            logger << log4cpp::Priority::INFO << "DDoS Mitigation: Firewall initialized (backend: "
                   << backend_name << ")";
        }
    }

    if (all_ok) {
        logger << log4cpp::Priority::INFO << "DDoS Mitigation: All subsystems initialized successfully";
    } else {
        logger << log4cpp::Priority::WARN << "DDoS Mitigation: Some subsystems failed to initialize";
    }

    return all_ok;
}

void ddos_mitigation_shutdown() {
    if (!current_config.enabled) return;

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Shutting down all subsystems";

    if (current_config.xdp_firewall_enabled) {
        xdp_firewall_shutdown();
    }

    if (current_config.firewall_enabled) {
        firewall_action_shutdown();
    }

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Shutdown complete";
}

void ddos_mitigation_ban(attack_action_t action,
                         uint32_t client_ip,
                         const std::string& client_ip_as_string,
                         bool ipv6,
                         const std::string& ipv6_as_string,
                         const attack_details_t& attack_details) {

    if (!current_config.enabled) return;

    if (action != attack_action_t::ban) return;

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Applying mitigation for "
           << (ipv6 ? ipv6_as_string : client_ip_as_string)
           << " (mode: " << static_cast<int>(current_config.mode) << ")";

    bool should_block = (current_config.mode == ddos_mitigation_mode_t::block_only ||
                         current_config.mode == ddos_mitigation_mode_t::block_and_ratelimit);

    bool should_ratelimit = (current_config.mode == ddos_mitigation_mode_t::ratelimit_only ||
                             current_config.mode == ddos_mitigation_mode_t::block_and_ratelimit);

    // XDP Firewall - fastest path, drop at driver level
    if (should_block && current_config.xdp_firewall_enabled) {
        if (ipv6) {
            // IPv6 blocking via XDP requires converting string to in6_addr
            // This is handled by the caller in the integration layer
            logger << log4cpp::Priority::INFO << "DDoS Mitigation: XDP IPv6 block requested for " << ipv6_as_string;
        } else {
            xdp_firewall_block_ipv4(client_ip);
        }
    }

    // nftables/iptables - secondary layer, also handles rate limiting
    if (current_config.firewall_enabled) {
        if (should_block) {
            if (ipv6) {
                firewall_action_block_ipv6(ipv6_as_string);
            } else {
                firewall_action_block_ipv4(client_ip, client_ip_as_string);
            }
        }

        if (should_ratelimit && current_config.ratelimit_enabled) {
            if (!ipv6) {
                firewall_action_ratelimit_ipv4(client_ip_as_string,
                                               current_config.ratelimit_pps,
                                               current_config.ratelimit_mbps);
            }
        }
    }

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Mitigation applied for "
           << (ipv6 ? ipv6_as_string : client_ip_as_string);
}

void ddos_mitigation_unban(uint32_t client_ip,
                           const std::string& client_ip_as_string,
                           bool ipv6,
                           const std::string& ipv6_as_string) {

    if (!current_config.enabled) return;

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Removing mitigation for "
           << (ipv6 ? ipv6_as_string : client_ip_as_string);

    // Remove XDP block
    if (current_config.xdp_firewall_enabled) {
        if (!ipv6) {
            xdp_firewall_unblock_ipv4(client_ip);
        }
    }

    // Remove firewall rules
    if (current_config.firewall_enabled) {
        if (ipv6) {
            firewall_action_unblock_ipv6(ipv6_as_string);
        } else {
            firewall_action_unblock_ipv4(client_ip, client_ip_as_string);
            if (current_config.ratelimit_enabled) {
                firewall_action_remove_ratelimit_ipv4(client_ip_as_string);
            }
        }
    }

    logger << log4cpp::Priority::INFO << "DDoS Mitigation: Mitigation removed for "
           << (ipv6 ? ipv6_as_string : client_ip_as_string);
}

const ddos_mitigation_config_t& ddos_mitigation_get_config() {
    return current_config;
}
