# fastnetmon-addon

Anti-DDoS Active Mitigation addon for [FastNetMon Community Edition](https://github.com/pavel-odintsov/fastnetmon).

Extends FastNetMon from a **DDoS detector** into an **active DDoS mitigator** with three layers of defense:

| Layer | Technology | Performance | Description |
|-------|-----------|-------------|-------------|
| 1 | XDP/eBPF | ~10M+ pps | Drop packets at NIC driver level |
| 2 | nftables/iptables | ~1M pps | Kernel netfilter rules |
| 3 | Rate Limiting | Per-IP | Limit pps/mbps per attacker IP |

## Architecture

```
Attack Detected → FastNetMon → call_blackhole_actions_per_host()
                                        │
                                        ├── XDP Firewall (Layer 1 - fastest)
                                        │   └── BPF hash map: drop at NIC driver
                                        │
                                        ├── nftables/iptables (Layer 2 - kernel netfilter)
                                        │   └── inet table with DROP rules
                                        │
                                        └── Rate Limiting (Layer 3)
                                            └── nftables limit / iptables hashlimit
```

## Requirements

- FastNetMon Community Edition (source build)
- Linux kernel 5.x+ (for XDP features)
- `libbpf-dev`, `clang` (for XDP compilation)
- `nftables` or `iptables`
- Root privileges

## Installation

### 1. Clone this addon

```bash
git clone git@github.com:anlongawf/fastnetmon-addon.git
cd fastnetmon-addon
```

### 2. Copy files into your FastNetMon source tree

```bash
# Assuming FastNetMon source is at /path/to/fastnetmon
FASTNETMON_SRC=/path/to/fastnetmon/src

# Copy action modules
cp src/actions/*.hpp src/actions/*.cpp $FASTNETMON_SRC/actions/

# Copy XDP firewall kernel program
cp src/xdp_plugin/xdp_firewall_kernel.c $FASTNETMON_SRC/xdp_plugin/
```

### 3. Apply patches to FastNetMon source

Add the include in `fastnetmon_logic.cpp` (after the existing exabgp include):
```cpp
#include "actions/ddos_mitigation_action.hpp"
```

Add the mitigation hook in `call_blackhole_actions_per_host()` function (before the `usage_stats` block):
```cpp
// DDoS active mitigation (XDP firewall + nftables/iptables + rate limiting)
if (attack_action == attack_action_t::ban) {
    std::string ipv6_str = ipv6 ? client_ip_as_string : "";
    boost::thread mitigation_thread(ddos_mitigation_ban, attack_action, client_ip,
        client_ip_as_string, ipv6, ipv6_str, current_attack);
    mitigation_thread.detach();
} else if (attack_action == attack_action_t::unban) {
    std::string ipv6_str = ipv6 ? client_ip_as_string : "";
    boost::thread mitigation_thread(ddos_mitigation_unban, client_ip,
        client_ip_as_string, ipv6, ipv6_str);
    mitigation_thread.detach();
}
```

Add the include and config parsing in `fastnetmon.cpp` (see `patches/` directory for details).

### 4. Compile XDP firewall kernel program

```bash
cd $FASTNETMON_SRC/xdp_plugin
clang -c -g -O2 -target bpf xdp_firewall_kernel.c -o xdp_firewall_kernel.o
sudo cp xdp_firewall_kernel.o /etc/xdp_firewall_kernel.o
```

### 5. Rebuild FastNetMon

```bash
cd /path/to/fastnetmon/src
mkdir -p build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Configuration

Add these options to `/etc/fastnetmon.conf`:

### Minimal setup (nftables only)

```ini
# Enable active mitigation
ddos_mitigation = on
ddos_mitigation_mode = block

# Use nftables to block attackers
ddos_mitigation_firewall = on
ddos_mitigation_firewall_backend = nftables
```

### Full setup (XDP + firewall + rate limiting)

```ini
# Enable active mitigation
ddos_mitigation = on
ddos_mitigation_mode = block_and_ratelimit

# XDP firewall (highest performance)
ddos_mitigation_xdp_firewall = on
ddos_mitigation_xdp_interface = eth0
ddos_mitigation_xdp_microcode_path = /etc/xdp_firewall_kernel.o

# XDP rate limiting
ddos_mitigation_xdp_ratelimit = on
ddos_mitigation_xdp_ratelimit_pps = 50000

# nftables firewall (backup layer)
ddos_mitigation_firewall = on
ddos_mitigation_firewall_backend = nftables

# Per-IP rate limiting
ddos_mitigation_ratelimit = on
ddos_mitigation_ratelimit_pps = 10000
ddos_mitigation_ratelimit_mbps = 500
```

### Using iptables instead of nftables

```ini
ddos_mitigation_firewall = on
ddos_mitigation_firewall_backend = iptables
```

## Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `ddos_mitigation` | `off` | Master switch |
| `ddos_mitigation_mode` | `block` | `block`, `ratelimit`, or `block_and_ratelimit` |
| `ddos_mitigation_xdp_firewall` | `off` | Enable XDP/eBPF firewall |
| `ddos_mitigation_xdp_interface` | `eth0` | Network interface for XDP |
| `ddos_mitigation_xdp_microcode_path` | `/etc/xdp_firewall_kernel.o` | Path to compiled BPF object |
| `ddos_mitigation_xdp_ratelimit` | `off` | Enable XDP-level rate limiting |
| `ddos_mitigation_xdp_ratelimit_pps` | `50000` | XDP rate limit (packets/sec) |
| `ddos_mitigation_firewall` | `off` | Enable nftables/iptables |
| `ddos_mitigation_firewall_backend` | `nftables` | `nftables` or `iptables` |
| `ddos_mitigation_ratelimit` | `off` | Enable per-IP rate limiting |
| `ddos_mitigation_ratelimit_pps` | `10000` | Rate limit packets/sec |
| `ddos_mitigation_ratelimit_mbps` | `500` | Rate limit Mbps |

## Mitigation Modes

- **`block`** — Full block: drop all traffic from attacker IP (fastest mitigation)
- **`ratelimit`** — Rate limit only: allow some traffic through (less aggressive)
- **`block_and_ratelimit`** — Both: useful when XDP blocks + nftables rate limits as fallback

## Monitoring

Check active nftables rules:
```bash
sudo nft list table inet fastnetmon
```

Check iptables rules:
```bash
sudo iptables -L FASTNETMON_BLOCK -n -v
sudo iptables -L FASTNETMON_RATELIMIT -n -v
```

Check XDP status:
```bash
sudo xdp-loader status
```

## License

GPLv2 — Same as FastNetMon Community Edition.
