#!/usr/bin/env bash
#############################################
# Setup daemon2 (192.168.1.92)
# Role: FastNetMon Detector + Mitigator CHÍNH
# Interface: ens18
#
# CHẠY BẰNG ROOT:
#   sudo bash setup_node2_daemon2.sh
#############################################

set -e

echo "========================================="
echo " Setup daemon2 - DETECTOR CHÍNH"
echo "========================================="
echo ""

# === 1. CÀI DEPENDENCIES ===
echo "[1/8] Cài dependencies..."
apt update -y
apt install -y wget curl git dnsutils nftables
echo "[1/8] Done."

# === 2. CÀI FASTNETMON ===
echo "[2/8] Cài FastNetMon..."
if ! command -v fastnetmon_client &>/dev/null; then
    wget -q https://install.fastnetmon.com/installer -O /tmp/fastnetmon_install.pl
    perl /tmp/fastnetmon_install.pl
else
    echo "  FastNetMon đã có sẵn, skip."
fi
echo "[2/8] Done."

# === 3. CẤU HÌNH NETWORK LIST ===
echo "[3/8] Cấu hình networks_list..."
cat > /etc/networks_list << 'EOF'
192.168.1.0/24
EOF
cat > /etc/networks_whitelist << 'EOF'
EOF
echo "[3/8] Done."

# === 4. CẤU HÌNH FASTNETMON ===
echo "[4/8] Cấu hình FastNetMon..."
cat > /etc/fastnetmon.conf << 'CONF'
###
### FastNetMon - daemon2 (Detector chính)
###

logging_level = info

enable_ban = on
enable_ban_ipv6 = on

process_incoming_traffic = on
process_outgoing_traffic = on

# Ban 30 phút
ban_time = 1800
unban_only_if_attack_finished = on
ban_details_records_count = 50

# Detect
ban_for_pps = on
ban_for_bandwidth = on
ban_for_flows = on

# Ngưỡng tổng - ĐIỀU CHỈNH SAU KHI XEM TRAFFIC BÌNH THƯỜNG
threshold_pps = 10000
threshold_mbps = 500
threshold_flows = 3500

# Per-protocol (game server cần chú ý UDP)
ban_for_tcp_pps = on
ban_for_udp_pps = on
ban_for_icmp_pps = on

threshold_tcp_pps = 10000
threshold_udp_pps = 5000
threshold_icmp_pps = 1000

ban_for_tcp_bandwidth = on
ban_for_udp_bandwidth = on
ban_for_icmp_bandwidth = on

threshold_tcp_mbps = 500
threshold_udp_mbps = 300
threshold_icmp_mbps = 50

# Capture trên ens18
mirror_afpacket = on
interfaces = ens18

average_calculation_time = 5
speed_calculation_delay = 1

# Notify script
notify_script_path = /usr/local/bin/notify_about_attack.sh

collect_attack_pcap_dumps = on

enable_api = on

prometheus = on
prometheus_port = 9209
prometheus_host = 0.0.0.0

pid_path = /var/run/fastnetmon.pid
cli_stats_file_path = /tmp/fastnetmon.dat
CONF
echo "[4/8] Done."

# === 5. SETUP NFTABLES ===
echo "[5/8] Setup nftables..."
systemctl enable nftables
systemctl start nftables

nft add table inet fastnetmon 2>/dev/null || true
nft add chain inet fastnetmon ddos_input '{ type filter hook input priority -200; policy accept; }' 2>/dev/null || true
nft add chain inet fastnetmon ddos_forward '{ type filter hook forward priority -200; policy accept; }' 2>/dev/null || true
nft list ruleset > /etc/nftables.conf
echo "[5/8] Done."

# === 6. SSH KEY ===
echo "[6/8] Tạo SSH key..."
if [ ! -f /root/.ssh/fastnetmon_key ]; then
    ssh-keygen -t ed25519 -f /root/.ssh/fastnetmon_key -N "" -q
    echo "  Key tạo tại /root/.ssh/fastnetmon_key"
else
    echo "  Key đã tồn tại, skip."
fi
echo "[6/8] Done."

# === 7. TẠO NOTIFY SCRIPT ===
echo "[7/8] Tạo notify script..."
cat > /usr/local/bin/notify_about_attack.sh << 'SCRIPT'
#!/usr/bin/env bash
#############################################
# FastNetMon Notify - daemon2 (Detector chính)
# Discord + nftables (INPUT+FORWARD) + Sync daemon1 & root
#############################################

CLIENT_IP="$1"
DIRECTION="$2"
PPS="$3"
ACTION="$4"

# =========== CẤU HÌNH ===========
# PASTE DISCORD WEBHOOK URL:
DISCORD_WEBHOOK=""

# Node phụ cần sync
REMOTE_NODES="192.168.1.36 192.168.1.2"
SSH_USER="root"
SSH_KEY="/root/.ssh/fastnetmon_key"
LOG_FILE="/var/log/fastnetmon_mitigation.log"
# =================================

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$ACTION] $CLIENT_IP - $1" >> "$LOG_FILE"
}

discord_notify() {
    [ -z "$DISCORD_WEBHOOK" ] && return 0

    local hostname
    hostname=$(dig -x "$CLIENT_IP" +short 2>/dev/null || echo "unknown")

    if [ "$ACTION" = "ban" ]; then
        local color="14425373"
        local title="DDoS Attack - BANNED"
    elif [ "$ACTION" = "unban" ]; then
        local color="3857437"
        local title="Attack Stopped - UNBANNED"
    else
        local color="1957075"
        local title="Attack Details"
    fi

    local payload="{
        \"username\": \"FastNetMon\",
        \"embeds\": [{
            \"title\": \"$title\",
            \"color\": $color,
            \"fields\": [
                {\"name\": \"IP\", \"value\": \"\`$CLIENT_IP\`\", \"inline\": true},
                {\"name\": \"Direction\", \"value\": \"$DIRECTION\", \"inline\": true},
                {\"name\": \"PPS\", \"value\": \"$PPS\", \"inline\": true},
                {\"name\": \"Hostname\", \"value\": \"$hostname\", \"inline\": true},
                {\"name\": \"Action\", \"value\": \"$ACTION\", \"inline\": true},
                {\"name\": \"Detector\", \"value\": \"daemon2\", \"inline\": true}
            ],
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }]
    }"

    curl --connect-timeout 10 --max-time 30 -s -S \
        -X POST -H 'Content-type: application/json' \
        --data "$payload" "$DISCORD_WEBHOOK" &>/dev/null &
}

nftables_local() {
    if [ "$ACTION" = "ban" ]; then
        nft add rule inet fastnetmon ddos_input ip saddr "$CLIENT_IP" counter drop \
            comment "\"fnm_${CLIENT_IP}\"" 2>/dev/null
        nft add rule inet fastnetmon ddos_forward ip saddr "$CLIENT_IP" counter drop \
            comment "\"fnm_${CLIENT_IP}\"" 2>/dev/null
        log_msg "LOCAL: BLOCKED"
    elif [ "$ACTION" = "unban" ]; then
        for chain in ddos_input ddos_forward; do
            nft -a list chain inet fastnetmon "$chain" 2>/dev/null | \
                grep "fnm_${CLIENT_IP}" | awk '{print $NF}' | \
                xargs -I{} nft delete rule inet fastnetmon "$chain" handle {} 2>/dev/null
        done
        log_msg "LOCAL: UNBLOCKED"
    fi
}

nftables_remote() {
    local node="$1"
    if [ "$ACTION" = "ban" ]; then
        ssh -i $SSH_KEY -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            $SSH_USER@$node \
            "nft add rule inet fastnetmon ddos_input ip saddr $CLIENT_IP counter drop comment '\"fnm_${CLIENT_IP}\"' 2>/dev/null; \
             nft add rule inet fastnetmon ddos_forward ip saddr $CLIENT_IP counter drop comment '\"fnm_${CLIENT_IP}\"' 2>/dev/null" \
            2>/dev/null
        log_msg "$node: BLOCKED"
    elif [ "$ACTION" = "unban" ]; then
        ssh -i $SSH_KEY -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            $SSH_USER@$node \
            "for chain in ddos_input ddos_forward; do nft -a list chain inet fastnetmon \$chain 2>/dev/null | grep 'fnm_${CLIENT_IP}' | awk '{print \$NF}' | xargs -I{} nft delete rule inet fastnetmon \$chain handle {}; done" \
            2>/dev/null
        log_msg "$node: UNBLOCKED"
    fi
}

# === MAIN ===
if [ "$ACTION" = "ban" ]; then
    ATTACK_DETAILS=$(cat)
else
    cat > /dev/null
fi

log_msg "START direction=$DIRECTION pps=$PPS"

discord_notify
nftables_local

for node in $REMOTE_NODES; do
    nftables_remote "$node" &
done

wait
log_msg "DONE"
exit 0
SCRIPT

chmod +x /usr/local/bin/notify_about_attack.sh

# Emergency unban
cat > /usr/local/bin/emergency_unban.sh << 'UNBAN'
#!/usr/bin/env bash
REMOTE_NODES="192.168.1.36 192.168.1.2"
SSH_USER="root"
SSH_KEY="/root/.ssh/fastnetmon_key"

list_banned() {
    echo "=== daemon2 (local) ==="
    nft list chain inet fastnetmon ddos_input 2>/dev/null | grep "fnm_" | sed 's/.*saddr \([^ ]*\).*/  \1/' | sort -u
    for node in $REMOTE_NODES; do
        echo "=== $node ==="
        ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            "$SSH_USER@$node" \
            "nft list chain inet fastnetmon ddos_input 2>/dev/null | grep 'fnm_'" 2>/dev/null | \
            sed 's/.*saddr \([^ ]*\).*/  \1/' | sort -u
    done
    echo ""
    echo "=== FastNetMon banlist ==="
    fastnetmon_api_client show_banlist 2>/dev/null || echo "  (API unavailable)"
}

unban_ip() {
    local ip="$1"
    echo "Unbanning $ip..."
    for chain in ddos_input ddos_forward; do
        nft -a list chain inet fastnetmon "$chain" 2>/dev/null | grep "fnm_${ip}" | \
            awk '{print $NF}' | xargs -I{} nft delete rule inet fastnetmon "$chain" handle {} 2>/dev/null
    done
    echo "  daemon2: OK"
    for node in $REMOTE_NODES; do
        for chain in ddos_input ddos_forward; do
            ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft -a list chain inet fastnetmon $chain 2>/dev/null | grep 'fnm_${ip}' | awk '{print \$NF}' | xargs -I{} nft delete rule inet fastnetmon $chain handle {}" 2>/dev/null
        done
        echo "  $node: OK"
    done
    fastnetmon_api_client unban "$ip" 2>/dev/null
    echo "Done."
}

unban_all() {
    echo "Unbanning ALL..."
    for chain in ddos_input ddos_forward; do
        nft flush chain inet fastnetmon "$chain" 2>/dev/null
    done
    echo "  daemon2: OK"
    for node in $REMOTE_NODES; do
        ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            "$SSH_USER@$node" \
            "nft flush chain inet fastnetmon ddos_input 2>/dev/null; nft flush chain inet fastnetmon ddos_forward 2>/dev/null" 2>/dev/null
        echo "  $node: OK"
    done
    echo "Done."
}

case "${1:-help}" in
    list) list_banned ;;
    all)  read -p "Unban ALL? (y/N): " c; [ "$c" = "y" ] && unban_all ;;
    help) echo "Usage: $0 <IP|list|all>" ;;
    *)    unban_ip "$1" ;;
esac
UNBAN

chmod +x /usr/local/bin/emergency_unban.sh
echo "[7/8] Done."

# === 8. START ===
echo "[8/8] Khởi động FastNetMon..."
systemctl enable fastnetmon
systemctl restart fastnetmon

echo ""
echo "========================================="
echo " daemon2 (DETECTOR CHÍNH) SETUP HOÀN TẤT!"
echo "========================================="
echo ""
echo "CÒN LÀM TIẾP:"
echo ""
echo "1. Copy SSH key sang daemon1 & root:"
echo "   ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.36"
echo "   ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.2"
echo ""
echo "2. Paste Discord webhook URL:"
echo "   nano /usr/local/bin/notify_about_attack.sh"
echo "   nano /usr/local/bin/emergency_unban.sh"
echo "   (sửa dòng DISCORD_WEBHOOK)"
echo ""
echo "3. Xem traffic bình thường để tuning threshold:"
echo "   sudo fastnetmon_client"
echo ""
