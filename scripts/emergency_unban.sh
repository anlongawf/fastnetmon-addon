#!/usr/bin/env bash
#############################################
# Emergency Unban Script
# Xóa ban trên tất cả node (Node 1, 2, 3)
#
# Cách dùng:
#   sudo ./emergency_unban.sh 1.2.3.4        # Unban 1 IP
#   sudo ./emergency_unban.sh all             # Unban TẤT CẢ
#   sudo ./emergency_unban.sh list            # Xem danh sách IP đang bị ban
#############################################

# === CẤU HÌNH (sửa cho đúng IP của bạn) ===
REMOTE_NODES="192.168.1.11 192.168.1.12"
SSH_USER="root"
SSH_KEY="/root/.ssh/fastnetmon_key"

# Discord webhook (để thông báo unban, để trống nếu không cần)
DISCORD_WEBHOOK=""

ALL_NODES="localhost $REMOTE_NODES"

# === FUNCTIONS ===

list_banned() {
    echo "=== IP đang bị ban ==="
    echo ""
    for node in $ALL_NODES; do
        if [ "$node" = "localhost" ]; then
            echo "--- Node 1 (local) ---"
            nft list chain inet fastnetmon ddos_block 2>/dev/null | grep "saddr" | \
                sed 's/.*saddr \([^ ]*\).*/  \1/'
        else
            echo "--- Node $node ---"
            ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft list chain inet fastnetmon ddos_block 2>/dev/null | grep 'saddr'" 2>/dev/null | \
                sed 's/.*saddr \([^ ]*\).*/  \1/'
        fi
        echo ""
    done

    echo "=== FastNetMon ban list ==="
    fastnetmon_api_client show_banlist 2>/dev/null || echo "  (API không khả dụng)"
}

unban_ip() {
    local ip="$1"
    echo "Unbanning $ip trên tất cả node..."

    for node in $ALL_NODES; do
        if [ "$node" = "localhost" ]; then
            echo -n "  Node 1 (local): "
            local handles
            handles=$(nft -a list chain inet fastnetmon ddos_block 2>/dev/null | \
                grep "fastnetmon_${ip}\|saddr ${ip} " | awk '{print $NF}')
            if [ -n "$handles" ]; then
                for handle in $handles; do
                    nft delete rule inet fastnetmon ddos_block handle "$handle" 2>/dev/null
                done
                echo "OK (removed)"
            else
                echo "không có rule"
            fi
        else
            echo -n "  Node $node: "
            ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft -a list chain inet fastnetmon ddos_block 2>/dev/null | grep 'fastnetmon_${ip}\|saddr ${ip} ' | awk '{print \$NF}' | xargs -I{} nft delete rule inet fastnetmon ddos_block handle {}" \
                2>/dev/null && echo "OK" || echo "FAIL"
        fi
    done

    # Unban trong FastNetMon
    fastnetmon_api_client unban "$ip" 2>/dev/null

    # Discord notification
    if [ -n "$DISCORD_WEBHOOK" ]; then
        local payload="{\"username\":\"FastNetMon\",\"embeds\":[{\"title\":\"EMERGENCY UNBAN\",\"color\":3066993,\"fields\":[{\"name\":\"IP\",\"value\":\"$ip\"},{\"name\":\"By\",\"value\":\"$(whoami)@$(hostname)\"}],\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]}"
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$DISCORD_WEBHOOK" &>/dev/null
    fi

    echo "Done. $ip đã được unban."
}

unban_all() {
    echo "UNBANNING TẤT CẢ IP trên tất cả node..."
    echo ""

    for node in $ALL_NODES; do
        if [ "$node" = "localhost" ]; then
            echo -n "  Node 1 (local): "
            nft flush chain inet fastnetmon ddos_block 2>/dev/null && echo "OK" || echo "FAIL"
        else
            echo -n "  Node $node: "
            ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft flush chain inet fastnetmon ddos_block" \
                2>/dev/null && echo "OK" || echo "FAIL"
        fi
    done

    if [ -n "$DISCORD_WEBHOOK" ]; then
        local payload="{\"username\":\"FastNetMon\",\"embeds\":[{\"title\":\"EMERGENCY: ALL IPs UNBANNED\",\"color\":15844367,\"fields\":[{\"name\":\"By\",\"value\":\"$(whoami)@$(hostname)\"}],\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]}"
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$DISCORD_WEBHOOK" &>/dev/null
    fi

    echo ""
    echo "Done. Tất cả IP đã được unban."
}

# === MAIN ===

if [ -z "$1" ]; then
    echo "Cách dùng:"
    echo "  $0 <IP>    - Unban 1 IP cụ thể"
    echo "  $0 all     - Unban TẤT CẢ"
    echo "  $0 list    - Xem danh sách IP đang bị ban"
    exit 1
fi

case "$1" in
    list)
        list_banned
        ;;
    all)
        read -p "Bạn chắc chắn muốn unban TẤT CẢ? (y/N): " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            unban_all
        else
            echo "Hủy."
        fi
        ;;
    *)
        unban_ip "$1"
        ;;
esac
