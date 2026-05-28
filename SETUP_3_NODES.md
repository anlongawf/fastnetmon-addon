# Setup FastNetMon Anti-DDoS cho 3 Node (Ubuntu/Debian)

## Kiến truc

```
Internet
   │
   ▼
[Modem/Router] ── LAN 192.168.1.0/24
   │
   ├── Node 1: 192.168.1.10 (Detector + Mitigator chính)
   │   └── FastNetMon + nftables + Discord webhook
   │
   ├── Node 2: 192.168.1.11 (Game Server)
   │   └── nftables auto-sync block list từ Node 1
   │
   └── Node 3: 192.168.1.12 (Game Server)
       └── nftables auto-sync block list từ Node 1
```

> **Lưu ý**: Thay IP theo mạng thực tế của bạn. Chạy `ip a` trên mỗi node để xem IP.

---

## PHẦN 1: Setup Node 1 (Detector chính)

### 1.1 Cài đặt FastNetMon

```bash
# SSH vào Node 1
ssh user@192.168.1.10

# Cài dependencies
sudo apt update
sudo apt install -y wget curl git

# Cài FastNetMon Community Edition
wget https://install.fastnetmon.com/installer -O /tmp/fastnetmon_install.pl
sudo perl /tmp/fastnetmon_install.pl
```

### 1.2 Cấu hình mạng cần monitor

```bash
# Tìm IP public / dải IP của bạn
curl -4 ifconfig.me
# Ghi lại IP public, ví dụ: 14.225.xxx.xxx

# Hoặc nếu dùng IP nội bộ
ip a | grep "inet "
```

Thêm dải mạng cần bảo vệ:

```bash
# Thêm dải mạng LAN
echo "192.168.1.0/24" | sudo tee /etc/networks_list

# Nếu có IP public cần bảo vệ, thêm vào:
# echo "14.225.xxx.xxx/32" | sudo tee -a /etc/networks_list
```

### 1.3 Cấu hình FastNetMon

```bash
sudo nano /etc/fastnetmon.conf
```

Sửa các dòng sau:

```ini
###
### Main configuration params
###

logging_level = info

# Bật ban khi phát hiện attack
enable_ban = on
enable_ban_ipv6 = on

# Xử lý cả 2 chiều traffic
process_incoming_traffic = on
process_outgoing_traffic = on

# Thời gian ban (giây) - 1800 = 30 phút
ban_time = 1800

# Unban chỉ khi attack đã dừng
unban_only_if_attack_finished = on

# Thu thập 50 packet mẫu khi bị attack
ban_details_records_count = 50

###
### Ngưỡng phát hiện DDoS
### Điều chỉnh theo bandwidth thực tế của bạn
###

# Bật phát hiện theo PPS và bandwidth
ban_for_pps = on
ban_for_bandwidth = on
ban_for_flows = on

# Ngưỡng tổng (vượt qua = bị ban)
# Game server thường cần giá trị thấp hơn
threshold_pps = 10000
threshold_mbps = 500
threshold_flows = 3500

# Ngưỡng theo protocol (quan trọng cho game server)
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

###
### Capture method
### Dùng AF_PACKET mirror mode cho LAN
###

mirror_afpacket = on

# Interface mạng chính (thay bằng interface của bạn)
# Chạy "ip a" để xem tên interface (thường là eth0, ens18, enp0s3...)
interfaces = eth0

# Thời gian tính trung bình (giây)
average_calculation_time = 5
speed_calculation_delay = 1

###
### Notification - Script + Discord webhook
###

notify_script_path = /usr/local/bin/notify_about_attack.sh

# Lưu pcap dump khi attack
collect_attack_pcap_dumps = on

###
### Bật API (để quản lý và đồng bộ giữa các node)
###

enable_api = on

###
### Prometheus monitoring
###

prometheus = on
prometheus_port = 9209
prometheus_host = 0.0.0.0
```

### 1.4 Setup Discord Webhook

Tạo webhook trên Discord:
1. Mở Discord → Server → **Server Settings** → **Integrations** → **Webhooks**
2. Bấm **New Webhook**, chọn channel, copy URL

```bash
# Copy script Discord có sẵn
sudo cp /opt/fastnetmon-community/src/scripts/notify_with_discord.sh /usr/local/bin/notify_about_attack.sh
sudo chmod +x /usr/local/bin/notify_about_attack.sh

# Sửa webhook URL
sudo nano /usr/local/bin/notify_about_attack.sh
```

Sửa dòng `webhook_url=""` thành:
```bash
webhook_url="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

### 1.5 Setup nftables trên Node 1

```bash
# Cài nftables
sudo apt install -y nftables
sudo systemctl enable nftables
sudo systemctl start nftables

# Tạo table FastNetMon
sudo nft add table inet fastnetmon
sudo nft add chain inet fastnetmon ddos_block '{ type filter hook input priority -200; policy accept; }'
sudo nft add chain inet fastnetmon ddos_ratelimit '{ type filter hook input priority -150; policy accept; }'

# Kiểm tra
sudo nft list table inet fastnetmon
```

### 1.6 Tạo script ban tổng hợp (Discord + nftables + sync sang Node 2,3)

```bash
sudo nano /usr/local/bin/notify_about_attack.sh
```

Thay toàn bộ nội dung bằng:

```bash
#!/usr/bin/env bash

#############################################
# FastNetMon Ban/Unban Script
# - Discord webhook notification
# - nftables local block
# - Sync block to Node 2 & Node 3 via SSH
#############################################

CLIENT_IP="$1"
DIRECTION="$2"
PPS="$3"
ACTION="$4"

# === CẤU HÌNH ===

# Discord Webhook URL (paste URL của bạn vào đây)
DISCORD_WEBHOOK=""

# Các node game server cần đồng bộ (cách nhau bởi space)
REMOTE_NODES="192.168.1.11 192.168.1.12"

# SSH user để kết nối đến các node khác
SSH_USER="root"

# Log file
LOG_FILE="/var/log/fastnetmon_mitigation.log"

# === FUNCTIONS ===

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$ACTION] $CLIENT_IP - $1" >> "$LOG_FILE"
}

discord_notify() {
    if [ -z "$DISCORD_WEBHOOK" ]; then
        return 0
    fi

    local hostname
    hostname=$(dig -x "$CLIENT_IP" +short 2>/dev/null || echo "unknown")

    if [ "$ACTION" = "ban" ]; then
        local color="14425373"  # Red
        local title="DDoS Attack Detected - BANNED"
    elif [ "$ACTION" = "unban" ]; then
        local color="3857437"   # Green
        local title="Attack Stopped - UNBANNED"
    else
        local color="1957075"   # Yellow
        local title="Attack Details"
    fi

    local payload="{
        \"username\": \"FastNetMon\",
        \"embeds\": [{
            \"title\": \"$title\",
            \"color\": $color,
            \"fields\": [
                {\"name\": \"IP\", \"value\": \"$CLIENT_IP\", \"inline\": true},
                {\"name\": \"Hostname\", \"value\": \"$hostname\", \"inline\": true},
                {\"name\": \"Direction\", \"value\": \"$DIRECTION\", \"inline\": true},
                {\"name\": \"PPS\", \"value\": \"$PPS\", \"inline\": true},
                {\"name\": \"Action\", \"value\": \"$ACTION\", \"inline\": true},
                {\"name\": \"Node\", \"value\": \"$(hostname)\", \"inline\": true}
            ],
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }]
    }"

    curl --connect-timeout 10 --max-time 30 -s -S \
        -X POST -H 'Content-type: application/json' \
        --data "$payload" "$DISCORD_WEBHOOK" &
}

nftables_local() {
    if [ "$ACTION" = "ban" ]; then
        # Block trên local node
        nft add rule inet fastnetmon ddos_block ip saddr "$CLIENT_IP" counter drop \
            comment "\"fastnetmon_${CLIENT_IP}\"" 2>/dev/null
        log_msg "LOCAL: nftables block added"
    elif [ "$ACTION" = "unban" ]; then
        # Tìm và xóa rule
        local handles
        handles=$(nft -a list chain inet fastnetmon ddos_block 2>/dev/null | \
            grep "fastnetmon_${CLIENT_IP}" | awk '{print $NF}')
        for handle in $handles; do
            nft delete rule inet fastnetmon ddos_block handle "$handle" 2>/dev/null
        done
        log_msg "LOCAL: nftables block removed"
    fi
}

sync_remote_nodes() {
    for node in $REMOTE_NODES; do
        if [ "$ACTION" = "ban" ]; then
            ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft add rule inet fastnetmon ddos_block ip saddr $CLIENT_IP counter drop comment '\"fastnetmon_${CLIENT_IP}\"'" \
                2>/dev/null &
            log_msg "REMOTE $node: ban synced"
        elif [ "$ACTION" = "unban" ]; then
            ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "$SSH_USER@$node" \
                "nft -a list chain inet fastnetmon ddos_block 2>/dev/null | grep 'fastnetmon_${CLIENT_IP}' | awk '{print \$NF}' | xargs -I{} nft delete rule inet fastnetmon ddos_block handle {}" \
                2>/dev/null &
            log_msg "REMOTE $node: unban synced"
        fi
    done
}

# === MAIN ===

# Đọc attack details từ stdin (FastNetMon yêu cầu)
if [ "$ACTION" = "ban" ]; then
    ATTACK_DETAILS=$(cat)
else
    cat > /dev/null
fi

log_msg "START - Direction: $DIRECTION, PPS: $PPS"

# 1. Gửi Discord notification
discord_notify

# 2. Block/Unblock trên local (Node 1)
nftables_local

# 3. Đồng bộ sang Node 2 & Node 3
sync_remote_nodes

log_msg "DONE"

# Chờ background jobs hoàn tất
wait
exit 0
```

```bash
sudo chmod +x /usr/local/bin/notify_about_attack.sh
```

### 1.7 Setup SSH key để Node 1 kết nối Node 2, 3 không cần password

```bash
# Tạo SSH key (bấm Enter hết, không cần passphrase)
sudo ssh-keygen -t ed25519 -f /root/.ssh/fastnetmon_key -N ""

# Copy key sang Node 2 và Node 3
sudo ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.11
sudo ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.12

# Test
sudo ssh -i /root/.ssh/fastnetmon_key root@192.168.1.11 "echo OK"
sudo ssh -i /root/.ssh/fastnetmon_key root@192.168.1.12 "echo OK"
```

Sửa lại script để dùng key:
```bash
sudo nano /usr/local/bin/notify_about_attack.sh
```
Thêm `-i /root/.ssh/fastnetmon_key` vào các dòng ssh:
```bash
ssh -i /root/.ssh/fastnetmon_key -o ConnectTimeout=5 ...
```

### 1.8 Khởi động FastNetMon

```bash
sudo systemctl enable fastnetmon
sudo systemctl restart fastnetmon

# Kiểm tra status
sudo systemctl status fastnetmon

# Xem log
sudo tail -f /var/log/fastnetmon.log
```

---

## PHẦN 2: Setup Node 2 (Game Server)

```bash
# SSH vào Node 2
ssh user@192.168.1.11
```

### 2.1 Cài nftables

```bash
sudo apt update
sudo apt install -y nftables
sudo systemctl enable nftables
sudo systemctl start nftables

# Tạo table giống Node 1
sudo nft add table inet fastnetmon
sudo nft add chain inet fastnetmon ddos_block '{ type filter hook input priority -200; policy accept; }'

# Verify
sudo nft list table inet fastnetmon
```

### 2.2 Lưu nftables config để persist sau reboot

```bash
sudo bash -c 'nft list ruleset > /etc/nftables.conf'
```

### 2.3 (Tùy chọn) Cài FastNetMon client để xem stats từ Node 1

```bash
# Không bắt buộc, chỉ để monitor
wget https://install.fastnetmon.com/installer -O /tmp/fastnetmon_install.pl
sudo perl /tmp/fastnetmon_install.pl
```

Node 2 done. Không cần cấu hình gì thêm - Node 1 sẽ SSH sang tự động block.

---

## PHẦN 3: Setup Node 3 (Game Server)

**Lặp lại y hệt Phần 2**, chỉ thay IP:

```bash
ssh user@192.168.1.12

sudo apt update
sudo apt install -y nftables
sudo systemctl enable nftables
sudo systemctl start nftables

sudo nft add table inet fastnetmon
sudo nft add chain inet fastnetmon ddos_block '{ type filter hook input priority -200; policy accept; }'

sudo bash -c 'nft list ruleset > /etc/nftables.conf'
```

---

## PHẦN 4: Test toàn bộ hệ thống

### 4.1 Test Discord webhook

```bash
# Trên Node 1, chạy thử script
echo "test" | sudo /usr/local/bin/notify_about_attack.sh 1.2.3.4 incoming 99999 ban
```

Kiểm tra Discord channel có nhận được alert không.

### 4.2 Test nftables sync

```bash
# Trên Node 1, kiểm tra rule
sudo nft list chain inet fastnetmon ddos_block

# Trên Node 2
sudo nft list chain inet fastnetmon ddos_block

# Trên Node 3
sudo nft list chain inet fastnetmon ddos_block
```

Cả 3 node đều phải có rule block IP `1.2.3.4`.

### 4.3 Test unban

```bash
echo "" | sudo /usr/local/bin/notify_about_attack.sh 1.2.3.4 incoming 0 unban
```

Kiểm tra rule đã bị xóa trên cả 3 node.

### 4.4 Test FastNetMon API

```bash
# Xem traffic hiện tại
sudo fastnetmon_api_client show_traffic

# Ban thủ công 1 IP để test
sudo fastnetmon_api_client ban 1.2.3.4
```

---

## PHẦN 5: Monitoring

### Xem log mitigation

```bash
sudo tail -f /var/log/fastnetmon_mitigation.log
```

### Xem danh sách IP đang bị ban

```bash
# Qua FastNetMon
sudo fastnetmon_api_client show_banlist

# Qua nftables (bất kỳ node nào)
sudo nft list chain inet fastnetmon ddos_block
```

### Xem traffic realtime

```bash
sudo fastnetmon_client
```

### Prometheus metrics

Truy cập: `http://192.168.1.10:9209/metrics`

---

## PHẦN 6: Tinh chỉnh ngưỡng

Quan trọng nhất là **tuning thresholds** phù hợp với traffic thật:

```bash
# Xem traffic bình thường trước
sudo fastnetmon_client
```

Ghi lại PPS và Mbps bình thường, sau đó set ngưỡng **gấp 3-5 lần** traffic bình thường:

```bash
sudo nano /etc/fastnetmon.conf
```

| Traffic bình thường | Đề xuất threshold |
|---------------------|-------------------|
| 1000 pps           | threshold_pps = 5000 |
| 50 Mbps            | threshold_mbps = 200 |
| 500 flows          | threshold_flows = 2000 |

Sau khi sửa:
```bash
sudo systemctl restart fastnetmon
```

---

## Tóm tắt lệnh nhanh

| Tác vụ | Lệnh |
|--------|-------|
| Xem traffic | `sudo fastnetmon_client` |
| Xem ban list | `sudo fastnetmon_api_client show_banlist` |
| Ban thủ công | `sudo fastnetmon_api_client ban <IP>` |
| Unban thủ công | `sudo fastnetmon_api_client unban <IP>` |
| Xem nftables rules | `sudo nft list table inet fastnetmon` |
| Xem log | `sudo tail -f /var/log/fastnetmon_mitigation.log` |
| Restart | `sudo systemctl restart fastnetmon` |
