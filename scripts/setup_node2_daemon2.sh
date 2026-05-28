#!/usr/bin/env bash
#############################################
# Setup Node 2: daemon2 (192.168.1.92)
# Role: Game Server - nftables protection only
# Interface: ens18
#
# CHẠY BẰNG ROOT:
#   sudo bash setup_node2_daemon2.sh
#############################################

set -e

echo "========================================="
echo " Setup Node 2: daemon2 (Game Server)"
echo "========================================="
echo ""

# === 1. CÀI NFTABLES ===
echo "[1/3] Cài nftables..."
apt update -y
apt install -y nftables
systemctl enable nftables
systemctl start nftables
echo "[1/3] Done."

# === 2. TẠO TABLE FASTNETMON ===
echo "[2/3] Tạo nftables table..."

# Tạo table với chain INPUT + FORWARD (cho Pterodactyl Docker containers)
nft add table inet fastnetmon 2>/dev/null || true
nft add chain inet fastnetmon ddos_input '{ type filter hook input priority -200; policy accept; }' 2>/dev/null || true
nft add chain inet fastnetmon ddos_forward '{ type filter hook forward priority -200; policy accept; }' 2>/dev/null || true

# Lưu config persist sau reboot
nft list ruleset > /etc/nftables.conf

echo "[2/3] Done."

# === 3. VERIFY ===
echo "[3/3] Kiểm tra..."
echo ""
nft list table inet fastnetmon
echo ""

echo "========================================="
echo " Node 2 (daemon2) SETUP HOÀN TẤT!"
echo "========================================="
echo ""
echo "Node này không cần cài thêm gì."
echo "daemon1 sẽ SSH sang tự động block/unblock khi có attack."
echo ""
echo "Đảm bảo daemon1 đã copy SSH key sang node này:"
echo "  (trên daemon1) ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.92"
echo ""
