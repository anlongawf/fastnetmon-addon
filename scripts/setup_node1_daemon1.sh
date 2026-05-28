#!/usr/bin/env bash
#############################################
# Setup daemon1 (192.168.1.36)
# Role: Game Server (node phụ, chỉ nftables)
# Interface: ens18
#
# CHẠY BẰNG ROOT:
#   sudo bash setup_node1_daemon1.sh
#############################################

set -e

echo "========================================="
echo " Setup daemon1 - Game Server (node phụ)"
echo "========================================="
echo ""

echo "[1/2] Cài nftables..."
apt update -y
apt install -y nftables
systemctl enable nftables
systemctl start nftables

echo "[2/2] Tạo nftables table..."
nft add table inet fastnetmon 2>/dev/null || true
nft add chain inet fastnetmon ddos_input '{ type filter hook input priority -200; policy accept; }' 2>/dev/null || true
nft add chain inet fastnetmon ddos_forward '{ type filter hook forward priority -200; policy accept; }' 2>/dev/null || true
nft list ruleset > /etc/nftables.conf

echo ""
nft list table inet fastnetmon
echo ""
echo "========================================="
echo " daemon1 SETUP HOÀN TẤT!"
echo "========================================="
echo ""
echo "daemon2 sẽ SSH sang tự động block/unblock."
echo "Đảm bảo daemon2 đã copy SSH key:"
echo "  (trên daemon2) ssh-copy-id -i /root/.ssh/fastnetmon_key root@192.168.1.36"
echo ""
