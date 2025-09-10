#!/bin/bash

echo "[*] Cleaning up old processes..."
# Kill dnsmasq lama kalau ada
sudo pkill dnsmasq 2>/dev/null
# Kill hostapd lama kalau ada
sudo pkill hostapd 2>/dev/null

echo "[*] Stopping systemd-resolved..."
sudo systemctl stop systemd-resolved 2>/dev/null
sudo systemctl disable systemd-resolved 2>/dev/null

echo "[*] Flushing old iptables rules..."
sudo iptables -F
sudo iptables -t nat -F

echo "[*] Setting up interface..."
sudo ip addr flush dev wlx00c0cab84be3
sudo ip addr add 10.0.0.1/24 dev wlx00c0cab84be3
sudo ip link set wlx00c0cab84be3 up

echo "[*] Starting hostapd..."
sudo ./hostapd/hostapd ./hostapd/config.conf &

sleep 3

echo "[*] Starting dnsmasq..."
sudo dnsmasq -C ./dnsmasq.conf -d &

sleep 2

echo "[*] Enabling NAT..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -F
sudo iptables -F
sudo iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE
sudo iptables -A FORWARD -i wlx00c0cab84be3 -o wlp3s0 -j ACCEPT
sudo iptables -A FORWARD -i wlp3s0 -o wlx00c0cab84be3 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A PREROUTING -i wlx00c0cab84be3 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
sudo iptables -t nat -A PREROUTING -i wlx00c0cab84be3 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:443 -j DNAT --to-destination 10.0.0.1:443

echo "service started."
