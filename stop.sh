#!/bin/bash
# Script to stop all services

echo "[*] Stopping all services..."

# Stop Node.js servers
sudo killall node 2>/dev/null || true

# Stop dnsmasq
sudo killall dnsmasq 2>/dev/null || true
sudo systemctl stop dnsmasq 2>/dev/null || true

# Stop hostapd
sudo killall hostapd 2>/dev/null || true
sudo systemctl stop hostapd 2>/dev/null || true

# Stop nginx
sudo systemctl stop nginx

echo "[✓] All services stopped"
