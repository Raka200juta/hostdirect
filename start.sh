#!/bin/bash
IFACE="wlx00c0cab84be3"

echo "[*] Start hostapd..."
sudo ./hostapd/hostapd ./hostapd/hostapd.conf &

sleep 2

echo "[*] Start dnsmasq..."
sudo dnsmasq -C ./dnsmasq.conf -d
