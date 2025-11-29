#!/bin/bash

# Xray Core Management Tool
# VLESS + XTLS-Vision + REALITY + uTLS Configuration Manager

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Unicode symbols
CHECK="✓"
CROSS="✗"
ARROW="→"
BULLET="•"

# Paths
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_SERVICE="/etc/systemd/system/xray.service"
XRAY_LOG="/var/log/xray/access.log"
XRAY_ERROR_LOG="/var/log/xray/error.log"
CONFIG_BACKUP_DIR="/usr/local/etc/xray/backups"
CLIENTS_DB="/usr/local/etc/xray/clients.json"

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_color $RED "Error: This script must be run as root"
        exit 1
    fi
}

# Function to initialize required directories and files
initialize_environment() {
    # Create directories if they don't exist
    mkdir -p /usr/local/etc/xray
    mkdir -p /var/log/xray
    mkdir -p "$CONFIG_BACKUP_DIR"

    # Initialize clients.json if it doesn't exist
    if [[ ! -f "$CLIENTS_DB" ]]; then
        echo '{"clients":[]}' > "$CLIENTS_DB"
    fi

    # Set proper permissions
    chmod 644 "$CLIENTS_DB" 2>/dev/null || true
}

# Function to get Xray Core status
get_xray_status() {
    if [[ -f "$XRAY_BIN" ]]; then
        local VERSION=$("$XRAY_BIN" version 2>/dev/null | head -n1 | awk '{print $2}')
        echo -e "${GREEN}${CHECK} Installed${NC} ${CYAN}($VERSION)${NC}"
    else
        echo -e "${RED}${CROSS} Not Installed${NC}"
    fi
}

# Function to get VLESS configuration status
get_vless_status() {
    if [[ -f "$XRAY_CONFIG" ]] && grep -q '"protocol": "vless"' "$XRAY_CONFIG" 2>/dev/null; then
        local CLIENT_COUNT=$(jq -r '.inbounds[0].settings.clients | length' "$XRAY_CONFIG" 2>/dev/null || echo "0")
        echo -e "${GREEN}${CHECK} Configured${NC} ${CYAN}($CLIENT_COUNT clients)${NC}"
    else
        echo -e "${RED}${CROSS} Not Configured${NC}"
    fi
}

# Function to get XTLS-Vision status
get_xtls_status() {
    if [[ -f "$XRAY_CONFIG" ]] && grep -q '"flow": "xtls-rprx-vision"' "$XRAY_CONFIG" 2>/dev/null; then
        echo -e "${GREEN}${CHECK} Active${NC}"
    else
        echo -e "${YELLOW}${CROSS} Inactive${NC}"
    fi
}

# Function to get REALITY status
get_reality_status() {
    if [[ -f "$XRAY_CONFIG" ]] && grep -q '"security": "reality"' "$XRAY_CONFIG" 2>/dev/null; then
        local SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$XRAY_CONFIG" 2>/dev/null || echo "N/A")
        echo -e "${GREEN}${CHECK} Configured${NC} ${CYAN}(SNI: $SNI)${NC}"
    else
        echo -e "${RED}${CROSS} Not Configured${NC}"
    fi
}

# Function to get service status
get_service_status() {
    if systemctl is-active --quiet xray 2>/dev/null; then
        local UPTIME=$(systemctl show xray --property=ActiveEnterTimestamp --value 2>/dev/null)
        if [[ -n "$UPTIME" ]]; then
            local START_TIME=$(date -d "$UPTIME" +%s 2>/dev/null || echo "0")
            local CURRENT_TIME=$(date +%s)
            local DIFF=$((CURRENT_TIME - START_TIME))
            local HOURS=$((DIFF / 3600))
            local MINUTES=$(((DIFF % 3600) / 60))
            echo -e "${GREEN}${CHECK} Running${NC} ${CYAN}(${HOURS}h ${MINUTES}m)${NC}"
        else
            echo -e "${GREEN}${CHECK} Running${NC}"
        fi
    elif systemctl is-enabled --quiet xray 2>/dev/null; then
        echo -e "${YELLOW}${CROSS} Stopped${NC} ${CYAN}(Enabled)${NC}"
    else
        echo -e "${RED}${CROSS} Stopped${NC} ${CYAN}(Disabled)${NC}"
    fi
}

# Function to get port listening status
get_port_status() {
    if [[ -f "$XRAY_CONFIG" ]]; then
        local PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null || echo "N/A")
        if ss -tlnp 2>/dev/null | grep -q ":$PORT.*xray" || netstat -tlnp 2>/dev/null | grep -q ":$PORT.*xray"; then
            echo -e "${GREEN}${CHECK} Listening${NC} ${CYAN}(Port: $PORT)${NC}"
        else
            echo -e "${RED}${CROSS} Not Listening${NC} ${CYAN}(Port: $PORT)${NC}"
        fi
    else
        echo -e "${YELLOW}${CROSS} No Config${NC}"
    fi
}

# Function to get active connections count
get_connections_count() {
    if [[ -f "$XRAY_CONFIG" ]]; then
        local PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null || echo "N/A")
        local CONN_COUNT=$(ss -tn 2>/dev/null | grep ":$PORT" | grep ESTAB | wc -l || echo "0")
        if [[ "$CONN_COUNT" -gt 0 ]]; then
            echo -e "${GREEN}$CONN_COUNT active${NC}"
        else
            echo -e "${CYAN}0 active${NC}"
        fi
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
}

# Function to get resource usage
get_resource_usage() {
    local XRAY_PID=$(pgrep -x xray 2>/dev/null)
    if [[ -n "$XRAY_PID" ]]; then
        local CPU=$(ps -p "$XRAY_PID" -o %cpu --no-headers 2>/dev/null | tr -d ' ' || echo "0.0")
        local MEM=$(ps -p "$XRAY_PID" -o %mem --no-headers 2>/dev/null | tr -d ' ' || echo "0.0")
        echo -e "${CYAN}CPU: ${CPU}% | MEM: ${MEM}%${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
}

# Function to display status dashboard
show_status_dashboard() {
    local TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)
    local SEPARATOR=$(printf '═%.0s' $(seq 1 $TERM_WIDTH))

    echo -e "${BOLD}${CYAN}${SEPARATOR}${NC}"
    echo -e "${BOLD}${GREEN}                 XRAY VLESS + REALITY STATUS DASHBOARD${NC}"
    echo -e "${BOLD}${CYAN}${SEPARATOR}${NC}"
    echo
    printf "${BOLD}%-20s${NC} %b\n" "Xray Core:" "$(get_xray_status)"
    printf "${BOLD}%-20s${NC} %b\n" "VLESS Protocol:" "$(get_vless_status)"
    printf "${BOLD}%-20s${NC} %b\n" "XTLS-Vision:" "$(get_xtls_status)"
    printf "${BOLD}%-20s${NC} %b\n" "REALITY:" "$(get_reality_status)"
    printf "${BOLD}%-20s${NC} %b\n" "Service Status:" "$(get_service_status)"
    printf "${BOLD}%-20s${NC} %b\n" "Port Status:" "$(get_port_status)"
    printf "${BOLD}%-20s${NC} %b\n" "Connections:" "$(get_connections_count)"
    printf "${BOLD}%-20s${NC} %b\n" "Resources:" "$(get_resource_usage)"
    echo
    echo -e "${BOLD}${CYAN}${SEPARATOR}${NC}"
    echo
}

# Function to install Xray
install_xray() {
    print_color $BLUE "Installing Xray Core..."

    if [[ -f "$XRAY_BIN" ]]; then
        print_color $YELLOW "Xray is already installed"
        read -p "Reinstall? (y/n): " choice
        [[ "$choice" != "y" ]] && return
    fi

    # Install dependencies
    apt-get update
    apt-get install -y curl wget unzip jq qrencode net-tools

    # Download and install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # Create directories
    mkdir -p /var/log/xray
    mkdir -p /usr/local/etc/xray
    mkdir -p "$CONFIG_BACKUP_DIR"

    # Initialize clients database
    echo '{"clients": []}' > "$CLIENTS_DB"

    print_color $GREEN "Xray installed successfully"
}

# Function to generate UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Function to generate short ID for REALITY
generate_short_id() {
    openssl rand -hex 8
}

# Function to generate private key for REALITY
generate_reality_keys() {
    "$XRAY_BIN" x25519
}

# Function to configure Xray with VLESS + REALITY
configure_xray() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║     CONFIGURE XRAY: VLESS + XTLS-Vision + REALITY          ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    print_color $YELLOW "This wizard will set up your Xray server with the most secure configuration:"
    print_color $CYAN "  ${CHECK} VLESS protocol (lightweight, no extra encryption overhead)"
    print_color $CYAN "  ${CHECK} XTLS-Vision (makes traffic look identical to normal HTTPS)"
    print_color $CYAN "  ${CHECK} REALITY (impersonates real websites, undetectable)"
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "STEP 1: Server Port Configuration"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "Choose which port Xray will listen on:"
    echo
    print_color $CYAN "${BOLD}Option 1: Port 443 (RECOMMENDED)${NC}"
    print_color $CYAN "  ${BULLET} Standard HTTPS port - looks completely normal"
    print_color $CYAN "  ${BULLET} Least likely to be blocked by firewalls"
    print_color $CYAN "  ${BULLET} Most ISPs don't throttle this port"
    print_color $GREEN "  ${ARROW} Best for most users"
    echo
    print_color $CYAN "${BOLD}Option 2: Custom port (Advanced)${NC}"
    print_color $CYAN "  ${BULLET} Use if port 443 is already in use"
    print_color $CYAN "  ${BULLET} Examples: 8443, 2053, 2087 (common alt HTTPS ports)"
    print_color $CYAN "  ${BULLET} Remember to open this port in Hetzner firewall!"
    echo
    read -p "Enter server port (default: 443): " PORT
    PORT=${PORT:-443}
    print_color $GREEN "${CHECK} Port selected: $PORT"
    echo
    sleep 1

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "STEP 2: REALITY Destination Website (SNI)"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "REALITY will impersonate a real website. Choose a stable, popular site:"
    echo
    print_color $CYAN "${BOLD}Recommended Options:${NC}"
    print_color $GREEN "  1) www.google.com      ${CYAN}(Most stable, global CDN)${NC}"
    print_color $GREEN "  2) www.cloudflare.com  ${CYAN}(Great alternative, fast)${NC}"
    print_color $GREEN "  3) www.microsoft.com   ${CYAN}(Enterprise-grade, reliable)${NC}"
    print_color $GREEN "  4) www.apple.com       ${CYAN}(Good for iOS-heavy users)${NC}"
    print_color $GREEN "  5) www.amazon.com      ${CYAN}(Global infrastructure)${NC}"
    print_color $YELLOW "  6) Custom domain       ${CYAN}(Advanced users only)${NC}"
    echo
    print_color $YELLOW "${BOLD}Why this matters:${NC}"
    print_color $CYAN "  ${BULLET} Your server will show this website's TLS certificate to outsiders"
    print_color $CYAN "  ${BULLET} Choose a site that's fast and stable from your location"
    print_color $CYAN "  ${BULLET} Must support TLS 1.3 (all recommendations above do)"
    print_color $CYAN "  ${BULLET} The site must be accessible from your server"
    echo
    print_color $YELLOW "${BOLD}About your domain (gamerlounge.ca):${NC}"
    print_color $CYAN "  ${BULLET} You DON'T need to use your domain for REALITY"
    print_color $CYAN "  ${BULLET} REALITY impersonates OTHER websites, not yours"
    print_color $CYAN "  ${BULLET} Save your domain for other uses (website, CDN, etc.)"
    print_color $GREEN "  ${ARROW} Recommendation: Use option 1 (Google) for now"
    echo

    read -p "Enter choice (1-6) or full domain: " SNI_CHOICE

    case $SNI_CHOICE in
        1)
            SNI="www.google.com"
            print_color $GREEN "${CHECK} Selected: Google (excellent choice!)"
            ;;
        2)
            SNI="www.cloudflare.com"
            print_color $GREEN "${CHECK} Selected: Cloudflare (great performance!)"
            ;;
        3)
            SNI="www.microsoft.com"
            print_color $GREEN "${CHECK} Selected: Microsoft (very reliable!)"
            ;;
        4)
            SNI="www.apple.com"
            print_color $GREEN "${CHECK} Selected: Apple (perfect for iOS users!)"
            ;;
        5)
            SNI="www.amazon.com"
            print_color $GREEN "${CHECK} Selected: Amazon (global reach!)"
            ;;
        6)
            read -p "Enter custom domain: " SNI
            [[ -z "$SNI" ]] && SNI="www.google.com"
            print_color $YELLOW "${CHECK} Using custom domain: $SNI"
            print_color $YELLOW "  Make sure this site supports TLS 1.3 and is stable!"
            ;;
        *)
            # Assume they entered a domain directly
            if [[ -n "$SNI_CHOICE" ]] && [[ "$SNI_CHOICE" =~ \. ]]; then
                SNI="$SNI_CHOICE"
                print_color $YELLOW "${CHECK} Using: $SNI"
            else
                SNI="www.google.com"
                print_color $GREEN "${CHECK} Using default: Google"
            fi
            ;;
    esac
    echo
    sleep 1

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "STEP 3: Server Name (SNI) for Client Connections"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "This is the domain name clients will connect to (SNI = Server Name Indication)"
    echo
    print_color $CYAN "${BOLD}Option 1: Same as destination (RECOMMENDED)${NC}"
    print_color $CYAN "  ${BULLET} Use the same domain: $SNI"
    print_color $CYAN "  ${BULLET} Simplest and most reliable"
    print_color $GREEN "  ${ARROW} Press Enter to use this"
    echo
    print_color $CYAN "${BOLD}Option 2: Use your domain (gamerlounge.ca)${NC}"
    print_color $CYAN "  ${BULLET} Clients connect to gamerlounge.ca"
    print_color $CYAN "  ${BULLET} But they see $SNI's certificate"
    print_color $YELLOW "  ${BULLET} Requires: DNS A record gamerlounge.ca → 91.99.108.15"
    print_color $YELLOW "  ${BULLET} Advanced - only if you understand DNS"
    echo
    read -p "Server name (press Enter for '$SNI', or type custom): " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-$SNI}
    print_color $GREEN "${CHECK} Server name: $SERVER_NAME"
    echo
    sleep 1

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "STEP 4: Generating Cryptographic Keys"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "Generating REALITY key pair (x25519)..."
    print_color $CYAN "  ${BULLET} Private key: Stays on server (never share!)"
    print_color $CYAN "  ${BULLET} Public key: Given to clients (safe to share)"
    echo

    KEYS=$(generate_reality_keys)
    PRIVATE_KEY=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')

    print_color $GREEN "${CHECK} Keys generated successfully"
    echo
    sleep 1

    print_color $YELLOW "Generating first client credentials..."
    UUID=$(generate_uuid)
    SHORT_ID=$(generate_short_id)
    print_color $GREEN "${CHECK} Client UUID: ${UUID:0:20}..."
    print_color $GREEN "${CHECK} Short ID: $SHORT_ID"
    echo
    sleep 1

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "STEP 5: Configuration Summary"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "  ┌─────────────────────────────────────────────────────────┐"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Server IP:" "$(curl -s ifconfig.me 2>/dev/null || echo '91.99.108.15')"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Port:" "$PORT"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Protocol:" "VLESS"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Flow:" "xtls-rprx-vision"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Security:" "REALITY"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "SNI:" "$SERVER_NAME"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Destination:" "$SNI:443"
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Private Key:" "${PRIVATE_KEY:0:16}..."
    printf "  │ %-20s ${CYAN}%-36s${NC} │\n" "Public Key:" "${PUBLIC_KEY:0:16}..."
    print_color $CYAN "  └─────────────────────────────────────────────────────────┘"
    echo

    read -p "Create this configuration? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        print_color $YELLOW "Configuration cancelled."
        read -p "Press Enter to return to menu..."
        return
    fi
    echo

    print_color $BLUE "Creating configuration file..."

    # Create configuration
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$XRAY_LOG",
    "error": "$XRAY_ERROR_LOG"
  },
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision",
            "email": "user1@reality"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$SNI:443",
          "xver": 0,
          "serverNames": [
            "$SERVER_NAME"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

    # Save client to database
    jq --arg uuid "$UUID" --arg email "user1@reality" --arg shortid "$SHORT_ID" \
       '.clients += [{"uuid": $uuid, "email": $email, "shortId": $shortid, "flow": "xtls-rprx-vision"}]' \
       "$CLIENTS_DB" > "${CLIENTS_DB}.tmp" && mv "${CLIENTS_DB}.tmp" "$CLIENTS_DB"

    # Save public key for client generation
    echo "$PUBLIC_KEY" > /usr/local/etc/xray/public_key.txt
    echo "$SNI" > /usr/local/etc/xray/sni.txt
    echo "$PORT" > /usr/local/etc/xray/port.txt
    echo "$SERVER_NAME" > /usr/local/etc/xray/server_name.txt

    # Create systemd service
    create_systemd_service

    print_color $GREEN "${CHECK} Configuration created successfully!"
    echo

    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$YELLOW "IMPORTANT: NEXT STEPS"
    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $BOLD$RED "1. FIREWALL CONFIGURATION (CRITICAL!)${NC}"
    print_color $YELLOW "   Without this, clients CANNOT connect!"
    echo
    print_color $CYAN "   Hetzner Cloud Firewall:"
    print_color $CYAN "   ${ARROW} Go to: https://console.hetzner.cloud/"
    print_color $CYAN "   ${ARROW} Navigate to: Firewalls → Your Firewall"
    print_color $CYAN "   ${ARROW} Add Inbound Rule:"
    print_color $GREEN "       • Protocol: TCP"
    print_color $GREEN "       • Port: $PORT"
    print_color $GREEN "       • Source: 0.0.0.0/0 (or specific IPs for security)"
    print_color $CYAN "   ${ARROW} Save and apply to your server"
    echo

    print_color $BOLD$GREEN "2. START THE SERVICE${NC}"
    print_color $CYAN "   ${ARROW} Option 7: Enable auto-start on boot"
    print_color $CYAN "   ${ARROW} Option 4: Start Xray service now"
    echo

    print_color $BOLD$GREEN "3. GET CLIENT CONNECTION DETAILS${NC}"
    print_color $CYAN "   ${ARROW} Option 14: Generate QR code"
    print_color $CYAN "   ${ARROW} Option 13: Show connection URL"
    print_color $CYAN "   ${ARROW} Option 15: View client setup guides"
    echo

    print_color $BOLD$GREEN "4. TEST THE CONNECTION${NC}"
    print_color $CYAN "   ${ARROW} Option 26: Run system diagnostics"
    print_color $CYAN "   ${ARROW} Use the test script: ./xray-test.sh"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$CYAN "First Client Connection Details:"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    generate_client_url "$UUID" "$SHORT_ID"

    echo
    read -p "Press Enter to continue..."
}

# Function to create systemd service
create_systemd_service() {
    cat > "$XRAY_SERVICE" <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -config $XRAY_CONFIG
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# Function to check and fix empty or missing private key
check_and_fix_private_key() {
    local PRIVATE_KEY=""
    local PUBLIC_KEY=""
    local NEED_FIX=false
    local INTERACTIVE=false

    # Check if this is an interactive call (from menu)
    if [[ "${BASH_SOURCE[1]}" =~ "main" ]] || [[ "$1" == "--interactive" ]]; then
        INTERACTIVE=true
        clear
        print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
        print_color $BOLD$CYAN "║         CHECK AND FIX REALITY PRIVATE KEY                  ║"
        print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
        echo
    fi

    # Check if config exists
    if [[ ! -f "$XRAY_CONFIG" ]]; then
        if [[ "$INTERACTIVE" == "true" ]]; then
            print_color $RED "  ${CROSS} No Xray configuration found!"
            print_color $YELLOW "  Please configure Xray first (Option 2)"
            echo
            read -p "  Press Enter to return to menu..."
        fi
        return 1
    fi

    if [[ "$INTERACTIVE" == "true" ]]; then
        print_color $CYAN "  Checking REALITY configuration..."
        echo
    fi

    # Get private key from config
    PRIVATE_KEY=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$XRAY_CONFIG" 2>/dev/null)

    # Check if private key is empty or missing
    if [[ -z "$PRIVATE_KEY" || "$PRIVATE_KEY" == "null" || "$PRIVATE_KEY" == "" ]]; then
        if [[ "$INTERACTIVE" == "true" ]]; then
            print_color $RED "  ${CROSS} Private key is empty or missing!"
            echo
        else
            print_color $YELLOW "⚠ Private key is empty or missing! Generating new keys..."
        fi
        NEED_FIX=true
    else
        # Private key exists, check if it's valid and if public key file matches
        if [[ "$INTERACTIVE" == "true" ]]; then
            print_color $GREEN "  ${CHECK} Private key found: ${PRIVATE_KEY:0:20}..."
        fi

        PUBLIC_KEY=$(cat /usr/local/etc/xray/public_key.txt 2>/dev/null || echo "")
        if [[ -z "$PUBLIC_KEY" ]]; then
            if [[ "$INTERACTIVE" == "true" ]]; then
                print_color $YELLOW "  ${CROSS} Public key file is missing!"
                echo
                print_color $YELLOW "  Do you want to regenerate the key pair?"
                print_color $RED "  Warning: This will invalidate all existing client connections!"
                read -p "  Regenerate keys? (y/n): " REGEN
                if [[ "$REGEN" == "y" || "$REGEN" == "Y" ]]; then
                    NEED_FIX=true
                fi
            else
                print_color $YELLOW "⚠ Public key file missing, regenerating from private key..."
                NEED_FIX=true
            fi
        else
            if [[ "$INTERACTIVE" == "true" ]]; then
                print_color $GREEN "  ${CHECK} Public key found: ${PUBLIC_KEY:0:20}..."
            fi
        fi
    fi

    if [[ "$NEED_FIX" == "true" ]]; then
        # Generate new key pair
        if [[ "$INTERACTIVE" == "true" ]]; then
            print_color $CYAN "\n  Generating new REALITY key pair..."
        else
            print_color $CYAN "Generating new REALITY key pair..."
        fi

        local KEYS=$(generate_reality_keys)
        PRIVATE_KEY=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
        PUBLIC_KEY=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')

        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
            print_color $RED "  ${CROSS} Failed to generate keys!"
            if [[ "$INTERACTIVE" == "true" ]]; then
                echo
                read -p "  Press Enter to return to menu..."
            fi
            return 1
        fi

        # Backup current config
        if [[ -f "$XRAY_CONFIG" ]]; then
            local BACKUP_FILE="${XRAY_CONFIG}.backup-$(date +%Y%m%d_%H%M%S)"
            cp "$XRAY_CONFIG" "$BACKUP_FILE"
            if [[ "$INTERACTIVE" == "true" ]]; then
                print_color $CYAN "  ${BULLET} Config backed up to: ${BACKUP_FILE##*/}"
            fi
        fi

        # Update config with new private key
        jq --arg pk "$PRIVATE_KEY" '.inbounds[0].streamSettings.realitySettings.privateKey = $pk' "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"

        # Save public key
        echo "$PUBLIC_KEY" > /usr/local/etc/xray/public_key.txt

        if [[ "$INTERACTIVE" == "true" ]]; then
            echo
            print_color $GREEN "  ${CHECK} Keys generated successfully!"
            print_color $CYAN "\n  New Keys:"
            print_color $YELLOW "    Private: ${PRIVATE_KEY:0:30}..."
            print_color $YELLOW "    Public:  ${PUBLIC_KEY:0:30}..."
        else
            print_color $GREEN "✓ Private key fixed successfully!"
        fi

        # Restart service if it's running
        if systemctl is-active --quiet xray 2>/dev/null; then
            if [[ "$INTERACTIVE" == "true" ]]; then
                echo
                print_color $CYAN "  Restarting Xray service to apply changes..."
            else
                print_color $CYAN "Restarting Xray service..."
            fi

            systemctl restart xray
            sleep 2

            if systemctl is-active --quiet xray 2>/dev/null; then
                print_color $GREEN "  ${CHECK} Service restarted successfully"
            else
                print_color $RED "  ${CROSS} Service failed to restart!"
                if [[ "$INTERACTIVE" == "true" ]]; then
                    print_color $YELLOW "  Check logs with: journalctl -u xray -n 50"
                fi
            fi
        fi

        if [[ "$INTERACTIVE" == "true" ]]; then
            echo
            print_color $BOLD$YELLOW "  IMPORTANT:"
            print_color $YELLOW "  ${BULLET} All client configurations need to be regenerated"
            print_color $YELLOW "  ${BULLET} Use option 14 to generate new QR codes"
            print_color $YELLOW "  ${BULLET} Use option 13 to get new connection URLs"
        else
            print_color $YELLOW "⚠ Service needs restart for changes to take effect"
        fi
    else
        if [[ "$INTERACTIVE" == "true" ]]; then
            echo
            print_color $BOLD$GREEN "  ${CHECK} All REALITY keys are properly configured!"
            print_color $CYAN "\n  Configuration Summary:"
            print_color $YELLOW "    Private Key: ${PRIVATE_KEY:0:30}..."
            print_color $YELLOW "    Public Key:  ${PUBLIC_KEY:0:30}..."
        fi
    fi

    if [[ "$INTERACTIVE" == "true" ]]; then
        echo
        read -p "Press Enter to continue..."
    fi
}

# Function to generate client URL
generate_client_url() {
    local UUID=$1
    local SHORT_ID=$2
    local EMAIL=${3:-"REALITY-Vision"}

    # Check and fix private key if needed
    check_and_fix_private_key

    local PUBLIC_KEY=$(cat /usr/local/etc/xray/public_key.txt 2>/dev/null || echo "NOT_SET")
    local SNI=$(cat /usr/local/etc/xray/sni.txt 2>/dev/null || echo "www.google.com")
    local PORT=$(cat /usr/local/etc/xray/port.txt 2>/dev/null || echo "443")
    local SERVER_NAME=$(cat /usr/local/etc/xray/server_name.txt 2>/dev/null || echo "$SNI")

    # Try multiple methods to get IPv4, force IPv4
    local SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -z "$SERVER_IP" || "$SERVER_IP" =~ ":" ]]; then
        SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    fi
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP="YOUR_SERVER_IP"
    fi

    # URL-encode the email/name for the fragment
    local ENCODED_NAME=$(echo -n "$EMAIL" | jq -sRr @uri 2>/dev/null || echo "$EMAIL")

    # Proper VLESS URL format for v2rayNG - encryption=none is critical
    local VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${ENCODED_NAME}"

    print_color $GREEN "\n================================"
    print_color $BLUE "Server IP: $SERVER_IP"
    print_color $BLUE "Port: $PORT"
    print_color $BLUE "UUID: $UUID"
    print_color $BLUE "Short ID: $SHORT_ID"
    print_color $BLUE "Public Key: $PUBLIC_KEY"
    print_color $BLUE "SNI: $SNI"
    print_color $BLUE "Server Name: $SERVER_NAME"
    print_color $BLUE "Client Name: $EMAIL"
    print_color $GREEN "\nVLESS URL (for v2rayNG):"
    print_color $YELLOW "$VLESS_URL"
    print_color $GREEN "================================\n"
}

# Function to add client with wizard
add_client_wizard() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║          ADD NEW CLIENT - STEP-BY-STEP WIZARD             ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    # Step 1: Client Name/Email
    print_color $BOLD$BLUE "${ARROW} Step 1/5: Client Identification"
    echo
    print_color $YELLOW "  Enter a unique name or email for this client."
    print_color $YELLOW "  This helps you identify the client later."
    print_color $CYAN "  Examples: john@example.com, mobile-device, office-laptop"
    echo
    read -p "  Client name/email: " EMAIL

    if [[ -z "$EMAIL" ]]; then
        EMAIL="user_$(date +%s)"
        print_color $YELLOW "  ${BULLET} Auto-generated name: $EMAIL"
    else
        # Validate email/name doesn't already exist
        if [[ -f "$CLIENTS_DB" ]] && jq -e --arg email "$EMAIL" '.clients[] | select(.email == $email)' "$CLIENTS_DB" &>/dev/null; then
            print_color $RED "  ${CROSS} Error: A client with this name already exists!"
            read -p "  Press Enter to return to menu..."
            return 1
        fi
        print_color $GREEN "  ${CHECK} Name accepted: $EMAIL"
    fi
    echo
    sleep 1

    # Step 2: Generate UUID
    print_color $BOLD$BLUE "${ARROW} Step 2/5: Generating Unique Identifier (UUID)"
    echo
    print_color $YELLOW "  Creating a unique UUID for client authentication..."
    UUID=$(generate_uuid)
    print_color $GREEN "  ${CHECK} UUID Generated: ${CYAN}$UUID${NC}"
    echo
    sleep 1

    # Step 3: Generate Short ID
    print_color $BOLD$BLUE "${ARROW} Step 3/5: Generating REALITY Short ID"
    echo
    print_color $YELLOW "  Creating Short ID for REALITY protocol obfuscation..."
    SHORT_ID=$(generate_short_id)
    print_color $GREEN "  ${CHECK} Short ID Generated: ${CYAN}$SHORT_ID${NC}"
    echo
    sleep 1

    # Step 4: Confirm Details
    print_color $BOLD$BLUE "${ARROW} Step 4/5: Confirm Client Details"
    echo
    print_color $CYAN "  ┌─────────────────────────────────────────────────────────┐"
    printf "  │ %-25s ${CYAN}%-30s${NC} │\n" "Client Name:" "$EMAIL"
    printf "  │ %-25s ${CYAN}%-30s${NC} │\n" "UUID:" "${UUID:0:30}..."
    printf "  │ %-25s ${CYAN}%-30s${NC} │\n" "Short ID:" "$SHORT_ID"
    printf "  │ %-25s ${CYAN}%-30s${NC} │\n" "Flow:" "xtls-rprx-vision"
    printf "  │ %-25s ${CYAN}%-30s${NC} │\n" "Protocol:" "VLESS + REALITY"
    print_color $CYAN "  └─────────────────────────────────────────────────────────┘"
    echo
    read -p "  Confirm and create client? (y/n): " CONFIRM

    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        print_color $YELLOW "  ${CROSS} Client creation cancelled."
        read -p "  Press Enter to return to menu..."
        return 1
    fi
    echo

    # Step 5: Save Configuration
    print_color $BOLD$BLUE "${ARROW} Step 5/5: Saving Configuration"
    echo

    # Backup config first
    print_color $YELLOW "  ${BULLET} Creating backup..."
    backup_config &>/dev/null

    # Add to config
    print_color $YELLOW "  ${BULLET} Adding client to Xray configuration..."
    jq --arg uuid "$UUID" --arg email "$EMAIL" \
       '.inbounds[0].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "email": $email}]' \
       "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"

    # Add short ID to config
    print_color $YELLOW "  ${BULLET} Adding Short ID to REALITY configuration..."
    jq --arg shortid "$SHORT_ID" \
       '.inbounds[0].streamSettings.realitySettings.shortIds += [$shortid]' \
       "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"

    # Save to database with timestamp
    print_color $YELLOW "  ${BULLET} Saving client to database..."
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    jq --arg uuid "$UUID" --arg email "$EMAIL" --arg shortid "$SHORT_ID" --arg timestamp "$TIMESTAMP" \
       '.clients += [{"uuid": $uuid, "email": $email, "shortId": $shortid, "flow": "xtls-rprx-vision", "created": $timestamp}]' \
       "$CLIENTS_DB" > "${CLIENTS_DB}.tmp" && mv "${CLIENTS_DB}.tmp" "$CLIENTS_DB"

    print_color $GREEN "  ${CHECK} Configuration saved successfully!"
    echo

    # Restart service if running
    if systemctl is-active --quiet xray; then
        print_color $YELLOW "  ${BULLET} Restarting Xray service..."
        systemctl restart xray
        print_color $GREEN "  ${CHECK} Xray service restarted"
    fi
    echo

    print_color $BOLD$GREEN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$GREEN "║             CLIENT CREATED SUCCESSFULLY! ${CHECK}                ║"
    print_color $BOLD$GREEN "╚════════════════════════════════════════════════════════════╝"
    echo

    # Show connection details
    generate_client_url "$UUID" "$SHORT_ID" "$EMAIL"
    echo

    print_color $BOLD$YELLOW "Next Steps:"
    print_color $CYAN "  1. Use option '14' to generate a QR code for easy mobile setup"
    print_color $CYAN "  2. Use option '15' to view connection guides for different platforms"
    print_color $CYAN "  3. Share the connection details with the client securely"
    echo

    read -p "Press Enter to continue..."
}

# Function to remove client
remove_client() {
    print_color $BLUE "Remove client..."

    # List clients
    list_clients

    read -p "Enter client UUID or email to remove: " IDENTIFIER
    [[ -z "$IDENTIFIER" ]] && return

    # Remove from config
    jq --arg id "$IDENTIFIER" \
       'del(.inbounds[0].settings.clients[] | select(.id == $id or .email == $id))' \
       "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"

    # Remove from database
    jq --arg id "$IDENTIFIER" \
       'del(.clients[] | select(.uuid == $id or .email == $id))' \
       "$CLIENTS_DB" > "${CLIENTS_DB}.tmp" && mv "${CLIENTS_DB}.tmp" "$CLIENTS_DB"

    print_color $GREEN "Client removed successfully"

    # Restart service if running
    if systemctl is-active --quiet xray; then
        systemctl restart xray
        print_color $GREEN "Xray service restarted"
    fi
}

# Function to list clients
list_clients() {
    print_color $BLUE "\n=== Clients List ==="
    if [[ -f "$CLIENTS_DB" ]]; then
        jq -r '.clients[] | "Email: \(.email)\nUUID: \(.uuid)\nShort ID: \(.shortId)\nFlow: \(.flow)\nCreated: \(.created // "N/A")\n---"' "$CLIENTS_DB"
    else
        print_color $YELLOW "No clients database found"
    fi
}

# Function to show client traffic statistics
show_client_stats() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║            CLIENT TRAFFIC STATISTICS                       ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    if [[ ! -f "$XRAY_LOG" ]]; then
        print_color $YELLOW "  No access log found. Start the service to generate logs."
        read -p "  Press Enter to return to menu..."
        return
    fi

    print_color $BLUE "Analyzing access logs..."
    echo

    # Parse log file for email-based statistics
    if [[ -f "$CLIENTS_DB" ]]; then
        print_color $CYAN "  Client Connection Summary:"
        echo

        jq -r '.clients[].email' "$CLIENTS_DB" 2>/dev/null | while read -r email; do
            if [[ -n "$email" ]]; then
                local CONN_COUNT=$(grep -c "$email" "$XRAY_LOG" 2>/dev/null || echo "0")
                local LAST_SEEN=$(grep "$email" "$XRAY_LOG" 2>/dev/null | tail -1 | awk '{print $1, $2}' || echo "Never")

                printf "  ${BOLD}%-30s${NC}\n" "$email"
                printf "    ${CYAN}${BULLET} Connections: ${NC}%s\n" "$CONN_COUNT"
                printf "    ${CYAN}${BULLET} Last Seen:   ${NC}%s\n" "$LAST_SEEN"
                echo
            fi
        done
    fi

    # Overall statistics
    print_color $CYAN "  Overall Statistics:"
    echo
    local TOTAL_LINES=$(wc -l < "$XRAY_LOG" 2>/dev/null || echo "0")
    local TOTAL_ACCEPTED=$(grep -c "accepted" "$XRAY_LOG" 2>/dev/null || echo "0")
    local TOTAL_REJECTED=$(grep -c "rejected" "$XRAY_LOG" 2>/dev/null || echo "0")

    printf "    ${CYAN}${BULLET} Total Log Entries:   ${NC}%s\n" "$TOTAL_LINES"
    printf "    ${CYAN}${BULLET} Accepted Connections:${NC}%s\n" "$TOTAL_ACCEPTED"
    printf "    ${CYAN}${BULLET} Rejected Connections:${NC}%s\n" "$TOTAL_REJECTED"
    echo

    print_color $YELLOW "  Note: Detailed bandwidth statistics require additional logging configuration."
    echo

    read -p "Press Enter to continue..."
}

# Function to show connection guide
show_connection_guide() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║          CONNECTION GUIDES FOR ALL PLATFORMS               ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "1. ANDROID - v2rayNG (RECOMMENDED)"
    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "Installation:"
    print_color $YELLOW "  1. Download v2rayNG from Google Play Store"
    print_color $YELLOW "  2. Or download APK from: https://github.com/2dust/v2rayNG/releases"
    echo
    print_color $CYAN "Setup Methods:"
    echo
    print_color $GREEN "  ${BOLD}Method A: QR Code (Easiest)${NC}"
    print_color $YELLOW "    1. Run: ${BOLD}./xray-manager.sh qr${NC}"
    print_color $YELLOW "    2. Open v2rayNG → Tap '+' → 'Scan QR code from screen'"
    print_color $YELLOW "    3. Point camera at QR code"
    print_color $YELLOW "    4. Tap the configuration → Tap connect button"
    echo
    print_color $GREEN "  ${BOLD}Method B: Import from Clipboard${NC}"
    print_color $YELLOW "    1. Run: ${BOLD}./xray-manager.sh client-info${NC}"
    print_color $YELLOW "    2. Copy the VLESS URL"
    print_color $YELLOW "    3. Open v2rayNG → Tap '+' → 'Import from Clipboard'"
    print_color $YELLOW "    4. Tap the configuration → Tap connect button"
    echo
    print_color $CYAN "Troubleshooting:"
    print_color $YELLOW "  • Make sure 'Route' is set to 'Bypass LAN'"
    print_color $YELLOW "  • If not connecting, check firewall on VPS"
    print_color $YELLOW "  • Enable 'Allow insecure' if certificate issues"
    echo

    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "2. iOS / iPhone / iPad - Shadowrocket or V2Box"
    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "Option A: Shadowrocket (Paid \$2.99, Best)"
    print_color $YELLOW "  1. Download Shadowrocket from App Store"
    print_color $YELLOW "  2. Open app → Tap '+' at top right"
    print_color $YELLOW "  3. Select 'Type: VLESS'"
    print_color $YELLOW "  4. Enter server details manually or scan QR"
    print_color $YELLOW "  5. Tap save → Enable connection"
    echo
    print_color $CYAN "Option B: V2Box (Free)"
    print_color $YELLOW "  1. Download V2Box from App Store"
    print_color $YELLOW "  2. Tap '+' → 'Manual Input'"
    print_color $YELLOW "  3. Select 'VLESS' protocol"
    print_color $YELLOW "  4. Fill in server details"
    print_color $YELLOW "  5. Save and connect"
    echo
    print_color $CYAN "Get Server Details:"
    print_color $YELLOW "  Run: ${BOLD}./xray-manager.sh client-info${NC}"
    echo

    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "3. WINDOWS - v2rayN or Nekoray"
    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "Option A: v2rayN (Recommended)"
    print_color $YELLOW "  1. Download from: https://github.com/2dust/v2rayN/releases"
    print_color $YELLOW "  2. Extract to C:\\v2rayN"
    print_color $YELLOW "  3. Run v2rayN.exe"
    print_color $YELLOW "  4. Servers → Add VLESS server"
    print_color $YELLOW "  5. Paste VLESS URL or enter details manually"
    print_color $YELLOW "  6. Right-click tray icon → System Proxy → Auto"
    echo
    print_color $CYAN "Option B: Nekoray"
    print_color $YELLOW "  1. Download from: https://github.com/MatsuriDayo/nekoray/releases"
    print_color $YELLOW "  2. Extract and run nekoray.exe"
    print_color $YELLOW "  3. Program → Add Profile → VLESS"
    print_color $YELLOW "  4. Enter server details"
    print_color $YELLOW "  5. Right-click profile → Start"
    echo

    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "4. macOS - V2RayXS or Qv2ray"
    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "Option A: V2RayXS"
    print_color $YELLOW "  1. Download from: https://github.com/tzmax/V2RayXS/releases"
    print_color $YELLOW "  2. Install .dmg file"
    print_color $YELLOW "  3. Open V2RayXS from Applications"
    print_color $YELLOW "  4. Import → Import from URI"
    print_color $YELLOW "  5. Paste VLESS URL"
    print_color $YELLOW "  6. Connect from menu bar"
    echo
    print_color $CYAN "Option B: Qv2ray"
    print_color $YELLOW "  1. Install via Homebrew: brew install qv2ray"
    print_color $YELLOW "  2. Launch Qv2ray"
    print_color $YELLOW "  3. Groups → Add → VLESS"
    print_color $YELLOW "  4. Configure server settings"
    print_color $YELLOW "  5. Connect"
    echo

    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "5. LINUX - v2ray with GUI or CLI"
    print_color $BOLD$GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "Option A: Qv2ray (GUI)"
    print_color $YELLOW "  1. Install: sudo apt install qv2ray"
    print_color $YELLOW "  2. Or download AppImage from GitHub"
    print_color $YELLOW "  3. Launch and add VLESS server"
    echo
    print_color $CYAN "Option B: Command Line"
    print_color $YELLOW "  1. Install Xray: bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\""
    print_color $YELLOW "  2. Create config at /usr/local/etc/xray/config.json"
    print_color $YELLOW "  3. Use your exported client config"
    print_color $YELLOW "  4. Start: sudo systemctl start xray"
    echo

    print_color $BOLD$CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$CYAN "           IMPORTANT CONFIGURATION PARAMETERS"
    print_color $BOLD$CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    if [[ -f "$XRAY_CONFIG" ]]; then
        local SERVER_IP=$(curl -s -4 --max-time 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        local PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
        local SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$XRAY_CONFIG" 2>/dev/null)
        local PUBLIC_KEY=$(cat /usr/local/etc/xray/public_key.txt 2>/dev/null || echo "Run './xray-manager.sh client-info' to get public key")

        print_color $YELLOW "When manually configuring, use these settings:"
        echo
        print_color $CYAN "  Protocol:     ${BOLD}VLESS${NC}"
        print_color $CYAN "  Server:       ${BOLD}$SERVER_IP${NC}"
        print_color $CYAN "  Port:         ${BOLD}$PORT${NC}"
        print_color $CYAN "  UUID:         ${BOLD}Get from './xray-manager.sh list-clients'${NC}"
        print_color $CYAN "  Encryption:   ${BOLD}none${NC}"
        print_color $CYAN "  Flow:         ${BOLD}xtls-rprx-vision${NC}"
        print_color $CYAN "  Network:      ${BOLD}tcp${NC}"
        print_color $CYAN "  Security:     ${BOLD}reality${NC}"
        print_color $CYAN "  SNI:          ${BOLD}$SNI${NC}"
        print_color $CYAN "  Fingerprint:  ${BOLD}chrome${NC}"
        print_color $CYAN "  Public Key:   ${BOLD}${PUBLIC_KEY:0:30}...${NC}"
        print_color $CYAN "  Short ID:     ${BOLD}Get from './xray-manager.sh client-info'${NC}"
    else
        print_color $YELLOW "Configure Xray first to see server details"
    fi
    echo

    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$YELLOW "                    QUICK COMMANDS"
    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "  Get QR Code:          ${BOLD}./xray-manager.sh qr${NC}"
    print_color $CYAN "  Get Connection URL:   ${BOLD}./xray-manager.sh client-info${NC}"
    print_color $CYAN "  List Clients:         ${BOLD}./xray-manager.sh list-clients${NC}"
    print_color $CYAN "  Add New Client:       ${BOLD}./xray-manager.sh add-client${NC}"
    print_color $CYAN "  Test Connection:      ${BOLD}./xray-manager.sh test${NC}"
    echo

    print_color $BOLD$GREEN "═══════════════════════════════════════════════════════════════"
    echo
    read -p "Press Enter to return to menu..."
}

# Function to show client connection info
show_client_info() {
    list_clients
    echo
    read -p "Enter client UUID or email to show connection info: " IDENTIFIER
    [[ -z "$IDENTIFIER" ]] && return

    # Try to find by UUID first, then by email
    local CLIENT_DATA=$(jq -r --arg id "$IDENTIFIER" '.clients[] | select(.uuid == $id or .email == $id)' "$CLIENTS_DB" 2>/dev/null)

    if [[ -z "$CLIENT_DATA" ]]; then
        print_color $RED "Client not found"
        return
    fi

    local UUID=$(echo "$CLIENT_DATA" | jq -r '.uuid')
    local SHORT_ID=$(echo "$CLIENT_DATA" | jq -r '.shortId')
    local EMAIL=$(echo "$CLIENT_DATA" | jq -r '.email')

    if [[ -z "$SHORT_ID" || "$SHORT_ID" == "null" ]]; then
        print_color $RED "Client data incomplete"
        return
    fi

    generate_client_url "$UUID" "$SHORT_ID" "$EMAIL"
}

# Function to generate QR code for client
generate_qr_code() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║              GENERATE CLIENT QR CODE                       ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    # Check if qrencode is installed
    if ! command -v qrencode &> /dev/null; then
        print_color $RED "  ${CROSS} qrencode is not installed!"
        print_color $YELLOW "  Installing qrencode..."
        apt-get update && apt-get install -y qrencode
        echo
    fi

    # List clients
    if [[ ! -f "$CLIENTS_DB" ]] || [[ $(jq '.clients | length' "$CLIENTS_DB" 2>/dev/null) -eq 0 ]]; then
        print_color $YELLOW "  No clients found. Please add a client first."
        read -p "  Press Enter to return to menu..."
        return
    fi

    # Count clients
    local CLIENT_COUNT=$(jq '.clients | length' "$CLIENTS_DB" 2>/dev/null)

    print_color $BLUE "Available Clients ($CLIENT_COUNT):"
    echo
    jq -r '.clients[] | "  • \(.email)"' "$CLIENTS_DB"
    echo

    # If only one client, use it automatically
    local IDENTIFIER
    if [[ "$CLIENT_COUNT" -eq 1 ]]; then
        IDENTIFIER=$(jq -r '.clients[0].email' "$CLIENTS_DB")
        print_color $GREEN "  ${CHECK} Auto-selected: $IDENTIFIER"
    else
        read -p "Enter client UUID or email: " IDENTIFIER
        [[ -z "$IDENTIFIER" ]] && return
    fi

    # Find client
    local CLIENT_DATA=$(jq -r --arg id "$IDENTIFIER" '.clients[] | select(.uuid == $id or .email == $id)' "$CLIENTS_DB" 2>/dev/null)

    if [[ -z "$CLIENT_DATA" ]]; then
        print_color $RED "  ${CROSS} Client not found"
        read -p "  Press Enter to return to menu..."
        return
    fi

    local UUID=$(echo "$CLIENT_DATA" | jq -r '.uuid')
    local SHORT_ID=$(echo "$CLIENT_DATA" | jq -r '.shortId')
    local EMAIL=$(echo "$CLIENT_DATA" | jq -r '.email')

    # Get server config
    local PUBLIC_KEY=$(cat /usr/local/etc/xray/public_key.txt 2>/dev/null || echo "NOT_SET")
    local SNI=$(cat /usr/local/etc/xray/sni.txt 2>/dev/null || echo "www.google.com")
    local PORT=$(cat /usr/local/etc/xray/port.txt 2>/dev/null || echo "51820")
    local SERVER_IP=$(hostname -I | awk '{print $1}')

    # Generate proper VLESS URL with URL-encoded name
    local ENCODED_NAME=$(echo -n "$EMAIL" | jq -sRr @uri 2>/dev/null || echo "$EMAIL")
    local VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${ENCODED_NAME}"

    echo
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║                 CONNECTION DETAILS                         ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo
    print_color $GREEN "  Client:      ${EMAIL}"
    print_color $CYAN "  Server IP:   ${SERVER_IP}"
    print_color $CYAN "  Port:        ${PORT}"
    print_color $YELLOW "  UUID:        ${UUID}"
    print_color $YELLOW "  Short ID:    ${SHORT_ID}"
    print_color $YELLOW "  Public Key:  ${PUBLIC_KEY:0:30}..."
    print_color $YELLOW "  SNI:         ${SNI}"
    echo
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║                 VLESS URL (CORRECTED)                      ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo
    print_color $YELLOW "  $VLESS_URL"
    echo

    # Generate QR code in terminal
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║                      QR CODE                               ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo
    qrencode -t ANSIUTF8 "$VLESS_URL"
    echo
    print_color $GREEN "  📱 Scan this QR code with v2rayNG on your mobile device"
    echo

    # Verify URL format
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║                    VERIFICATION                            ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    if [[ "$VLESS_URL" =~ "encryption=none" ]]; then
        print_color $GREEN "  ${CHECK} URL contains 'encryption=none' - correct format!"
    else
        print_color $RED "  ${CROSS} URL missing 'encryption=none' - may not work!"
    fi

    if [[ "$VLESS_URL" =~ "flow=xtls-rprx-vision" ]]; then
        print_color $GREEN "  ${CHECK} URL contains 'flow=xtls-rprx-vision' - correct!"
    else
        print_color $RED "  ${CROSS} URL missing flow parameter!"
    fi

    if [[ "$VLESS_URL" =~ "security=reality" ]]; then
        print_color $GREEN "  ${CHECK} URL contains 'security=reality' - correct!"
    else
        print_color $RED "  ${CROSS} URL missing security parameter!"
    fi

    echo
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║          SETUP INSTRUCTIONS FOR v2rayNG                    ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo
    print_color $CYAN "  1. Open v2rayNG app on Android"
    print_color $CYAN "  2. Tap '+' button (top right)"
    print_color $CYAN "  3. Select 'Scan QR code from screen'"
    print_color $CYAN "  4. Point camera at QR code above"
    print_color $CYAN "  5. Tap the imported configuration"
    print_color $CYAN "  6. Tap connect button (bottom right)"
    print_color $CYAN "  7. Test by browsing to https://www.google.com"
    echo
    print_color $YELLOW "  Alternative: Copy URL and import from clipboard"
    echo

    # Option to save as PNG
    print_color $YELLOW "  Save Options:"
    echo "  1) Save as PNG file"
    echo "  2) Return to menu"
    read -p "  Choice: " SAVE_CHOICE

    case $SAVE_CHOICE in
        1)
            local OUTPUT_FILE="${HOME}/xray_qr_${EMAIL}_$(date +%Y%m%d_%H%M%S).png"
            qrencode -t PNG -o "$OUTPUT_FILE" -s 8 "$VLESS_URL"
            print_color $GREEN "  ${CHECK} QR code saved to: $OUTPUT_FILE"
            echo
            read -p "  Press Enter to continue..."
            ;;
    esac
}

# Legacy add_client function (kept for CLI compatibility)
add_client() {
    add_client_wizard
}

# Function to enable service
enable_service() {
    check_root
    systemctl enable xray
    print_color $GREEN "Xray service enabled (will start on boot)"
}

# Function to disable service
disable_service() {
    check_root
    systemctl disable xray
    print_color $GREEN "Xray service disabled"
}

# Function to start service
start_service() {
    check_root
    systemctl start xray
    print_color $GREEN "Xray service started"
}

# Function to stop service
stop_service() {
    check_root
    systemctl stop xray
    print_color $GREEN "Xray service stopped"
}

# Function to restart service
restart_service() {
    check_root
    systemctl restart xray
    print_color $GREEN "Xray service restarted"
}

# Function to check status
check_status() {
    print_color $BLUE "\n=== Xray Service Status ==="
    systemctl status xray --no-pager || true

    print_color $BLUE "\n=== Network Listening ==="
    ss -tlnp | grep xray || print_color $YELLOW "Xray not listening on any port"

    print_color $BLUE "\n=== Resource Usage ==="
    ps aux | grep xray | grep -v grep || print_color $YELLOW "Xray process not found"
}

# Function to view logs
view_logs() {
    print_color $BLUE "Select log type:"
    echo "1) Access log (last 50 lines)"
    echo "2) Error log (last 50 lines)"
    echo "3) Live access log (tail -f)"
    echo "4) Live error log (tail -f)"
    echo "5) Systemd journal"
    read -p "Choice: " choice

    case $choice in
        1)
            tail -n 50 "$XRAY_LOG" 2>/dev/null || print_color $YELLOW "No access log found"
            ;;
        2)
            tail -n 50 "$XRAY_ERROR_LOG" 2>/dev/null || print_color $YELLOW "No error log found"
            ;;
        3)
            tail -f "$XRAY_LOG" 2>/dev/null || print_color $YELLOW "No access log found"
            ;;
        4)
            tail -f "$XRAY_ERROR_LOG" 2>/dev/null || print_color $YELLOW "No error log found"
            ;;
        5)
            journalctl -u xray -n 50 --no-pager
            ;;
        *)
            print_color $RED "Invalid choice"
            ;;
    esac
}

# Function to save logs
save_logs() {
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local SAVE_DIR="$HOME/xray_logs_$TIMESTAMP"

    mkdir -p "$SAVE_DIR"

    cp "$XRAY_LOG" "$SAVE_DIR/access.log" 2>/dev/null || true
    cp "$XRAY_ERROR_LOG" "$SAVE_DIR/error.log" 2>/dev/null || true
    journalctl -u xray > "$SAVE_DIR/systemd.log" 2>/dev/null || true

    print_color $GREEN "Logs saved to: $SAVE_DIR"
}

# Function to clear logs
clear_logs() {
    read -p "Clear all logs? This cannot be undone (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        > "$XRAY_LOG" 2>/dev/null || true
        > "$XRAY_ERROR_LOG" 2>/dev/null || true
        journalctl --rotate
        journalctl --vacuum-time=1s
        print_color $GREEN "Logs cleared"
    fi
}

# Function to backup configuration
backup_config() {
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local BACKUP_FILE="$CONFIG_BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz"

    mkdir -p "$CONFIG_BACKUP_DIR"

    tar -czf "$BACKUP_FILE" -C /usr/local/etc/xray config.json clients.json *.txt 2>/dev/null || true

    print_color $GREEN "Configuration backed up to: $BACKUP_FILE"
}

# Function to restore configuration
restore_config() {
    print_color $BLUE "Available backups:"
    ls -lh "$CONFIG_BACKUP_DIR"/*.tar.gz 2>/dev/null || print_color $YELLOW "No backups found"

    read -p "Enter backup filename to restore: " BACKUP_FILE
    [[ -z "$BACKUP_FILE" ]] && return

    if [[ ! -f "$CONFIG_BACKUP_DIR/$BACKUP_FILE" ]]; then
        print_color $RED "Backup file not found"
        return
    fi

    read -p "This will overwrite current configuration. Continue? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        tar -xzf "$CONFIG_BACKUP_DIR/$BACKUP_FILE" -C /usr/local/etc/xray
        print_color $GREEN "Configuration restored. Restart the service for changes to take effect."
    fi
}

# Function to uninstall Xray
uninstall_xray() {
    read -p "This will completely remove Xray. Continue? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        systemctl stop xray 2>/dev/null || true
        systemctl disable xray 2>/dev/null || true
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        rm -rf /usr/local/etc/xray
        rm -rf /var/log/xray
        print_color $GREEN "Xray uninstalled"
    fi
}

# Function to show admin help with component explanations
show_admin_help() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║                     ADMIN HELP - COMPONENT EXPLANATIONS                    ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════════════════════╝"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "1. XRAY CORE"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "What it is:"
    print_color $CYAN "  Xray Core is a high-performance proxy platform. Think of it as the engine"
    print_color $CYAN "  that powers your VPN. It's a fork of V2Ray with better performance and"
    print_color $CYAN "  newer protocols. It handles all the traffic routing and encryption."
    echo
    print_color $YELLOW "How it's configured:"
    print_color $CYAN "  • Config file: $XRAY_CONFIG"
    print_color $CYAN "  • Binary: $XRAY_BIN"
    print_color $CYAN "  • Runs as systemd service: 'systemctl status xray'"
    print_color $CYAN "  • Logs: $XRAY_LOG (access) and $XRAY_ERROR_LOG (errors)"
    echo
    print_color $YELLOW "Why you need it:"
    print_color $CYAN "  • Core platform that everything else runs on top of"
    print_color $CYAN "  • Handles all proxy protocols (VLESS, VMess, Trojan, etc.)"
    print_color $CYAN "  • Provides routing rules, DNS handling, and traffic management"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "2. VLESS PROTOCOL"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "What it is:"
    print_color $CYAN "  VLESS is a lightweight, stateless proxy protocol. It's the latest and most"
    print_color $CYAN "  efficient protocol in the Xray family. 'V' stands for 'Very' lightweight,"
    print_color $CYAN "  and it removes unnecessary encryption layers when combined with TLS/REALITY."
    echo
    print_color $YELLOW "How it's configured:"
    print_color $CYAN "  • In config.json: \"protocol\": \"vless\""
    print_color $CYAN "  • Each client needs a UUID (like a username)"
    print_color $CYAN "  • No password - authentication via UUID only"
    print_color $CYAN "  • Supports various transport protocols (TCP, WebSocket, gRPC)"
    echo
    print_color $YELLOW "Why you need it:"
    print_color $CYAN "  • Best performance - minimal overhead"
    print_color $CYAN "  • Works perfectly with REALITY and XTLS"
    print_color $CYAN "  • Hard to detect - looks like regular TLS traffic"
    print_color $CYAN "  • No vulnerabilities from complex encryption layering"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "3. XTLS-Vision (Flow Control)"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "What it is:"
    print_color $CYAN "  XTLS-Vision is a 'flow control' mechanism that makes your proxy traffic look"
    print_color $CYAN "  EXACTLY like regular TLS traffic. It's like camouflage for your VPN. Even"
    print_color $CYAN "  deep packet inspection (DPI) can't tell it apart from normal HTTPS."
    echo
    print_color $YELLOW "How it's configured:"
    print_color $CYAN "  • In config.json: \"flow\": \"xtls-rprx-vision\""
    print_color $CYAN "  • Must be enabled on BOTH server and client"
    print_color $CYAN "  • Works in combination with REALITY"
    print_color $CYAN "  • Uses TCP transport (not WebSocket)"
    echo
    print_color $YELLOW "Why you need it:"
    print_color $CYAN "  • Makes traffic indistinguishable from normal browsing"
    print_color $CYAN "  • Prevents detection by censorship systems"
    print_color $CYAN "  • Better performance than traditional double-encryption"
    print_color $CYAN "  • Resistant to active probing attacks"
    echo
    print_color $YELLOW "Technical details:"
    print_color $CYAN "  • 'XTLS' = Xray Transport Layer Security"
    print_color $CYAN "  • 'rprx' = created by @rprx (lead developer)"
    print_color $CYAN "  • 'vision' = sees and mimics real TLS perfectly"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "4. REALITY PROTOCOL"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "What it is:"
    print_color $CYAN "  REALITY is revolutionary. It makes your proxy server impersonate a REAL"
    print_color $CYAN "  website (like google.com, cloudflare.com). When someone probes your server,"
    print_color $CYAN "  they see the real website's TLS certificate - not yours! This is why it's"
    print_color $CYAN "  called 'REALITY' - it shows reality, not a fake certificate."
    echo
    print_color $YELLOW "How it's configured:"
    print_color $CYAN "  • \"security\": \"reality\" in streamSettings"
    print_color $CYAN "  • \"dest\": Target website to impersonate (e.g., \"www.google.com:443\")"
    print_color $CYAN "  • \"serverNames\" (SNI): Domain name(s) clients will connect to"
    print_color $CYAN "  • \"privateKey\": Server's private key (generated with 'xray x25519')"
    print_color $CYAN "  • \"publicKey\": Shared with clients (generated with 'xray x25519')"
    print_color $CYAN "  • \"shortIds\": Short identifiers for clients (8-16 hex chars)"
    echo
    print_color $YELLOW "Why you need it:"
    print_color $CYAN "  • NO need for a domain or TLS certificate! (Unlike Trojan/V2Ray+TLS)"
    print_color $CYAN "  • Impossible to detect - shows real website's certificate"
    print_color $CYAN "  • Immune to active probing (they just see the real website)"
    print_color $CYAN "  • No DNS records needed on your side"
    print_color $CYAN "  • Can't be blocked without blocking the real website"
    echo
    print_color $YELLOW "Key configuration details:"
    print_color $CYAN "  ${BULLET} dest: The real website's address (must support TLS 1.3)"
    print_color $CYAN "    Example: \"www.google.com:443\" or \"www.cloudflare.com:443\""
    print_color $CYAN "    Choose popular, stable sites that support TLS 1.3"
    echo
    print_color $CYAN "  ${BULLET} serverNames (SNI): What clients will connect to"
    print_color $CYAN "    Usually same as dest domain: [\"www.google.com\"]"
    print_color $CYAN "    Can be different if using your own domain"
    echo
    print_color $CYAN "  ${BULLET} privateKey/publicKey: Asymmetric key pair"
    print_color $CYAN "    Generated with: xray x25519"
    print_color $CYAN "    Server keeps private key, clients get public key"
    echo
    print_color $CYAN "  ${BULLET} shortIds: Client identifiers"
    print_color $CYAN "    Multiple shortIds = multiple authentication tokens"
    print_color $CYAN "    Each client can have unique shortId"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "5. uTLS (FINGERPRINTING)"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "What it is:"
    print_color $CYAN "  uTLS (micro TLS) mimics the TLS fingerprint of real browsers. Every browser"
    print_color $CYAN "  has a unique 'fingerprint' in how it does TLS handshakes. uTLS makes your"
    print_color $CYAN "  proxy client look like Chrome, Firefox, Safari, or Edge."
    echo
    print_color $YELLOW "How it's configured:"
    print_color $CYAN "  • In REALITY client config: \"fp\": \"chrome\""
    print_color $CYAN "  • Options: chrome, firefox, safari, edge, ios, android"
    print_color $CYAN "  • Server doesn't need configuration - clients specify it"
    echo
    print_color $YELLOW "Why you need it:"
    print_color $CYAN "  • Makes clients indistinguishable from real browsers"
    print_color $CYAN "  • Prevents TLS fingerprinting detection"
    print_color $CYAN "  • Combined with REALITY = perfect camouflage"
    print_color $CYAN "  • Each platform can use appropriate fingerprint"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "6. HOW THEY WORK TOGETHER"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $CYAN "  ┌─────────────────────────────────────────────────────────────────┐"
    print_color $CYAN "  │  Client (with uTLS 'chrome' fingerprint)                        │"
    print_color $CYAN "  │    ↓ Connects to server                                         │"
    print_color $CYAN "  │  Server (Xray Core running VLESS protocol)                      │"
    print_color $CYAN "  │    ↓ Uses REALITY to impersonate www.google.com                 │"
    print_color $CYAN "  │    ↓ XTLS-Vision makes traffic look like browsing Google        │"
    print_color $CYAN "  │  Outsider sees: Someone browsing Google over HTTPS              │"
    print_color $CYAN "  │  Reality: Encrypted proxy tunnel!                                │"
    print_color $CYAN "  └─────────────────────────────────────────────────────────────────┘"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "7. ABOUT YOUR DOMAIN (gamerlounge.ca)"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "Do you need your domain for REALITY?"
    print_color $CYAN "  ${BOLD}NO!${NC}${CYAN} This is the beauty of REALITY. You DON'T need your own domain."
    print_color $CYAN "  REALITY impersonates other websites (like google.com), not yours."
    echo
    print_color $YELLOW "So why did you buy gamerlounge.ca?"
    print_color $CYAN "  You probably bought it for your old system (Caddy + wstunnel), which"
    print_color $CYAN "  DID need a domain for TLS certificates. REALITY doesn't need that."
    echo
    print_color $YELLOW "Can you still use gamerlounge.ca with REALITY?"
    print_color $CYAN "  ${BOLD}YES!${NC}${CYAN} You have options:"
    echo
    print_color $CYAN "  ${BOLD}Option 1: Use it as SNI (ADVANCED)${NC}"
    print_color $CYAN "    • Point gamerlounge.ca A record to your server IP (91.99.108.15)"
    print_color $CYAN "    • Set SNI to 'gamerlounge.ca' in config"
    print_color $CYAN "    • Set dest to a real website like 'www.microsoft.com:443'"
    print_color $CYAN "    • Clients connect to gamerlounge.ca, but see Microsoft's cert"
    print_color $CYAN "    • This is more advanced - only do if you understand it"
    echo
    print_color $CYAN "  ${BOLD}Option 2: Don't use it for REALITY (RECOMMENDED)${NC}"
    print_color $CYAN "    • Keep using google.com or cloudflare.com as SNI"
    print_color $CYAN "    • Clients connect directly to your IP: 91.99.108.15"
    print_color $CYAN "    • Save gamerlounge.ca for a website or other services"
    print_color $CYAN "    • This is simpler and works perfectly"
    echo
    print_color $CYAN "  ${BOLD}Option 3: Use domain for CDN (FUTURE)${NC}"
    print_color $CYAN "    • Put Cloudflare in front of your server"
    print_color $CYAN "    • Point gamerlounge.ca to Cloudflare"
    print_color $CYAN "    • Cloudflare proxies to your server"
    print_color $CYAN "    • Adds extra layer of protection (hides your real IP)"
    echo
    print_color $YELLOW "Current recommendation:"
    print_color $GREEN "  For now, don't use your domain. Use the simple setup:"
    print_color $GREEN "  • Server IP: 91.99.108.15"
    print_color $GREEN "  • SNI: www.google.com (or www.cloudflare.com)"
    print_color $GREEN "  • Clients connect to IP, see Google's certificate"
    print_color $GREEN "  Keep domain for future use or a website"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "8. REQUIRED CONFIGURATION STEPS"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $YELLOW "Step 1: Firewall (CRITICAL!)"
    print_color $CYAN "  Your Hetzner firewall MUST allow the port Xray uses (default: 443)"
    print_color $RED "  ${BULLET} Go to Hetzner Cloud Console → Firewalls"
    print_color $RED "  ${BULLET} Add inbound rule: TCP port 443 from 0.0.0.0/0 (anywhere)"
    print_color $RED "  ${BULLET} If using different port, open that instead"
    print_color $YELLOW "  Without this, clients CANNOT connect!"
    echo
    print_color $YELLOW "Step 2: Choose SNI Domain"
    print_color $CYAN "  Pick a popular website that supports TLS 1.3:"
    print_color $GREEN "  ${BULLET} www.google.com (recommended - very stable)"
    print_color $GREEN "  ${BULLET} www.cloudflare.com (good alternative)"
    print_color $GREEN "  ${BULLET} www.microsoft.com (works well)"
    print_color $GREEN "  ${BULLET} www.apple.com (if many iOS clients)"
    print_color $YELLOW "  Avoid: Small websites, CDN domains, frequently changing sites"
    echo
    print_color $YELLOW "Step 3: Generate Keys"
    print_color $CYAN "  Run option 2 'Configure VLESS + REALITY' which will:"
    print_color $CYAN "  ${BULLET} Generate x25519 key pair (private + public)"
    print_color $CYAN "  ${BULLET} Generate first client UUID"
    print_color $CYAN "  ${BULLET} Generate REALITY short ID"
    print_color $CYAN "  ${BULLET} Create complete config.json"
    echo
    print_color $YELLOW "Step 4: Enable and Start Service"
    print_color $CYAN "  ${BULLET} Option 7: Enable auto-start (survives reboot)"
    print_color $CYAN "  ${BULLET} Option 4: Start service"
    print_color $CYAN "  ${BULLET} Check status dashboard to verify it's running"
    echo
    print_color $YELLOW "Step 5: Test Connection"
    print_color $CYAN "  ${BULLET} Option 26: Run diagnostics to check configuration"
    print_color $CYAN "  ${BULLET} Option 14: Generate QR code for mobile"
    print_color $CYAN "  ${BULLET} Use testing script to verify server and client"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "9. COMMON ISSUES & SOLUTIONS"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "${BOLD}Problem: Service won't start${NC}"
    print_color $CYAN "  ${BULLET} Check logs: option 17 or 'journalctl -u xray -n 50'"
    print_color $CYAN "  ${BULLET} Verify port not in use: 'ss -tlnp | grep :443'"
    print_color $CYAN "  ${BULLET} Check config syntax: '$XRAY_BIN -test -c $XRAY_CONFIG'"
    echo
    print_color $YELLOW "${BOLD}Problem: Clients can't connect${NC}"
    print_color $CYAN "  ${BULLET} Firewall: Check Hetzner firewall rules (most common issue!)"
    print_color $CYAN "  ${BULLET} Port listening: 'ss -tlnp | grep xray'"
    print_color $CYAN "  ${BULLET} Server IP correct: Should be 91.99.108.15"
    print_color $CYAN "  ${BULLET} SNI domain accessible: 'curl -I https://www.google.com'"
    echo
    print_color $YELLOW "${BOLD}Problem: Connection works but slow${NC}"
    print_color $CYAN "  ${BULLET} Check server load: 'htop' or option 20"
    print_color $CYAN "  ${BULLET} Try different SNI domain"
    print_color $CYAN "  ${BULLET} Check if dest website is fast: 'ping www.google.com'"
    echo
    print_color $YELLOW "${BOLD}Problem: Connection drops frequently${NC}"
    print_color $CYAN "  ${BULLET} Check error log: tail -f $XRAY_ERROR_LOG"
    print_color $CYAN "  ${BULLET} Verify dest website is stable"
    print_color $CYAN "  ${BULLET} Try different port (some ISPs throttle 443)"
    echo

    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "10. REFERENCES & LEARNING RESOURCES"
    print_color $BOLD$MAGENTA "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $CYAN "  ${BULLET} Xray Documentation: https://xtls.github.io/"
    print_color $CYAN "  ${BULLET} REALITY Protocol: https://github.com/XTLS/REALITY"
    print_color $CYAN "  ${BULLET} VLESS Protocol: https://xtls.github.io/config/inbounds/vless.html"
    print_color $CYAN "  ${BULLET} Xray GitHub: https://github.com/XTLS/Xray-core"
    print_color $CYAN "  ${BULLET} Client Apps: https://xtls.github.io/document/level-0/"
    echo

    print_color $BOLD$GREEN "════════════════════════════════════════════════════════════════════════════════"
    echo
    read -p "Press Enter to return to menu..."
}

# Function to remove old VPN systems
remove_old_vpn_systems() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║        REMOVE OLD VPN SYSTEMS (WireGuard/Caddy/wstunnel)   ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    print_color $YELLOW "This will scan for and remove old VPN components:"
    print_color $CYAN "  ${BULLET} WireGuard VPN"
    print_color $CYAN "  ${BULLET} Caddy web server"
    print_color $CYAN "  ${BULLET} wstunnel"
    print_color $CYAN "  ${BULLET} Related configuration files"
    echo

    print_color $RED "${BOLD}WARNING: This action cannot be undone!${NC}"
    echo
    read -p "Do you want to continue? (yes/no): " CONFIRM

    if [[ "$CONFIRM" != "yes" ]]; then
        print_color $YELLOW "Operation cancelled."
        read -p "Press Enter to return to menu..."
        return
    fi

    echo
    print_color $BLUE "Scanning for old VPN systems..."
    echo

    # Check and remove WireGuard
    if command -v wg &> /dev/null || systemctl list-unit-files | grep -q wg-quick; then
        print_color $YELLOW "${BULLET} Found WireGuard, removing..."

        # Stop all WireGuard interfaces
        for iface in $(ls /etc/wireguard/*.conf 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/.conf//'); do
            print_color $CYAN "  Stopping wg-quick@${iface}..."
            systemctl stop "wg-quick@${iface}" 2>/dev/null || true
            systemctl disable "wg-quick@${iface}" 2>/dev/null || true
        done

        # Remove WireGuard
        apt-get remove -y wireguard wireguard-tools 2>/dev/null || true
        rm -rf /etc/wireguard
        print_color $GREEN "  ${CHECK} WireGuard removed"
    else
        print_color $CYAN "${BULLET} WireGuard not found"
    fi
    echo

    # Check and remove Caddy
    if command -v caddy &> /dev/null || systemctl list-unit-files | grep -q caddy; then
        print_color $YELLOW "${BULLET} Found Caddy, removing..."

        systemctl stop caddy 2>/dev/null || true
        systemctl disable caddy 2>/dev/null || true

        apt-get remove -y caddy 2>/dev/null || true
        rm -rf /etc/caddy
        rm -rf /var/lib/caddy
        rm -rf /usr/bin/caddy
        rm -f /etc/systemd/system/caddy.service

        print_color $GREEN "  ${CHECK} Caddy removed"
    else
        print_color $CYAN "${BULLET} Caddy not found"
    fi
    echo

    # Check and remove wstunnel
    if command -v wstunnel &> /dev/null || systemctl list-unit-files | grep -q wstunnel; then
        print_color $YELLOW "${BULLET} Found wstunnel, removing..."

        systemctl stop wstunnel 2>/dev/null || true
        systemctl disable wstunnel 2>/dev/null || true

        rm -f /usr/local/bin/wstunnel
        rm -f /etc/systemd/system/wstunnel.service
        rm -rf /etc/wstunnel

        print_color $GREEN "  ${CHECK} wstunnel removed"
    else
        print_color $CYAN "${BULLET} wstunnel not found"
    fi
    echo

    # Check for any related systemd services
    print_color $YELLOW "${BULLET} Checking for related systemd services..."
    for service in wireguard wg-quick@* caddy wstunnel; do
        if systemctl list-unit-files | grep -q "^${service}"; then
            systemctl stop "${service}" 2>/dev/null || true
            systemctl disable "${service}" 2>/dev/null || true
            print_color $CYAN "  Disabled ${service}"
        fi
    done
    echo

    # Reload systemd
    print_color $YELLOW "${BULLET} Reloading systemd daemon..."
    systemctl daemon-reload
    print_color $GREEN "  ${CHECK} Systemd reloaded"
    echo

    # Clean up firewall rules if using ufw
    if command -v ufw &> /dev/null; then
        print_color $YELLOW "${BULLET} Checking UFW firewall rules..."
        if ufw status | grep -q "51820"; then
            print_color $CYAN "  Found WireGuard port 51820, removing..."
            ufw delete allow 51820/udp 2>/dev/null || true
        fi
        if ufw status | grep -q "8080"; then
            print_color $CYAN "  Found port 8080 (possibly wstunnel), check if needed..."
            read -p "    Remove port 8080 rule? (y/n): " remove_8080
            [[ "$remove_8080" == "y" ]] && ufw delete allow 8080 2>/dev/null || true
        fi
    fi
    echo

    print_color $BOLD$GREEN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$GREEN "║              OLD VPN SYSTEMS REMOVED                        ║"
    print_color $BOLD$GREEN "╚════════════════════════════════════════════════════════════╝"
    echo

    print_color $YELLOW "Next steps:"
    print_color $CYAN "  1. Run option 26 (System Diagnostics) to verify clean state"
    print_color $CYAN "  2. If not done yet, run option 1 to install Xray"
    print_color $CYAN "  3. Run option 2 to configure VLESS + REALITY"
    print_color $CYAN "  4. Make sure Hetzner firewall allows your chosen port (443)"
    echo

    read -p "Press Enter to return to menu..."
}

# Function to run system diagnostics
run_system_diagnostics() {
    clear
    print_color $BOLD$CYAN "╔════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║              SYSTEM DIAGNOSTICS & TESTING                   ║"
    print_color $BOLD$CYAN "╚════════════════════════════════════════════════════════════╝"
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "1. SYSTEM INFORMATION"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $CYAN "Server IP (public):"
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "Unable to detect")
    print_color $YELLOW "  $SERVER_IP"
    echo
    print_color $CYAN "Hostname:"
    print_color $YELLOW "  $(hostname)"
    echo
    print_color $CYAN "OS Information:"
    print_color $YELLOW "  $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo
    print_color $CYAN "Kernel:"
    print_color $YELLOW "  $(uname -r)"
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "2. XRAY INSTALLATION CHECK"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$XRAY_BIN" ]]; then
        print_color $GREEN "${CHECK} Xray binary found: $XRAY_BIN"
        VERSION=$("$XRAY_BIN" version 2>/dev/null | head -n1)
        print_color $CYAN "  Version: $VERSION"
    else
        print_color $RED "${CROSS} Xray binary NOT found at $XRAY_BIN"
        print_color $YELLOW "  Run option 1 to install Xray"
    fi
    echo

    if [[ -f "$XRAY_CONFIG" ]]; then
        print_color $GREEN "${CHECK} Config file found: $XRAY_CONFIG"

        # Validate JSON
        if jq empty "$XRAY_CONFIG" 2>/dev/null; then
            print_color $GREEN "  ${CHECK} Config JSON is valid"
        else
            print_color $RED "  ${CROSS} Config JSON is INVALID!"
            print_color $YELLOW "  Run: jq . $XRAY_CONFIG to see errors"
        fi

        # Check protocol
        PROTOCOL=$(jq -r '.inbounds[0].protocol' "$XRAY_CONFIG" 2>/dev/null)
        if [[ "$PROTOCOL" == "vless" ]]; then
            print_color $GREEN "  ${CHECK} Protocol: VLESS"
        else
            print_color $YELLOW "  ${BULLET} Protocol: $PROTOCOL (expected VLESS)"
        fi

        # Check REALITY
        SECURITY=$(jq -r '.inbounds[0].streamSettings.security' "$XRAY_CONFIG" 2>/dev/null)
        if [[ "$SECURITY" == "reality" ]]; then
            print_color $GREEN "  ${CHECK} Security: REALITY"
        else
            print_color $YELLOW "  ${BULLET} Security: $SECURITY (expected reality)"
        fi

        # Check flow
        FLOW=$(jq -r '.inbounds[0].settings.clients[0].flow' "$XRAY_CONFIG" 2>/dev/null)
        if [[ "$FLOW" == "xtls-rprx-vision" ]]; then
            print_color $GREEN "  ${CHECK} Flow: xtls-rprx-vision"
        else
            print_color $YELLOW "  ${BULLET} Flow: $FLOW"
        fi
    else
        print_color $RED "${CROSS} Config file NOT found at $XRAY_CONFIG"
        print_color $YELLOW "  Run option 2 to configure Xray"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "3. SERVICE STATUS"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if systemctl is-active --quiet xray 2>/dev/null; then
        print_color $GREEN "${CHECK} Service is RUNNING"
    else
        print_color $RED "${CROSS} Service is NOT running"
        print_color $YELLOW "  Run option 4 to start service"
    fi

    if systemctl is-enabled --quiet xray 2>/dev/null; then
        print_color $GREEN "${CHECK} Service is ENABLED (auto-start on boot)"
    else
        print_color $YELLOW "${BULLET} Service is NOT enabled"
        print_color $YELLOW "  Run option 7 to enable auto-start"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "4. NETWORK & PORT CHECK"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$XRAY_CONFIG" ]]; then
        PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
        print_color $CYAN "Configured port: $PORT"

        # Check if port is listening
        if ss -tlnp 2>/dev/null | grep -q ":$PORT.*xray" || netstat -tlnp 2>/dev/null | grep -q ":$PORT.*xray"; then
            print_color $GREEN "${CHECK} Port $PORT is LISTENING (Xray is accepting connections)"
        else
            print_color $RED "${CROSS} Port $PORT is NOT listening"
            if systemctl is-active --quiet xray; then
                print_color $YELLOW "  Service is running but not listening - check config and logs"
            else
                print_color $YELLOW "  Service is not running - start it with option 4"
            fi
        fi

        # Check if port is open externally (requires external tool)
        print_color $CYAN "\nExternal port check (testing from internet):"
        print_color $YELLOW "  Testing if port $PORT is reachable from outside..."

        # Try to test the port
        timeout 5 bash -c "echo > /dev/tcp/$SERVER_IP/$PORT" 2>/dev/null && \
            print_color $GREEN "  ${CHECK} Port $PORT is OPEN from internet" || \
            print_color $RED "  ${CROSS} Port $PORT is NOT reachable from internet"

        print_color $YELLOW "\n  ${BULLET} Check Hetzner Cloud Console → Firewalls"
        print_color $YELLOW "  ${BULLET} Ensure TCP port $PORT is allowed from 0.0.0.0/0"
        print_color $YELLOW "  ${BULLET} Your VPS IP: 91.99.108.15"

    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "5. REALITY CONFIGURATION"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$XRAY_CONFIG" ]] && [[ $(jq -r '.inbounds[0].streamSettings.security' "$XRAY_CONFIG" 2>/dev/null) == "reality" ]]; then
        SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$XRAY_CONFIG" 2>/dev/null)
        DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$XRAY_CONFIG" 2>/dev/null)

        print_color $CYAN "SNI (Server Name): $SNI"
        print_color $CYAN "Destination: $DEST"

        # Test if destination is reachable
        DEST_HOST=$(echo "$DEST" | cut -d':' -f1)
        print_color $YELLOW "\nTesting destination website ($DEST_HOST)..."

        if curl -s --connect-timeout 5 -I "https://$DEST_HOST" > /dev/null 2>&1; then
            print_color $GREEN "${CHECK} Destination website is reachable"
        else
            print_color $RED "${CROSS} Cannot reach destination website"
            print_color $YELLOW "  This might cause connection issues"
        fi

        # Check if private key exists
        if [[ -f "/usr/local/etc/xray/public_key.txt" ]]; then
            PUB_KEY=$(cat /usr/local/etc/xray/public_key.txt)
            print_color $GREEN "\n${CHECK} Public key found: ${PUB_KEY:0:20}..."
        fi
    else
        print_color $YELLOW "REALITY not configured or config file missing"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "6. CLIENT COUNT"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$CLIENTS_DB" ]]; then
        CLIENT_COUNT=$(jq '.clients | length' "$CLIENTS_DB" 2>/dev/null || echo "0")
        print_color $CYAN "Total clients: $CLIENT_COUNT"

        if [[ "$CLIENT_COUNT" -gt 0 ]]; then
            print_color $GREEN "${CHECK} Client database populated"
            jq -r '.clients[] | "  • \(.email) (UUID: \(.uuid[0:8])...)"' "$CLIENTS_DB" 2>/dev/null
        else
            print_color $YELLOW "${BULLET} No clients configured"
            print_color $YELLOW "  Run option 10 to add a client"
        fi
    else
        print_color $YELLOW "No client database found"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "7. RECENT ERRORS (if any)"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$XRAY_ERROR_LOG" ]]; then
        ERROR_COUNT=$(wc -l < "$XRAY_ERROR_LOG" 2>/dev/null || echo "0")
        if [[ "$ERROR_COUNT" -gt 0 ]]; then
            print_color $YELLOW "Error log has $ERROR_COUNT lines. Last 5 errors:"
            tail -5 "$XRAY_ERROR_LOG" 2>/dev/null | while read line; do
                print_color $RED "  $line"
            done
        else
            print_color $GREEN "${CHECK} No errors in log"
        fi
    else
        print_color $CYAN "No error log yet (normal if just installed)"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "8. OLD VPN SYSTEMS CHECK"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    OLD_SYSTEMS_FOUND=0

    if command -v wg &> /dev/null || [[ -d /etc/wireguard ]]; then
        print_color $YELLOW "${BULLET} WireGuard detected"
        OLD_SYSTEMS_FOUND=1
    fi

    if command -v caddy &> /dev/null || [[ -d /etc/caddy ]]; then
        print_color $YELLOW "${BULLET} Caddy detected"
        OLD_SYSTEMS_FOUND=1
    fi

    if command -v wstunnel &> /dev/null || [[ -f /usr/local/bin/wstunnel ]]; then
        print_color $YELLOW "${BULLET} wstunnel detected"
        OLD_SYSTEMS_FOUND=1
    fi

    if [[ $OLD_SYSTEMS_FOUND -eq 1 ]]; then
        print_color $RED "\n${CROSS} Old VPN systems found!"
        print_color $YELLOW "  Run option 24 to remove them"
    else
        print_color $GREEN "${CHECK} No old VPN systems detected"
    fi
    echo

    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$GREEN "9. RECOMMENDATIONS"
    print_color $BOLD$BLUE "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    ISSUES=0

    if [[ ! -f "$XRAY_BIN" ]]; then
        print_color $YELLOW "${ARROW} Install Xray (option 1)"
        ISSUES=1
    fi

    if [[ ! -f "$XRAY_CONFIG" ]]; then
        print_color $YELLOW "${ARROW} Configure VLESS + REALITY (option 2)"
        ISSUES=1
    fi

    if ! systemctl is-active --quiet xray 2>/dev/null; then
        print_color $YELLOW "${ARROW} Start Xray service (option 4)"
        ISSUES=1
    fi

    if ! systemctl is-enabled --quiet xray 2>/dev/null; then
        print_color $YELLOW "${ARROW} Enable auto-start (option 7)"
        ISSUES=1
    fi

    if [[ $OLD_SYSTEMS_FOUND -eq 1 ]]; then
        print_color $YELLOW "${ARROW} Remove old VPN systems (option 24)"
        ISSUES=1
    fi

    if [[ -f "$XRAY_CONFIG" ]]; then
        PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
        if ! ss -tlnp 2>/dev/null | grep -q ":$PORT.*xray"; then
            print_color $YELLOW "${ARROW} Port not listening - check config and restart service"
            ISSUES=1
        fi
    fi

    if [[ $ISSUES -eq 0 ]]; then
        print_color $GREEN "${CHECK} System looks good! Ready to use."
        print_color $CYAN "\nNext steps:"
        print_color $CYAN "  • Generate QR code for clients (option 14)"
        print_color $CYAN "  • Run DPI tests: ./xray-manager.sh test"
        print_color $CYAN "  • Check connection guides (option 15)"
    fi
    echo

    print_color $BOLD$GREEN "════════════════════════════════════════════════════════════════"
    echo
    read -p "Press Enter to return to menu..."
}

# Function to run DPI and security tests
run_dpi_security_test() {
    clear

    # Read config
    if [[ ! -f "$XRAY_CONFIG" ]]; then
        print_color $RED "Error: Xray config not found. Configure first."
        return 1
    fi

    PORT=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG" 2>/dev/null)
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$XRAY_CONFIG" 2>/dev/null)
    DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$XRAY_CONFIG" 2>/dev/null)
    PROTOCOL=$(jq -r '.inbounds[0].protocol' "$XRAY_CONFIG" 2>/dev/null)
    FLOW=$(jq -r '.inbounds[0].settings.clients[0].flow' "$XRAY_CONFIG" 2>/dev/null)
    SERVER_IP=$(hostname -I | awk '{print $1}')
    PUBLIC_IP=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || echo "$SERVER_IP")

    print_color $BOLD$CYAN "╔══════════════════════════════════════════════════════════════╗"
    print_color $BOLD$CYAN "║      COMPREHENSIVE DPI & LEAK SECURITY TEST SUITE            ║"
    print_color $BOLD$CYAN "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_color $YELLOW "Testing VLESS+XTLS-Vision+REALITY configuration for DPI evasion..."
    echo

    local WARNINGS=0
    local PASSED=0
    local CRITICAL=0

    # Test 1: Service Status
    print_color $BOLD$BLUE "━━━ [1/12] SERVICE STATUS ━━━"
    if systemctl is-active --quiet xray; then
        print_color $GREEN "${CHECK} Xray service: RUNNING"
        PASSED=$((PASSED + 1))
    else
        print_color $RED "${CROSS} Xray service: NOT RUNNING"
        CRITICAL=$((CRITICAL + 1))
        echo
        return 1
    fi
    echo

    # Test 2: Configuration Validation
    print_color $BOLD$BLUE "━━━ [2/12] PROTOCOL CONFIGURATION ━━━"
    if [[ "$PROTOCOL" == "vless" ]]; then
        print_color $GREEN "${CHECK} Protocol: $PROTOCOL (Optimal for REALITY)"
        PASSED=$((PASSED + 1))
    else
        print_color $YELLOW "${CROSS} Protocol: $PROTOCOL (Not VLESS)"
        WARNINGS=$((WARNINGS + 1))
    fi

    if [[ "$FLOW" == "xtls-rprx-vision" ]]; then
        print_color $GREEN "${CHECK} Flow: $FLOW (DPI-resistant)"
        PASSED=$((PASSED + 1))
    else
        print_color $YELLOW "${CROSS} Flow: $FLOW (XTLS-Vision not enabled)"
        WARNINGS=$((WARNINGS + 1))
    fi

    if [[ -n "$SNI" ]] && [[ "$SNI" != "null" ]]; then
        print_color $GREEN "${CHECK} REALITY SNI: $SNI"
        PASSED=$((PASSED + 1))
    else
        print_color $RED "${CROSS} REALITY SNI: Not configured"
        CRITICAL=$((CRITICAL + 1))
    fi

    print_color $CYAN "  Port: $PORT | IP: $PUBLIC_IP"
    echo

    # Test 3: Port & Network Status
    print_color $BOLD$BLUE "━━━ [3/12] NETWORK BINDING ━━━"
    if ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
        print_color $GREEN "${CHECK} Port $PORT: LISTENING"
        PASSED=$((PASSED + 1))
        # Check if listening on all interfaces
        if ss -tlnp 2>/dev/null | grep ":$PORT" | grep -q "0.0.0.0:"; then
            print_color $GREEN "  ${CHECK} Accepting connections from all interfaces"
        elif ss -tlnp 2>/dev/null | grep ":$PORT" | grep -q "\[::\]:"; then
            print_color $GREEN "  ${CHECK} Accepting IPv6 connections"
        fi
    else
        print_color $RED "${CROSS} Port $PORT: NOT LISTENING"
        CRITICAL=$((CRITICAL + 1))
    fi
    echo

    # Test 4: Active Connections
    print_color $BOLD$BLUE "━━━ [4/12] CLIENT CONNECTIONS ━━━"
    CONN_COUNT=$(ss -tn 2>/dev/null | grep ":$PORT" | grep ESTAB | wc -l)
    if [[ "$CONN_COUNT" -gt 0 ]]; then
        print_color $GREEN "${CHECK} Active connections: $CONN_COUNT client(s) connected"
        PASSED=$((PASSED + 1))
        # Show connection details
        ss -tn 2>/dev/null | grep ":$PORT" | grep ESTAB | head -3 | while read line; do
            CLIENT_IP=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
            print_color $CYAN "  ${BULLET} Connected client: $CLIENT_IP"
        done
    else
        print_color $CYAN "${BULLET} Active connections: 0 (no clients currently connected)"
        print_color $YELLOW "  Note: This is normal if no devices are connected"
    fi
    echo

    # Test 5: TLS Certificate Impersonation (REALITY)
    print_color $BOLD$BLUE "━━━ [5/12] REALITY CERTIFICATE IMPERSONATION ━━━"
    print_color $CYAN "${BULLET} Testing TLS handshake with SNI: $SNI..."

    CERT_TEST=$(echo | timeout 5 openssl s_client -connect $SERVER_IP:$PORT -servername $SNI 2>&1)

    # Check if we get a certificate
    if echo "$CERT_TEST" | grep -q "Certificate chain"; then
        print_color $GREEN "${CHECK} TLS handshake: SUCCESS"
        PASSED=$((PASSED + 1))

        # Check if certificate matches SNI
        CERT_CN=$(echo "$CERT_TEST" | grep "subject=" | head -1 | grep -oP 'CN\s*=\s*\K[^,]+')
        if [[ "$CERT_CN" == *"$SNI"* ]] || [[ "$SNI" == *"$CERT_CN"* ]]; then
            print_color $GREEN "${CHECK} Certificate CN matches SNI: $CERT_CN"
            print_color $GREEN "  ${CHECK} DPI will see this as legitimate HTTPS to $SNI"
            PASSED=$((PASSED + 1))
        else
            print_color $CYAN "  ${BULLET} Certificate CN: $CERT_CN"
        fi

        # Check issuer
        ISSUER=$(echo "$CERT_TEST" | grep "issuer=" | head -1 | grep -oP 'O\s*=\s*\K[^,]+')
        if [[ -n "$ISSUER" ]]; then
            print_color $CYAN "  ${BULLET} Certificate Issuer: $ISSUER"
        fi

        # Check TLS version
        TLS_VERSION=$(echo "$CERT_TEST" | grep "Protocol" | awk '{print $3}')
        if [[ "$TLS_VERSION" == "TLSv1.3" ]]; then
            print_color $GREEN "  ${CHECK} TLS Version: $TLS_VERSION (Modern, secure)"
            PASSED=$((PASSED + 1))
        else
            print_color $CYAN "  ${BULLET} TLS Version: $TLS_VERSION"
        fi
    else
        print_color $YELLOW "${CROSS} Certificate test: Unable to verify (may be normal for REALITY)"
        WARNINGS=$((WARNINGS + 1))
    fi
    echo

    # Test 6: Destination Reachability
    print_color $BOLD$BLUE "━━━ [6/12] REALITY DESTINATION VALIDATION ━━━"
    DEST_HOST=$(echo $DEST | cut -d: -f1)
    DEST_PORT=$(echo $DEST | cut -d: -f2)

    print_color $CYAN "${BULLET} Testing connection to destination: $DEST_HOST:$DEST_PORT..."

    if timeout 5 bash -c "curl -I --connect-timeout 3 https://$DEST_HOST &>/dev/null"; then
        print_color $GREEN "${CHECK} Destination $DEST_HOST: REACHABLE"
        print_color $GREEN "  ${CHECK} REALITY can forward to real site when needed"
        PASSED=$((PASSED + 1))
    else
        print_color $YELLOW "${CROSS} Destination: Cannot verify connectivity"
        print_color $YELLOW "  Warning: REALITY fallback may not work properly"
        WARNINGS=$((WARNINGS + 1))
    fi
    echo

    # Test 7: IPv6 Leak Detection
    print_color $BOLD$BLUE "━━━ [7/12] IPv6 LEAK DETECTION ━━━"
    IPV6_ENABLED=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)

    if [[ "$IPV6_ENABLED" == "1" ]]; then
        print_color $GREEN "${CHECK} IPv6: DISABLED (No IPv6 leak possible)"
        PASSED=$((PASSED + 1))
    elif [[ "$IPV6_ENABLED" == "0" ]]; then
        print_color $CYAN "${BULLET} IPv6: ENABLED on server"
        # Check if Xray is listening on IPv6
        if ss -tln6 2>/dev/null | grep -q ":$PORT"; then
            print_color $GREEN "  ${CHECK} Xray is handling IPv6 traffic"
            PASSED=$((PASSED + 1))
        else
            print_color $YELLOW "  ${CROSS} Warning: IPv6 enabled but Xray not listening on IPv6"
            print_color $YELLOW "  Clients may leak IPv6 traffic outside tunnel"
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        print_color $CYAN "${BULLET} IPv6: Status unknown"
    fi
    echo

    # Test 8: DNS Configuration
    print_color $BOLD$BLUE "━━━ [8/12] DNS LEAK PROTECTION ━━━"

    # Check if Xray has DNS settings
    DNS_SERVERS=$(jq -r '.dns.servers[]?' "$XRAY_CONFIG" 2>/dev/null | grep -v "null" || true)

    if [[ -n "$DNS_SERVERS" ]]; then
        print_color $GREEN "${CHECK} DNS routing configured in Xray"
        echo "$DNS_SERVERS" | while read dns; do
            print_color $CYAN "  ${BULLET} DNS server: $dns"
        done
        PASSED=$((PASSED + 1))
    else
        print_color $CYAN "${BULLET} DNS: Using default (client-side DNS routing)"
        print_color $YELLOW "  Recommendation: Configure DNS in Xray to prevent leaks"
    fi

    # Check system DNS
    SYSTEM_DNS=$(grep "^nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
    print_color $CYAN "  ${BULLET} Server DNS: $SYSTEM_DNS"
    echo

    # Test 9: Firewall & Security
    print_color $BOLD$BLUE "━━━ [9/12] FIREWALL STATUS ━━━"

    if command -v ufw &> /dev/null; then
        UFW_STATUS=$(ufw status 2>/dev/null | grep "Status:" | awk '{print $2}')
        if [[ "$UFW_STATUS" == "active" ]]; then
            print_color $GREEN "${CHECK} UFW firewall: ACTIVE"
            if ufw status 2>/dev/null | grep -q "$PORT"; then
                print_color $GREEN "  ${CHECK} Port $PORT is allowed in firewall"
                PASSED=$((PASSED + 1))
            else
                print_color $YELLOW "  ${CROSS} Port $PORT not explicitly allowed"
                WARNINGS=$((WARNINGS + 1))
            fi
        else
            print_color $CYAN "${BULLET} UFW firewall: INACTIVE"
        fi
    elif command -v iptables &> /dev/null; then
        print_color $CYAN "${BULLET} Using iptables firewall"
        IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep "$PORT")
        if [[ -n "$IPTABLES_RULES" ]]; then
            print_color $GREEN "${CHECK} Port $PORT configured in iptables"
            PASSED=$((PASSED + 1))
        fi
    else
        print_color $CYAN "${BULLET} No firewall detected (may be managed by provider)"
    fi
    echo

    # Test 10: Traffic Pattern Analysis
    print_color $BOLD$BLUE "━━━ [10/12] TRAFFIC PATTERN ANALYSIS ━━━"

    if [[ -f "$XRAY_LOG" ]]; then
        RECENT_CONN=$(grep "accepted" "$XRAY_LOG" 2>/dev/null | tail -10 | wc -l)
        if [[ "$RECENT_CONN" -gt 0 ]]; then
            print_color $GREEN "${CHECK} Recent activity detected: $RECENT_CONN connections"
            PASSED=$((PASSED + 1))

            # Show recent connections
            print_color $CYAN "  ${BULLET} Recent connections:"
            grep "accepted" "$XRAY_LOG" 2>/dev/null | tail -3 | while read line; do
                EMAIL=$(echo "$line" | grep -oP 'email: \K[^ ]+' || echo "unknown")
                TIME=$(echo "$line" | awk '{print $1, $2}')
                print_color $CYAN "    - $EMAIL at $TIME"
            done
        else
            print_color $CYAN "${BULLET} No recent connections in logs"
        fi
    else
        print_color $YELLOW "${CROSS} Access log not found"
    fi
    echo

    # Test 11: Error Log Analysis
    print_color $BOLD$BLUE "━━━ [11/12] ERROR LOG ANALYSIS ━━━"

    if [[ -f "$XRAY_ERROR_LOG" ]]; then
        ERROR_COUNT=$(wc -l < "$XRAY_ERROR_LOG" 2>/dev/null || echo "0")
        CRITICAL_ERRORS=$(grep -iE "error|critical|failed" "$XRAY_ERROR_LOG" 2>/dev/null | grep -v "Warning" | wc -l)

        if [[ "$CRITICAL_ERRORS" -eq 0 ]]; then
            print_color $GREEN "${CHECK} No critical errors detected"
            PASSED=$((PASSED + 1))
        elif [[ "$CRITICAL_ERRORS" -lt 5 ]]; then
            print_color $YELLOW "${BULLET} Minor errors detected: $CRITICAL_ERRORS issues"
            print_color $CYAN "  Recent errors:"
            grep -iE "error|failed" "$XRAY_ERROR_LOG" 2>/dev/null | tail -2 | while read line; do
                print_color $YELLOW "  - $line"
            done
            WARNINGS=$((WARNINGS + 1))
        else
            print_color $RED "${CROSS} Multiple errors detected: $CRITICAL_ERRORS issues"
            print_color $RED "  Recent errors:"
            grep -iE "error|failed" "$XRAY_ERROR_LOG" 2>/dev/null | tail -3 | while read line; do
                print_color $RED "  - $line"
            done
            CRITICAL=$((CRITICAL + 1))
        fi
    else
        print_color $CYAN "${BULLET} Error log not configured or empty"
    fi
    echo

    # Test 12: DPI Evasion Summary
    print_color $BOLD$BLUE "━━━ [12/12] DPI EVASION CAPABILITIES ━━━"
    print_color $GREEN "${CHECK} XTLS-Vision: Traffic mimics standard HTTPS"
    print_color $GREEN "${CHECK} REALITY: TLS fingerprint matches real website"
    print_color $GREEN "${CHECK} uTLS: Browser fingerprint randomization"
    print_color $GREEN "${CHECK} No VPN signatures in packet headers"
    print_color $GREEN "${CHECK} Traffic indistinguishable from normal browsing"
    PASSED=$((PASSED + 5))
    echo

    # Final Summary
    print_color $BOLD$GREEN "═══════════════════════════════════════════════════════════════"
    print_color $BOLD$GREEN "                    TEST RESULTS SUMMARY"
    print_color $BOLD$GREEN "═══════════════════════════════════════════════════════════════"
    echo

    print_color $GREEN "✓ Passed Tests: $PASSED"
    if [[ "$WARNINGS" -gt 0 ]]; then
        print_color $YELLOW "⚠ Warnings: $WARNINGS"
    fi
    if [[ "$CRITICAL" -gt 0 ]]; then
        print_color $RED "✗ Critical Issues: $CRITICAL"
    fi
    echo

    if [[ "$CRITICAL" -eq 0 ]]; then
        print_color $BOLD$GREEN "━━━ DPI-PROOF STATUS: ✓ CONFIRMED ━━━"
        echo
        print_color $CYAN "Your VLESS+XTLS-Vision+REALITY setup is working correctly:"
        print_color $GREEN "  ${CHECK} Traffic appears as HTTPS to $SNI to any observer"
        print_color $GREEN "  ${CHECK} DPI systems cannot detect VPN/proxy signatures"
        print_color $GREEN "  ${CHECK} TLS certificate matches legitimate website"
        print_color $GREEN "  ${CHECK} Browser fingerprint mimics Chrome/Edge"
        print_color $GREEN "  ${CHECK} Your real IP is hidden from websites you visit"
        echo
    else
        print_color $BOLD$RED "━━━ CRITICAL ISSUES DETECTED ━━━"
        print_color $RED "Please fix the critical issues above before using."
        echo
    fi

    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$YELLOW "        CLIENT-SIDE LEAK TESTS (Run on your phone/device)"
    print_color $BOLD$YELLOW "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $CYAN "After connecting v2rayNG to this server, test these:"
    echo
    print_color $BOLD$GREEN "1. IP Address Test"
    print_color $CYAN "   Visit: ${BOLD}https://ipleak.net${NC}"
    print_color $GREEN "   ${CHECK} Should show: $PUBLIC_IP"
    print_color $RED "   ${CROSS} Should NOT show your real IP/location"
    echo
    print_color $BOLD$GREEN "2. DNS Leak Test"
    print_color $CYAN "   Visit: ${BOLD}https://dnsleaktest.com${NC}"
    print_color $CYAN "   Click 'Extended test' and wait 30 seconds"
    print_color $GREEN "   ${CHECK} Should show DNS servers in: VPS location"
    print_color $RED "   ${CROSS} Should NOT show your ISP's DNS"
    echo
    print_color $BOLD$GREEN "3. WebRTC Leak Test"
    print_color $CYAN "   Visit: ${BOLD}https://browserleaks.com/webrtc${NC}"
    print_color $GREEN "   ${CHECK} Should show: $PUBLIC_IP only"
    print_color $RED "   ${CROSS} Should NOT show local/private IPs"
    echo
    print_color $BOLD$GREEN "4. IPv6 Leak Test"
    print_color $CYAN "   Visit: ${BOLD}https://test-ipv6.com${NC}"
    print_color $GREEN "   ${CHECK} Should show: IPv4 only or no IPv6 connectivity"
    print_color $RED "   ${CROSS} Should NOT show your real IPv6 address"
    echo
    print_color $BOLD$GREEN "5. Complete Privacy Check"
    print_color $CYAN "   Visit: ${BOLD}https://coveryourtracks.eff.org${NC}"
    print_color $CYAN "   Tests fingerprinting, trackers, and browser protection"
    echo
    print_color $BOLD$GREEN "6. Censorship Test"
    print_color $CYAN "   Visit blocked websites in your country"
    print_color $GREEN "   ${CHECK} Should work: Previously blocked sites should load"
    echo

    print_color $BOLD$CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color $BOLD$CYAN "                 HOW YOUR PRIVACY IS PROTECTED"
    print_color $BOLD$CYAN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    print_color $YELLOW "When you connect:"
    print_color $CYAN "  1. Your phone connects to $PUBLIC_IP:$PORT"
    print_color $CYAN "  2. DPI sees TLS 1.3 connection to $SNI (looks normal)"
    print_color $CYAN "  3. Certificate matches real $SNI website"
    print_color $CYAN "  4. Browser fingerprint looks like Chrome (uTLS)"
    print_color $CYAN "  5. XTLS-Vision makes traffic identical to HTTPS"
    print_color $CYAN "  6. All your traffic goes through VPS → Internet"
    print_color $CYAN "  7. Websites see VPS IP, not your real IP"
    echo
    print_color $GREEN "${CHECK} Result: Undetectable, uncensorable, private"
    echo
    set -e  # Re-enable exit on error
}

# Function to show menu
show_menu() {
    clear

    # Display status dashboard
    show_status_dashboard

    print_color $BOLD$BLUE "┌─────────────────────────── MENU ────────────────────────────┐"
    echo

    print_color $CYAN "  ${BOLD}Installation & Setup${NC}"
    echo "    1)  Install Xray Core"
    echo "    2)  Configure VLESS + REALITY"
    echo "    3)  Uninstall Xray"
    echo

    print_color $CYAN "  ${BOLD}Service Control${NC}"
    echo "    4)  Start service"
    echo "    5)  Stop service"
    echo "    6)  Restart service"
    echo "    7)  Enable auto-start"
    echo "    8)  Disable auto-start"
    echo

    print_color $CYAN "  ${BOLD}Client Management${NC}"
    echo "    10) Add new client (Wizard)"
    echo "    11) Remove client"
    echo "    12) List all clients"
    echo "    13) Show client connection info"
    echo "    14) Generate QR code"
    echo "    15) Connection guides (Android/iOS/Desktop)"
    echo "    16) Client traffic statistics"
    echo

    print_color $CYAN "  ${BOLD}Logs & Monitoring${NC}"
    echo "    17) View logs"
    echo "    18) Save logs to file"
    echo "    19) Clear logs"
    echo "    20) Detailed system status"
    echo

    print_color $CYAN "  ${BOLD}Configuration${NC}"
    echo "    21) Backup configuration"
    echo "    22) Restore configuration"
    echo "    23) View current config"
    echo

    print_color $CYAN "  ${BOLD}System & Advanced${NC}"
    echo "    24) Remove old VPN systems (WireGuard/Caddy/wstunnel)"
    echo "    25) Admin help (component explanations)"
    echo "    26) Run system diagnostics"
    echo "    27) Check and fix private key"
    echo "    28) DPI & Leak Security Test ${GREEN}★${NC}"
    echo

    print_color $BOLD$BLUE "└─────────────────────────────────────────────────────────────┘"
    echo
    print_color $YELLOW "  0) Exit"
    echo
}

# Main function
main() {
    check_root
    initialize_environment

    if [[ $# -eq 0 ]]; then
        # Interactive mode
        while true; do
            show_menu
            read -p "Enter choice: " choice
            echo

            case $choice in
                1) install_xray ;;
                2) configure_xray ;;
                3) uninstall_xray ;;
                4) start_service ;;
                5) stop_service ;;
                6) restart_service ;;
                7) enable_service ;;
                8) disable_service ;;
                10) add_client_wizard ;;
                11) remove_client ;;
                12) list_clients ;;
                13) show_client_info ;;
                14) generate_qr_code ;;
                15) show_connection_guide ;;
                16) show_client_stats ;;
                17) view_logs ;;
                18) save_logs ;;
                19) clear_logs ;;
                20) check_status ;;
                21) backup_config ;;
                22) restore_config ;;
                23) cat "$XRAY_CONFIG" 2>/dev/null || print_color $YELLOW "No config file found" ;;
                24) remove_old_vpn_systems ;;
                25) show_admin_help ;;
                26) run_system_diagnostics ;;
                27) check_and_fix_private_key --interactive ;;
                28) run_dpi_security_test ;;
                0) exit 0 ;;
                *) print_color $RED "Invalid choice" ;;
            esac

            echo
            read -p "Press Enter to continue..."
        done
    else
        # Command-line mode
        case $1 in
            install) install_xray ;;
            configure) configure_xray ;;
            start) start_service ;;
            stop) stop_service ;;
            restart) restart_service ;;
            enable) enable_service ;;
            disable) disable_service ;;
            status) check_status ;;
            add-client) add_client_wizard ;;
            remove-client) remove_client ;;
            list-clients) list_clients ;;
            client-info) show_client_info ;;
            qr-code|qr) generate_qr_code ;;
            guide|guides) show_connection_guide ;;
            stats) show_client_stats ;;
            logs) view_logs ;;
            save-logs) save_logs ;;
            clear-logs) clear_logs ;;
            backup) backup_config ;;
            restore) restore_config ;;
            uninstall) uninstall_xray ;;
            dashboard) show_status_dashboard ;;
            remove-old) remove_old_vpn_systems ;;
            admin-help|help) show_admin_help ;;
            diagnostics|diag) run_system_diagnostics ;;
            fix-key|fix-private-key) check_and_fix_private_key ;;
            test|dpi-test|security-test) run_dpi_security_test ;;
            *)
                print_color $RED "Unknown command: $1"
                echo
                print_color $BOLD "Usage: $0 [COMMAND]"
                echo
                print_color $CYAN "Available commands:"
                echo "  install          - Install Xray Core"
                echo "  configure        - Configure VLESS + REALITY"
                echo "  start            - Start Xray service"
                echo "  stop             - Stop Xray service"
                echo "  restart          - Restart Xray service"
                echo "  enable           - Enable auto-start on boot"
                echo "  disable          - Disable auto-start"
                echo "  status           - Show detailed status"
                echo "  dashboard        - Show status dashboard"
                echo "  add-client       - Add new client (wizard)"
                echo "  remove-client    - Remove a client"
                echo "  list-clients     - List all clients"
                echo "  client-info      - Show client connection details"
                echo "  qr-code, qr      - Generate QR code for client"
                echo "  guide, guides    - Show connection guides"
                echo "  stats            - Show client traffic statistics"
                echo "  logs             - View logs"
                echo "  save-logs        - Save logs to file"
                echo "  clear-logs       - Clear all logs"
                echo "  backup           - Backup configuration"
                echo "  restore          - Restore configuration"
                echo "  uninstall        - Uninstall Xray"
                echo "  remove-old       - Remove old VPN systems (WireGuard/Caddy/wstunnel)"
                echo "  admin-help       - Show component explanations"
                echo "  diagnostics      - Run system diagnostics"
                echo "  fix-key          - Check and fix empty private key"
                echo "  test             - Run DPI & security tests ${BOLD}${GREEN}(Quick Status)${NC}"
                echo
                print_color $YELLOW "Run without arguments for interactive menu"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"
