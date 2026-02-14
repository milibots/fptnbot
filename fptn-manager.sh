#!/usr/bin/env bash
# =============================================================================
# fptn-manager — FPTN VPN + Telegram Bot Manager
# Usage: sudo bash fptn-manager.sh
# =============================================================================
set -Eeuo pipefail

# =============================================================================
# Constants & Defaults
# =============================================================================
readonly INSTALL_DIR="/opt/fptn"
readonly BOT_DIR="/opt/fptnbot"
readonly CFG_DIR="/etc/fptn"
readonly CFG_FILE="${CFG_DIR}/manager.conf"
readonly BOT_CFG="${BOT_DIR}/bot.conf"
readonly BOT_SCRIPT="${BOT_DIR}/fptnbot.py"
readonly BOT_SERVICE="/etc/systemd/system/fptnbot.service"
readonly RAW_BASE="https://raw.githubusercontent.com/milibots/fptnbot/main"

readonly DEFAULT_FPTN_PORT="443"
readonly DEFAULT_PROXY_DOMAIN="cdnvideo.com"
readonly DEFAULT_ENABLE_DETECT_PROBING="true"
readonly DEFAULT_DISABLE_BITTORRENT="true"
readonly DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER="3"
readonly DEFAULT_DNS_IPV4_PRIMARY="8.8.8.8"
readonly DEFAULT_DNS_IPV4_SECONDARY="8.8.4.4"
readonly DEFAULT_DNS_IPV6_PRIMARY="2001:4860:4860::8888"
readonly DEFAULT_DNS_IPV6_SECONDARY="2001:4860:4860::8844"
readonly DEFAULT_BANDWIDTH_MBPS="100"
readonly VPN_USERNAME="fptnuser"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" >&2; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# =============================================================================
# Helpers
# =============================================================================
has_cmd()     { command -v "$1" >/dev/null 2>&1; }
require_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run as root (sudo)."; }

is_installed() {
    [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]
}

is_bot_installed() {
    [[ -f "$BOT_SCRIPT" && -f "$BOT_CFG" ]]
}

detect_pkg_mgr() {
    if   has_cmd apt-get; then echo "apt"
    elif has_cmd dnf;     then echo "dnf"
    elif has_cmd yum;     then echo "yum"
    else                       die "Unsupported package manager."; fi
}

fetch_public_ip() {
    local services=("https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com")
    for svc in "${services[@]}"; do
        local ip
        ip="$(curl -fsSL --max-time 5 "$svc" 2>/dev/null | tr -d ' \r\n')" && { echo "$ip"; return 0; }
    done
    warn "Could not detect public IP automatically."
    return 1
}

write_file() {
    local path="$1" content="$2"
    mkdir -p "$(dirname "$path")"
    printf "%s\n" "$content" > "$path"
}

confirm() {
    local prompt="${1:-Are you sure?}"
    local answer
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]:${NC} ")" answer
    [[ "${answer,,}" == "y" ]]
}

press_enter() {
    echo
    read -r -p "Press ENTER to continue..."
}

# =============================================================================
# Dependency installation
# =============================================================================
ensure_curl() {
    has_cmd curl && return
    local pm; pm="$(detect_pkg_mgr)"
    info "Installing curl..."
    case "$pm" in
        apt) apt-get update -y -qq && apt-get install -y -qq curl ;;
        dnf) dnf install -y curl ;;
        yum) yum install -y curl ;;
    esac
}

ensure_docker() {
    has_cmd docker && { info "Docker already installed."; return; }
    info "Installing Docker..."
    ensure_curl
    curl -fsSL https://get.docker.com | sh >/dev/null 2>&1
    systemctl enable --now docker >/dev/null 2>&1 || service docker start || true
    success "Docker installed."
}

ensure_compose() {
    docker compose version >/dev/null 2>&1 && { info "Docker Compose already installed."; return; }
    info "Installing Docker Compose v2..."
    local pm; pm="$(detect_pkg_mgr)"
    case "$pm" in
        apt)       apt-get update -y -qq && apt-get install -y -qq docker-compose-plugin ;;
        dnf | yum) "$pm" install -y docker-compose-plugin ;;
    esac
    success "Docker Compose installed."
}

ensure_python() {
    local pm; pm="$(detect_pkg_mgr)"
    if ! has_cmd python3; then
        info "Installing Python3..."
        case "$pm" in
            apt) apt-get install -y -qq python3 python3-pip ;;
            dnf) dnf install -y python3 python3-pip ;;
            yum) yum install -y python3 python3-pip ;;
        esac
    fi
    if ! has_cmd pip3; then
        case "$pm" in
            apt) apt-get install -y -qq python3-pip ;;
            dnf) dnf install -y python3-pip ;;
            yum) yum install -y python3-pip ;;
        esac
    fi
    info "Installing Python bot dependencies..."
    pip3 install -q "python-telegram-bot[job-queue]==20.7" aiofiles 2>/dev/null || \
    pip3 install -q --break-system-packages "python-telegram-bot[job-queue]==20.7" aiofiles 2>/dev/null || true
    success "Python dependencies installed."
}

# =============================================================================
# Docker Compose + .env writers
# =============================================================================
write_compose() {
    cat > "${INSTALL_DIR}/docker-compose.yml" <<'YAML'
services:
  fptn-server:
    restart: unless-stopped
    image: fptnvpn/fptn-vpn-server:latest
    cap_add: [NET_ADMIN, SYS_MODULE, NET_RAW, SYS_ADMIN]
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
      - net.ipv4.conf.all.rp_filter=0
      - net.ipv4.conf.default.rp_filter=0
    ulimits:
      nproc:    { soft: 524288, hard: 524288 }
      nofile:   { soft: 524288, hard: 524288 }
      memlock:  { soft: 524288, hard: 524288 }
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "${FPTN_PORT}:443/tcp"
    volumes:
      - ./fptn-server-data:/etc/fptn
    environment:
      - ENABLE_DETECT_PROBING=${ENABLE_DETECT_PROBING}
      - DEFAULT_PROXY_DOMAIN=${DEFAULT_PROXY_DOMAIN}
      - ALLOWED_SNI_LIST=${ALLOWED_SNI_LIST}
      - DISABLE_BITTORRENT=${DISABLE_BITTORRENT}
      - PROMETHEUS_SECRET_ACCESS_KEY=${PROMETHEUS_SECRET_ACCESS_KEY}
      - USE_REMOTE_SERVER_AUTH=${USE_REMOTE_SERVER_AUTH}
      - REMOTE_SERVER_AUTH_HOST=${REMOTE_SERVER_AUTH_HOST}
      - REMOTE_SERVER_AUTH_PORT=${REMOTE_SERVER_AUTH_PORT}
      - MAX_ACTIVE_SESSIONS_PER_USER=${MAX_ACTIVE_SESSIONS_PER_USER}
      - SERVER_EXTERNAL_IPS=${SERVER_EXTERNAL_IPS}
      - DNS_IPV4_PRIMARY=${DNS_IPV4_PRIMARY}
      - DNS_IPV4_SECONDARY=${DNS_IPV4_SECONDARY}
      - DNS_IPV6_PRIMARY=${DNS_IPV6_PRIMARY}
      - DNS_IPV6_SECONDARY=${DNS_IPV6_SECONDARY}
    healthcheck:
      test: ["CMD", "sh", "-c", "pgrep dnsmasq && pgrep fptn-server"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
YAML
}

write_env() {
    local server_ip="$1"
    write_file "${INSTALL_DIR}/.env" \
"FPTN_PORT=${DEFAULT_FPTN_PORT}
SERVER_EXTERNAL_IPS=${server_ip}
ENABLE_DETECT_PROBING=${DEFAULT_ENABLE_DETECT_PROBING}
DEFAULT_PROXY_DOMAIN=${DEFAULT_PROXY_DOMAIN}
ALLOWED_SNI_LIST=
DISABLE_BITTORRENT=${DEFAULT_DISABLE_BITTORRENT}
USE_REMOTE_SERVER_AUTH=false
REMOTE_SERVER_AUTH_HOST=
REMOTE_SERVER_AUTH_PORT=443
PROMETHEUS_SECRET_ACCESS_KEY=
MAX_ACTIVE_SESSIONS_PER_USER=${DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER}
DNS_IPV4_PRIMARY=${DEFAULT_DNS_IPV4_PRIMARY}
DNS_IPV4_SECONDARY=${DEFAULT_DNS_IPV4_SECONDARY}
DNS_IPV6_PRIMARY=${DEFAULT_DNS_IPV6_PRIMARY}
DNS_IPV6_SECONDARY=${DEFAULT_DNS_IPV6_SECONDARY}"
}

# =============================================================================
# Container helpers
# =============================================================================
dc() { (cd "$INSTALL_DIR" && docker compose "$@"); }

wait_for_container() {
    info "Waiting for fptn-server to be ready..."
    local i
    for i in $(seq 1 90); do
        dc exec -T fptn-server sh -c "true" >/dev/null 2>&1 && { success "Server is ready."; return 0; }
        sleep 1
    done
    die "fptn-server did not become ready in 90 seconds."
}

ssl_gen() {
    mkdir -p "${INSTALL_DIR}/fptn-server-data"
    if [[ -f "${INSTALL_DIR}/fptn-server-data/server.key" && \
          -f "${INSTALL_DIR}/fptn-server-data/server.crt" ]]; then
        info "SSL certificates already exist."; return 0
    fi
    info "Generating SSL certificates..."
    (cd "$INSTALL_DIR" && docker compose run --rm fptn-server sh -c \
        "cd /etc/fptn && openssl genrsa -out server.key 2048 && \
         openssl req -new -x509 -key server.key -out server.crt -days 365 -subj '/CN=fptn'")
    success "SSL certificates generated."
}

fptn_passwd_add() {
    local username="$1" password="$2" bw="$3"
    printf "y\n" | dc exec -i -T fptn-server fptn-passwd --del-user "$username" >/dev/null 2>&1 || true
    printf "%s\n%s\n" "$password" "$password" | \
        dc exec -i -T fptn-server fptn-passwd --add-user "$username" --bandwidth "$bw" >/dev/null 2>&1
}

generate_token() {
    local username="$1" password="$2" server_ip="$3"
    dc run --rm fptn-server token-generator \
        --user "$username" --password "$password" \
        --server-ip "$server_ip" --port "$DEFAULT_FPTN_PORT" 2>/dev/null \
    | awk '/^fptn:/ { print; exit }'
}

# =============================================================================
# Bot helpers
# =============================================================================
download_bot() {
    mkdir -p "$BOT_DIR"
    info "Downloading latest Telegram bot..."
    if curl -fsSL "${RAW_BASE}/fptnbot.py" -o "$BOT_SCRIPT" 2>/dev/null; then
        chmod +x "$BOT_SCRIPT"
        success "Bot script downloaded."
    else
        die "Could not download fptnbot.py from GitHub. Check your connection."
    fi
}

install_bot_service() {
    cat > "$BOT_SERVICE" <<EOF
[Unit]
Description=FPTN Telegram Bot
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${BOT_SCRIPT}
Restart=always
RestartSec=10
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${BOT_CFG}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable fptnbot >/dev/null 2>&1
    success "Bot systemd service installed."
}

bot_status() {
    systemctl is-active fptnbot 2>/dev/null || echo "inactive"
}

vpn_status() {
    if is_installed && dc ps --format "{{.State}}" 2>/dev/null | grep -q "running"; then
        echo "running"
    else
        echo "stopped"
    fi
}

print_status_bar() {
    local vpn_s bot_s
    vpn_s="$(vpn_status)"
    bot_s="$(bot_status)"
    local vpn_icon bot_icon
    [[ "$vpn_s" == "running"  ]] && vpn_icon="${GREEN}●${NC}" || vpn_icon="${RED}●${NC}"
    [[ "$bot_s" == "active"   ]] && bot_icon="${GREEN}●${NC}" || bot_icon="${RED}●${NC}"
    echo -e "  VPN: ${vpn_icon} ${vpn_s}    Bot: ${bot_icon} ${bot_s}"
}

# =============================================================================
# ── MENU ACTIONS ──────────────────────────────────────────────────────────────
# =============================================================================

# ── 1. Install ────────────────────────────────────────────────────────────────
action_install() {
    if is_installed; then
        warn "FPTN is already installed. Use Update or Reset to reinstall."
        press_enter; return
    fi

    echo
    echo -e "${BOLD}${CYAN}Starting full installation...${NC}"
    echo

    # Dependencies
    info "Step 1/7 — Installing dependencies..."
    ensure_curl
    ensure_docker
    ensure_compose
    ensure_python

    # Directories + IP
    info "Step 2/7 — Setting up directories..."
    mkdir -p "$INSTALL_DIR" "$CFG_DIR" "$BOT_DIR"
    echo "$INSTALL_DIR" > "$CFG_FILE"

    local server_ip
    server_ip="$(fetch_public_ip || echo "")"
    if [[ -z "$server_ip" ]]; then
        IFS= read -r -p "  Enter your server public IP: " server_ip
    fi

    write_compose
    write_env "$server_ip"

    # SSL
    info "Step 3/7 — Generating SSL certificates..."
    ssl_gen

    # Start VPN
    info "Step 4/7 — Starting FPTN VPN server..."
    dc up -d
    wait_for_container

    # Create VPN user
    info "Step 5/7 — Creating VPN user..."
    local vpn_password
    vpn_password="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
    fptn_passwd_add "$VPN_USERNAME" "$vpn_password" "$DEFAULT_BANDWIDTH_MBPS"
    local token=""
    token="$(generate_token "$VPN_USERNAME" "$vpn_password" "$server_ip" || true)"
    success "VPN user created: ${VPN_USERNAME}"

    # Telegram bot config
    info "Step 6/7 — Telegram Bot configuration..."
    echo
    echo -e "${YELLOW}  You need a Telegram Bot Token.${NC}"
    echo -e "  1. Open Telegram → search @BotFather"
    echo -e "  2. Send: /newbot"
    echo -e "  3. Copy the token it gives you"
    echo

    local bot_token
    while true; do
        IFS= read -r -p "  Paste your Telegram Bot Token: " bot_token
        [[ "$bot_token" =~ ^[0-9]+:.{30,}$ ]] && break
        warn "Invalid token format. Try again."
    done

    echo
    echo -e "${YELLOW}  Now get your Telegram User ID:${NC}"
    echo -e "  1. Open Telegram → search @userinfobot"
    echo -e "  2. Send /start — it shows your numeric ID"
    echo

    local admin_id
    while true; do
        IFS= read -r -p "  Paste your Telegram User ID (numbers only): " admin_id
        [[ "$admin_id" =~ ^[0-9]+$ ]] && break
        warn "Numbers only. Try again."
    done

    write_file "$BOT_CFG" \
"BOT_TOKEN=${bot_token}
ADMIN_IDS=${admin_id}
SERVER_IP=${server_ip}
SERVER_PORT=${DEFAULT_FPTN_PORT}
INSTALL_DIR=${INSTALL_DIR}
BOT_DIR=${BOT_DIR}
VPN_DEFAULT_BW=${DEFAULT_BANDWIDTH_MBPS}"

    # Download + start bot
    info "Step 7/7 — Installing Telegram bot..."
    download_bot
    install_bot_service
    systemctl restart fptnbot

    echo
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          INSTALLATION COMPLETE ✓         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${CYAN}VPN Server:${NC} ${server_ip}:${DEFAULT_FPTN_PORT}"
    echo -e "  ${CYAN}Bot Status:${NC} $(bot_status)"
    if [[ -n "${token:-}" ]]; then
        echo
        echo -e "  ${CYAN}Your admin FPTN token:${NC}"
        echo -e "  ${GREEN}${token}${NC}"
    fi
    echo
    echo -e "  ${YELLOW}→ Open Telegram and send /start to your bot${NC}"
    press_enter
}

# ── 2. Uninstall ──────────────────────────────────────────────────────────────
action_uninstall() {
    echo
    warn "This will STOP and REMOVE the VPN server and Telegram bot."
    warn "VPN user data and certificates will be deleted."
    echo
    confirm "Are you sure you want to uninstall?" || { echo "Cancelled."; press_enter; return; }

    info "Stopping Telegram bot..."
    systemctl stop fptnbot  2>/dev/null || true
    systemctl disable fptnbot 2>/dev/null || true
    rm -f "$BOT_SERVICE"
    systemctl daemon-reload 2>/dev/null || true

    info "Stopping and removing VPN containers..."
    if is_installed; then
        dc down --volumes --remove-orphans 2>/dev/null || true
    fi

    info "Removing files..."
    rm -rf "$INSTALL_DIR" "$BOT_DIR" "$CFG_DIR"

    success "Uninstall complete. Docker itself was NOT removed."
    press_enter
}

# ── 3. Restart ────────────────────────────────────────────────────────────────
action_restart() {
    echo
    if ! is_installed; then
        warn "FPTN is not installed yet."; press_enter; return
    fi

    info "Restarting VPN server..."
    dc restart
    success "VPN server restarted."

    if [[ "$(bot_status)" != "inactive" ]]; then
        info "Restarting Telegram bot..."
        systemctl restart fptnbot
        success "Telegram bot restarted."
    fi

    echo
    print_status_bar
    press_enter
}

# ── 4. Update ─────────────────────────────────────────────────────────────────
action_update() {
    echo
    if ! is_installed; then
        warn "FPTN is not installed yet. Run Install first."; press_enter; return
    fi

    info "Pulling latest FPTN VPN Docker image..."
    dc pull
    dc up -d
    success "VPN server updated and restarted."

    info "Downloading latest Telegram bot script..."
    download_bot

    info "Restarting Telegram bot..."
    systemctl restart fptnbot
    success "Bot updated and restarted."

    echo
    print_status_bar
    echo
    success "Update complete!"
    press_enter
}

# ── 5. View Logs ──────────────────────────────────────────────────────────────
action_logs() {
    echo
    echo -e "${BOLD}Which logs do you want to view?${NC}"
    echo
    echo "  1) VPN server logs"
    echo "  2) Telegram bot logs"
    echo "  3) Both (split view)"
    echo "  0) Back"
    echo
    local c
    read -r -p "Select: " c
    echo

    case "$c" in
        1)
            if ! is_installed; then warn "VPN not installed."; press_enter; return; fi
            echo -e "${YELLOW}VPN logs — press Ctrl+C to stop${NC}"
            echo
            dc logs --tail=50 -f
            ;;
        2)
            echo -e "${YELLOW}Bot logs — press Ctrl+C to stop${NC}"
            echo
            journalctl -u fptnbot -n 50 -f
            ;;
        3)
            echo -e "${YELLOW}Both logs — press Ctrl+C to stop${NC}"
            echo
            # Run both in background, tail together
            journalctl -u fptnbot -f --no-pager 2>/dev/null &
            local jpid=$!
            if is_installed; then
                dc logs --tail=30 -f 2>/dev/null &
                local dpid=$!
                wait "$jpid" "$dpid" 2>/dev/null || true
                kill "$dpid" 2>/dev/null || true
            else
                wait "$jpid" 2>/dev/null || true
            fi
            kill "$jpid" 2>/dev/null || true
            ;;
        0) return ;;
        *) warn "Invalid option." ;;
    esac
    press_enter
}

# ── 6. Reset & Reinstall ──────────────────────────────────────────────────────
action_reset() {
    echo
    warn "This will COMPLETELY WIPE everything and run a fresh install."
    warn "All users, tokens, certificates and bot data will be lost."
    echo
    confirm "Type 'y' to confirm full reset and reinstall" || { echo "Cancelled."; press_enter; return; }

    info "Wiping existing installation..."

    # Stop bot
    systemctl stop fptnbot    2>/dev/null || true
    systemctl disable fptnbot 2>/dev/null || true
    rm -f "$BOT_SERVICE"
    systemctl daemon-reload   2>/dev/null || true

    # Stop + remove containers
    if is_installed; then
        dc down --volumes --remove-orphans 2>/dev/null || true
    fi

    # Remove all data
    rm -rf "$INSTALL_DIR" "$BOT_DIR" "$CFG_DIR"

    success "Wipe complete. Starting fresh install..."
    echo
    sleep 1

    # Run install flow
    action_install
}

# =============================================================================
# Status summary for menu header
# =============================================================================
print_header() {
    clear
    echo
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║        FPTN VPN + Bot Manager            ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════╝${NC}"
    echo
    print_status_bar
    echo
    echo -e "  ${BOLD}1)${NC} Install"
    echo -e "  ${BOLD}2)${NC} Uninstall"
    echo -e "  ${BOLD}3)${NC} Restart"
    echo -e "  ${BOLD}4)${NC} Update  ${CYAN}(pull latest image + bot)${NC}"
    echo -e "  ${BOLD}5)${NC} View Logs"
    echo -e "  ${BOLD}6)${NC} Reset & Reinstall  ${RED}(wipes everything)${NC}"
    echo -e "  ${BOLD}0)${NC} Exit"
    echo
}

# =============================================================================
# Main menu loop
# =============================================================================
main() {
    require_root

    while true; do
        print_header
        read -r -p "Select: " choice
        echo

        case "$choice" in
            1) action_install   ;;
            2) action_uninstall ;;
            3) action_restart   ;;
            4) action_update    ;;
            5) action_logs      ;;
            6) action_reset     ;;
            0) echo "Bye."; exit 0 ;;
            *) warn "Invalid option: ${choice}"; sleep 1 ;;
        esac
    done
}

main "$@"
