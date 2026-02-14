#!/usr/bin/env bash
# =============================================================================
# fptn-manager — Fully Automatic FPTN VPN + Telegram Bot Setup
# Usage: curl -fsSL https://raw.githubusercontent.com/milibots/fptnbot/main/fptn-manager.sh | sudo bash
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

readonly RAW_BASE="https://raw.githubusercontent.com/milibots/fptnbot/main"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" >&2; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# =============================================================================
# Helpers
# =============================================================================
has_cmd()     { command -v "$1" >/dev/null 2>&1; }
require_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run as root (sudo)."; }

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
    pip3 install -q python-telegram-bot==20.7 aiofiles 2>/dev/null || \
    pip3 install -q --break-system-packages python-telegram-bot==20.7 aiofiles 2>/dev/null || true
    success "Python dependencies installed."
}

# =============================================================================
# Docker Compose + .env
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
# SSL
# =============================================================================
ssl_gen() {
    local dir="$INSTALL_DIR"
    mkdir -p "${dir}/fptn-server-data"
    if [[ -f "${dir}/fptn-server-data/server.key" && -f "${dir}/fptn-server-data/server.crt" ]]; then
        info "SSL certificates already exist."; return 0
    fi
    info "Generating SSL certificates..."
    (cd "$dir" && docker compose run --rm fptn-server sh -c \
        "cd /etc/fptn && openssl genrsa -out server.key 2048 && \
         openssl req -new -x509 -key server.key -out server.crt -days 365 -subj '/CN=fptn'")
    success "SSL certificates generated."
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

fptn_passwd_add() {
    local username="$1" password="$2" bw="$3"
    # Delete if exists first (silent)
    printf "y\n" | dc exec -i -T fptn-server fptn-passwd --del-user "$username" >/dev/null 2>&1 || true
    # Add user non-interactively by passing password via stdin
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
# Download bot script from GitHub
# =============================================================================
download_bot() {
    mkdir -p "$BOT_DIR"
    info "Downloading Telegram bot..."
    curl -fsSL "${RAW_BASE}/fptnbot.py" -o "$BOT_SCRIPT" 2>/dev/null || {
        warn "Could not download fptnbot.py from GitHub — writing bundled version..."
        write_bundled_bot
    }
    chmod +x "$BOT_SCRIPT"
    success "Bot script ready."
}

# =============================================================================
# Systemd service for bot
# =============================================================================
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

# =============================================================================
# Main automatic install flow
# =============================================================================
main() {
    require_root

    echo
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      FPTN VPN + Telegram Bot Setup       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo

    # ── 1. Dependencies ──────────────────────────────────────────────────────
    info "Step 1/7 — Installing dependencies..."
    ensure_curl
    ensure_docker
    ensure_compose
    ensure_python

    # ── 2. Setup directories ─────────────────────────────────────────────────
    info "Step 2/7 — Setting up FPTN VPN server..."
    mkdir -p "$INSTALL_DIR" "$CFG_DIR" "$BOT_DIR"
    echo "$INSTALL_DIR" > "$CFG_FILE"

    local server_ip
    server_ip="$(fetch_public_ip || echo "")"
    [[ -z "$server_ip" ]] && { IFS= read -r -p "Enter your server public IP: " server_ip; }

    write_compose
    write_env "$server_ip"

    # ── 3. SSL ───────────────────────────────────────────────────────────────
    info "Step 3/7 — Generating SSL certificates..."
    ssl_gen

    # ── 4. Start VPN ─────────────────────────────────────────────────────────
    info "Step 4/7 — Starting FPTN VPN server..."
    dc up -d
    wait_for_container

    # ── 5. Create VPN user ───────────────────────────────────────────────────
    info "Step 5/7 — Creating VPN admin user..."
    local vpn_password
    vpn_password="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
    fptn_passwd_add "$VPN_USERNAME" "$vpn_password" "$DEFAULT_BANDWIDTH_MBPS"

    local token=""
    token="$(generate_token "$VPN_USERNAME" "$vpn_password" "$server_ip" || true)"

    success "VPN user created: ${VPN_USERNAME}"

    # ── 6. Telegram Bot setup ─────────────────────────────────────────────────
    info "Step 6/7 — Telegram Bot configuration..."
    echo
    echo -e "${YELLOW}  You need a Telegram Bot Token.${NC}"
    echo -e "  If you don't have one:"
    echo -e "    1. Open Telegram → search @BotFather"
    echo -e "    2. Send: /newbot"
    echo -e "    3. Copy the token it gives you"
    echo
    local bot_token
    while true; do
        IFS= read -r -p "  Paste your Telegram Bot Token: " bot_token
        [[ "$bot_token" =~ ^[0-9]+:.{30,}$ ]] && break
        warn "That doesn't look like a valid token. Try again."
    done

    echo
    echo -e "${YELLOW}  Now get your Telegram User ID (for admin access):${NC}"
    echo -e "    1. Open Telegram → search @userinfobot"
    echo -e "    2. Send /start — it will show your ID"
    echo
    local admin_id
    while true; do
        IFS= read -r -p "  Paste your Telegram User ID (numbers only): " admin_id
        [[ "$admin_id" =~ ^[0-9]+$ ]] && break
        warn "User ID should be numbers only. Try again."
    done

    # Write bot config
    write_file "$BOT_CFG" \
"BOT_TOKEN=${bot_token}
ADMIN_IDS=${admin_id}
SERVER_IP=${server_ip}
SERVER_PORT=${DEFAULT_FPTN_PORT}
INSTALL_DIR=${INSTALL_DIR}
VPN_DEFAULT_BW=${DEFAULT_BANDWIDTH_MBPS}"

    # ── 7. Download & start bot ──────────────────────────────────────────────
    info "Step 7/7 — Installing and starting Telegram bot..."
    download_bot
    install_bot_service
    systemctl restart fptnbot

    # ── Done ─────────────────────────────────────────────────────────────────
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            SETUP COMPLETE! ✓             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${CYAN}VPN Server:${NC}    ${server_ip}:${DEFAULT_FPTN_PORT}"
    echo -e "  ${CYAN}VPN User:${NC}      ${VPN_USERNAME}"
    echo -e "  ${CYAN}Bot Status:${NC}    $(systemctl is-active fptnbot 2>/dev/null || echo 'starting...')"
    echo
    if [[ -n "${token:-}" ]]; then
        echo -e "  ${CYAN}Your admin FPTN token:${NC}"
        echo -e "  ${GREEN}${token}${NC}"
        echo
    fi
    echo -e "  ${YELLOW}Open your Telegram bot and send /start${NC}"
    echo -e "  ${YELLOW}You are set as admin (ID: ${admin_id})${NC}"
    echo
    echo -e "  Bot logs: ${CYAN}journalctl -u fptnbot -f${NC}"
    echo -e "  VPN logs: ${CYAN}cd ${INSTALL_DIR} && docker compose logs -f${NC}"
    echo
}

main "$@"
