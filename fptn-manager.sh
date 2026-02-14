#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2005,SC2034,SC1091
set -Eeuo pipefail

# ==========================================================
# FPTN Manager - Telegram Bot Edition
# ==========================================================
# This script installs the FPTN VPN server and a Telegram 
# Admin Bot to manage it completely via GUI.
# ==========================================================

APP_NAME="fptn-manager"
BIN_PATH="/usr/local/bin/${APP_NAME}"
CFG_DIR="/etc/fptn"
CFG_FILE="${CFG_DIR}/manager.conf"
BOT_DIR="/opt/fptn-bot"
BOT_FILE="${BOT_DIR}/fptn_bot.py"
BOT_SERVICE="/etc/systemd/system/fptn-bot.service"
RAW_INSTALL_URL="https://raw.githubusercontent.com/FarazFe/fptn-manager/main/fptn-manager.sh"

# -------------------------
# Colors & UI
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# -------------------------
# Defaults
# -------------------------
DEFAULT_INSTALL_DIR="/opt/fptn"
DEFAULT_FPTN_PORT="443"
DEFAULT_PROXY_DOMAIN="cdnvideo.com"
DEFAULT_ENABLE_DETECT_PROBING="true"
DEFAULT_DISABLE_BITTORRENT="true"
DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER="3"
DEFAULT_DNS_IPV4_PRIMARY="8.8.8.8"
DEFAULT_DNS_IPV4_SECONDARY="8.8.4.4"
DEFAULT_DNS_IPV6_PRIMARY="2001:4860:4860::8888"
DEFAULT_DNS_IPV6_SECONDARY="2001:4860:4860::8844"
DEFAULT_BANDWIDTH_MBPS="100"

# -------------------------
# Helpers
# -------------------------
has_cmd() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run as root (sudo).${NC}" >&2
    exit 1
  fi
}

print_banner() {
  clear
  echo -e "${PURPLE}"
  echo "╔════════════════════════════════════════════════════════╗"
  echo "║                                                        ║"
  echo "║          ███████╗████████╗ █████╗ ██████╗              ║"
  echo "║          ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗             ║"
  echo "║          █████╗     ██║   ███████║██████╔╝             ║"
  echo "║          ██╔══╝     ██║   ██╔══██║██╔══██╗             ║"
  echo "║          ██║        ██║   ██║  ██║██║  ██║             ║"
  echo "║          ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝             ║"
  echo "║                                                        ║"
  echo "║        FPTN Manager - Telegram Bot Edition             ║"
  echo "╚════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

msg_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
msg_ok()    { echo -e "${GREEN}[ OK ]${NC} $1"; }
msg_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_err()   { echo -e "${RED}[ERR!]${NC} $1"; }

detect_pkg_mgr() {
  if has_cmd apt-get; then echo "apt"
  elif has_cmd dnf; then echo "dnf"
  elif has_cmd yum; then echo "yum"
  else echo "unknown"
  fi
}

ensure_curl() {
  has_cmd curl && return
  local pm; pm="$(detect_pkg_mgr)"
  msg_info "Installing curl..."
  case "$pm" in
    apt) apt-get update -y && apt-get install -y curl ;;
    dnf) dnf install -y curl ;;
    yum) yum install -y curl ;;
    *) msg_err "curl not available and package manager unsupported."; exit 1 ;;
  esac
}

start_enable_docker() {
  systemctl enable --now docker >/dev/null 2>&1 || service docker start || true
}

ensure_docker() {
  if has_cmd docker; then
      msg_ok "Docker already installed."
      return
  fi
  msg_info "Installing Docker..."
  ensure_curl
  curl -fsSL https://get.docker.com | sh
  start_enable_docker
  msg_ok "Docker installed successfully."
}

ensure_compose() {
  if docker compose version >/dev/null 2>&1; then
      return
  fi
  msg_info "Installing Docker Compose v2..."
  local pm; pm="$(detect_pkg_mgr)"
  case "$pm" in
    apt) apt-get update -y && apt-get install -y docker-compose-plugin ;;
    dnf|yum) $pm install -y docker-compose-plugin ;;
    *) msg_err "Docker Compose v2 not available."; exit 1 ;;
  esac
}

ensure_docker_stack() {
  require_root
  ensure_docker
  ensure_compose
}

ensure_python_venv() {
    local pm; pm="$(detect_pkg_mgr)"
    msg_info "Ensuring Python3 and Venv are available..."
    case "$pm" in
        apt) apt-get update -qq && apt-get install -y python3 python3-venv python3-pip ;;
        dnf|yum) $pm install -y python3 python3-virtualenv ;;
        *) msg_err "Could not install Python venv." && exit 1 ;;
    esac
    msg_ok "Python environment ready."
}

fetch_public_ip() {
  ensure_curl
  curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null | tr -d ' \r\n' || true
}

write_file() {
  local path="$1" content="$2"
  mkdir -p "$(dirname "$path")"
  printf "%s\n" "$content" > "$path"
}

save_manager_config() {
  mkdir -p "$CFG_DIR"
  write_file "$CFG_FILE" "$1"
}

load_install_dir() {
  if [ -f "$CFG_FILE" ]; then
    local d
    d="$(tr -d '\r\n' <"$CFG_FILE" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -n "$d" ]; then
      echo "$d"
      return 0
    fi
  fi
  echo "$DEFAULT_INSTALL_DIR"
}

dc() {
  local dir; dir="$(load_install_dir)"
  (cd "$dir" && docker compose "$@")
}

need_install_dir() {
  local dir; dir="$(load_install_dir)"
  if [ ! -f "${dir}/docker-compose.yml" ]; then
    msg_err "Not installed yet. Run install first."
    return 1
  fi
  return 0
}

wait_for_container_ready() {
  local i
  msg_info "Waiting for fptn-server container to start..."
  for i in $(seq 1 60); do
    if dc exec -T fptn-server sh -c "true" >/dev/null 2>&1; then
      msg_ok "Container is ready."
      return 0
    fi
    sleep 2
  done
  msg_err "fptn-server did not become ready in time."
  return 1
}

env_get() {
  local key="$1"
  local dir; dir="$(load_install_dir)"
  local envfile="${dir}/.env"
  [ -f "$envfile" ] || return 1
  awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$envfile"
}

# -------------------------
# Compose + Env
# -------------------------
write_compose() {
  local dir="$1"
  cat > "${dir}/docker-compose.yml" <<'YAML'
services:
  fptn-server:
    restart: unless-stopped
    image: fptnvpn/fptn-vpn-server:latest
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
      - NET_RAW
      - SYS_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
      - net.ipv4.conf.all.rp_filter=0
      - net.ipv4.conf.default.rp_filter=0
    ulimits:
      nproc:
        soft: 524288
        hard: 524288
      nofile:
        soft: 524288
        hard: 524288
      memlock:
        soft: 524288
        hard: 524288
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
  local dir="$1"
  local fptn_port="$2"
  local server_external_ips="$3"
  local proxy_domain="$4"
  local detect_probing="$5"
  local disable_bt="$6"
  local max_sessions="$7"
  local dns4_1="$8"
  local dns4_2="$9"
  local dns6_1="${10}"
  local dns6_2="${11}"

  write_file "$dir/.env" \
"FPTN_PORT=${fptn_port}
SERVER_EXTERNAL_IPS=${server_external_ips}
ENABLE_DETECT_PROBING=${detect_probing}
DEFAULT_PROXY_DOMAIN=${proxy_domain}
ALLOWED_SNI_LIST=
DISABLE_BITTORRENT=${disable_bt}
USE_REMOTE_SERVER_AUTH=false
REMOTE_SERVER_AUTH_HOST=
REMOTE_SERVER_AUTH_PORT=443
PROMETHEUS_SECRET_ACCESS_KEY=
MAX_ACTIVE_SESSIONS_PER_USER=${max_sessions}
DNS_IPV4_PRIMARY=${dns4_1}
DNS_IPV4_SECONDARY=${dns4_2}
DNS_IPV6_PRIMARY=${dns6_1}
DNS_IPV6_SECONDARY=${dns6_2}
"
}

# -------------------------
# Bot Installation
# -------------------------

install_bot_dependencies() {
    msg_info "Setting up Python Virtual Environment..."
    mkdir -p "$BOT_DIR"
    
    # Create venv
    python3 -m venv "${BOT_DIR}/venv"
    
    # Install libraries
    source "${BOT_DIR}/venv/bin/activate"
    pip install --upgrade pip
    pip install pyTelegramBotAPI schedule
    deactivate
    msg_ok "Virtual environment ready."
}

write_bot_script() {
    local BOT_TOKEN="$1"
    local ADMIN_ID="$2"
    local INSTALL_DIR="$3"
    local PUBLIC_IP="$4"
    local PORT="$5"

    msg_info "Writing FPTN Bot Script..."
    cat > "$BOT_FILE" << PYTHON_EOF
#!/usr/bin/env python3
import os
import sys
import subprocess
import sqlite3
import time
import datetime
import random
import string
import telebot
import schedule
import threading
from telebot import types

# Configuration
BOT_TOKEN = "${BOT_TOKEN}"
ADMIN_ID = ${ADMIN_ID}
INSTALL_DIR = "${INSTALL_DIR}"
SERVER_IP = "${PUBLIC_IP}"
SERVER_PORT = "${SERVER_PORT}"
DB_PATH = os.path.join(INSTALL_DIR, "users.db")
COMPOSE_CMD = f"docker compose -f {INSTALL_DIR}/docker-compose.yml"

bot = telebot.TeleBot(BOT_TOKEN)

# Database Setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, 
                  password TEXT,
                  expiry_date TEXT,
                  traffic_limit_mb INTEGER,
                  used_traffic_mb INTEGER DEFAULT 0,
                  active INTEGER DEFAULT 1)''')
    conn.commit()
    conn.close()

init_db()

# Helpers
def gen_pass(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"
    except Exception as e:
        return f"Error: {str(e)}"

def docker_exec(cmd):
    # Run command inside docker container
    # Example: docker exec -i container_name cmd
    return run_cmd(f"docker exec -i fptn-server {cmd}")

def add_user_docker(username, password):
    # Note: fptn-passwd might be interactive. 
    # Assuming it accepts input like: fptn-passwd --add-user user --password pass
    # Or piping: echo -e "pass\\npass" | fptn-passwd --add-user user
    # Adjusting for standard interaction simulation:
    cmd = f'docker exec -i fptn-server sh -c "echo -e \\"{password}\\n{password}\\" | fptn-passwd --add-user {username}"'
    return run_cmd(cmd)

def del_user_docker(username):
    # Assuming 'y' for confirmation
    cmd = f'docker exec -i fptn-server sh -c "echo y | fptn-passwd --del-user {username}"'
    return run_cmd(cmd)

def get_token(username, password):
    # Generate token using the container utility
    cmd = f'docker exec -i fptn-server token-generator --user {username} --password {password} --server-ip {SERVER_IP} --port {SERVER_PORT}'
    out = run_cmd(cmd)
    # Extract token (assuming it returns just the token or line starting with fptn:)
    for line in out.splitlines():
        if line.startswith("fptn:"):
            return line.strip()
    return out.strip() # Fallback

# Scheduler / Expiry Checker
def check_expirations():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.datetime.now()
    
    # Find expired users
    c.execute("SELECT username FROM users WHERE active=1 AND expiry_date < ?", (now.isoformat(),))
    expired = c.fetchall()
    
    for (user,) in expired:
        print(f"User {user} expired. Disabling...")
        # Delete from docker
        del_user_docker(user)
        # Update DB
        c.execute("UPDATE users SET active=0 WHERE username=?", (user,))
    
    conn.commit()
    conn.close()

def scheduler_thread():
    while True:
        schedule.run_pending()
        time.sleep(60)

schedule.every(5).minutes.do(check_expirations)
threading.Thread(target=scheduler_thread, daemon=True).start()

# Bot Handlers
@bot.message_handler(commands=['start'])
def send_welcome(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "⛔ Unauthorized")
        return
    
    markup = types.InlineKeyboardMarkup()
    btn_users = types.InlineKeyboardButton("👥 All Users", callback_data="list_users")
    btn_add = types.InlineKeyboardButton("➕ Create User", callback_data="add_user_start")
    markup.row(btn_users, btn_add)
    
    bot.reply_to(message, "🔧 <b>FPTN Admin Panel</b>\n\nSelect an action:", parse_mode="HTML", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.from_user.id != ADMIN_ID:
        return

    data = call.data
    
    if data == "list_users":
        list_users(call.message, edit=True)
    elif data == "add_user_start":
        msg = bot.send_message(call.message.chat.id, "🆔 Send the username (or type 'auto' for random):")
        bot.register_next_step_handler(msg, process_username_step)
    elif data.startswith("del_"):
        username = data.split("_")[1]
        remove_user(username, call.message)
    elif data.startswith("renew_"):
        username = data.split("_")[1]
        msg = bot.send_message(call.message.chat.id, f"📅 Send days to extend for {username}:")
        bot.register_next_step_handler(msg, process_renew_step, username)
    elif data.startswith("get_token_"):
        username = data.split("_")[1]
        send_token_info(username, call.message)

def process_username_step(message):
    username = message.text
    if username == "auto":
        username = "user_" + gen_pass(4)
    
    msg = bot.send_message(message.chat.id, "📅 Send expiry days (e.g., 30):")
    bot.register_next_step_handler(msg, process_days_step, username)

def process_days_step(message, username):
    try:
        days = int(message.text)
        msg = bot.send_message(message.chat.id, "💾 Send traffic limit in MB (0 for unlimited):")
        bot.register_next_step_handler(msg, process_traffic_step, username, days)
    except ValueError:
        bot.reply_to(message, "Invalid number.")

def process_traffic_step(message, username, days):
    try:
        traffic = int(message.text)
        create_user(username, days, traffic, message)
    except ValueError:
        bot.reply_to(message, "Invalid number.")

def create_user(username, days, traffic, message):
    password = gen_pass(12)
    expiry = datetime.datetime.now() + datetime.timedelta(days=days)
    
    # Add to Docker
    result = add_user_docker(username, password)
    if "Error" in result:
        bot.reply_to(message, f"Failed to add user to server:\n{result}")
        return

    # Add to DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", 
              (username, password, expiry.isoformat(), traffic, 0, 1))
    conn.commit()
    conn.close()

    token = get_token(username, password)
    
    text = (
        f"✅ <b>User Created</b>\n\n"
        f"👤 User: {username}\n"
        f"🔑 Pass: {password}\n"
        f"📅 Expiry: {expiry.strftime('%Y-%m-%d')} ({days} days)\n"
        f"💾 Traffic: {traffic} MB\n\n"
        f"🎫 <code>{token}</code>"
    )
    bot.send_message(message.chat.id, text, parse_mode="HTML")

def list_users(message, edit=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, expiry_date, active FROM users")
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        text = "No users found."
    else:
        text = "👥 <b>User List:</b>\n\n"
        for u, exp, act in rows:
            status = "🟢" if act else "🔴"
            exp_date = datetime.datetime.fromisoformat(exp).strftime('%Y-%m-%d')
            text += f"{status} <b>{u}</b> - Exp: {exp_date}\n"
    
    markup = types.InlineKeyboardMarkup()
    btn_back = types.InlineKeyboardButton("🔙 Back", callback_data="start_back")
    markup.add(btn_back)
    
    if edit:
        bot.edit_message_text(text, message.chat.id, message.message_id, parse_mode="HTML", reply_markup=markup)
    else:
        bot.send_message(message.chat.id, text, parse_mode="HTML", reply_markup=markup)

def send_token_info(username, message):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    
    if row:
        token = get_token(username, row[0])
        bot.send_message(message.chat.id, f"🎫 Token for {username}:\n\n<code>{token}</code>", parse_mode="HTML")
    else:
        bot.send_message(message.chat.id, "User not found locally.")

def remove_user(username, message):
    # Docker
    del_user_docker(username)
    # DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    bot.edit_message_text(f"🗑 User {username} deleted.", message.chat.id, message.message_id)

def process_renew_step(message, username):
    try:
        days = int(message.text)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT expiry_date, active FROM users WHERE username=?", (username,))
        row = c.fetchone()
        
        if row:
            old_exp = datetime.datetime.fromisoformat(row[0])
            if old_exp < datetime.datetime.now():
                old_exp = datetime.datetime.now()
            new_exp = old_exp + datetime.timedelta(days=days)
            
            c.execute("UPDATE users SET expiry_date=?, active=1 WHERE username=?", (new_exp.isoformat(), username))
            conn.commit()
            
            # If was inactive, recreate in docker
            if row[1] == 0:
                c.execute("SELECT password FROM users WHERE username=?", (username,))
                pw = c.fetchone()[0]
                add_user_docker(username, pw)
                
            bot.reply_to(message, f"✅ Renewed {username} for {days} days. New Expiry: {new_exp.strftime('%Y-%m-%d')}")
        else:
            bot.reply_to(message, "User not found.")
        conn.close()
    except Exception as e:
        bot.reply_to(message, f"Error: {e}")

# Inline buttons for specific user management
@bot.message_handler(func=lambda message: True)
def handle_message(message):
    # This handles the 'Start' implicitly if not command
    if message.from_user.id == ADMIN_ID:
        send_welcome(message)

print("Bot started...")
bot.infinity_polling()
PYTHON_EOF

    chmod +x "$BOT_FILE"
    msg_ok "Bot script created at $BOT_FILE"
}

create_systemd_service() {
    msg_info "Creating Systemd Service..."
    cat > "$BOT_SERVICE" << EOF
[Unit]
Description=FPTN Telegram Bot
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=${BOT_DIR}/venv/bin/python3 ${BOT_FILE}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable fptn-bot >/dev/null 2>&1
    systemctl restart fptn-bot
    msg_ok "FPTN Bot Service started."
}

# -------------------------
# Main Install Flow
# -------------------------
do_install() {
    print_banner
    ensure_docker_stack
    ensure_python_venv

    local dir fptn_port server_ip
    dir="$DEFAULT_INSTALL_DIR"
    fptn_port="$DEFAULT_FPTN_PORT"
    
    echo -e "${CYAN}"
    read -r -p "Enter VPN Port [443]: " fptn_port_input
    echo -e "${NC}"
    fptn_port="${fptn_port_input:-$DEFAULT_FPTN_PORT}"

    server_ip="$(fetch_public_ip || true)"
    if [ -z "$server_ip" ]; then
        echo -e "${CYAN}"
        read -r -p "Could not auto-detect IP. Enter Server Public IP: " server_ip
        echo -e "${NC}"
    fi

    # Save config
    save_manager_config "$dir"
    mkdir -p "$dir"

    # Write Docker Compose
    write_compose "$dir"
    write_env "$dir" \
        "$fptn_port" \
        "$server_ip" \
        "$DEFAULT_PROXY_DOMAIN" \
        "$DEFAULT_ENABLE_DETECT_PROBING" \
        "$DEFAULT_DISABLE_BITTORRENT" \
        "$DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER" \
        "$DEFAULT_DNS_IPV4_PRIMARY" \
        "$DEFAULT_DNS_IPV4_SECONDARY" \
        "$DEFAULT_DNS_IPV6_PRIMARY" \
        "$DEFAULT_DNS_IPV6_SECONDARY"

    # SSL & Start Container
    msg_info "Generating SSL certs..."
    mkdir -p "${dir}/fptn-server-data"
    if [ ! -f "${dir}/fptn-server-data/server.key" ]; then
        dc run --rm fptn-server sh -c "cd /etc/fptn && openssl genrsa -out server.key 2048" >/dev/null 2>&1
        dc run --rm fptn-server sh -c "cd /etc/fptn && openssl req -new -x509 -key server.key -out server.crt -days 365 -subj '/CN=fptn'" >/dev/null 2>&1
    fi

    msg_info "Starting VPN Server..."
    dc up -d
    wait_for_container_ready

    # --- Bot Setup ---
    echo -e "${YELLOW}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}       TELEGRAM BOT CONFIGURATION      ${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════${NC}"
    
    echo -e "${CYAN}Talk to @BotFather on Telegram to create a bot and get the API Token.${NC}"
    read -r -p "Enter Bot Token: " bot_token
    
    echo -e "${CYAN}Your Telegram User ID is required for admin access.${NC}"
    echo -e "You can find it using @userinfobot."
    read -r -p "Enter Admin Telegram ID: " admin_id

    if [ -z "$bot_token" ] || [ -z "$admin_id" ]; then
        msg_err "Bot Token and Admin ID are required!"
        exit 1
    fi

    install_bot_dependencies
    write_bot_script "$bot_token" "$admin_id" "$dir" "$server_ip" "$fptn_port"
    create_systemd_service

    echo
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       INSTALLATION COMPLETE           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo
    echo -e "  VPN Server IP : ${YELLOW}$server_ip${NC}"
    echo -e "  VPN Port      : ${YELLOW}$fptn_port${NC}"
    echo -e "  Bot Service   : ${YELLOW}systemctl status fptn-bot${NC}"
    echo
    echo -e "  Open Telegram and start your bot! 🤖"
    echo
}

# -------------------------
# Self-install
# -------------------------
install_self() {
  require_root

  if [ -e "$BIN_PATH" ] && [ "$(readlink -f "$0" 2>/dev/null || echo "$0")" = "$(readlink -f "$BIN_PATH" 2>/dev/null || echo "$BIN_PATH")" ]; then
    return 0
  fi

  if [[ "${0##*/}" == "bash" || "${0##*/}" == "-bash" || "$0" == "-" ]]; then
    cat <<EOF
NOTE:
You ran this via pipe (curl | bash), so it can't self-install reliably.
Use this instead:

curl -fsSL ${RAW_INSTALL_URL} -o /tmp/${APP_NAME} && sudo bash /tmp/${APP_NAME}

EOF
    exit 0
  fi

  if [ -f "$0" ]; then
    install -m 0755 "$0" "$BIN_PATH"
    echo "[*] Installed command: $BIN_PATH"
    return 0
  fi

  echo "ERROR: Cannot locate script path for self-install." >&2
  exit 1
}

# -------------------------
# Main
# -------------------------
if [ "$1" == "uninstall" ]; then
    msg_warn "Uninstalling..."
    systemctl stop fptn-bot 2>/dev/null || true
    systemctl disable fptn-bot 2>/dev/null || true
    rm -rf "$BOT_DIR"
    rm -f "$BOT_SERVICE"
    rm -f "$BIN_PATH"
    rm -rf "$(load_install_dir)"
    msg_ok "Uninstalled."
    exit 0
fi

install_self
do_install
