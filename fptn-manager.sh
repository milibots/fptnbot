#!/usr/bin/env bash
# =============================================================================
# fptn-manager — FPTN VPN Server Manager
# Repository: https://github.com/FarazFe/fptn-manager
# =============================================================================
set -Eeuo pipefail

# =============================================================================
# Constants
# =============================================================================
readonly APP_NAME="fptn-manager"
readonly BIN_PATH="/usr/local/bin/${APP_NAME}"
readonly CFG_DIR="/etc/fptn"
readonly CFG_FILE="${CFG_DIR}/manager.conf"
readonly RAW_INSTALL_URL="https://raw.githubusercontent.com/FarazFe/fptn-manager/main/fptn-manager.sh"

# =============================================================================
# Defaults
# =============================================================================
readonly DEFAULT_INSTALL_DIR="/opt/fptn"
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
readonly DEFAULT_EASY_USERNAME_PREFIX="fptn"

# =============================================================================
# Utility helpers
# =============================================================================

# Check if a command exists
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Die with an error message
die() { echo "ERROR: $*" >&2; exit 1; }

# Abort unless running as root
require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run as root (sudo)."
}

# Detect the system package manager
detect_pkg_mgr() {
    if   has_cmd apt-get; then echo "apt"
    elif has_cmd dnf;     then echo "dnf"
    elif has_cmd yum;     then echo "yum"
    else                       echo "unknown"
    fi
}

# Prompt with a labelled default; echo the chosen value
prompt_default() {
    local label="$1" def="$2" ans
    read -r -p "${label} [${def}]: " ans
    echo "${ans:-$def}"
}

# Write text to a file, creating parent dirs as needed
write_file() {
    local path="$1" content="$2"
    mkdir -p "$(dirname "$path")"
    printf "%s\n" "$content" > "$path"
}

# Read a secret from /dev/tty (no echo)
read_secret_tty() {
    local prompt="$1" var
    IFS= read -r -s -p "$prompt" var < /dev/tty
    printf "%s" "$var"
}

# Build a timestamped easy username
easy_username() {
    printf "%s%s" "$DEFAULT_EASY_USERNAME_PREFIX" "$(date +%H%M%S)"
}

# Run a command with a timeout (uses system `timeout` or a background-job fallback)
run_with_timeout() {
    local seconds="$1"; shift
    if has_cmd timeout; then
        timeout "$seconds" "$@"
    else
        local pid killer rc=0
        ("$@") & pid=$!
        ( sleep "$seconds"; kill -TERM "$pid" 2>/dev/null || true ) & killer=$!
        wait "$pid" || rc=$?
        kill "$killer" 2>/dev/null || true
        return "$rc"
    fi
}

# =============================================================================
# Dependency installation
# =============================================================================

ensure_curl() {
    has_cmd curl && return
    local pm; pm="$(detect_pkg_mgr)"
    echo "[*] Installing curl..."
    case "$pm" in
        apt) apt-get update -y && apt-get install -y curl ;;
        dnf) dnf install -y curl ;;
        yum) yum install -y curl ;;
        *)   die "curl not available and package manager is unsupported." ;;
    esac
}

ensure_docker() {
    has_cmd docker && return
    echo "[*] Installing Docker..."
    ensure_curl
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || service docker start || true
}

ensure_compose() {
    docker compose version >/dev/null 2>&1 && return
    echo "[*] Installing Docker Compose v2..."
    local pm; pm="$(detect_pkg_mgr)"
    case "$pm" in
        apt)       apt-get update -y && apt-get install -y docker-compose-plugin ;;
        dnf | yum) "$pm" install -y docker-compose-plugin ;;
        *)         die "Docker Compose v2 not available for this package manager." ;;
    esac
}

# Ensure root + Docker + Compose are all present
ensure_docker_stack() {
    require_root
    ensure_docker
    ensure_compose
}

# =============================================================================
# Config / install-dir management
# =============================================================================

save_manager_config() {
    mkdir -p "$CFG_DIR"
    write_file "$CFG_FILE" "$1"
}

load_install_dir() {
    if [[ -f "$CFG_FILE" ]]; then
        local d
        d="$(tr -d '\r\n' < "$CFG_FILE" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -n "$d" ]] && echo "$d" && return
    fi
    echo "$DEFAULT_INSTALL_DIR"
}

# Run `docker compose` inside the install directory
dc() {
    local dir; dir="$(load_install_dir)"
    (cd "$dir" && docker compose "$@")
}

# Abort if no docker-compose.yml is found in the install directory
need_install_dir() {
    local dir; dir="$(load_install_dir)"
    [[ -f "${dir}/docker-compose.yml" ]] || die "Not installed yet. Run an install first."
}

# Read a single variable from the .env file
env_get() {
    local key="$1"
    local envfile; envfile="$(load_install_dir)/.env"
    [[ -f "$envfile" ]] || return 1
    awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/,""); print; exit }' "$envfile"
}

# Fetch the server's public IP via several fallback services
fetch_public_ip() {
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )
    for svc in "${services[@]}"; do
        local ip
        ip="$(curl -fsSL --max-time 5 "$svc" 2>/dev/null | tr -d ' \r\n')" && {
            echo "$ip"; return 0
        }
    done
    return 1
}

# Poll until the fptn-server container is accepting exec commands (up to 90 s)
wait_for_container_ready() {
    local i
    for i in $(seq 1 90); do
        dc exec -T fptn-server sh -c "true" >/dev/null 2>&1 && return 0
        sleep 1
    done
    die "fptn-server did not become ready within 90 seconds."
}

# =============================================================================
# Compose / env file writers
# =============================================================================

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

    write_file "${dir}/.env" \
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
DNS_IPV6_SECONDARY=${dns6_2}"
}

# =============================================================================
# SSL helpers
# =============================================================================

ssl_gen_if_missing() {
    ensure_docker_stack
    need_install_dir
    local dir; dir="$(load_install_dir)"
    mkdir -p "${dir}/fptn-server-data"

    if [[ -f "${dir}/fptn-server-data/server.key" && \
          -f "${dir}/fptn-server-data/server.crt" ]]; then
        echo "[*] SSL certificates already exist — skipping generation."
        return 0
    fi

    echo "[*] Generating self-signed SSL certificates..."
    dc run --rm fptn-server sh -c "cd /etc/fptn && openssl genrsa -out server.key 2048"
    dc run --rm fptn-server sh -c \
        "cd /etc/fptn && openssl req -new -x509 -key server.key -out server.crt -days 365 -subj '/CN=fptn'"
    echo "[+] SSL certificates generated."
}

ssl_fingerprint() {
    ensure_docker_stack
    need_install_dir
    dc run --rm fptn-server sh -c \
        "openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt \
         | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f' | xargs -I{} echo 'MD5 Fingerprint: {}'"
}

# =============================================================================
# User management
# =============================================================================

# Silently remove a user if they already exist (non-interactive, with timeout)
delete_user_if_exists() {
    local username="$1"
    echo "[*] Removing existing user (if present): ${username}"
    run_with_timeout 10 \
        bash -c "printf 'y\n' | \
            (cd \"$(load_install_dir)\" && \
             docker compose exec -i -T fptn-server fptn-passwd --del-user \"$username\") \
            >/dev/null 2>&1" \
    || true
}

# Interactive user deletion (passes a TTY through)
del_user_interactive() {
    local username="$1"
    local dir; dir="$(load_install_dir)"
    (cd "$dir" && docker compose exec -it fptn-server fptn-passwd --del-user "$username")
}

# Interactive user creation
add_user_interactive() {
    local username="$1" bw="$2"
    local dir; dir="$(load_install_dir)"
    (cd "$dir" && docker compose exec -it fptn-server \
        fptn-passwd --add-user "$username" --bandwidth "$bw")
}

# =============================================================================
# Token generation
# =============================================================================

# Raw token output (all stdout)
generate_token_raw() {
    local username="$1" password="$2" server_ip="$3" server_port="$4"
    dc run --rm fptn-server token-generator \
        --user "$username" --password "$password" \
        --server-ip "$server_ip" --port "$server_port"
}

# Filtered token output — extracts lines starting with "fptn:"
generate_token() {
    local username="$1" password="$2" server_ip="$3" server_port="$4"
    generate_token_raw "$username" "$password" "$server_ip" "$server_port" \
        | awk '/^fptn:/ { print; found=1 } END { exit (found ? 0 : 1) }'
}

print_token_block() {
    local token="$1"
    echo
    echo "================ TOKEN ================"
    echo "$token"
    echo "======================================="
}

# =============================================================================
# Install flows
# =============================================================================

easy_install() {
    ensure_docker_stack

    local dir="$DEFAULT_INSTALL_DIR"
    save_manager_config "$dir"
    mkdir -p "$dir"

    echo "[*] Detecting public IP..."
    local server_external_ips
    server_external_ips="$(fetch_public_ip || true)"

    write_compose "$dir"
    write_env "$dir" \
        "$DEFAULT_FPTN_PORT" \
        "$server_external_ips" \
        "$DEFAULT_PROXY_DOMAIN" \
        "$DEFAULT_ENABLE_DETECT_PROBING" \
        "$DEFAULT_DISABLE_BITTORRENT" \
        "$DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER" \
        "$DEFAULT_DNS_IPV4_PRIMARY" \
        "$DEFAULT_DNS_IPV4_SECONDARY" \
        "$DEFAULT_DNS_IPV6_PRIMARY" \
        "$DEFAULT_DNS_IPV6_SECONDARY"

    if [[ -z "$server_external_ips" ]]; then
        echo "[!] Warning: Could not auto-detect public IP." >&2
        echo "    Edit SERVER_EXTERNAL_IPS in ${dir}/.env manually." >&2
    fi

    echo "[*] Generating SSL certificates (if missing)..."
    ssl_gen_if_missing

    echo "[*] Starting server..."
    dc up -d

    echo "[*] Waiting for fptn-server to be ready..."
    wait_for_container_ready

    echo
    ssl_fingerprint || true
    echo
    echo "[*] Server status:"
    dc ps || true

    # --- Create easy user and generate token ---
    local username server_ip server_port installed_port password token
    username="$(easy_username)"
    server_ip="$(fetch_public_ip || true)"
    installed_port="$(env_get FPTN_PORT 2>/dev/null || true)"
    server_port="${installed_port:-$DEFAULT_FPTN_PORT}"

    echo
    echo "[*] Creating easy VPN user (new each run): ${username}"
    echo "[!] You will be prompted INSIDE the container to set a password for '${username}'."
    echo

    add_user_interactive "$username" "$DEFAULT_BANDWIDTH_MBPS"

    echo
    password="$(read_secret_tty "[*] Re-enter the SAME password to generate the access token: ")"
    echo

    [[ -z "${server_ip:-}" ]] && server_ip="YOUR_SERVER_PUBLIC_IP"

    echo "[!] Easy user credentials (save these):"
    echo "    Username : ${username}"
    echo "    Password : ${password}"

    token="$(generate_token "$username" "$password" "$server_ip" "$server_port" || true)"
    if [[ -n "${token:-}" ]]; then
        print_token_block "$token"
    else
        echo
        echo "[!] Token generation failed. Raw generator output:"
        generate_token_raw "$username" "$password" "$server_ip" "$server_port" || true
    fi

    echo
    echo "[+] Easy install complete."
}

custom_install() {
    ensure_docker_stack

    local dir fptn_port server_external_ips proxy_domain detect_probing
    local disable_bt max_sessions dns4_1 dns4_2 dns6_1 dns6_2
    local username password bw server_ip server_port token

    echo
    echo "--- Custom Installation ---"
    dir="$(prompt_default            "Install directory"                   "$DEFAULT_INSTALL_DIR")"
    fptn_port="$(prompt_default      "FPTN_PORT (host port)"               "$DEFAULT_FPTN_PORT")"
    server_external_ips="$(prompt_default \
        "SERVER_EXTERNAL_IPS (comma-separated, optional)" \
        "$(fetch_public_ip || true)")"
    proxy_domain="$(prompt_default   "DEFAULT_PROXY_DOMAIN"                "$DEFAULT_PROXY_DOMAIN")"
    detect_probing="$(prompt_default "ENABLE_DETECT_PROBING (true/false)"  "$DEFAULT_ENABLE_DETECT_PROBING")"
    disable_bt="$(prompt_default     "DISABLE_BITTORRENT (true/false)"     "$DEFAULT_DISABLE_BITTORRENT")"
    max_sessions="$(prompt_default   "MAX_ACTIVE_SESSIONS_PER_USER"        "$DEFAULT_MAX_ACTIVE_SESSIONS_PER_USER")"
    dns4_1="$(prompt_default         "DNS_IPV4_PRIMARY"                    "$DEFAULT_DNS_IPV4_PRIMARY")"
    dns4_2="$(prompt_default         "DNS_IPV4_SECONDARY"                  "$DEFAULT_DNS_IPV4_SECONDARY")"
    dns6_1="$(prompt_default         "DNS_IPV6_PRIMARY"                    "$DEFAULT_DNS_IPV6_PRIMARY")"
    dns6_2="$(prompt_default         "DNS_IPV6_SECONDARY"                  "$DEFAULT_DNS_IPV6_SECONDARY")"

    IFS= read -r -p "VPN Username: "  username
    bw="$(prompt_default "Bandwidth (Mbps)" "$DEFAULT_BANDWIDTH_MBPS")"

    save_manager_config "$dir"
    mkdir -p "$dir"

    write_compose "$dir"
    write_env "$dir" \
        "$fptn_port" \
        "$server_external_ips" \
        "$proxy_domain" \
        "$detect_probing" \
        "$disable_bt" \
        "$max_sessions" \
        "$dns4_1" \
        "$dns4_2" \
        "$dns6_1" \
        "$dns6_2"

    echo "[*] Generating SSL certificates (if missing)..."
    ssl_gen_if_missing

    echo "[*] Starting server..."
    dc up -d

    echo "[*] Waiting for fptn-server to be ready..."
    wait_for_container_ready

    echo
    echo "[*] Creating VPN user: ${username}"
    echo "[!] You will be prompted INSIDE the container to set a password."
    echo

    delete_user_if_exists "$username"
    add_user_interactive "$username" "$bw"

    echo
    password="$(read_secret_tty "[*] Re-enter the SAME password to generate the access token: ")"
    echo

    server_ip="$(fetch_public_ip || true)"
    server_port="${fptn_port:-$DEFAULT_FPTN_PORT}"
    [[ -z "${server_ip:-}" ]] && server_ip="YOUR_SERVER_PUBLIC_IP"

    token="$(generate_token "$username" "$password" "$server_ip" "$server_port" || true)"
    if [[ -n "${token:-}" ]]; then
        print_token_block "$token"
    else
        echo
        echo "[!] Token generation failed. Raw generator output:"
        generate_token_raw "$username" "$password" "$server_ip" "$server_port" || true
    fi

    echo
    echo "[+] Custom install complete."
}

# =============================================================================
# Service operations
# =============================================================================

service_start()  { need_install_dir; dc up -d;         echo "[+] Service started."; }
service_stop()   { need_install_dir; dc down;          echo "[+] Service stopped."; }
service_status() { need_install_dir; dc ps; }
service_logs()   { need_install_dir; dc logs --tail=100 -f; }

service_update() {
    need_install_dir
    echo "[*] Pulling latest FPTN image..."
    dc pull
    echo "[*] Restarting with new image..."
    dc up -d
    echo "[+] Update complete."
}

# =============================================================================
# User/token operations (post-install menu options)
# =============================================================================

add_vpn_user() {
    ensure_docker_stack
    need_install_dir

    local username bw server_ip server_port installed_port password token
    IFS= read -r -p "VPN Username: " username
    bw="$(prompt_default "Bandwidth (Mbps)" "$DEFAULT_BANDWIDTH_MBPS")"

    echo "[*] Creating user: ${username}"
    delete_user_if_exists "$username"
    add_user_interactive "$username" "$bw"

    echo
    password="$(read_secret_tty "[*] Re-enter the SAME password to generate the access token: ")"
    echo

    server_ip="$(fetch_public_ip || true)"
    installed_port="$(env_get FPTN_PORT 2>/dev/null || true)"
    server_port="${installed_port:-$DEFAULT_FPTN_PORT}"
    [[ -z "${server_ip:-}" ]] && server_ip="YOUR_SERVER_PUBLIC_IP"

    token="$(generate_token "$username" "$password" "$server_ip" "$server_port" || true)"
    if [[ -n "${token:-}" ]]; then
        print_token_block "$token"
    else
        echo
        echo "[!] Token generation failed. Raw generator output:"
        generate_token_raw "$username" "$password" "$server_ip" "$server_port" || true
    fi
}

gen_token_menu() {
    ensure_docker_stack
    need_install_dir

    local username password server_ip server_port installed_port token
    IFS= read -r -p "VPN Username: " username
    password="$(read_secret_tty "Password: ")"
    echo

    server_ip="$(fetch_public_ip || true)"
    installed_port="$(env_get FPTN_PORT 2>/dev/null || true)"
    server_port="${installed_port:-$DEFAULT_FPTN_PORT}"
    [[ -z "${server_ip:-}" ]] && server_ip="YOUR_SERVER_PUBLIC_IP"

    echo "[*] Generating token for: ${username}"
    token="$(generate_token "$username" "$password" "$server_ip" "$server_port" || true)"
    if [[ -n "${token:-}" ]]; then
        print_token_block "$token"
    else
        echo
        echo "[!] Token generation failed. Raw generator output:"
        generate_token_raw "$username" "$password" "$server_ip" "$server_port" || true
    fi
}

delete_vpn_user() {
    ensure_docker_stack
    need_install_dir

    local username
    IFS= read -r -p "Username to delete: " username
    del_user_interactive "$username"
    echo "[+] Done."
}

# =============================================================================
# Self-install / self-update
# =============================================================================

is_self_managed() {
    [[ "$(readlink -f "$0" 2>/dev/null || echo "$0")" == \
       "$(readlink -f "$BIN_PATH" 2>/dev/null || echo "$BIN_PATH")" ]]
}

self_install() {
    # Skip when invoked via pipe (curl | bash)
    if [[ "${0##*/}" == "bash" || "${0##*/}" == "-bash" || "$0" == "-" ]]; then
        cat <<'EOF'
[!] Pipe-install detected.
    To install fptn-manager as a system command, save this script and run:

    sudo bash fptn-manager.sh --install

EOF
        return 0
    fi

    require_root

    if is_self_managed; then
        echo "[*] fptn-manager is already installed at ${BIN_PATH}."
        return 0
    fi

    echo "[*] Installing fptn-manager to ${BIN_PATH}..."
    cp -f "$0" "$BIN_PATH"
    chmod +x "$BIN_PATH"
    echo "[+] Installed. Run: ${APP_NAME}"
}

self_update() {
    require_root
    echo "[*] Downloading latest fptn-manager..."
    ensure_curl
    curl -fsSL "$RAW_INSTALL_URL" -o "$BIN_PATH"
    chmod +x "$BIN_PATH"
    echo "[+] fptn-manager updated. Run: ${APP_NAME}"
}

# =============================================================================
# Interactive menu
# =============================================================================

menu() {
    while true; do
        echo
        echo "FPTN VPN Manager — ${APP_NAME}"
        echo "================================="
        echo "Install dir : $(load_install_dir)"
        echo
        echo "  1)  Easy install   (auto user + token)"
        echo "  2)  Custom install (full configuration)"
        echo "  3)  Start service"
        echo "  4)  Stop service"
        echo "  5)  Show status"
        echo "  6)  View logs"
        echo "  7)  Update (pull latest image)"
        echo "  8)  SSL: generate certs (if missing)"
        echo "  9)  SSL: show MD5 fingerprint"
        echo "  10) Add VPN user (prints token)"
        echo "  11) Generate token (existing user)"
        echo "  12) Delete VPN user"
        echo "  13) Self-install (add to PATH)"
        echo "  14) Self-update  (download latest)"
        echo "  0)  Exit"
        echo
        read -r -p "Select: " c
        echo

        case "$c" in
            1)  easy_install       ;;
            2)  custom_install     ;;
            3)  service_start      ;;
            4)  service_stop       ;;
            5)  service_status     ;;
            6)  service_logs       ;;
            7)  service_update     ;;
            8)  ssl_gen_if_missing ;;
            9)  ssl_fingerprint    ;;
            10) add_vpn_user       ;;
            11) gen_token_menu     ;;
            12) delete_vpn_user    ;;
            13) self_install       ;;
            14) self_update        ;;
            0)  echo "Bye."; exit 0 ;;
            *)  echo "Unknown option: ${c}" ;;
        esac
    done
}

# =============================================================================
# Entry point
# =============================================================================

main() {
    case "${1:-}" in
        --install)      self_install   ;;
        --update)       self_update    ;;
        --easy-install) easy_install   ;;
        --start)        service_start  ;;
        --stop)         service_stop   ;;
        --status)       service_status ;;
        --logs)         service_logs   ;;
        --add-user)     add_vpn_user   ;;
        --gen-token)    gen_token_menu ;;
        "")             menu           ;;
        *)              echo "Usage: ${APP_NAME} [--install|--update|--easy-install|--start|--stop|--status|--logs|--add-user|--gen-token]" >&2
                        exit 1 ;;
    esac
}

main "$@"
