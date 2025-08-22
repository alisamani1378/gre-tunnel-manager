#!/usr/bin/env bash
# ------------------------------------------------------------------
#  Universal GRE Tunnel Manager & Server Optimizer (Domain-aware)
#  Author  : Ali Samani – 2025
#  License : MIT
#  Notes   : - Remote endpoints can be domain or IPv4
#            - Monitor only tracks domain endpoints (not IP)
#            - Local server IP is detected once at boot (persistence)
# ------------------------------------------------------------------

set -Eeuo pipefail
SCRIPT_START=$(date +%s)

# ---------- Constants ---------------------------------------------------------
CONFIG_FILE="/etc/gre-tunnels.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/gre-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/gre-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/gre-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/gre-monitor.service"
PING_INTERVAL=10            # seconds (monitor loop interval)
MONITOR_FAIL_THRESHOLD=3    # pings for healthcheck

# ---------- Pretty print helpers ---------------------------------------------
NC='\033[0m'
C_BLUE='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'

info()    { echo -e "${C_BLUE}[INFO]${NC}    $*"; }
success() { echo -e "${C_GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${C_YELLOW}[WARN]${NC}   $*"; }
error()   { echo -e "${C_RED}[ERROR]${NC}  $*" >&2; }

# ---------- Root check --------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root (try with sudo)."
  exit 1
fi

# ---------- Utils -------------------------------------------------------------
is_valid_ip() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r o1 o2 o3 o4 <<<"$ip"
  for o in $o1 $o2 $o3 $o4; do
    ((o <= 255)) || return 1
  done
}

is_valid_hostname() {
  local h=$1
  [[ $h =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

resolve_remote() { # $1=hostname_or_ip -> echo IPv4 or fail
  local target="$1" ip=""
  if is_valid_ip "$target"; then
    echo "$target"; return 0
  fi
  # Prefer libc/NSS
  ip=$(getent ahostsv4 "$target" | awk '{print $1; exit}') || true
  if [[ -z $ip ]]; then
    if command -v dig >/dev/null 2>&1; then
      ip=$(dig +short A "$target" | grep -E '^[0-9]+\.' | head -n1) || true
    elif command -v drill >/dev/null 2>&1; then
      ip=$(drill "$target" A | awk '/IN[ \t]+A[ \t]+/ {print $5; exit}') || true
    elif command -v host >/dev/null 2>&1; then
      ip=$(host -t A "$target" | awk '/ has address /{print $4; exit}') || true
    fi
  fi
  [[ -n $ip ]] && echo "$ip" || return 1
}

prompt_default() { # $1=question  $2=default
  local ans
  read -r -p "$1 [$2]: " ans
  echo "${ans:-$2}"
}

# =====================================================================
# ====================== Actions (Wizard) =============================
# =====================================================================

create_new_tunnels() {
  clear
  info "------------- GRE Tunnel Configuration Wizard -------------"

  # 1) Location
  local location_choice
  location_choice=$(prompt_default "Choose server location (1=Iran, 2=Abroad)" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "Invalid choice. Defaulting to Abroad."; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "Server location set. Internal IPs will end with .$LOCAL_IP_SUFFIX"

  # 2) Delete existing tunnels / flush FW?
  local delete_choice flush_choice
  delete_choice=$(prompt_default "Delete existing GRE tunnels first? (1=Yes, 2=No)" "1")
  flush_choice=$(prompt_default "Flush ALL firewall rules? (1=Yes, 2=No)" "1")

  # 3) Select network interface
  mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
  echo "--------------------------------------------------"
  for i in "${!INTERFACES[@]}"; do echo " $((i+1))) ${INTERFACES[$i]}"; done
  echo "--------------------------------------------------"
  local iface_choice MAIN_INTERFACE
  while true; do
    iface_choice=$(prompt_default "Select main network interface" "1")
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && ((iface_choice>=1 && iface_choice<=${#INTERFACES[@]})); then
      MAIN_INTERFACE=${INTERFACES[$((iface_choice-1))]}
      break
    else warn "Invalid option. Try again."; fi
  done
  success "Interface '$MAIN_INTERFACE' selected."

  # ---------- Cleanup (optional) ----------------
  if [[ $delete_choice != 2 ]]; then
    info "Deleting existing GRE tunnels..."
    ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r tun; do
      [[ -n $tun ]] && { ip link delete "$tun" && echo "  - $tun removed."; } || true
    done
  fi

  if [[ $flush_choice != 2 ]]; then
    info "Flushing iptables rules..."
    iptables -F; iptables -t nat -F; iptables -t mangle -F
    iptables -X; iptables -t nat -X; iptables -t mangle -X
  fi

  # ---------- Basic net config ---------------
  info "Enabling IP forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  LOCAL_IP=$(curl -4 -s icanhazip.com || true)
  [[ -z $LOCAL_IP ]] && { error "Couldn't auto-detect public IP"; exit 1; }
  success "Public IP detected: $LOCAL_IP"

  # 4) Remote endpoints (domain or IP)
  info "Enter remote server endpoints (domain or IPv4). Blank line to finish:"
  REMOTE_ENDPOINTS=()
  while :; do
    read -r -p "Remote endpoint: " ep
    [[ -z $ep ]] && break
    if is_valid_ip "$ep" || is_valid_hostname "$ep"; then
      REMOTE_ENDPOINTS+=("$ep")
    else
      warn "Invalid domain/IP, ignored."
    fi
  done
  (( ${#REMOTE_ENDPOINTS[@]} )) || { error "No valid endpoints supplied."; return; }

  # 5) Internal IP mode
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(prompt_default "Assign internal IPs (1=auto, 2=manual)" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "Internal IP assignment mode: $TUNNEL_IP_MODE"

  # ---------- Create tunnels -----------------
  INTERNAL_TUNNEL_IPS=()
  RESOLVED_REMOTE_IPS=()
  info "Creating tunnels..."
  for idx in "${!REMOTE_ENDPOINTS[@]}"; do
    local ENDPOINT="${REMOTE_ENDPOINTS[$idx]}"
    local RESOLVED_REMOTE
    if ! RESOLVED_REMOTE=$(resolve_remote "$ENDPOINT"); then
      error "Cannot resolve $ENDPOINT — skipping."
      continue
    fi
    RESOLVED_REMOTE_IPS+=("$RESOLVED_REMOTE")

    local TUN="gre$((idx+1))"
    local SUBNET_BASE=$(( (idx+1) * 10 ))
    local TUN_IP

    if [[ $TUNNEL_IP_MODE == manual ]]; then
      read -r -p "Internal IP for $TUN → $ENDPOINT ($RESOLVED_REMOTE) (e.g. ${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24): " TUN_IP
      is_valid_ip "${TUN_IP%%/*}" || { warn "Invalid IP, using auto."; TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    ip link show "$TUN" &>/dev/null || ip tunnel add "$TUN" mode gre remote "$RESOLVED_REMOTE" local "$LOCAL_IP" ttl 255
    ip addr show dev "$TUN" | grep -q "$TUN_IP" || ip addr add "$TUN_IP" dev "$TUN"
    ip link set "$TUN" up
    sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
    echo "  • $TUN ↔ $ENDPOINT ($RESOLVED_REMOTE)  [$TUN_IP]"
  done

  # ---------- Configure NAT based on location ----------
  info "Configuring NAT..."
  declare -a MASQUERADE_RULES
  if [[ "$location_choice" == "1" ]]; then
    # Iran server: Masquerade on each GRE tunnel
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      TUN="gre$((i+1))"
      rule="iptables -t nat -A POSTROUTING -o $TUN -j MASQUERADE"
      MASQUERADE_RULES+=("$rule")
      iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || eval "$rule"
    done
    success "NAT configured on all GRE tunnels."
  else
    # Abroad server: Masquerade on main interface
    rule="iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE"
    MASQUERADE_RULES+=("$rule")
    iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null || eval "$rule"
    success "NAT configured on main interface '$MAIN_INTERFACE'."
  fi

  # ---------- Port Forwarding Setup (optional) ----------
  declare -a FORWARDING_RULES
  if [[ "$location_choice" == "1" ]]; then
    info "------------- Port Forwarding Setup -------------"
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
while true; do
    read -r -p "Add port forwarding for tunnel to ${REMOTE_ENDPOINTS[$i]}? (y/n): " add_forward
    [[ $add_forward =~ ^[Yy]$ ]] || break

    read -r -p "  Port to forward (e.g., 8080 or 8080=7070): " PORT_INPUT
    if [[ "$PORT_INPUT" == *"="* ]]; then
        SRC_PORT="${PORT_INPUT%%=*}"
        DST_PORT="${PORT_INPUT##*=}"
    else
        SRC_PORT="$PORT_INPUT"
        DST_PORT="$PORT_INPUT"
    fi
    read -r -p "  Protocol (tcp/udp): " PROTOCOL

    SUBNET_BASE=$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1 | cut -d'.' -f1-3)
    SOURCE_IP="${SUBNET_BASE}.${LOCAL_IP_SUFFIX}"
    DEST_IP="${SUBNET_BASE}.${GATEWAY_IP_SUFFIX}"

    PREROUTING_RULE="iptables -t nat -A PREROUTING -p $PROTOCOL --dport $SRC_PORT -j DNAT --to-destination ${DEST_IP}:${DST_PORT}"
    POSTROUTING_RULE="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $DST_PORT -j SNAT --to-source $SOURCE_IP"

    info "  Applying rule: $PREROUTING_RULE"
    eval "$PREROUTING_RULE"
    info "  Applying rule: $POSTROUTING_RULE"
    eval "$POSTROUTING_RULE"

    FORWARDING_RULES+=("$PREROUTING_RULE" "$POSTROUTING_RULE")
    success "Forwarding rule added: $SRC_PORT → $DST_PORT/$PROTOCOL"
done

    done
  fi

  # ---------- Save config ---------------
  info "Saving configuration → $CONFIG_FILE"
  {
    echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
    echo "LOCAL_IP=\"$LOCAL_IP\""
    echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
    echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
    printf "REMOTE_ENDPOINTS=("
    for ep in "${REMOTE_ENDPOINTS[@]}"; do printf "%q " "$ep"; done
    printf ")\n"
    printf "RESOLVED_REMOTE_IPS=("
    for ip in "${RESOLVED_REMOTE_IPS[@]}"; do printf "%q " "$ip"; done
    printf ")\n"
    printf "INTERNAL_TUNNEL_IPS=("
    for tip in "${INTERNAL_TUNNEL_IPS[@]}"; do printf "%q " "$tip"; done
    printf ")\n"
    printf "MASQUERADE_RULES=("
    for rule in "${MASQUERADE_RULES[@]}"; do printf "%q " "$rule"; done
    printf ")\n"
    printf "FORWARDING_RULES=("
    for rule in "${FORWARDING_RULES[@]}"; do printf "%q " "$rule"; done
    printf ")\n"
    echo "PING_INTERVAL=$PING_INTERVAL"
    echo "MONITOR_FAIL_THRESHOLD=$MONITOR_FAIL_THRESHOLD"
  } > "$CONFIG_FILE"

  # ---------- Create services ----------------
  create_persistence_service
  create_monitor_service

  systemctl daemon-reload
  systemctl enable --now gre-persistence.service gre-monitor.service

  # ---------- Final Step: Optimizer ----------
  run_optimizer

  success "All done! Total time: $(( $(date +%s) - SCRIPT_START )) s"
  info    "Reboot may be needed for kernel optimizations to take full effect."
}

create_persistence_service() {
  info "Building persistence service..."
  cat > "$PERSISTENCE_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /etc/gre-tunnels.conf ]] || exit 0
# shellcheck disable=SC1091
source /etc/gre-tunnels.conf

# Detect current server's local/public IPv4 once at boot
detect_local_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}' \
  || ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 \
  || curl -4 -s icanhazip.com 2>/dev/null
}

is_valid_ip() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
resolve_remote() {
  local t="$1" ip=""
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  ip=$(getent ahostsv4 "$t" | awk '{print $1; exit}') || true
  [[ -n $ip ]] && echo "$ip" || return 1
}

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# (0) If local IP changed (e.g., snapshot), update config & use the new one
CURRENT_LOCAL_IP="$(detect_local_ip)"
if [[ -n "$CURRENT_LOCAL_IP" && "$CURRENT_LOCAL_IP" != "$LOCAL_IP" ]]; then
  echo "[INFO] LOCAL_IP changed: $LOCAL_IP -> $CURRENT_LOCAL_IP (updating config & tunnels)"
  sed -i -E 's|^LOCAL_IP="[^"]*"|LOCAL_IP="'"$CURRENT_LOCAL_IP"'"|' /etc/gre-tunnels.conf || true
  LOCAL_IP="$CURRENT_LOCAL_IP"
fi

# Restore NAT/Masquerade rules (idempotent)
for rule_cmd in "${MASQUERADE_RULES[@]}"; do
  check_cmd="${rule_cmd/ -A /-C }"
  if ! eval "$check_cmd" &>/dev/null; then eval "$rule_cmd"; fi
done

# Create/restore tunnels (resolve endpoints each boot)
for i in "${!REMOTE_ENDPOINTS[@]}"; do
  TUN="gre$((i+1))"
  ENDPOINT="${REMOTE_ENDPOINTS[$i]}"
  RESOLVED="$(resolve_remote "$ENDPOINT" || true)"
  [[ -z "$RESOLVED" ]] && { echo "WARN: cannot resolve $ENDPOINT"; continue; }

  ip link set "$TUN" down 2>/dev/null || true
  ip tunnel del "$TUN" 2>/dev/null || true
  ip tunnel add "$TUN" mode gre remote "$RESOLVED" local "$LOCAL_IP" ttl 255
  ip addr add "${INTERNAL_TUNNEL_IPS[$i]}" dev "$TUN" 2>/dev/null || true
  ip link set "$TUN" up
  sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
done

# Restore custom port forwarding rules
for rule in "${FORWARDING_RULES[@]}"; do
  check_cmd="${rule/-A /-C }"
  if ! eval "$check_cmd" &>/dev/null; then eval "$rule"; fi
done
BASH
  chmod +x "$PERSISTENCE_SCRIPT"

  cat > "$PERSISTENCE_SERVICE" <<EOF
[Unit]
Description=Restore GRE tunnels at boot (domain-aware; detect local IP once)
After=network-online.target
Wants=network-online.target
ConditionPathExists=$CONFIG_FILE

[Service]
Type=oneshot
ExecStart=$PERSISTENCE_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
  success "Persistence unit created."
}

create_monitor_service() {
  info "Building monitor service..."
  cat > "$MONITOR_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /etc/gre-tunnels.conf ]] || exit 0
# shellcheck disable=SC1091
source /etc/gre-tunnels.conf

INTERVAL=${PING_INTERVAL:-10}
THRESHOLD=${MONITOR_FAIL_THRESHOLD:-3}

is_valid_ip() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

# hostname -> IPv4
resolve_remote() {
  local t="$1" ip=""
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  ip=$(getent ahostsv4 "$t" | awk '{print $1; exit}') || true
  [[ -n $ip ]] && echo "$ip" || return 1
}

# اگر تونل وجود نداشت، با endpoint و LOCAL_IP بسازش و بالا بیار
ensure_tun_present() { # $1=tun $2=endpoint $3=cidr
  local tun="$1" ep="$2" cidr="$3" remote=""
  if ip link show "$tun" &>/dev/null; then
    return 0
  fi
  remote="$(resolve_remote "$ep" || true)"
  [[ -z "$remote" ]] && { echo "[MONITOR] WARN: cannot resolve $ep to create $tun"; return 1; }
  ip tunnel add "$tun" mode gre remote "$remote" local "$LOCAL_IP" ttl 255 || return 1
  ip addr add "$cidr" dev "$tun" 2>/dev/null || true
  ip link set "$tun" up || true
  sysctl -w "net.ipv4.conf.${tun}.rp_filter=0" >/dev/null || true
  echo "[MONITOR] recreated $tun → remote=$remote cidr=$cidr"
  return 0
}

# مطمئن شو آدرس داخلی هست و لینک up است
ensure_addr_up() { # $1=tun $2=cidr
  ip addr show dev "$1" | grep -q " ${2//\//\\/} " || ip addr add "$2" dev "$1"
  ip link set "$1" up || true
}

while true; do
  for i in "${!REMOTE_ENDPOINTS[@]}"; do
    TUN="gre$((i+1))"
    EP="${REMOTE_ENDPOINTS[$i]}"
    CIDR="${INTERNAL_TUNNEL_IPS[$i]}"

    # 0) اگر تونل نیست، بساز
    ensure_tun_present "$TUN" "$EP" "$CIDR" || { sleep "$INTERVAL"; continue; }

    # 1) ensure link & address
    ensure_addr_up "$TUN" "$CIDR"

    # 2) DNS-monitor: فقط برای دامنه‌ها → اگر IP عوض شد، rebuild
    if ! is_valid_ip "$EP"; then
      NEW_REMOTE="$(resolve_remote "$EP" || true)"
      CUR_REMOTE="$(ip -d tunnel show "$TUN" 2>/dev/null | awk '/remote/ {print $4; exit}')"
      if [[ -n "$NEW_REMOTE" && "$NEW_REMOTE" != "$CUR_REMOTE" ]]; then
        echo "[MONITOR] $TUN remote changed for $EP: $CUR_REMOTE -> $NEW_REMOTE (rebuild)"
        ip link set "$TUN" down 2>/dev/null || true
        ip tunnel del "$TUN" 2>/dev/null || true
        ip tunnel add "$TUN" mode gre remote "$NEW_REMOTE" local "$LOCAL_IP" ttl 255
        ensure_addr_up "$TUN" "$CIDR"
        sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
      fi
    fi

    # 3) Health-monitor: پینگ به IP داخلی طرف مقابل (برای همه‌ی تونل‌ها)
    LOCAL_INNER="${CIDR%%/*}"                 # مثل 20.0.0.2
    BASE="$(echo "$LOCAL_INNER" | cut -d'.' -f1-3)"
    HOST="$(echo "$LOCAL_INNER" | cut -d'.' -f4)"
    if [[ "$HOST" == "$LOCAL_IP_SUFFIX" ]]; then
      PEER="$BASE.$GATEWAY_IP_SUFFIX"        # 20.0.0.1
    else
      PEER="$BASE.$LOCAL_IP_SUFFIX"          # fallback
    fi

    if ! ping -c "$THRESHOLD" -W 2 "$PEER" &>/dev/null; then
      echo "[MONITOR] $TUN ping $PEER failed → bounce"
      ip link set "$TUN" down 2>/dev/null || true
      ip link set "$TUN" up   2>/dev/null || true
      # اگر تونل در bounce حذف شد، دوباره بساز
      ip link show "$TUN" &>/dev/null || ensure_tun_present "$TUN" "$EP" "$CIDR"
      ping -c 1 -W 2 "$PEER" &>/dev/null || echo "[MONITOR] $TUN still failing to ping $PEER"
    fi

  done
  sleep "${INTERVAL:-10}"
done
BASH
  chmod +x "$MONITOR_SCRIPT"

  cat > "$MONITOR_SERVICE" <<EOF
[Unit]
Description=Keep GRE tunnels alive (DNS + Health ping; auto-recreate greX)
After=gre-persistence.service
Wants=gre-persistence.service
ConditionPathExists=$CONFIG_FILE

[Service]
ExecStart=$MONITOR_SCRIPT
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  success "Monitor unit created."
}

# --- Optimizer Functions (unchanged) ---
apply_tcp_settings() {
    info "Writing TCP-optimized settings..."
    cat > /etc/sysctl.conf <<'EOF'
# TCP-focused Kernel Settings (Auto-generated by script)
vm.swappiness = 1
vm.min_free_kbytes = 65536
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
vm.vfs_cache_pressure = 50
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
}

apply_udp_settings() {
    info "Writing UDP-optimized settings..."
    cat > /etc/sysctl.conf <<'EOF'
# UDP-focused Kernel Settings (Auto-generated by script)
vm.swappiness = 1
vm.min_free_kbytes = 65536
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
vm.vfs_cache_pressure = 50
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.udp_mem = 2097152 4194304 8388608
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
}

run_optimizer() {
    info "------------- Kernel Optimization Wizard -------------"
    read -r -p "Do you want to optimize server kernel settings now? (y/N): " optimize_confirm
    [[ $optimize_confirm =~ ^[Yy]$ ]] || { info "Skipping kernel optimization."; return; }

    echo
    info "Please select the optimization profile:"
    echo "  1) TCP Profile (Best for VLESS, Trojan, etc.)"
    echo "  2) UDP Profile (Best for Gaming, WireGuard, etc.)"
    echo

    local choice
    while true; do
        read -p "Enter your choice [1 or 2]: " choice
        case $choice in
            1|2) break ;;
            *) warn "Invalid input. Please enter 1 or 2." ;;
        esac
    done

    echo
    read -p "This will OVERWRITE /etc/sysctl.conf. Are you sure? [y/N]: " final_confirm
    if [[ ! "$final_confirm" =~ ^[Yy]$ ]]; then
        info "Operation cancelled."
        return
    fi

    info "Backing up /etc/sysctl.conf to /etc/sysctl.conf.bak.$(date +%F)..."
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F) 2>/dev/null || true

    if [ "$choice" -eq 1 ]; then
        apply_tcp_settings
    else
        apply_udp_settings
    fi

    info "Applying new sysctl settings..."
    if sysctl -p; then
        success "Kernel settings applied."
    else
        error "Failed to apply kernel settings."
    fi

    echo
    read -p "A reboot is recommended. Reboot now? [y/N]: " reboot_confirm
    if [[ "$reboot_confirm" =~ ^[Yy]$ ]]; then
        info "Rebooting now..."
        reboot
    else
        warn "Please remember to reboot later to apply all changes."
    fi
}

delete_all_tunnels() {
  warn "This will remove EVERY tunnel, config & service created by this tool."
  read -r -p "Really continue? (y/N): " confirm
  [[ $confirm =~ ^[Yy]$ ]] || { info "Aborted."; return; }

  systemctl stop gre-monitor.service gre-persistence.service 2>/dev/null || true
  systemctl disable gre-monitor.service gre-persistence.service 2>/dev/null || true
  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" "$CONFIG_FILE"
  systemctl daemon-reload

  ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r tun; do
    [[ -n $tun ]] && { ip link delete "$tun" && echo "  - $tun removed."; } || true
  done
  
  warn "Note: Kernel settings in /etc/sysctl.conf have NOT been reverted."
  warn "Original backups are stored as /etc/sysctl.conf.bak.YYYY-MM-DD"
  success "Cleanup complete."
}

main_menu() {
  clear
  echo "--------- GRE Tunnel Manager ---------"
  echo " 1) Create / Reconfigure tunnels"
  echo " 2) Delete ALL tunnels & services"
  echo " 3) Exit"
  read -r -p "Select an option: " choice
  case $choice in
    1) create_new_tunnels ;;
    2) delete_all_tunnels ;;
    3) exit 0 ;;
    *) error "Invalid choice."; exit 1 ;;
  esac
}

main_menu
