#!/usr/bin/env bash
# ------------------------------------------------------------------
#  Universal Tunnel Manager (GRE or IPIP) + Domain-aware + Monitors
#  Based on: "Universal GRE Tunnel Manager (Domain-aware) + Dual Monitors"
#  Author  : Ali Samani – 2025 (extended for GRE/IPIP choice)
#  License : MIT
# ------------------------------------------------------------------

set -Eeuo pipefail
SCRIPT_START=$(date +%s)

# ---------- Constants ---------------------------------------------------------
CONFIG_FILE="/etc/tunnel-manager.conf"     # renamed to be mode-agnostic
PERSISTENCE_SCRIPT="/usr/local/bin/tunnel-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/tunnel-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/tunnel-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/tunnel-monitor.service"
PING_INTERVAL=10            # seconds
MONITOR_FAIL_THRESHOLD=3    # pings

# ---------- Pretty print helpers ---------------------------------------------
NC='\033[0m'; C_BLUE='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'
info()    { echo -e "${C_BLUE}[INFO]${NC}    $*"; }
success() { echo -e "${C_GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${C_YELLOW}[WARN]${NC}   $*"; }
error()   { echo -e "${C_RED}[ERROR]${NC}  $*" >&2; }

# ---------- Root check --------------------------------------------------------
if [[ $EUID -ne 0 ]]; then error "Run as root (sudo)."; exit 1; fi

# ---------- Utils -------------------------------------------------------------
is_valid_ip() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"; for o in $a $b $c $d; do ((o<=255)) || return 1; done
}
is_valid_hostname() { [[ $1 =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$ ]]; }
resolve_remote_once() { # hostname/ip -> one IPv4
  local t="$1" ip=""
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  ip=$(getent ahostsv4 "$t" | awk '{print $1; exit}') || true
  [[ -n $ip ]] && echo "$ip" || return 1
}
prompt_default(){ local a; read -r -p "$1 [$2]: " a; echo "${a:-$2}"; }

# ---------- Firewall cleanup helpers -----------------------------------------
_eval_on_iptables_variants(){
  local cmd="$1"
  eval "$cmd" 2>/dev/null || true
  if command -v iptables-legacy >/dev/null 2>&1; then
    local legacy_cmd
    legacy_cmd="${cmd/iptables /iptables-legacy }"
    eval "$legacy_cmd" 2>/dev/null || true
  fi
}

remove_rules_from_config(){
  [[ -f "$CONFIG_FILE" ]] || return 0
  set +u
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set -u
  local had=0
  if declare -p MASQUERADE_RULES >/dev/null 2>&1; then
    if ((${#MASQUERADE_RULES[@]} > 0)); then
      info "Removing previously configured firewall rules from $CONFIG_FILE..."
      had=1
    fi
    for r in "${MASQUERADE_RULES[@]}"; do
      [[ -n "$r" ]] || continue
      local del; del="${r/ -A / -D }"; del="${del/-A /-D }"
      if [[ "$del" != iptables* ]]; then del="iptables ${del}"; fi
      _eval_on_iptables_variants "$del"
    done
  fi
  if declare -p FORWARDING_RULES >/dev/null 2>&1; then
    ((had==0 && ${#FORWARDING_RULES[@]} > 0)) && { info "Removing previously configured firewall rules from $CONFIG_FILE..."; had=1; }
    for r in "${FORWARDING_RULES[@]}"; do
      [[ -n "$r" ]] || continue
      local del; del="${r/ -A / -D }"; del="${del/-A /-D }"
      if [[ "$del" != iptables* ]]; then del="iptables ${del}"; fi
      _eval_on_iptables_variants "$del"
    done
  fi
  [[ $had -eq 1 ]] && success "Old rules removed (if present)."
}

remove_tunnel_masquerade_best_effort(){
  info "Scanning for stray MASQUERADE rules on gre* / ipip*..."
  local line del
  {
    iptables -t nat -S POSTROUTING 2>/dev/null || true
    if command -v iptables-legacy >/dev/null 2>&1; then iptables-legacy -t nat -S POSTROUTING 2>/dev/null || true; fi
  } | awk '/^-A POSTROUTING/ && /-o (gre|ipip)[0-9]+/ && /-j MASQUERADE/' | while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    del="${line/-A /-D }"
    _eval_on_iptables_variants "iptables -t nat $del"
  done
  success "Stray MASQUERADE cleanup attempted."
}

flush_all_tables(){
  info "Flushing iptables (all tables)..."
  local tbl
  for tbl in filter nat mangle raw security; do
    iptables -t "$tbl" -F 2>/dev/null || true
    iptables -t "$tbl" -X 2>/dev/null || true
  done
  if command -v iptables-legacy >/dev/null 2>&1; then
    for tbl in filter nat mangle raw security; do
      iptables-legacy -t "$tbl" -F 2>/dev/null || true
      iptables-legacy -t "$tbl" -X 2>/dev/null || true
    done
  fi
  success "Firewall flushed."
}

remove_services_and_config(){
  info "Stopping and removing tunnel services and config..."
  systemctl stop tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  systemctl disable tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" 2>/dev/null || true
  rm -f "$CONFIG_FILE" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  success "Services and config removed."
}

# =====================================================================
# ====================== Actions (Wizard) =============================
# =====================================================================
create_new_tunnels() {
  clear
  info "------------- Tunnel Configuration Wizard -------------"

  # 0) Mode
  local tm_choice
  tm_choice=$(prompt_default "Tunnel mode (1=GRE, 2=IPIP)" "1")
  case "$tm_choice" in
    1) TUN_MODE="gre"; TUN_PREFIX="gre" ;;
    2) TUN_MODE="ipip"; TUN_PREFIX="ipip" ;;
    *) warn "Invalid choice. Defaulting to GRE."; TUN_MODE="gre"; TUN_PREFIX="gre" ;;
  esac
  success "Using mode: $TUN_MODE (interfaces like ${TUN_PREFIX}1, ${TUN_PREFIX}2, ...)"

  # 1) Location (suffix ها)
  local location_choice
  location_choice=$(prompt_default "Choose server location (1=Iran, 2=Abroad)" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "Invalid choice. Defaulting to Abroad."; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "Internal IPs will end with .$LOCAL_IP_SUFFIX"

  # 2) Cleanup
  local delete_choice flush_choice
  delete_choice=$(prompt_default "Delete existing ${TUN_MODE^^} tunnels first? (1=Yes, 2=No)" "1")
  flush_choice=$(prompt_default "Flush ALL firewall rules? (1=Yes, 2=No)" "1")

  # 3) Main interface
  mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
  echo "--------------------------------------------------"; for i in "${!INTERFACES[@]}"; do echo " $((i+1))) ${INTERFACES[$i]}"; done; echo "--------------------------------------------------"
  local iface_choice MAIN_INTERFACE
  while true; do
    iface_choice=$(prompt_default "Select main network interface" "1")
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && ((iface_choice>=1 && iface_choice<=${#INTERFACES[@]})); then
      MAIN_INTERFACE=${INTERFACES[$((iface_choice-1))]}; break
    else warn "Invalid option. Try again."; fi
  done
  success "Interface '$MAIN_INTERFACE' selected."

  # Cleanup
  if [[ "$flush_choice" == "1" ]]; then
    remove_services_and_config
    info "Deleting existing tunnels (both GRE and IPIP)..."
    ip -o link show type gre  | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r t; do [[ -n $t ]] && ip link delete "$t" && echo "  - $t removed."; done
    ip -o link show type ipip | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r t; do [[ -n $t ]] && ip link delete "$t" && echo "  - $t removed."; done
    flush_all_tables
  else
    if [[ $delete_choice != 2 ]]; then
      info "Deleting existing ${TUN_MODE^^} tunnels..."
      ip -o link show type "$TUN_MODE" | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r t; do [[ -n $t ]] && ip link delete "$t" && echo "  - $t removed."; done
      remove_rules_from_config
      remove_tunnel_masquerade_best_effort
    else
      remove_rules_from_config
      remove_tunnel_masquerade_best_effort
    fi
  fi

  # Net basic
  info "Enabling IP forwarding..."; sysctl -w net.ipv4.ip_forward=1 >/dev/null

  LOCAL_IP=$(curl -4 -s icanhazip.com || true)
  [[ -z $LOCAL_IP ]] && { error "Couldn't auto-detect public IP"; exit 1; }
  success "Public IP detected: $LOCAL_IP"

  # 4) Remote endpoints (domain/ip)
  info "Enter remote endpoints (domain or IPv4). Blank to finish:"
  REMOTE_ENDPOINTS=()
  while :; do
    read -r -p "Remote endpoint: " ep
    [[ -z $ep ]] && break
    if is_valid_ip "$ep" || is_valid_hostname "$ep"; then REMOTE_ENDPOINTS+=("$ep"); else warn "Invalid endpoint, ignored."; fi
  done
  (( ${#REMOTE_ENDPOINTS[@]} )) || { error "No endpoints supplied."; return; }

  # 5) Internal IP mode
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(prompt_default "Assign internal IPs (1=auto, 2=manual)" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "Internal IP assignment mode: $TUNNEL_IP_MODE"

  # Create tunnels
  INTERNAL_TUNNEL_IPS=(); RESOLVED_REMOTE_IPS=()
  info "Creating tunnels..."
  for idx in "${!REMOTE_ENDPOINTS[@]}"; do
    local ENDPOINT="${REMOTE_ENDPOINTS[$idx]}"
    local RESOLVED_REMOTE
    if ! RESOLVED_REMOTE=$(resolve_remote_once "$ENDPOINT"); then warn "Cannot resolve $ENDPOINT — skipping."; continue; fi
    RESOLVED_REMOTE_IPS+=("$RESOLVED_REMOTE")

    local TUN="${TUN_PREFIX}$((idx+1))"; local SUBNET_BASE=$(( (idx+1) * 10 )); local TUN_IP
    if [[ $TUNNEL_IP_MODE == manual ]]; then
      read -r -p "Internal IP for $TUN → $ENDPOINT ($RESOLVED_REMOTE) (e.g. ${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24): " TUN_IP
      [[ "${TUN_IP}" == */* ]] || TUN_IP="${TUN_IP}/24"
      is_valid_ip "${TUN_IP%%/*}" || { warn "Invalid IP, using auto."; TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    ip link show "$TUN" &>/dev/null || ip tunnel add "$TUN" mode "$TUN_MODE" remote "$RESOLVED_REMOTE" local "$LOCAL_IP" ttl 255
    ip addr show dev "$TUN" | grep -q "$TUN_IP" || ip addr add "$TUN_IP" dev "$TUN"
    ip link set "$TUN" up
    sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
    echo "  • $TUN ↔ $ENDPOINT ($RESOLVED_REMOTE)  [$TUN_IP]"
  done

  # NAT
  info "Configuring NAT..."
  declare -a MASQUERADE_RULES
  if [[ "$location_choice" == "1" ]]; then
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      TUN="${TUN_PREFIX}$((i+1))"; rule="iptables -t nat -A POSTROUTING -o $TUN -j MASQUERADE"
      MASQUERADE_RULES+=("$rule"); iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || eval "$rule"
    done
    success "NAT on ${TUN_MODE^^} tunnels."
  else
    rule="iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE"
    MASQUERADE_RULES+=("$rule"); iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null || eval "$rule"
    success "NAT on main interface '$MAIN_INTERFACE'."
  fi

  # Port Forward (optional, only Iran side)
  declare -a FORWARDING_RULES
  if [[ "$location_choice" == "1" ]]; then
    info "------------- Port Forwarding Setup -------------"
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      while true; do
        read -r -p "Add port forwarding for tunnel to ${REMOTE_ENDPOINTS[$i]}? (y/n): " add_forward
        [[ $add_forward =~ ^[Yy]$ ]] || break
        read -r -p "  Port (e.g., 8080 or 8080=7070): " PORT_INPUT
        if [[ "$PORT_INPUT" == *"="* ]]; then SRC_PORT="${PORT_INPUT%%=*}"; DST_PORT="${PORT_INPUT##*=}"; else SRC_PORT="$PORT_INPUT"; DST_PORT="$PORT_INPUT"; fi
        read -r -p "  Protocol (tcp/udp): " PROTOCOL

        SUBNET_BASE=$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1 | cut -d'.' -f1-3)
        SOURCE_IP="${SUBNET_BASE}.${LOCAL_IP_SUFFIX}"
        DEST_IP="${SUBNET_BASE}.${GATEWAY_IP_SUFFIX}"

        PR="iptables -t nat -A PREROUTING -p $PROTOCOL --dport $SRC_PORT -j DNAT --to-destination ${DEST_IP}:${DST_PORT}"
        PO="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $DST_PORT -j SNAT --to-source $SOURCE_IP"
        info "  Applying: $PR"; eval "$PR"; info "  Applying: $PO"; eval "$PO"
        FORWARDING_RULES+=("$PR" "$PO")
        success "Forward added: $SRC_PORT → $DST_PORT/$PROTOCOL"
      done
    done
  fi

  # Save config
  info "Saving → $CONFIG_FILE"
  {
    echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
    echo "LOCAL_IP=\"$LOCAL_IP\""
    echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
    echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
    echo "TUN_MODE=\"$TUN_MODE\""
    echo "TUN_PREFIX=\"$TUN_PREFIX\""
    printf "REMOTE_ENDPOINTS=("; for ep in "${REMOTE_ENDPOINTS[@]}"; do printf "%q " "$ep"; done; printf ")\n"
    printf "RESOLVED_REMOTE_IPS=("; for ip in "${RESOLVED_REMOTE_IPS[@]}"; do printf "%q " "$ip"; done; printf ")\n"
    printf "INTERNAL_TUNNEL_IPS=("; for tip in "${INTERNAL_TUNNEL_IPS[@]}"; do printf "%q " "$tip"; done; printf ")\n"
    printf "MASQUERADE_RULES=("; for r in "${MASQUERADE_RULES[@]}"; do printf "%q " "$r"; done; printf ")\n"
    printf "FORWARDING_RULES=("; for r in "${FORWARDING_RULES[@]}"; do printf "%q " "$r"; done; printf ")\n"
    echo "PING_INTERVAL=$PING_INTERVAL"
    echo "MONITOR_FAIL_THRESHOLD=$MONITOR_FAIL_THRESHOLD"
  } > "$CONFIG_FILE"

  create_persistence_service
  create_monitor_service

  systemctl daemon-reload
  systemctl enable tunnel-persistence.service tunnel-monitor.service
  systemctl restart tunnel-persistence.service tunnel-monitor.service

  run_optimizer

  success "All done! Time: $(( $(date +%s) - SCRIPT_START )) s"
  info "You may reboot for kernel tweaks to fully apply."
}

create_persistence_service() {
  info "Building persistence service..."
  cat > "$PERSISTENCE_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /etc/tunnel-manager.conf ]] || exit 0
set +u
source /etc/tunnel-manager.conf
set -u

detect_local_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}' \
  || ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 \
  || curl -4 -s icanhazip.com 2>/dev/null
}
is_valid_ip(){ [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
resolve_once(){ local t="$1"; is_valid_ip "$t" && { echo "$t"; return 0; }; getent ahostsv4 "$t" | awk '{print $1; exit}'; }

sysctl -w net.ipv4.ip_forward=1 >/dev/null

CURRENT_LOCAL_IP="$(detect_local_ip)"
if [[ -n "$CURRENT_LOCAL_IP" && "$CURRENT_LOCAL_IP" != "$LOCAL_IP" ]]; then
  echo "[INFO] LOCAL_IP changed: $LOCAL_IP -> $CURRENT_LOCAL_IP (update config)"
  sed -i -E 's|^LOCAL_IP="[^"]*"|LOCAL_IP="'"$CURRENT_LOCAL_IP"'"|' /etc/tunnel-manager.conf || true
  LOCAL_IP="$CURRENT_LOCAL_IP"
fi

# Restore NAT (idempotent)
if declare -p MASQUERADE_RULES >/dev/null 2>&1; then
  for cmd in "${MASQUERADE_RULES[@]}"; do chk="${cmd/ -A /-C }"; eval "$chk" &>/dev/null || eval "$cmd"; done
fi

# Re-create tunnels on boot (fresh resolve)
for i in "${!REMOTE_ENDPOINTS[@]}"; do
  TUN="${TUN_PREFIX}$((i+1))"; EP="${REMOTE_ENDPOINTS[$i]}"; CIDR="${INTERNAL_TUNNEL_IPS[$i]}"
  REM="$(resolve_once "$EP" || true)"; [[ -z "$REM" ]] && { echo "[WARN] cannot resolve $EP"; continue; }
  ip link set "$TUN" down 2>/dev/null || true; ip tunnel del "$TUN" 2>/dev/null || true
  ip tunnel add "$TUN" mode "$TUN_MODE" remote "$REM" local "$LOCAL_IP" ttl 255
  ip addr add "$CIDR" dev "$TUN" 2>/dev/null || true
  ip link set "$TUN" up
  sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
done

# Restore custom forwards
if declare -p FORWARDING_RULES >/dev/null 2>&1; then
  for r in "${FORWARDING_RULES[@]}"; do chk="${r/-A /-C }"; eval "$chk" &>/dev/null || eval "$r"; done
fi
BASH
  chmod +x "$PERSISTENCE_SCRIPT"

  cat > "$PERSISTENCE_SERVICE" <<EOF
[Unit]
Description=Restore GRE/IPIP tunnels at boot (domain-aware; detect local IP once)
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
[[ -f /etc/tunnel-manager.conf ]] || exit 0
source /etc/tunnel-manager.conf

INTERVAL=${PING_INTERVAL:-10}
THRESHOLD=${MONITOR_FAIL_THRESHOLD:-3}

is_valid_ip(){ [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

resolve_all(){
  local t="$1"
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  local ips; ips=$(getent ahostsv4 "$t" | awk '{print $1}' | awk '!seen[$0]++') || true
  [[ -n $ips ]] && echo "$ips" || return 1
}

ensure_tun_present(){ # $1=tun $2=endpoint $3=cidr
  local tun="$1" ep="$2" cidr="$3" set first
  ip link show "$tun" &>/dev/null && return 0
  set="$(resolve_all "$ep" || true)"; first="$(awk '{print $1}' <<<"$set")"
  [[ -z "$first" ]] && { echo "[MONITOR] WARN: cannot resolve $ep"; return 1; }
  ip tunnel add "$tun" mode "$TUN_MODE" remote "$first" local "$LOCAL_IP" ttl 255 || return 1
  ip addr add "$cidr" dev "$tun" 2>/dev/null || true
  ip link set "$tun" up || true
  sysctl -w "net.ipv4.conf.${tun}.rp_filter=0" >/dev/null || true
  echo "[MONITOR] recreated $tun → remote=$first cidr=$cidr mode=$TUN_MODE"
  return 0
}

ensure_addr_up(){ ip addr show dev "$1" | grep -q " ${2//\//\\/} " || ip addr add "$2" dev "$1"; ip link set "$1" up || true; }

while true; do
  for i in "${!REMOTE_ENDPOINTS[@]}"; do
    TUN="${TUN_PREFIX}$((i+1))"; EP="${REMOTE_ENDPOINTS[$i]}"; CIDR="${INTERNAL_TUNNEL_IPS[$i]}"

    ensure_tun_present "$TUN" "$EP" "$CIDR" || { sleep "$INTERVAL"; continue; }
    ensure_addr_up "$TUN" "$CIDR"

    if ! is_valid_ip "$EP"; then
      NEW_SET="$(resolve_all "$EP" || true)"
      CUR_REMOTE="$(ip -d tunnel show "$TUN" 2>/dev/null | awk '/remote/ {print $4; exit}')"
      if [[ -n "$NEW_SET" ]] && ! grep -qw "$CUR_REMOTE" <<<"$NEW_SET"; then
        NEW_REMOTE="$(awk '{print $1; exit}' <<<"$NEW_SET")"
        echo "[MONITOR] $TUN remote changed for $EP: $CUR_REMOTE -> $NEW_REMOTE (rebuild)"
        ip link set "$TUN" down 2>/dev/null || true
        ip tunnel del "$TUN" 2>/dev/null || true
        ip tunnel add "$TUN" mode "$TUN_MODE" remote "$NEW_REMOTE" local "$LOCAL_IP" ttl 255
        ensure_addr_up "$TUN" "$CIDR"
        sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
      fi
    fi

    LOCAL_INNER="${CIDR%%/*}"; BASE="$(echo "$LOCAL_INNER" | cut -d'.' -f1-3)"; HOST="$(echo "$LOCAL_INNER" | cut -d'.' -f4)"
    if [[ "$HOST" == "$LOCAL_IP_SUFFIX" ]]; then PEER="$BASE.$GATEWAY_IP_SUFFIX"; else PEER="$BASE.$LOCAL_IP_SUFFIX"; fi
    if ! ping -c "$THRESHOLD" -W 2 "$PEER" &>/dev/null; then
      echo "[MONITOR] $TUN ping $PEER failed → bounce"
      ip link set "$TUN" down 2>/dev/null || true
      ip link set "$TUN" up   2>/dev/null || true
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
Description=Keep GRE/IPIP tunnels alive (DNS + Health; auto-recreate)
After=tunnel-persistence.service
Wants=tunnel-persistence.service
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

apply_tcp_settings(){ cat > /etc/sysctl.conf <<'EOF'
# ---- High-Concurrency TCP Profile (BBR + FQ) ----
vm.swappiness = 1
vm.min_free_kbytes = 65536
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
vm.vfs_cache_pressure = 50
fs.file-max = 2097152
net.core.default_qdisc = fq
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.optmem_max = 65536
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.ip_local_port_range = 10000 65000
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
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096
EOF
}

apply_udp_settings(){ cat > /etc/sysctl.conf <<'EOF'
# ---- High-Concurrency UDP/QUIC + Mixed Profile ----
vm.swappiness = 1
vm.min_free_kbytes = 65536
vm.dirty_ratio = 5
vm.dirty_background_ratio = 2
vm.vfs_cache_pressure = 50
fs.file-max = 2097152
net.core.default_qdisc = fq
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.optmem_max = 131072
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_local_port_range = 10000 65000
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
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096
EOF
}

run_optimizer(){
  info "------------- Kernel Optimization Wizard -------------"
  read -r -p "Do you want to optimize server kernel settings now? (y/N): " ok
  [[ $ok =~ ^[Yy]$ ]] || { info "Skipping kernel optimization."; return; }
  echo; info "Select profile:"; echo "  1) TCP Profile"; echo "  2) UDP Profile"; echo
  local c; while true; do read -p "Enter your choice [1 or 2]: " c; [[ $c =~ ^[12]$ ]] && break || warn "Enter 1 or 2."; done
  read -p "This will OVERWRITE /etc/sysctl.conf. Are you sure? [y/N]: " y; [[ $y =~ ^[Yy]$ ]] || { info "Cancelled."; return; }
  info "Backup -> /etc/sysctl.conf.bak.$(date +%F)"; cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F) 2>/dev/null || true
  [[ $c -eq 1 ]] && apply_tcp_settings || apply_udp_settings
  info "Applying sysctl..."; sysctl -p && success "Kernel settings applied." || error "Failed to apply sysctl."
  read -p "Reboot now? [y/N]: " rb; [[ $rb =~ ^[Yy]$ ]] && { info "Rebooting..."; reboot; } || warn "Reboot later to fully apply."
}

delete_all_tunnels(){
  warn "This removes ALL tunnels, config & services created by this tool."
  read -r -p "Really continue? (y/N): " c; [[ $c =~ ^[Yy]$ ]] || { info "Aborted."; return; }
  systemctl stop tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  systemctl disable tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  remove_rules_from_config
  remove_tunnel_masquerade_best_effort
  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" "$CONFIG_FILE"
  systemctl daemon-reload
  ip -o link show type gre  | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r t; do [[ -n $t ]] && ip link delete "$t" && echo "  - $t removed."; done
  ip -o link show type ipip | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r t; do [[ -n $t ]] && ip link delete "$t" && echo "  - $t removed."; done
  warn "Kernel /etc/sysctl.conf NOT reverted. Backups in /etc/sysctl.conf.bak.YYYY-MM-DD"
  success "Cleanup complete."
}

main_menu(){
  clear; echo "--------- Tunnel Manager (GRE/IPIP) ---------"
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
