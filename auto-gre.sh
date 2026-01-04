#!/usr/bin/env bash
# ------------------------------------------------------------------
#  Universal Tunnel Manager (GRE or IPIP) + Domain-aware + Monitors
#  Author  : Ali Samani – 2025
#  Fixed   : Solved 'gre0 file exists' crash on boot
#  License : MIT
# ------------------------------------------------------------------

set -Eeuo pipefail
SCRIPT_START=$(date +%s)

# ---------- Constants ---------------------------------------------------------
CONFIG_FILE="/etc/tunnel-manager.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/tunnel-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/tunnel-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/tunnel-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/tunnel-monitor.service"

PING_INTERVAL=10            # seconds
MONITOR_FAIL_THRESHOLD=3    # pings
TMGR_COMMENT="TMGR"         # comment tag for firewall rules

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

detect_iface_ip() { # $1=iface -> first global v4
  ip -4 addr show dev "$1" scope global 2>/dev/null \
    | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

detect_src_ip_for_remote() { # $1=remote_ip $2=main_iface
  local remote="$1" iface="$2" src=""
  src="$(ip -4 route get "$remote" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  if [[ -z "$src" ]]; then
    src="$(detect_iface_ip "$iface" || true)"
  fi
  is_valid_ip "${src:-}" && echo "$src" || return 1
}

# ---------- iptables helpers (nft/legacy aware) -------------------------------
_use_legacy() { command -v iptables-legacy >/dev/null 2>&1; }

_eval_on_iptables_variants(){
  local cmd="$1"
  eval "$cmd" 2>/dev/null || true
  if _use_legacy; then
    local legacy_cmd="${cmd/iptables /iptables-legacy }"
    eval "$legacy_cmd" 2>/dev/null || true
  fi
}

ipt_apply_once(){
  local add="$1"
  local chk="${add/ -A / -C }"
  _eval_on_iptables_variants "$chk" || _eval_on_iptables_variants "$add"
}

cleanup_tmgr_rules(){
  info "Removing firewall rules tagged with comment '$TMGR_COMMENT'..."
  local tbl line
  for tbl in nat filter mangle raw; do
    {
      iptables -t "$tbl" -S 2>/dev/null || true
      if _use_legacy; then iptables-legacy -t "$tbl" -S 2>/dev/null || true; fi
    } | awk -v tag="$TMGR_COMMENT" '$0 ~ ("-m comment --comment " tag) && $0 ~ /^-A /{sub(/^-A /,"-D "); print}' \
      | while IFS= read -r line; do
          [[ -n "$line" ]] || continue
          _eval_on_iptables_variants "iptables -t $tbl $line"
        done
  done
  success "Tagged rules removed (if any)."
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
      info "Removing previously configured MASQUERADE rules from $CONFIG_FILE..."
      had=1
    fi
    for r in "${MASQUERADE_RULES[@]}"; do
      [[ -n "$r" ]] || continue
      local del="${r/ -A / -D }"
      [[ "$del" == iptables* ]] || del="iptables ${del}"
      _eval_on_iptables_variants "$del"
    done
  fi

  if declare -p FORWARDING_RULES >/dev/null 2>&1; then
    ((had==0 && ${#FORWARDING_RULES[@]} > 0)) && { info "Removing previously configured forwarding rules from $CONFIG_FILE..."; had=1; }
    for r in "${FORWARDING_RULES[@]}"; do
      [[ -n "$r" ]] || continue
      local del="${r/ -A / -D }"
      [[ "$del" == iptables* ]] || del="iptables ${del}"
      _eval_on_iptables_variants "$del"
    done
  fi

  [[ $had -eq 1 ]] && success "Old rules removed (if present)."
}

remove_tunnel_masquerade_best_effort(){
  info "Scanning for stray MASQUERADE rules on gre* / ipip*..."
  local line
  {
    iptables -t nat -S POSTROUTING 2>/dev/null || true
    if _use_legacy; then iptables-legacy -t nat -S POSTROUTING 2>/dev/null || true; fi
  } | awk '/^-A POSTROUTING/ && /-o (gre|ipip)[0-9]+/ && /-j MASQUERADE/' \
    | while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        local del="${line/-A /-D }"
        _eval_on_iptables_variants "iptables -t nat $del"
      done
  success "Stray MASQUERADE cleanup attempted."
}

flush_all_tables(){
  warn "Flushing ALL iptables tables (filter/nat/mangle/raw/security)... this is DANGEROUS on production."
  local tbl
  for tbl in filter nat mangle raw security; do
    iptables -t "$tbl" -F 2>/dev/null || true
    iptables -t "$tbl" -X 2>/dev/null || true
  done
  if _use_legacy; then
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

# ---------- Tunnel helpers ----------------------------------------------------
safe_delete_tunnel_name(){
  local t="$1"
  [[ -z "$t" ]] && return 0
  [[ "$t" == "gre0" || "$t" == "ipip0" ]] && return 0
  ip link set "$t" down 2>/dev/null || true
  ip link delete "$t" 2>/dev/null || true
}

delete_existing_tunnels_all_types(){
  info "Deleting existing tunnels (both GRE and IPIP) except gre0/ipip0..."
  ip -o link show type gre  2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 \
    | while read -r t; do [[ -n $t ]] && safe_delete_tunnel_name "$t" && echo "  - $t removed."; done
  ip -o link show type ipip 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 \
    | while read -r t; do [[ -n $t ]] && safe_delete_tunnel_name "$t" && echo "  - $t removed."; done
}

tunnel_needs_rebuild(){
  # returns 0 if needs rebuild, 1 if OK
  local tun="$1" mode="$2" local_ip="$3" remote_ip="$4"
  local d
  d="$(ip -d tunnel show "$tun" 2>/dev/null || true)"
  [[ -z "$d" ]] && return 0
  [[ "$d" != *" local $local_ip "* ]] && return 0
  [[ "$d" != *" remote $remote_ip "* ]] && return 0
  return 1
}

ensure_tunnel(){
  local tun="$1" mode="$2" local_ip="$3" remote_ip="$4" cidr="$5"

  [[ -z "$tun" ]] && { error "Internal bug: empty tunnel name"; return 1; }
  [[ -z "$local_ip" || -z "$remote_ip" ]] && { error "Empty local/remote for $tun (local='$local_ip' remote='$remote_ip')"; return 1; }

  if ip link show "$tun" &>/dev/null; then
    if tunnel_needs_rebuild "$tun" "$mode" "$local_ip" "$remote_ip"; then
      warn "$tun exists but params differ -> rebuilding..."
      safe_delete_tunnel_name "$tun"
    fi
  fi

  if ! ip link show "$tun" &>/dev/null; then
    ip tunnel add "$tun" mode "$mode" local "$local_ip" remote "$remote_ip" ttl 255
  fi

  ip addr replace "$cidr" dev "$tun"
  ip link set "$tun" up
  sysctl -w "net.ipv4.conf.${tun}.rp_filter=0" >/dev/null || true
  return 0
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
    1) TUN_MODE="gre";  TUN_PREFIX="gre"  ;;
    2) TUN_MODE="ipip"; TUN_PREFIX="ipip" ;;
    *) warn "Invalid choice. Defaulting to GRE."; TUN_MODE="gre"; TUN_PREFIX="gre" ;;
  esac
  success "Using mode: $TUN_MODE (interfaces like ${TUN_PREFIX}1, ${TUN_PREFIX}2, ...)"

  # 1) Location
  local location_choice
  location_choice=$(prompt_default "Choose server location (1=Iran, 2=Abroad)" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "Invalid choice. Defaulting to Abroad."; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "Internal IPs will end with .$LOCAL_IP_SUFFIX"

  # 2) Cleanup options
  local flush_choice delete_choice
  flush_choice=$(prompt_default "Full flush firewall & services? (1=yes, 2=no)" "2")
  delete_choice=$(prompt_default "Delete existing tunnels? (1=yes, 2=no)" "1")

  if [[ "$flush_choice" == "1" ]]; then
    remove_services_and_config
    delete_existing_tunnels_all_types
    flush_all_tables
  elif [[ "$delete_choice" == "1" ]]; then
    delete_existing_tunnels_all_types
    remove_rules_from_config
    cleanup_tmgr_rules
    remove_tunnel_masquerade_best_effort
  else
    info "Skipping cleanup: no firewall or tunnel changes will be made."
  fi

  # 3) Main interface
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
    else
      warn "Invalid option. Try again."
    fi
  done
  success "Interface '$MAIN_INTERFACE' selected."

  info "Enabling IP forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # 4) Remote endpoints
  info "Enter remote endpoints (domain or IPv4). Blank to finish:"
  REMOTE_ENDPOINTS=()
  while :; do
    read -r -p "Remote endpoint: " ep
    [[ -z $ep ]] && break
    if is_valid_ip "$ep" || is_valid_hostname "$ep"; then
      REMOTE_ENDPOINTS+=("$ep")
    else
      warn "Invalid endpoint, ignored."
    fi
  done
  (( ${#REMOTE_ENDPOINTS[@]} )) || { error "No endpoints supplied."; return; }

  # 5) Internal IP mode
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(prompt_default "Assign internal IPs (1=auto, 2=manual)" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "Internal IP assignment mode: $TUNNEL_IP_MODE"

  # Create tunnels
  INTERNAL_TUNNEL_IPS=()
  RESOLVED_REMOTE_IPS=()

  info "Creating tunnels..."
  for idx in "${!REMOTE_ENDPOINTS[@]}"; do
    local ENDPOINT="${REMOTE_ENDPOINTS[$idx]}"
    local RESOLVED_REMOTE
    if ! RESOLVED_REMOTE=$(resolve_remote_once "$ENDPOINT"); then
      warn "Cannot resolve $ENDPOINT — skipping."
      continue
    fi
    RESOLVED_REMOTE_IPS+=("$RESOLVED_REMOTE")

    local TUN="${TUN_PREFIX}$((idx+1))"
    local SUBNET_BASE=$(( (idx+1) * 10 ))
    local TUN_IP

    if [[ $TUNNEL_IP_MODE == manual ]]; then
      read -r -p "Internal IP for $TUN → $ENDPOINT ($RESOLVED_REMOTE) (e.g. ${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30): " TUN_IP
      [[ "${TUN_IP}" == */* ]] || TUN_IP="${TUN_IP}/30"
      is_valid_ip "${TUN_IP%%/*}" || { warn "Invalid IP, using auto."; TUN_IP="${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    # IMPORTANT: choose correct local IP for THIS remote (prevents gre0 collision cases)
    local TUN_LOCAL_IP
    if ! TUN_LOCAL_IP="$(detect_src_ip_for_remote "$RESOLVED_REMOTE" "$MAIN_INTERFACE")"; then
      warn "Cannot determine src(local) IP for route to $RESOLVED_REMOTE. Skipping $TUN."
      continue
    fi

    ensure_tunnel "$TUN" "$TUN_MODE" "$TUN_LOCAL_IP" "$RESOLVED_REMOTE" "$TUN_IP" \
      || { warn "Failed to create $TUN. Skipping."; continue; }

    echo "  • $TUN ↔ $ENDPOINT ($RESOLVED_REMOTE)  [$TUN_IP]  [local=$TUN_LOCAL_IP]"
  done

  # NAT
  info "Configuring NAT..."
  declare -a MASQUERADE_RULES
  if [[ "$location_choice" == "1" ]]; then
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      TUN="${TUN_PREFIX}$((i+1))"
      rule="iptables -t nat -A POSTROUTING -o $TUN -m comment --comment $TMGR_COMMENT -j MASQUERADE"
      MASQUERADE_RULES+=("$rule"); ipt_apply_once "$rule"
    done
    success "NAT on ${TUN_MODE^^} tunnels."
  else
    rule="iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -m comment --comment $TMGR_COMMENT -j MASQUERADE"
    MASQUERADE_RULES+=("$rule"); ipt_apply_once "$rule"
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

        PR="iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p $PROTOCOL --dport $SRC_PORT -m comment --comment $TMGR_COMMENT -j DNAT --to-destination ${DEST_IP}:${DST_PORT}"
        PO="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $DST_PORT -m comment --comment $TMGR_COMMENT -j SNAT --to-source $SOURCE_IP"
        info "  Applying: $PR"; ipt_apply_once "$PR"
        info "  Applying: $PO"; ipt_apply_once "$PO"
        FORWARDING_RULES+=("$PR" "$PO")
        success "Forward added: $SRC_PORT → $DST_PORT/$PROTOCOL"
      done
    done
  fi

  # Save config
  info "Saving → $CONFIG_FILE"
  {
    echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
    echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
    echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
    echo "TUN_MODE=\"$TUN_MODE\""
    echo "TUN_PREFIX=\"$TUN_PREFIX\""
    printf "REMOTE_ENDPOINTS=("; for ep in "${REMOTE_ENDPOINTS[@]}"; do printf "%q " "$ep"; done; printf ")\n"
    printf "RESOLVED_REMOTE_IPS=("; for ipx in "${RESOLVED_REMOTE_IPS[@]}"; do printf "%q " "$ipx"; done; printf ")\n"
    printf "INTERNAL_TUNNEL_IPS=("; for tip in "${INTERNAL_TUNNEL_IPS[@]}"; do printf "%q " "$tip"; done; printf ")\n"
    printf "MASQUERADE_RULES=("; for r in "${MASQUERADE_RULES[@]}"; do printf "%q " "$r"; done; printf ")\n"
    printf "FORWARDING_RULES=("; for r in "${FORWARDING_RULES[@]}"; do printf "%q " "$r"; done; printf ")\n"
    echo "PING_INTERVAL=$PING_INTERVAL"
    echo "MONITOR_FAIL_THRESHOLD=$MONITOR_FAIL_THRESHOLD"
    echo "TMGR_COMMENT=\"$TMGR_COMMENT\""
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
# shellcheck disable=SC1090
source /etc/tunnel-manager.conf
set -u

is_valid_ip(){ [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
resolve_once(){ local t="$1"; is_valid_ip "$t" && { echo "$t"; return 0; }; getent ahostsv4 "$t" | awk '{print $1; exit}'; }

detect_iface_ip() {
  ip -4 addr show dev "$1" scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

detect_src_ip_for_remote() {
  local remote="$1" iface="$2" src=""
  src="$(ip -4 route get "$remote" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  [[ -z "$src" ]] && src="$(detect_iface_ip "$iface" || true)"
  is_valid_ip "${src:-}" && echo "$src" || return 1
}

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Restore NAT (idempotent)
if declare -p MASQUERADE_RULES >/dev/null 2>&1; then
  for cmd in "${MASQUERADE_RULES[@]}"; do
    chk="${cmd/ -A / -C }"
    eval "$chk" &>/dev/null || eval "$cmd"
  done
fi

# Re-create tunnels on boot (fresh resolve + correct local per remote)
for i in "${!REMOTE_ENDPOINTS[@]}"; do
  # Fallback for prefix
  PFX="${TUN_PREFIX:-gre}"
  TUN="${PFX}$((i+1))"
  
  # Safety check: Prevent messing with system gre0
  if [[ "$TUN" == "gre0" || "$TUN" == "ipip0" ]]; then
    echo "Skipping reserved tunnel name $TUN"
    continue
  fi

  EP="${REMOTE_ENDPOINTS[$i]}"
  CIDR="${INTERNAL_TUNNEL_IPS[$i]}"

  REM="$(resolve_once "$EP" || true)"
  [[ -z "$REM" ]] && { echo "[WARN] cannot resolve $EP"; continue; }

  LOC="$(detect_src_ip_for_remote "$REM" "$MAIN_INTERFACE" || true)"
  [[ -z "$LOC" ]] && { echo "[WARN] cannot determine local src for $REM"; continue; }

  # FORCE clean slate
  ip link set "$TUN" down 2>/dev/null || true
  ip link delete "$TUN" 2>/dev/null || true
  sleep 0.2

  if ! ip tunnel add "$TUN" mode "$TUN_MODE" remote "$REM" local "$LOC" ttl 255 2>/dev/null; then
     # Try again without stderr to capture existing? No, just ensure it's up.
     echo "Tunnel add failed for $TUN, checking if exists..."
  fi
  
  # Ensure IP and UP
  ip addr replace "$CIDR" dev "$TUN" 2>/dev/null || true
  ip link set "$TUN" up 2>/dev/null || true
  sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
done

# Restore custom forwards
if declare -p FORWARDING_RULES >/dev/null 2>&1; then
  for r in "${FORWARDING_RULES[@]}"; do
    chk="${r/ -A / -C }"
    eval "$chk" &>/dev/null || eval "$r"
  done
fi
BASH
  chmod +x "$PERSISTENCE_SCRIPT"

  cat > "$PERSISTENCE_SERVICE" <<EOF
[Unit]
Description=Restore GRE/IPIP tunnels at boot (domain-aware; local per remote)
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
# shellcheck disable=SC1090
source /etc/tunnel-manager.conf

INTERVAL=${PING_INTERVAL:-10}
THRESHOLD=${MONITOR_FAIL_THRESHOLD:-3}

is_valid_ip(){ [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

resolve_all(){
  local t="$1"
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  local ips
  ips=$(getent ahostsv4 "$t" | awk '{print $1}' | awk '!seen[$0]++') || true
  [[ -n $ips ]] && echo "$ips" || return 1
}

detect_iface_ip() {
  ip -4 addr show dev "$1" scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

detect_src_ip_for_remote() {
  local remote="$1" iface="$2" src=""
  src="$(ip -4 route get "$remote" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  [[ -z "$src" ]] && src="$(detect_iface_ip "$iface" || true)"
  is_valid_ip "${src:-}" && echo "$src" || return 1
}

ensure_tun_present(){ # $1=tun $2=endpoint $3=cidr
  local tun="$1" ep="$2" cidr="$3" set first loc
  
  if [[ "$tun" == "gre0" || "$tun" == "ipip0" ]]; then return 1; fi

  ip link show "$tun" &>/dev/null && return 0

  set="$(resolve_all "$ep" || true)"
  first="$(awk '{print $1}' <<<"$set")"
  [[ -z "$first" ]] && { echo "[MONITOR] WARN: cannot resolve $ep"; return 1; }

  loc="$(detect_src_ip_for_remote "$first" "$MAIN_INTERFACE" || true)"
  [[ -z "$loc" ]] && { echo "[MONITOR] WARN: cannot determine local src for $first"; return 1; }

  ip tunnel add "$tun" mode "$TUN_MODE" remote "$first" local "$loc" ttl 255 || return 1
  ip addr replace "$cidr" dev "$tun" 2>/dev/null || true
  ip link set "$tun" up || true
  sysctl -w "net.ipv4.conf.${tun}.rp_filter=0" >/dev/null || true
  echo "[MONITOR] recreated $tun → remote=$first local=$loc cidr=$cidr mode=$TUN_MODE"
  return 0
}

ensure_addr_up(){
  ip addr replace "$2" dev "$1" 2>/dev/null || true
  ip link set "$1" up || true
}

BOUNCE_MAX=3
declare -A BOUNCE_CNT

while true; do
  for i in "${!REMOTE_ENDPOINTS[@]}"; do
    TUN="${TUN_PREFIX}$((i+1))"
    EP="${REMOTE_ENDPOINTS[$i]}"
    CIDR="${INTERNAL_TUNNEL_IPS[$i]}"

    ensure_tun_present "$TUN" "$EP" "$CIDR" || { sleep "$INTERVAL"; continue; }
    ensure_addr_up "$TUN" "$CIDR"

    # DNS change handling
    if ! is_valid_ip "$EP"; then
      NEW_SET="$(resolve_all "$EP" || true)"
      CUR_REMOTE="$(ip -d tunnel show "$TUN" 2>/dev/null | awk '/remote/ {for(i=1;i<=NF;i++) if($i=="remote"){print $(i+1); exit}}')"
      if [[ -n "$NEW_SET" ]] && ! grep -qw "$CUR_REMOTE" <<<"$NEW_SET"; then
        NEW_REMOTE="$(awk '{print $1; exit}' <<<"$NEW_SET")"
        NEW_LOC="$(detect_src_ip_for_remote "$NEW_REMOTE" "$MAIN_INTERFACE" || true)"
        echo "[MONITOR] $TUN remote changed for $EP: $CUR_REMOTE -> $NEW_REMOTE (rebuild)"
        ip link set "$TUN" down 2>/dev/null || true
        ip link delete "$TUN" 2>/dev/null || true
        [[ -n "$NEW_LOC" ]] || { echo "[MONITOR] WARN: cannot determine local src for $NEW_REMOTE"; continue; }
        ip tunnel add "$TUN" mode "$TUN_MODE" remote "$NEW_REMOTE" local "$NEW_LOC" ttl 255
        ensure_addr_up "$TUN" "$CIDR"
        sysctl -w "net.ipv4.conf.${TUN}.rp_filter=0" >/dev/null || true
      fi
    fi

    LOCAL_INNER="${CIDR%%/*}"
    BASE="$(echo "$LOCAL_INNER" | cut -d'.' -f1-3)"
    HOST="$(echo "$LOCAL_INNER" | cut -d'.' -f4)"
    if [[ "$HOST" == "$LOCAL_IP_SUFFIX" ]]; then PEER="$BASE.$GATEWAY_IP_SUFFIX"; else PEER="$BASE.$LOCAL_IP_SUFFIX"; fi

    if ! ping -c "$THRESHOLD" -W 3 "$PEER" &>/dev/null; then
      BOUNCE_CNT["$TUN"]=$(( ${BOUNCE_CNT["$TUN"]:-0} + 1 ))
      if (( ${BOUNCE_CNT["$TUN"]} <= BOUNCE_MAX )); then
        echo "[MONITOR] $TUN ping $PEER failed → bounce (${BOUNCE_CNT["$TUN"]}/$BOUNCE_MAX)"
        ip link set "$TUN" down 2>/dev/null || true
        ip link set "$TUN" up   2>/dev/null || true
        ip link show "$TUN" &>/dev/null || ensure_tun_present "$TUN" "$EP" "$CIDR"
        ping -c 1 -W 3 "$PEER" &>/dev/null || echo "[MONITOR] $TUN still failing to ping $PEER"
      else
        echo "[MONITOR] $TUN persistent failure; skipping more bounces for now."
      fi
    else
      BOUNCE_CNT["$TUN"]=0
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
  local c
  while true; do read -r -p "Enter your choice [1 or 2]: " c; [[ $c =~ ^[12]$ ]] && break || warn "Enter 1 or 2."; done
  read -r -p "This will OVERWRITE /etc/sysctl.conf. Are you sure? [y/N]: " y
  [[ $y =~ ^[Yy]$ ]] || { info "Cancelled."; return; }
  info "Backup -> /etc/sysctl.conf.bak.$(date +%F)"
  cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%F)" 2>/dev/null || true
  [[ $c -eq 1 ]] && apply_tcp_settings || apply_udp_settings
  info "Applying sysctl..."
  sysctl -p && success "Kernel settings applied." || error "Failed to apply sysctl."
  read -r -p "Reboot now? [y/N]: " rb
  [[ $rb =~ ^[Yy]$ ]] && { info "Rebooting..."; reboot; } || warn "Reboot later to fully apply."
}

delete_all_tunnels(){
  warn "This removes ALL tunnels, config & services created by this tool."
  read -r -p "Really continue? (y/N): " c
  [[ $c =~ ^[Yy]$ ]] || { info "Aborted."; return; }

  systemctl stop tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  systemctl disable tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true

  remove_rules_from_config
  cleanup_tmgr_rules
  remove_tunnel_masquerade_best_effort

  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" "$CONFIG_FILE"
  systemctl daemon-reload

  delete_existing_tunnels_all_types

  warn "Kernel /etc/sysctl.conf NOT reverted. Backups in /etc/sysctl.conf.bak.YYYY-MM-DD"
  success "Cleanup complete."
}

main_menu(){
  clear
  echo "--------- Tunnel Manager (GRE/IPIP) ---------"
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
