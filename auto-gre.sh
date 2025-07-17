#!/usr/bin/env bash
# ------------------------------------------------------------------
#  Universal GRE Tunnel Manager (Refactored)
#  Author  : Ali Samani – 2025
#  License : MIT
# ------------------------------------------------------------------

set -Eeuo pipefail
SCRIPT_START=$(date +%s)

# ---------- Constants ---------------------------------------------------------
CONFIG_FILE="/etc/gre-tunnels.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/gre-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/gre-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/gre-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/gre-monitor.service"
PING_INTERVAL=10            # seconds
MONITOR_FAIL_THRESHOLD=3     # pings

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

prompt_default() { # $1=question  $2=default
  local ans
  read -r -p "$1 [$2]: " ans
  echo "${ans:-$2}"
}

# ---------- Core functions ----------------------------------------------------
create_new_tunnels() {
  clear
  info "------------- GRE Tunnel Configuration Wizard -------------"

  # 1️⃣ Location
  local location_choice
  location_choice=$(prompt_default "Choose server location (1=Iran, 2=Abroad)" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "Invalid choice. Defaulting to Abroad."; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "Server location set. Internal IPs will end with .$LOCAL_IP_SUFFIX"

  # 2️⃣ Delete existing tunnels / flush FW?
  local delete_choice flush_choice
  delete_choice=$(prompt_default "Delete existing GRE tunnels first? (1=Yes,2=No)" "1")
  flush_choice=$(prompt_default "Flush ALL firewall rules? (1=Yes,2=No)" "1")

  # 3️⃣ Select network interface
  mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
  echo "--------------------------------------------------"
  for i in "${!INTERFACES[@]}"; do echo " $((i+1))) ${INTERFACES[$i]}"; done
  echo "--------------------------------------------------"

  local iface_choice MAIN_INTERFACE
  while true; do
    iface_choice=$(prompt_default "Select main interface" "1")
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && ((iface_choice>=1 && iface_choice<=${#INTERFACES[@]})); then
      MAIN_INTERFACE=${INTERFACES[$((iface_choice-1))]}
      break
    else warn "Invalid option. Try again."; fi
  done
  success "Interface '$MAIN_INTERFACE' selected."

  # 4️⃣ Enter remote IPs
  info "Enter destination server IPs (blank line to finish):"
  REMOTE_IPS=()
  while :; do
    read -r -p "Remote IP: " ip
    [[ -z $ip ]] && break
    if is_valid_ip "$ip"; then REMOTE_IPS+=("$ip"); else warn "Invalid IP, ignored."; fi
  done
  (( ${#REMOTE_IPS[@]} )) || { error "No valid IPs supplied."; return; }

  # 5️⃣ Internal IP mode
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(prompt_default "Assign internal IPs (1=auto, 2=manual)" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "Internal IP assignment mode: $TUNNEL_IP_MODE"

  # ---------- Cleanup (optional) ----------------
  if [[ $delete_choice != 2 ]]; then
    info "Deleting existing GRE tunnels..."
    ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r tun; do
      [[ -n $tun ]] && ip link delete "$tun" && echo "  - $tun removed."
    done
  fi

  if [[ $flush_choice != 2 ]]; then
    info "Flushing iptables rules..."
    iptables -F; iptables -t nat -F; iptables -t mangle -F
    iptables -X; iptables -t nat -X; iptables -t mangle -X
    nft list tables &>/dev/null && nft flush ruleset || true
  fi

  # ---------- Basic net config ---------------
  info "Enabling IP forwarding and NAT..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE

  nft list tables &>/dev/null && {
    nft list table ip nat &>/dev/null || nft add table ip nat
    nft list chain ip nat postrouting &>/dev/null || nft add chain ip nat postrouting '{ type nat hook postrouting priority 100 ; }'
    nft insert rule ip nat postrouting oifname "$MAIN_INTERFACE" masquerade
  } || true
  success "IP forwarding & NAT configured."

  LOCAL_IP=$(curl -4 -s icanhazip.com || true)
  [[ -z $LOCAL_IP ]] && { error "Couldn't auto-detect public IP"; exit 1; }
  success "Public IP detected: $LOCAL_IP"

  # ---------- Save base config ---------------
  info "Saving base config → $CONFIG_FILE"
  cat > "$CONFIG_FILE" <<EOF
MAIN_INTERFACE="$MAIN_INTERFACE"
LOCAL_IP="$LOCAL_IP"
LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX
GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX
REMOTE_IPS=(${REMOTE_IPS[*]})
EOF

  # ---------- Create tunnels -----------------
  INTERNAL_TUNNEL_IPS=()
  info "Creating tunnels..."
  for idx in "${!REMOTE_IPS[@]}"; do
    local REMOTE="${REMOTE_IPS[$idx]}"
    local TUN="gre$((idx+1))"
    local SUBNET_BASE=$(( (idx+1) * 10 ))
    local TUN_IP

    if [[ $TUNNEL_IP_MODE == manual ]]; then
      read -r -p "Internal IP for tunnel $TUN → $REMOTE (e.g. ${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24): " TUN_IP
      is_valid_ip "${TUN_IP%%/*}" || { warn "Invalid IP, using auto."; TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    ip link show "$TUN" &>/dev/null || ip tunnel add "$TUN" mode gre remote "$REMOTE" local "$LOCAL_IP" ttl 255
    ip addr show dev "$TUN" | grep -q "$TUN_IP" || ip addr add "$TUN_IP" dev "$TUN"
    ip link set "$TUN" up
    echo "  • $TUN ↔ $REMOTE  [$TUN_IP]"
  done
  echo "INTERNAL_TUNNEL_IPS=(${INTERNAL_TUNNEL_IPS[*]})" >> "$CONFIG_FILE"

  # ---------- Create services ----------------
  create_persistence_service
  create_monitor_service

  systemctl daemon-reload
  systemctl enable --now gre-persistence.service gre-monitor.service

  success "All done! Total time: $(( $(date +%s) - SCRIPT_START )) s"
  info    "Reboot is NOT required, tunnels are live now."
}

create_persistence_service() {
  info "Building persistence service..."
  cat > "$PERSISTENCE_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /etc/gre-tunnels.conf ]] || exit 0
source /etc/gre-tunnels.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE

for i in "${!REMOTE_IPS[@]}"; do
  TUN="gre$((i+1))"
  ip link show "$TUN" &>/dev/null || ip tunnel add "$TUN" mode gre remote "${REMOTE_IPS[$i]}" local "$LOCAL_IP" ttl 255
  ip addr show dev "$TUN" | grep -q "${INTERNAL_TUNNEL_IPS[$i]}" || ip addr add "${INTERNAL_TUNNEL_IPS[$i]}" dev "$TUN"
  ip link set "$TUN" up
done
BASH
  chmod +x "$PERSISTENCE_SCRIPT"

  cat > "$PERSISTENCE_SERVICE" <<EOF
[Unit]
Description=Restore GRE tunnels at boot
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
source /etc/gre-tunnels.conf
INTERVAL=${PING_INTERVAL:-10}
THRESHOLD=${MONITOR_FAIL_THRESHOLD:-3}

while true; do
  for i in "${!REMOTE_IPS[@]}"; do
    SUBNET="$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1 | cut -d'.' -f1-3)"
    GW="${SUBNET}.${GATEWAY_IP_SUFFIX}"
    if ! ping -c "$THRESHOLD" -W 2 "$GW" &>/dev/null; then
      TUN="gre$((i+1))"
      ip link set "$TUN" down || true
      ip link set "$TUN" up   || true
    fi
  done
  sleep "$INTERVAL"
done
BASH
  chmod +x "$MONITOR_SCRIPT"

  cat > "$MONITOR_SERVICE" <<EOF
[Unit]
Description=Keep GRE tunnels alive
After=gre-persistence.service
Wants=gre-persistence.service
ConditionPathExists=$CONFIG_FILE

[Service]
ExecStart=$MONITOR_SCRIPT
Restart=always
RestartSec=$PING_INTERVAL

[Install]
WantedBy=multi-user.target
EOF
  success "Monitor unit created."
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
    [[ -n $tun ]] && ip link delete "$tun" && echo "  - $tun removed."
  done

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
