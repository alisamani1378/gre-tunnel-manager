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
  location_choice=$(prompt_default "مکان سرور را انتخاب کنید (1=ایران, 2=خارج)" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "انتخاب نامعتبر. پیش‌فرض خارج در نظر گرفته شد."; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "مکان سرور تنظیم شد. IP داخلی با .$LOCAL_IP_SUFFIX پایان می‌یابد"

  # 2️⃣ Delete existing tunnels / flush FW?
  local delete_choice flush_choice
  delete_choice=$(prompt_default "تونل‌های GRE قبلی حذف شوند؟ (1=بله, 2=خیر)" "1")
  flush_choice=$(prompt_default "تمام قوانین فایروال پاک شوند؟ (1=بله, 2=خیر)" "1")

  # 3️⃣ Select network interface
  mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
  echo "--------------------------------------------------"
  for i in "${!INTERFACES[@]}"; do echo " $((i+1))) ${INTERFACES[$i]}"; done
  echo "--------------------------------------------------"

  local iface_choice MAIN_INTERFACE
  while true; do
    iface_choice=$(prompt_default "اینترفیس اصلی شبکه را انتخاب کنید" "1")
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && ((iface_choice>=1 && iface_choice<=${#INTERFACES[@]})); then
      MAIN_INTERFACE=${INTERFACES[$((iface_choice-1))]}
      break
    else warn "گزینه نامعتبر است. دوباره تلاش کنید."; fi
  done
  success "اینترفیس '$MAIN_INTERFACE' انتخاب شد."

  # 4️⃣ Enter remote IPs
  info "IP سرورهای مقصد را وارد کنید (برای پایان خط خالی):"
  REMOTE_IPS=()
  while :; do
    read -r -p "IP ریموت: " ip
    [[ -z $ip ]] && break
    if is_valid_ip "$ip"; then REMOTE_IPS+=("$ip"); else warn "IP نامعتبر، نادیده گرفته شد."; fi
  done
  (( ${#REMOTE_IPS[@]} )) || { error "هیچ IP معتبری وارد نشد."; return; }

  # 5️⃣ Internal IP mode
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(prompt_default "نحوه تخصیص IP داخلی (1=خودکار, 2=دستی)" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "حالت تخصیص IP داخلی: $TUNNEL_IP_MODE"

  # ---------- Cleanup (optional) ----------------
  if [[ $delete_choice != 2 ]]; then
    info "در حال حذف تونل‌های GRE موجود..."
    ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r tun; do
      [[ -n $tun ]] && sudo ip link delete "$tun" && echo "  - $tun حذف شد."
    done
  fi

  if [[ $flush_choice != 2 ]]; then
    info "در حال پاکسازی قوانین iptables..."
    sudo iptables -F; sudo iptables -t nat -F; sudo iptables -t mangle -F
    sudo iptables -X; sudo iptables -t nat -X; sudo iptables -t mangle -X
  fi

  # ---------- Basic net config ---------------
  info "در حال فعال‌سازی IP forwarding و NAT..."
  sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sudo iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null \
    || sudo iptables -t nat -A POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE
  success "IP forwarding و NAT تنظیم شد."

  LOCAL_IP=$(curl -4 -s icanhazip.com || true)
  [[ -z $LOCAL_IP ]] && { error "شناسایی IP پابلیک ممکن نبود"; exit 1; }
  success "IP پابلیک شناسایی شد: $LOCAL_IP"

  # ---------- Create tunnels -----------------
  INTERNAL_TUNNEL_IPS=()
  info "در حال ساخت تونل‌ها..."
  for idx in "${!REMOTE_IPS[@]}"; do
    local REMOTE="${REMOTE_IPS[$idx]}"
    local TUN="gre$((idx+1))"
    local SUBNET_BASE=$(( (idx+1) * 10 ))
    local TUN_IP

    if [[ $TUNNEL_IP_MODE == manual ]]; then
      read -r -p "IP داخلی برای تونل $TUN → $REMOTE (مثال: ${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24): " TUN_IP
      is_valid_ip "${TUN_IP%%/*}" || { warn "IP نامعتبر، از حالت خودکار استفاده می‌شود."; TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.$LOCAL_IP_SUFFIX/24"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    sudo ip link show "$TUN" &>/dev/null || sudo ip tunnel add "$TUN" mode gre remote "$REMOTE" local "$LOCAL_IP" ttl 255
    sudo ip addr show dev "$TUN" | grep -q "$TUN_IP" || sudo ip addr add "$TUN_IP" dev "$TUN"
    sudo ip link set "$TUN" up
    echo "  • $TUN ↔ $REMOTE  [$TUN_IP]"
  done

  # ---------- Port Forwarding Setup (New) ----------------
  declare -a FORWARDING_RULES
  if [[ "$location_choice" == "1" ]]; then
      info "------------- تنظیمات Port Forwarding -------------"
      for i in "${!REMOTE_IPS[@]}"; do
          while true; do
              read -r -p "برای تونل به مقصد ${REMOTE_IPS[$i]} قانون Port Forwarding اضافه شود؟ (y/n): " add_forward
              [[ $add_forward =~ ^[Yy]$ ]] || break

              read -r -p "  پورت مورد نظر برای فوروارد (مثال: 8080): " PORT
              read -r -p "  پروتکل (tcp/udp): " PROTOCOL

              DEST_IP=$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1)
              SOURCE_IP_BASE=$(echo "$DEST_IP" | cut -d'.' -f1-3)
              SOURCE_IP="${SOURCE_IP_BASE}.${LOCAL_IP_SUFFIX}"
              
              PREROUTING_RULE="iptables -t nat -A PREROUTING -p $PROTOCOL --dport $PORT -j DNAT --to-destination ${DEST_IP}:${PORT}"
              POSTROUTING_RULE="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $PORT -j SNAT --to-source $SOURCE_IP"
              
              info "  در حال اعمال قانون: $PREROUTING_RULE"
              eval "$PREROUTING_RULE"
              info "  در حال اعمال قانون: $POSTROUTING_RULE"
              eval "$POSTROUTING_RULE"

              FORWARDING_RULES+=("$PREROUTING_RULE" "$POSTROUTING_RULE")
              success "قانون فوروارد برای پورت $PORT/$PROTOCOL اضافه شد."
          done
      done
  fi
  
  # ---------- Save config ---------------
  info "در حال ذخیره تنظیمات → $CONFIG_FILE"
  {
    echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
    echo "LOCAL_IP=\"$LOCAL_IP\""
    echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
    echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
    echo "REMOTE_IPS=(${REMOTE_IPS[*]})"
    echo "INTERNAL_TUNNEL_IPS=(${INTERNAL_TUNNEL_IPS[*]})"
    # Save forwarding rules safely
    printf "FORWARDING_RULES=("
    for rule in "${FORWARDING_RULES[@]}"; do printf "%q " "$rule"; done
    printf ")\n"
  } > "$CONFIG_FILE"


  # ---------- Create services ----------------
  create_persistence_service
  create_monitor_service

  sudo systemctl daemon-reload
  sudo systemctl enable --now gre-persistence.service gre-monitor.service

  success "پایان یافت! زمان کل: $(( $(date +%s) - SCRIPT_START )) ثانیه"
  info    "نیازی به ریبوت نیست، تونل‌ها فعال هستند."
}

create_persistence_service() {
  info "در حال ساخت سرویس پایداری..."
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

# Restore custom port forwarding rules
for rule in "${FORWARDING_RULES[@]}"; do
    eval "$rule"
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
  success "سرویس پایداری ایجاد شد."
}

create_monitor_service() {
  info "در حال ساخت سرویس نظارت..."
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
  success "سرویس نظارت ایجاد شد."
}

delete_all_tunnels() {
  warn "این عملیات تمام تونل‌ها، تنظیمات و سرویس‌های مرتبط را حذف می‌کند."
  read -r -p "آیا مطمئن هستید؟ (y/N): " confirm
  [[ $confirm =~ ^[Yy]$ ]] || { info "عملیات لغو شد."; return; }

  sudo systemctl stop gre-monitor.service gre-persistence.service 2>/dev/null || true
  sudo systemctl disable gre-monitor.service gre-persistence.service 2>/dev/null || true
  sudo rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" "$CONFIG_FILE"
  sudo systemctl daemon-reload

  ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1 | while read -r tun; do
    [[ -n $tun ]] && sudo ip link delete "$tun" && echo "  - $tun حذف شد."
  done

  success "پاکسازی کامل شد."
}

main_menu() {
  clear
  echo "--------- GRE Tunnel Manager ---------"
  echo " 1) ساخت / تنظیم مجدد تونل‌ها"
  echo " 2) حذف تمام تونل‌ها و سرویس‌ها"
  echo " 3) خروج"
  read -r -p "گزینه را انتخاب کنید: " choice
  case $choice in
    1) create_new_tunnels ;;
    2) delete_all_tunnels ;;
    3) exit 0 ;;
    *) error "گزینه نامعتبر."; exit 1 ;;
  esac
}

main_menu
