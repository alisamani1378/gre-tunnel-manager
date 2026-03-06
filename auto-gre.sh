#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  Universal Tunnel Manager v3.0 — GRE / IPIP                       ║
# ║  Author  : Ali Samani – 2025-2026                                  ║
# ║  GitHub  : github.com/alisamani1378/gre-tunnel-manager             ║
# ║  License : MIT                                                     ║
# ║  Fixed   : Solved 'gre0 file exists' crash on boot                 ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -Eeuo pipefail
SCRIPT_VERSION="3.0.0"
SCRIPT_START=$(date +%s)

# ─────────────────────────── Constants ───────────────────────────────
CONFIG_FILE="/etc/tunnel-manager.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/tunnel-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/tunnel-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/tunnel-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/tunnel-monitor.service"
LOG_FILE="/var/log/tunnel-manager.log"

PING_INTERVAL=10
MONITOR_FAIL_THRESHOLD=3
TMGR_COMMENT="TMGR"

# ─────────────────────────── Color Palette ───────────────────────────
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
UNDERLINE='\033[4m'

# Foreground
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'

# Bright
BRED='\033[1;31m'
BGREEN='\033[1;32m'
BYELLOW='\033[1;33m'
BBLUE='\033[1;34m'
BMAGENTA='\033[1;35m'
BCYAN='\033[1;36m'
BWHITE='\033[1;37m'

# Background
BG_BLACK='\033[40m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_BLUE='\033[44m'
BG_MAGENTA='\033[45m'
BG_CYAN='\033[46m'

# ─────────────────────────── Unicode Symbols ─────────────────────────
CHECK="✔"
CROSS="✘"
ARROW="➤"
BULLET="●"
DIAMOND="◆"
STAR="★"
GEAR="⚙"
SHIELD="🛡"
GLOBE="🌐"
ROCKET="🚀"
LINK="🔗"
FIRE="🔥"
WARN_ICON="⚠"
CLOCK="⏱"
PACKAGE="📦"
CHART="📊"

# ─────────────────────────── Terminal Size ───────────────────────────
TERM_COLS=$(tput cols 2>/dev/null || echo 80)
((TERM_COLS < 60)) && TERM_COLS=60

# ─────────────────────────── UI Functions ────────────────────────────

# Print a horizontal line
hr() {
  local char="${1:-─}" color="${2:-$DIM}"
  printf "${color}"
  printf '%*s' "$TERM_COLS" '' | tr ' ' "$char"
  printf "${NC}\n"
}

# Center-align text
center() {
  local text="$1" color="${2:-$NC}"
  local clean_text
  clean_text=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
  local pad=$(( (TERM_COLS - ${#clean_text}) / 2 ))
  ((pad < 0)) && pad=0
  printf "%${pad}s${color}%s${NC}\n" '' "$text"
}

# Box drawing
box_top()    { echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $((TERM_COLS-2))))╗${NC}"; }
box_bottom() { echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $((TERM_COLS-2))))╝${NC}"; }
box_sep()    { echo -e "${CYAN}╠$(printf '═%.0s' $(seq 1 $((TERM_COLS-2))))╣${NC}"; }
box_line() {
  local text="$1" color="${2:-$NC}"
  local clean_text
  clean_text=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
  local inner=$((TERM_COLS - 4))
  local pad=$((inner - ${#clean_text}))
  ((pad < 0)) && pad=0
  printf "${CYAN}║${NC} ${color}%s%${pad}s ${CYAN}║${NC}\n" "$text" ''
}

# Logging + Pretty messages
log() { echo "[$(date '+%F %T')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

info() {
  echo -e "  ${BCYAN}${ARROW}${NC} ${BOLD}$*${NC}"
  log "[INFO] $*"
}
success() {
  echo -e "  ${BGREEN}${CHECK}${NC} ${GREEN}$*${NC}"
  log "[OK]   $*"
}
warn() {
  echo -e "  ${BYELLOW}${WARN_ICON}${NC} ${YELLOW}$*${NC}"
  log "[WARN] $*"
}
error() {
  echo -e "  ${BRED}${CROSS}${NC} ${RED}${BOLD}$*${NC}" >&2
  log "[ERR]  $*"
}

# Progress spinner
spin() {
  local pid=$1 msg="${2:-Working...}"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  tput civis 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${BCYAN}${frames[$i]}${NC} ${DIM}%s${NC}" "$msg"
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.08
  done
  printf "\r%${TERM_COLS}s\r" ''
  tput cnorm 2>/dev/null || true
}

# Progress bar
progress_bar() {
  local current=$1 total=$2 label="${3:-Progress}"
  local pct=$(( current * 100 / total ))
  local filled=$(( current * 40 / total ))
  local empty=$(( 40 - filled ))
  local bar=""
  for ((i=0; i<filled; i++)); do bar+="█"; done
  for ((i=0; i<empty; i++)); do bar+="░"; done
  printf "\r  ${CYAN}%s${NC} ${BWHITE}[${BGREEN}%s${DIM}%s${BWHITE}]${NC} ${BOLD}%3d%%${NC}" \
    "$label" "${bar:0:$filled}" "${bar:$filled}" "$pct"
  ((current == total)) && echo
}

# Prompt with style
styled_prompt() {
  local msg="$1" default="$2" result
  echo -ne "  ${BMAGENTA}?${NC} ${BOLD}${msg}${NC} ${DIM}[${default}]${NC}: "
  read -r result
  echo "${result:-$default}"
}

styled_yn() {
  local msg="$1" default="${2:-n}" result
  echo -ne "  ${BMAGENTA}?${NC} ${BOLD}${msg}${NC} ${DIM}(y/N)${NC}: "
  read -r result
  result="${result:-$default}"
  [[ "$result" =~ ^[Yy]$ ]]
}

# Section header
section() {
  echo
  hr "─" "$CYAN"
  echo -e "  ${BWHITE}${GEAR} $*${NC}"
  hr "─" "$CYAN"
}

# ─────────────────────────── Banner ──────────────────────────────────
show_banner() {
  clear
  echo
  echo -e "${BCYAN}"
  cat << 'BANNER'
    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
       ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
       ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
BANNER
  echo -e "${NC}"

  echo -e "   ${BMAGENTA}███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗${NC}"
  echo -e "   ${BMAGENTA}████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗${NC}"
  echo -e "   ${BMAGENTA}██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝${NC}"
  echo -e "   ${BMAGENTA}██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗${NC}"
  echo -e "   ${BMAGENTA}██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║${NC}"
  echo -e "   ${BMAGENTA}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝${NC}"
  echo

  box_top
  box_line "${GLOBE} Universal GRE/IPIP Tunnel Manager" "$BWHITE"
  box_line "Version ${SCRIPT_VERSION} — $(date +%F)" "$DIM"
  box_line "Author: Ali Samani" "$DIM"
  box_sep
  box_line "${ROCKET} Fast ${BULLET} Persistent ${BULLET} Self-Healing" "$BGREEN"
  box_bottom
  echo
}

# ─────────────────────────── Root Check ──────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "\n  ${BRED}${CROSS} This script must be run as root (sudo).${NC}\n"
  exit 1
fi

# ─────────────────────────── Utilities ───────────────────────────────
is_valid_ip() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<< "$ip"
  for o in $a $b $c $d; do ((o <= 255)) || return 1; done
}

is_valid_hostname() {
  [[ $1 =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

resolve_remote_once() {
  local t="$1" ip=""
  if is_valid_ip "$t"; then echo "$t"; return 0; fi
  ip=$(getent ahostsv4 "$t" | awk '{print $1; exit}') || true
  [[ -n $ip ]] && echo "$ip" || return 1
}

detect_iface_ip() {
  ip -4 addr show dev "$1" scope global 2>/dev/null \
    | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

detect_src_ip_for_remote() {
  local remote="$1" iface="$2" src=""
  src="$(ip -4 route get "$remote" 2>/dev/null \
    | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  if [[ -z "$src" ]]; then
    src="$(detect_iface_ip "$iface" || true)"
  fi
  is_valid_ip "${src:-}" && echo "$src" || return 1
}

get_public_ip() {
  local ip=""
  ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null) || \
  ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null) || \
  ip=$(curl -s --max-time 5 https://icanhazip.com 2>/dev/null) || true
  echo "${ip:-N/A}"
}

# ─────────────────────────── System Info ─────────────────────────────
show_system_info() {
  local pub_ip hostname_str kernel_str uptime_str mem_str cpu_str
  pub_ip=$(get_public_ip)
  hostname_str=$(hostname 2>/dev/null || echo "unknown")
  kernel_str=$(uname -r 2>/dev/null || echo "unknown")
  uptime_str=$(uptime -p 2>/dev/null || echo "unknown")
  mem_str=$(free -h 2>/dev/null | awk '/Mem:/{printf "%s / %s", $3, $2}' || echo "N/A")
  cpu_str=$(nproc 2>/dev/null || echo "?")

  echo
  echo -e "  ${BWHITE}${CHART} System Overview${NC}"
  hr "·" "$DIM"
  printf "  ${CYAN}%-18s${NC} %s\n" "Hostname:"  "$hostname_str"
  printf "  ${CYAN}%-18s${NC} %s\n" "Kernel:"    "$kernel_str"
  printf "  ${CYAN}%-18s${NC} %s\n" "CPU Cores:"  "$cpu_str"
  printf "  ${CYAN}%-18s${NC} %s\n" "Uptime:"    "$uptime_str"
  printf "  ${CYAN}%-18s${NC} %s\n" "Memory:"    "$mem_str"
  printf "  ${CYAN}%-18s${NC} %s\n" "Public IP:" "$pub_ip"
  echo
}

# ─────────────────────────── iptables Helpers ────────────────────────
_use_legacy() { command -v iptables-legacy >/dev/null 2>&1; }

_eval_on_iptables_variants() {
  local cmd="$1"
  eval "$cmd" 2>/dev/null || true
  if _use_legacy; then
    local legacy_cmd="${cmd/iptables /iptables-legacy }"
    eval "$legacy_cmd" 2>/dev/null || true
  fi
}

ipt_apply_once() {
  local add="$1"
  local chk="${add/ -A / -C }"
  _eval_on_iptables_variants "$chk" || _eval_on_iptables_variants "$add"
}

cleanup_tmgr_rules() {
  info "Removing firewall rules tagged ${DIM}[${TMGR_COMMENT}]${NC}"
  local tbl line
  for tbl in nat filter mangle raw; do
    {
      iptables -t "$tbl" -S 2>/dev/null || true
      if _use_legacy; then iptables-legacy -t "$tbl" -S 2>/dev/null || true; fi
    } | awk -v tag="$TMGR_COMMENT" \
        '$0 ~ ("-m comment --comment " tag) && $0 ~ /^-A /{sub(/^-A /,"-D "); print}' \
      | while IFS= read -r line; do
          [[ -n "$line" ]] || continue
          _eval_on_iptables_variants "iptables -t $tbl $line"
        done
  done
  success "Tagged rules removed."
}

remove_rules_from_config() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  set +u
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set -u

  local had=0
  if declare -p MASQUERADE_RULES >/dev/null 2>&1; then
    if ((${#MASQUERADE_RULES[@]} > 0)); then
      info "Cleaning up previous MASQUERADE rules..."
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
    ((had == 0 && ${#FORWARDING_RULES[@]} > 0)) && { info "Cleaning up previous forwarding rules..."; had=1; }
    for r in "${FORWARDING_RULES[@]}"; do
      [[ -n "$r" ]] || continue
      local del="${r/ -A / -D }"
      [[ "$del" == iptables* ]] || del="iptables ${del}"
      _eval_on_iptables_variants "$del"
    done
  fi

  [[ $had -eq 1 ]] && success "Old rules removed."
}

remove_tunnel_masquerade_best_effort() {
  info "Scanning for stray MASQUERADE rules on tunnel interfaces..."
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
  success "Stray rules cleanup done."
}

flush_all_tables() {
  warn "Flushing ALL iptables tables — ${BOLD}dangerous on production!${NC}"
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

remove_services_and_config() {
  info "Stopping and removing services & config..."
  systemctl stop tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  systemctl disable tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" 2>/dev/null || true
  rm -f "$CONFIG_FILE" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  success "Services and config removed."
}

# ─────────────────────────── Tunnel Helpers ──────────────────────────
safe_delete_tunnel_name() {
  local t="$1"
  [[ -z "$t" ]] && return 0
  [[ "$t" == "gre0" || "$t" == "ipip0" ]] && return 0
  ip link set "$t" down 2>/dev/null || true
  ip link delete "$t" 2>/dev/null || true
}

delete_existing_tunnels_all_types() {
  info "Deleting existing tunnels (except gre0/ipip0)..."
  ip -o link show type gre 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 \
    | while read -r t; do
        [[ -n $t ]] && safe_delete_tunnel_name "$t" && \
          echo -e "    ${DIM}${CROSS} $t removed${NC}"
      done
  ip -o link show type ipip 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 \
    | while read -r t; do
        [[ -n $t ]] && safe_delete_tunnel_name "$t" && \
          echo -e "    ${DIM}${CROSS} $t removed${NC}"
      done
  success "Existing tunnels cleaned."
}

tunnel_needs_rebuild() {
  local tun="$1" mode="$2" local_ip="$3" remote_ip="$4"
  local d
  d="$(ip -d tunnel show "$tun" 2>/dev/null || true)"
  [[ -z "$d" ]] && return 0
  [[ "$d" != *" local $local_ip "* ]] && return 0
  [[ "$d" != *" remote $remote_ip "* ]] && return 0
  return 1
}

ensure_tunnel() {
  local tun="$1" mode="$2" local_ip="$3" remote_ip="$4" cidr="$5"

  [[ -z "$tun" ]] && { error "Internal bug: empty tunnel name"; return 1; }
  [[ -z "$local_ip" || -z "$remote_ip" ]] && { error "Empty local/remote for $tun"; return 1; }

  if ip link show "$tun" &>/dev/null; then
    if tunnel_needs_rebuild "$tun" "$mode" "$local_ip" "$remote_ip"; then
      warn "$tun params differ ${ARROW} rebuilding..."
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

# ═════════════════════════════════════════════════════════════════════
#  ACTION: Create / Reconfigure Tunnels (Wizard)
# ═════════════════════════════════════════════════════════════════════
create_new_tunnels() {
  show_banner
  show_system_info

  section "${LINK} Tunnel Configuration Wizard"

  # ── Step 1: Tunnel Mode ──
  echo
  echo -e "  ${BWHITE}Step 1: Tunnel Protocol${NC}"
  echo -e "    ${CYAN}1)${NC} ${BOLD}GRE${NC}  — Generic Routing Encapsulation ${DIM}(recommended)${NC}"
  echo -e "    ${CYAN}2)${NC} ${BOLD}IPIP${NC} — IP-in-IP encapsulation"
  echo
  local tm_choice
  tm_choice=$(styled_prompt "Select tunnel mode" "1")
  case "$tm_choice" in
    1) TUN_MODE="gre";  TUN_PREFIX="gre"  ;;
    2) TUN_MODE="ipip"; TUN_PREFIX="ipip" ;;
    *) warn "Invalid → defaulting to GRE"; TUN_MODE="gre"; TUN_PREFIX="gre" ;;
  esac
  success "Protocol: ${BOLD}${TUN_MODE^^}${NC} ${DIM}(interfaces: ${TUN_PREFIX}1, ${TUN_PREFIX}2, ...)${NC}"

  # ── Step 2: Location ──
  echo
  echo -e "  ${BWHITE}Step 2: Server Location${NC}"
  echo -e "    ${CYAN}1)${NC} ${BOLD}Iran${NC}      ${DIM}(internal .1 suffix)${NC}"
  echo -e "    ${CYAN}2)${NC} ${BOLD}Abroad${NC}    ${DIM}(internal .2 suffix)${NC}"
  echo
  local location_choice
  location_choice=$(styled_prompt "Select location" "2")
  case $location_choice in
    1) LOCAL_IP_SUFFIX=1; GATEWAY_IP_SUFFIX=2 ;;
    2) LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
    *) warn "Invalid → defaulting to Abroad"; LOCAL_IP_SUFFIX=2; GATEWAY_IP_SUFFIX=1 ;;
  esac
  success "Location set. Internal IPs will end with ${BOLD}.${LOCAL_IP_SUFFIX}${NC}"

  # ── Step 3: Cleanup ──
  section "${SHIELD} Pre-flight Cleanup"
  echo
  echo -e "  ${BWHITE}Cleanup Options:${NC}"
  echo -e "    ${CYAN}1)${NC} ${RED}Full reset${NC} — flush firewall, remove services & tunnels"
  echo -e "    ${CYAN}2)${NC} ${YELLOW}Soft reset${NC} — remove existing tunnels & old rules only"
  echo -e "    ${CYAN}3)${NC} ${GREEN}Skip${NC}       — keep everything as-is"
  echo
  local cleanup_choice
  cleanup_choice=$(styled_prompt "Select cleanup mode" "2")
  echo
  case "$cleanup_choice" in
    1)
      info "Performing full reset..."
      remove_services_and_config
      delete_existing_tunnels_all_types
      flush_all_tables
      ;;
    2)
      info "Performing soft reset..."
      delete_existing_tunnels_all_types
      remove_rules_from_config
      cleanup_tmgr_rules
      remove_tunnel_masquerade_best_effort
      ;;
    3)
      info "Skipping cleanup."
      ;;
    *)
      warn "Invalid → performing soft reset"
      delete_existing_tunnels_all_types
      remove_rules_from_config
      cleanup_tmgr_rules
      remove_tunnel_masquerade_best_effort
      ;;
  esac

  # ── Step 4: Network Interface ──
  section "${GEAR} Network Interface Selection"
  echo
  mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")

  echo -e "  ${BWHITE}Available interfaces:${NC}"
  echo
  for i in "${!INTERFACES[@]}"; do
    local iface="${INTERFACES[$i]}"
    local iface_ip
    iface_ip=$(detect_iface_ip "$iface" 2>/dev/null || echo "no-ip")
    local state
    state=$(ip -o link show "$iface" 2>/dev/null | grep -oP 'state \K\w+' || echo "UNKNOWN")
    local state_color="$RED"
    [[ "$state" == "UP" ]] && state_color="$GREEN"

    printf "    ${CYAN}%d)${NC} ${BOLD}%-15s${NC}  ${DIM}IP:${NC} %-15s  ${state_color}${BULLET} %s${NC}\n" \
      "$((i+1))" "$iface" "$iface_ip" "$state"
  done
  echo

  local iface_choice MAIN_INTERFACE
  while true; do
    iface_choice=$(styled_prompt "Select main interface" "1")
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && ((iface_choice >= 1 && iface_choice <= ${#INTERFACES[@]})); then
      MAIN_INTERFACE=${INTERFACES[$((iface_choice - 1))]}
      break
    else
      warn "Invalid selection. Try again."
    fi
  done
  success "Interface: ${BOLD}${MAIN_INTERFACE}${NC}"

  info "Enabling IP forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # ── Step 5: Remote Endpoints ──
  section "${GLOBE} Remote Endpoints"
  echo
  echo -e "  ${DIM}Enter remote endpoints (IPv4 or domain). Press Enter on empty line to finish.${NC}"
  echo
  REMOTE_ENDPOINTS=()
  local ep_num=0
  while :; do
    ((ep_num++))
    echo -ne "  ${BMAGENTA}${BULLET}${NC} ${BOLD}Endpoint #${ep_num}${NC}: "
    read -r ep
    [[ -z $ep ]] && break
    if is_valid_ip "$ep" || is_valid_hostname "$ep"; then
      REMOTE_ENDPOINTS+=("$ep")
      echo -e "    ${GREEN}${CHECK} Added${NC}: $ep"
    else
      warn "Invalid endpoint — skipped."
      ((ep_num--))
    fi
  done
  (( ${#REMOTE_ENDPOINTS[@]} )) || { error "No endpoints supplied. Aborting."; return; }
  echo
  success "${#REMOTE_ENDPOINTS[@]} endpoint(s) registered."

  # ── Step 6: Internal IP mode ──
  section "${DIAMOND} Internal IP Assignment"
  echo
  echo -e "  ${CYAN}1)${NC} ${BOLD}Auto${NC}   — sequential /30 subnets ${DIM}(10.0.0.x, 20.0.0.x, ...)${NC}"
  echo -e "  ${CYAN}2)${NC} ${BOLD}Manual${NC} — specify each IP yourself"
  echo
  local mode_choice TUNNEL_IP_MODE
  mode_choice=$(styled_prompt "IP assignment mode" "1")
  TUNNEL_IP_MODE=$([[ $mode_choice == 2 ]] && echo "manual" || echo "auto")
  success "Mode: ${BOLD}${TUNNEL_IP_MODE}${NC}"

  # ── Create Tunnels ──
  section "${ROCKET} Creating Tunnels"
  echo
  INTERNAL_TUNNEL_IPS=()
  RESOLVED_REMOTE_IPS=()
  local total=${#REMOTE_ENDPOINTS[@]}

  for idx in "${!REMOTE_ENDPOINTS[@]}"; do
    local ENDPOINT="${REMOTE_ENDPOINTS[$idx]}"
    local RESOLVED_REMOTE

    progress_bar "$((idx))" "$total" "Provisioning"

    if ! RESOLVED_REMOTE=$(resolve_remote_once "$ENDPOINT"); then
      warn "Cannot resolve $ENDPOINT — skipping."
      continue
    fi
    RESOLVED_REMOTE_IPS+=("$RESOLVED_REMOTE")

    local TUN="${TUN_PREFIX}$((idx + 1))"
    local SUBNET_BASE=$(( (idx + 1) * 10 ))
    local TUN_IP

    if [[ $TUNNEL_IP_MODE == manual ]]; then
      echo -ne "  ${BMAGENTA}?${NC} IP for ${BOLD}$TUN${NC} → $ENDPOINT ${DIM}[${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30]${NC}: "
      read -r TUN_IP
      [[ -z "$TUN_IP" ]] && TUN_IP="${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30"
      [[ "${TUN_IP}" == */* ]] || TUN_IP="${TUN_IP}/30"
      is_valid_ip "${TUN_IP%%/*}" || { warn "Invalid IP → using auto."; TUN_IP="${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30"; }
    else
      TUN_IP="${SUBNET_BASE}.0.0.${LOCAL_IP_SUFFIX}/30"
    fi
    INTERNAL_TUNNEL_IPS+=("$TUN_IP")

    local TUN_LOCAL_IP
    if ! TUN_LOCAL_IP="$(detect_src_ip_for_remote "$RESOLVED_REMOTE" "$MAIN_INTERFACE")"; then
      warn "Cannot determine source IP for $RESOLVED_REMOTE — skipping $TUN."
      continue
    fi

    ensure_tunnel "$TUN" "$TUN_MODE" "$TUN_LOCAL_IP" "$RESOLVED_REMOTE" "$TUN_IP" \
      || { warn "Failed to create $TUN."; continue; }

    echo -e "  ${BGREEN}${CHECK}${NC} ${BOLD}${TUN}${NC} ${CYAN}↔${NC} ${ENDPOINT} ${DIM}(${RESOLVED_REMOTE})${NC}"
    printf "    ${DIM}├─ Internal: %-20s Local: %s${NC}\n" "$TUN_IP" "$TUN_LOCAL_IP"
    printf "    ${DIM}└─ Remote:   %-20s Mode:  %s${NC}\n" "$RESOLVED_REMOTE" "${TUN_MODE^^}"
  done
  progress_bar "$total" "$total" "Provisioning"
  echo
  success "Tunnel creation complete."

  # ── NAT Rules ──
  section "${SHIELD} Configuring NAT"
  echo
  declare -a MASQUERADE_RULES
  if [[ "$location_choice" == "1" ]]; then
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      TUN="${TUN_PREFIX}$((i + 1))"
      rule="iptables -t nat -A POSTROUTING -o $TUN -m comment --comment $TMGR_COMMENT -j MASQUERADE"
      MASQUERADE_RULES+=("$rule")
      ipt_apply_once "$rule"
      echo -e "    ${GREEN}${CHECK}${NC} MASQUERADE on ${BOLD}${TUN}${NC}"
    done
  else
    rule="iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -m comment --comment $TMGR_COMMENT -j MASQUERADE"
    MASQUERADE_RULES+=("$rule")
    ipt_apply_once "$rule"
    echo -e "    ${GREEN}${CHECK}${NC} MASQUERADE on ${BOLD}${MAIN_INTERFACE}${NC}"
  fi
  success "NAT configured."

  # ── Port Forwarding (Iran side) ──
  declare -a FORWARDING_RULES
  if [[ "$location_choice" == "1" ]]; then
    section "${FIRE} Port Forwarding"
    echo
    for i in "${!REMOTE_ENDPOINTS[@]}"; do
      while true; do
        if ! styled_yn "Add port forward for tunnel to ${BWHITE}${REMOTE_ENDPOINTS[$i]}${NC}?"; then
          break
        fi
        echo -ne "    ${BMAGENTA}?${NC} Port ${DIM}(e.g. 8080 or 8080=7070)${NC}: "
        read -r PORT_INPUT
        if [[ "$PORT_INPUT" == *"="* ]]; then
          SRC_PORT="${PORT_INPUT%%=*}"; DST_PORT="${PORT_INPUT##*=}"
        else
          SRC_PORT="$PORT_INPUT"; DST_PORT="$PORT_INPUT"
        fi
        echo -ne "    ${BMAGENTA}?${NC} Protocol ${DIM}(tcp/udp)${NC}: "
        read -r PROTOCOL

        SUBNET_BASE=$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1 | cut -d'.' -f1-3)
        SOURCE_IP="${SUBNET_BASE}.${LOCAL_IP_SUFFIX}"
        DEST_IP="${SUBNET_BASE}.${GATEWAY_IP_SUFFIX}"

        PR="iptables -t nat -A PREROUTING -i $MAIN_INTERFACE -p $PROTOCOL --dport $SRC_PORT -m comment --comment $TMGR_COMMENT -j DNAT --to-destination ${DEST_IP}:${DST_PORT}"
        PO="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $DST_PORT -m comment --comment $TMGR_COMMENT -j SNAT --to-source $SOURCE_IP"
        ipt_apply_once "$PR"
        ipt_apply_once "$PO"
        FORWARDING_RULES+=("$PR" "$PO")
        echo -e "    ${GREEN}${CHECK}${NC} Forward: ${BOLD}:${SRC_PORT}${NC} → ${BOLD}${DEST_IP}:${DST_PORT}/${PROTOCOL}${NC}"
      done
    done
  fi

  # ── Save Config ──
  section "${PACKAGE} Saving Configuration"
  echo
  info "Writing ${BOLD}${CONFIG_FILE}${NC}"
  {
    echo "# Tunnel Manager Configuration — generated $(date '+%F %T')"
    echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
    echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
    echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
    echo "TUN_MODE=\"$TUN_MODE\""
    echo "TUN_PREFIX=\"$TUN_PREFIX\""
    printf 'REMOTE_ENDPOINTS=('; for ep in "${REMOTE_ENDPOINTS[@]}"; do printf "%q " "$ep"; done; printf ')\n'
    printf 'RESOLVED_REMOTE_IPS=('; for ipx in "${RESOLVED_REMOTE_IPS[@]}"; do printf "%q " "$ipx"; done; printf ')\n'
    printf 'INTERNAL_TUNNEL_IPS=('; for tip in "${INTERNAL_TUNNEL_IPS[@]}"; do printf "%q " "$tip"; done; printf ')\n'
    printf 'MASQUERADE_RULES=('; for r in "${MASQUERADE_RULES[@]}"; do printf "%q " "$r"; done; printf ')\n'
    printf 'FORWARDING_RULES=('; for r in "${FORWARDING_RULES[@]}"; do printf "%q " "$r"; done; printf ')\n'
    echo "PING_INTERVAL=$PING_INTERVAL"
    echo "MONITOR_FAIL_THRESHOLD=$MONITOR_FAIL_THRESHOLD"
    echo "TMGR_COMMENT=\"$TMGR_COMMENT\""
  } > "$CONFIG_FILE"
  success "Config saved."

  # ── Systemd Services ──
  info "Creating systemd services..."
  create_persistence_service
  create_monitor_service

  systemctl daemon-reload
  systemctl enable tunnel-persistence.service tunnel-monitor.service
  systemctl restart tunnel-persistence.service tunnel-monitor.service
  success "Services enabled & started."

  # ── Kernel Optimizer ──
  run_optimizer

  # ── Summary ──
  echo
  box_top
  box_line "${STAR} Setup Complete!" "$BGREEN"
  box_sep
  box_line "Tunnels: ${#REMOTE_ENDPOINTS[@]}  |  Mode: ${TUN_MODE^^}  |  Interface: ${MAIN_INTERFACE}" "$BWHITE"
  box_line "Config:  ${CONFIG_FILE}" "$DIM"
  box_line "Log:     ${LOG_FILE}" "$DIM"
  box_line "Time:    $(( $(date +%s) - SCRIPT_START ))s" "$DIM"
  box_bottom
  echo
  info "You may reboot for full kernel optimization to apply."
  echo
}

# ═════════════════════════════════════════════════════════════════════
#  ACTION: Show Tunnel Status
# ═════════════════════════════════════════════════════════════════════
show_tunnel_status() {
  show_banner

  section "${CHART} Tunnel Status Dashboard"
  echo

  if [[ ! -f "$CONFIG_FILE" ]]; then
    warn "No configuration found at ${CONFIG_FILE}"
    warn "Run the wizard first to create tunnels."
    echo
    read -r -p "  Press Enter to return..."
    return
  fi

  set +u
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set -u

  # Service status
  echo -e "  ${BWHITE}Systemd Services:${NC}"
  echo
  for svc in tunnel-persistence.service tunnel-monitor.service; do
    local state
    state=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    local enabled
    enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
    local svc_color="$RED"
    [[ "$state" == "active" ]] && svc_color="$GREEN"

    printf "    ${svc_color}${BULLET}${NC} %-35s ${svc_color}%-10s${NC} ${DIM}(%s)${NC}\n" \
      "$svc" "$state" "$enabled"
  done
  echo
  hr "·" "$DIM"
  echo

  # Tunnel details
  echo -e "  ${BWHITE}Tunnel Interfaces:${NC}"
  echo

  if ! declare -p REMOTE_ENDPOINTS >/dev/null 2>&1; then
    warn "No endpoints found in config."
    read -r -p "  Press Enter to return..."
    return
  fi

  printf "  ${DIM}%-10s %-22s %-18s %-18s %-8s${NC}\n" \
    "TUNNEL" "ENDPOINT" "INTERNAL IP" "REMOTE IP" "STATUS"
  hr "·" "$DIM"

  for i in "${!REMOTE_ENDPOINTS[@]}"; do
    local tun="${TUN_PREFIX:-gre}$((i + 1))"
    local ep="${REMOTE_ENDPOINTS[$i]}"
    local cidr="${INTERNAL_TUNNEL_IPS[$i]:-N/A}"
    local local_inner="${cidr%%/*}"
    local base peer

    # Determine peer IP
    base="$(echo "$local_inner" | cut -d'.' -f1-3)"
    local host_part
    host_part="$(echo "$local_inner" | cut -d'.' -f4)"
    if [[ "$host_part" == "${LOCAL_IP_SUFFIX:-1}" ]]; then
      peer="$base.${GATEWAY_IP_SUFFIX:-2}"
    else
      peer="$base.${LOCAL_IP_SUFFIX:-1}"
    fi

    # Check if interface exists and is UP
    local tun_state="DOWN"
    local tun_color="$RED"
    if ip link show "$tun" &>/dev/null; then
      local link_state
      link_state=$(ip -o link show "$tun" 2>/dev/null | grep -oP 'state \K\w+' || echo "UNKNOWN")
      if [[ "$link_state" == "UNKNOWN" || "$link_state" == "UP" ]]; then
        if ping -c 1 -W 2 "$peer" &>/dev/null; then
          tun_state="${CHECK} ALIVE"
          tun_color="$GREEN"
        else
          tun_state="${WARN_ICON} NO-PING"
          tun_color="$YELLOW"
        fi
      fi
    fi

    # Resolve current remote
    local cur_remote
    cur_remote="$(ip -d tunnel show "$tun" 2>/dev/null \
      | awk '/remote/ {for(i=1;i<=NF;i++) if($i=="remote"){print $(i+1); exit}}')" || cur_remote="N/A"

    printf "  ${BOLD}%-10s${NC} %-22s %-18s %-18s ${tun_color}%-8s${NC}\n" \
      "$tun" "$ep" "$cidr" "${cur_remote:-N/A}" "$tun_state"
  done
  echo
  hr "·" "$DIM"

  # Quick stats
  local total_tun=${#REMOTE_ENDPOINTS[@]}
  local alive_tun=0
  for i in "${!REMOTE_ENDPOINTS[@]}"; do
    local tun="${TUN_PREFIX:-gre}$((i + 1))"
    local cidr="${INTERNAL_TUNNEL_IPS[$i]:-}"
    local li="${cidr%%/*}"
    local b peer2
    b="$(echo "$li" | cut -d'.' -f1-3)"
    local hp
    hp="$(echo "$li" | cut -d'.' -f4)"
    [[ "$hp" == "${LOCAL_IP_SUFFIX:-1}" ]] && peer2="$b.${GATEWAY_IP_SUFFIX:-2}" || peer2="$b.${LOCAL_IP_SUFFIX:-1}"
    ping -c 1 -W 2 "$peer2" &>/dev/null && ((alive_tun++))
  done
  echo
  echo -e "  ${BWHITE}Summary:${NC} ${BOLD}${alive_tun}${NC}/${total_tun} tunnels responding  |  Mode: ${BOLD}${TUN_MODE:-N/A}${NC}  |  Interface: ${BOLD}${MAIN_INTERFACE:-N/A}${NC}"
  echo

  read -r -p "  Press Enter to return..."
}

# ═════════════════════════════════════════════════════════════════════
#  ACTION: View Logs
# ═════════════════════════════════════════════════════════════════════
show_logs() {
  show_banner
  section "${CHART} Recent Logs"
  echo

  if [[ -f "$LOG_FILE" ]]; then
    echo -e "  ${DIM}Last 30 lines from ${LOG_FILE}:${NC}"
    echo
    tail -n 30 "$LOG_FILE" | while IFS= read -r line; do
      if [[ "$line" == *"[ERR]"* ]]; then
        echo -e "  ${RED}${line}${NC}"
      elif [[ "$line" == *"[WARN]"* ]]; then
        echo -e "  ${YELLOW}${line}${NC}"
      elif [[ "$line" == *"[OK]"* ]]; then
        echo -e "  ${GREEN}${line}${NC}"
      else
        echo -e "  ${DIM}${line}${NC}"
      fi
    done
  else
    echo -e "  ${DIM}No log file found at ${LOG_FILE}${NC}"
  fi

  echo
  echo -e "  ${DIM}Monitor journal:${NC}"
  journalctl -u tunnel-monitor.service --no-pager -n 20 2>/dev/null || echo -e "  ${DIM}No journal entries.${NC}"
  echo
  read -r -p "  Press Enter to return..."
}

# ═════════════════════════════════════════════════════════════════════
#  Persistence & Monitor Service Generators
# ═════════════════════════════════════════════════════════════════════
create_persistence_service() {
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

# Re-create tunnels on boot
for i in "${!REMOTE_ENDPOINTS[@]}"; do
  PFX="${TUN_PREFIX:-gre}"
  TUN="${PFX}$((i+1))"

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

  ip link set "$TUN" down 2>/dev/null || true
  ip link delete "$TUN" 2>/dev/null || true
  sleep 0.2

  if ! ip tunnel add "$TUN" mode "$TUN_MODE" remote "$REM" local "$LOC" ttl 255 2>/dev/null; then
    echo "Tunnel add failed for $TUN, checking if exists..."
  fi

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
Description=Tunnel Manager — Restore tunnels at boot (domain-aware)
After=network-online.target
Wants=network-online.target
ConditionPathExists=$CONFIG_FILE

[Service]
Type=oneshot
ExecStart=$PERSISTENCE_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
  success "Persistence service created."
}

create_monitor_service() {
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

ensure_tun_present(){
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
Description=Tunnel Manager — Health monitor & auto-healer
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
  success "Monitor service created."
}

# ═════════════════════════════════════════════════════════════════════
#  Kernel Optimizer
# ═════════════════════════════════════════════════════════════════════
apply_tcp_settings() {
  cat > /etc/sysctl.conf <<'EOF'
# ─── High-Concurrency TCP Profile (BBR + FQ) ── Managed by Tunnel Manager ───
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

apply_udp_settings() {
  cat > /etc/sysctl.conf <<'EOF'
# ─── High-Concurrency UDP/QUIC + Mixed Profile ── Managed by Tunnel Manager ──
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

run_optimizer() {
  section "${FIRE} Kernel Optimization"
  echo
  if ! styled_yn "Optimize server kernel settings now?"; then
    info "Skipping kernel optimization."
    return
  fi

  echo
  echo -e "  ${BWHITE}Select Profile:${NC}"
  echo -e "    ${CYAN}1)${NC} ${BOLD}TCP${NC}  — optimized for HTTP/HTTPS/SSH traffic ${DIM}(BBR + FQ)${NC}"
  echo -e "    ${CYAN}2)${NC} ${BOLD}UDP${NC}  — optimized for QUIC/Gaming/VoIP traffic"
  echo

  local c
  while true; do
    c=$(styled_prompt "Enter your choice" "1")
    [[ $c =~ ^[12]$ ]] && break || warn "Enter 1 or 2."
  done

  echo
  warn "This will ${BOLD}OVERWRITE${NC}${YELLOW} /etc/sysctl.conf${NC}"
  if ! styled_yn "Are you sure?"; then
    info "Cancelled."
    return
  fi

  info "Creating backup → /etc/sysctl.conf.bak.$(date +%F)"
  cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%F)" 2>/dev/null || true

  [[ $c -eq 1 ]] && apply_tcp_settings || apply_udp_settings
  info "Applying sysctl parameters..."
  if sysctl -p >/dev/null 2>&1; then
    success "Kernel settings applied successfully."
  else
    error "Failed to apply some sysctl settings."
  fi

  echo
  if styled_yn "Reboot now for full effect?"; then
    info "Rebooting..."
    reboot
  else
    warn "Remember to reboot later."
  fi
}

# ═════════════════════════════════════════════════════════════════════
#  ACTION: Delete Everything
# ═════════════════════════════════════════════════════════════════════
delete_all_tunnels() {
  show_banner

  section "${CROSS} Remove All Tunnels & Services"
  echo
  echo -e "  ${BRED}${WARN_ICON} WARNING: This will remove ALL tunnels, config, and services!${NC}"
  echo
  if ! styled_yn "Really continue? This is irreversible"; then
    info "Aborted."
    return
  fi
  echo

  local steps=6 step=0

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  systemctl stop tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true
  systemctl disable tunnel-monitor.service tunnel-persistence.service 2>/dev/null || true

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  remove_rules_from_config

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  cleanup_tmgr_rules

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  remove_tunnel_masquerade_best_effort

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  rm -f "$MONITOR_SERVICE" "$PERSISTENCE_SERVICE" "$MONITOR_SCRIPT" "$PERSISTENCE_SCRIPT" "$CONFIG_FILE"
  systemctl daemon-reload

  ((step++)); progress_bar "$step" "$steps" "Cleanup    "
  delete_existing_tunnels_all_types

  echo
  warn "Kernel /etc/sysctl.conf NOT reverted. Backups in /etc/sysctl.conf.bak.*"
  echo
  box_top
  box_line "${CHECK} Cleanup complete — all tunnels & services removed." "$BGREEN"
  box_bottom
  echo
  read -r -p "  Press Enter to return..."
}

# ═════════════════════════════════════════════════════════════════════
#  ACTION: Restart Services
# ═════════════════════════════════════════════════════════════════════
restart_services() {
  show_banner
  section "${GEAR} Restarting Services"
  echo

  if [[ ! -f "$CONFIG_FILE" ]]; then
    warn "No config found. Run the wizard first."
    read -r -p "  Press Enter to return..."
    return
  fi

  info "Restarting tunnel-persistence.service..."
  systemctl restart tunnel-persistence.service 2>/dev/null && \
    success "Persistence restarted." || error "Failed to restart persistence."

  info "Restarting tunnel-monitor.service..."
  systemctl restart tunnel-monitor.service 2>/dev/null && \
    success "Monitor restarted." || error "Failed to restart monitor."

  echo
  success "Services restarted."
  echo
  read -r -p "  Press Enter to return..."
}

# ═════════════════════════════════════════════════════════════════════
#  ACTION: Standalone Kernel Optimizer
# ═════════════════════════════════════════════════════════════════════
standalone_optimizer() {
  show_banner
  run_optimizer
  echo
  read -r -p "  Press Enter to return..."
}

# ═════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═════════════════════════════════════════════════════════════════════
main_menu() {
  while true; do
    show_banner
    show_system_info

    echo -e "  ${BWHITE}${GEAR} Main Menu${NC}"
    hr "─" "$CYAN"
    echo
    echo -e "    ${BCYAN}1)${NC}  ${BOLD}${ROCKET} Create / Reconfigure Tunnels${NC}"
    echo -e "       ${DIM}Interactive wizard for GRE/IPIP tunnel setup${NC}"
    echo
    echo -e "    ${BCYAN}2)${NC}  ${BOLD}${CHART} Tunnel Status Dashboard${NC}"
    echo -e "       ${DIM}View real-time status of all tunnels & services${NC}"
    echo
    echo -e "    ${BCYAN}3)${NC}  ${BOLD}${GEAR} Restart Services${NC}"
    echo -e "       ${DIM}Restart persistence & monitor daemons${NC}"
    echo
    echo -e "    ${BCYAN}4)${NC}  ${BOLD}${FIRE} Kernel Optimizer${NC}"
    echo -e "       ${DIM}Apply optimized TCP/UDP sysctl profiles${NC}"
    echo
    echo -e "    ${BCYAN}5)${NC}  ${BOLD}${CHART} View Logs${NC}"
    echo -e "       ${DIM}Recent tunnel manager & monitor logs${NC}"
    echo
    echo -e "    ${BCYAN}6)${NC}  ${BOLD}${BRED}${CROSS} Delete Everything${NC}"
    echo -e "       ${DIM}Remove all tunnels, rules, config & services${NC}"
    echo
    echo -e "    ${BCYAN}0)${NC}  ${BOLD}Exit${NC}"
    echo
    hr "─" "$CYAN"

    local choice
    echo -ne "  ${BMAGENTA}${ARROW}${NC} ${BOLD}Select option${NC}: "
    read -r choice

    case $choice in
      1) create_new_tunnels ;;
      2) show_tunnel_status ;;
      3) restart_services ;;
      4) standalone_optimizer ;;
      5) show_logs ;;
      6) delete_all_tunnels ;;
      0) echo -e "\n  ${BCYAN}${STAR} Goodbye!${NC}\n"; exit 0 ;;
      *)
        echo -e "\n  ${RED}Invalid option. Try again.${NC}"
        sleep 1
        ;;
    esac
  done
}

# ─── Entry Point ────────────────────────────────────────────────────
main_menu
