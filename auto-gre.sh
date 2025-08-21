#!/usr/bin/env bash

# ------------------------------------------------------------------
# Universal GRE Tunnel Manager & Server Optimizer
# Author  : Ali Samani – 2025
# License : MIT
# ------------------------------------------------------------------

set -Eeuo pipefail
SCRIPT_START=$(date +%s)

# ---------- Constants ---------------------------------------------------------
CONFIG_FILE="/etc/gre-tunnels.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/gre-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/gre-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/gre-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/gre-monitor.service"
PING_INTERVAL=10 # seconds
MONITOR_FAIL_THRESHOLD=3 # pings

# ---------- Pretty print helpers ---------------------------------------------
NC='\033[0m'
C_BLUE='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'

info()    { echo -e "${C_BLUE}[INFO]${NC} $*"; }
success() { echo -e "${C_GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${C_YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${C_RED}[ERROR]${NC} $*" >&2; }

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

prompt_default() {
    # $1=question $2=default
    local ans
    read -r -p "$1 [$2]: " ans
    echo "${ans:-$2}"
}

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
    delete_choice=$(prompt_default "Delete existing GRE tunnels first? (1=Yes, 2=No)" "1")
    flush_choice=$(prompt_default "Flush ALL firewall rules? (1=Yes, 2=No)" "1")

    # 3️⃣ Select network interface
    mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
    echo "--------------------------------------------------"
    for i in "${!INTERFACES[@]}"; do
        echo " $((i+1))) ${INTERFACES[$i]}"
    done
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

    # 4️⃣ Enter remote IPs
    info "Enter destination server IPs (blank line to finish):"
    REMOTE_IPS=()
    while :; do
        read -r -p "Remote IP: " ip
        [[ -z $ip ]] && break
        if is_valid_ip "$ip"; then
            REMOTE_IPS+=("$ip")
        else
            warn "Invalid IP, ignored."
        fi
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
            [[ -n $tun ]] && sudo ip link delete "$tun" && echo " - $tun removed."
        done
    fi
    if [[ $flush_choice != 2 ]]; then
        info "Flushing iptables rules..."
        sudo iptables -F; sudo iptables -t nat -F; sudo iptables -t mangle -F
        sudo iptables -X; sudo iptables -t nat -X; sudo iptables -t mangle -X
    fi

    # ---------- Basic net config ---------------
    info "Enabling IP forwarding..."
    sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
    LOCAL_IP=$(curl -4 -s icanhazip.com || true)
    [[ -z $LOCAL_IP ]] && { error "Couldn't auto-detect public IP"; exit 1; }
    success "Public IP detected: $LOCAL_IP"

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
        sudo ip link show "$TUN" &>/dev/null || sudo ip tunnel add "$TUN" mode gre remote "$REMOTE" local "$LOCAL_IP" ttl 255
        sudo ip addr show dev "$TUN" | grep -q "$TUN_IP" || sudo ip addr add "$TUN_IP" dev "$TUN"
        sudo ip link set "$TUN" up
        echo " • $TUN ↔ $REMOTE [$TUN_IP]"
    done

    # ---------- Configure NAT based on location (MODIFIED) ----------
    info "Configuring NAT..."
    declare -a MASQUERADE_RULES
    if [[ "$location_choice" == "1" ]]; then
        # Iran server: Masquerade on each GRE tunnel
        for i in "${!REMOTE_IPS[@]}"; do
            TUN="gre$((i+1))"
            rule="iptables -t nat -A POSTROUTING -o $TUN -j MASQUERADE"
            MASQUERADE_RULES+=("$rule")
            sudo iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || eval "$rule"
        done
        success "NAT configured on all GRE tunnels."
    else
        # Abroad server: Masquerade on main interface
        rule="iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE"
        MASQUERADE_RULES+=("$rule")
        sudo iptables -t nat -C POSTROUTING -o "$MAIN_INTERFACE" -j MASQUERADE 2>/dev/null || eval "$rule"
        success "NAT configured on main interface '$MAIN_INTERFACE'."
    fi

    # ---------- Port Forwarding Setup ----------------
    declare -a FORWARDING_RULES
    if [[ "$location_choice" == "1" ]]; then
        info "------------- Port Forwarding Setup -------------"
        for i in "${!REMOTE_IPS[@]}"; do
            while true; do
                read -r -p "Add port forwarding for tunnel to ${REMOTE_IPS[$i]}? (y/n): " add_forward
                [[ $add_forward =~ ^[Yy]$ ]] || break
                read -r -p " Port to forward (e.g., 8080): " PORT
                read -r -p " Protocol (tcp/udp): " PROTOCOL
                SUBNET_BASE=$(echo "${INTERNAL_TUNNEL_IPS[$i]}" | cut -d'/' -f1 | cut -d'.' -f1-3)
                SOURCE_IP="${SUBNET_BASE}.${LOCAL_IP_SUFFIX}"
                DEST_IP="${SUBNET_BASE}.${GATEWAY_IP_SUFFIX}"
                PREROUTING_RULE="iptables -t nat -A PREROUTING -p $PROTOCOL --dport $PORT -j DNAT --to-destination ${DEST_IP}:${PORT}"
                POSTROUTING_RULE="iptables -t nat -A POSTROUTING -p $PROTOCOL -d $DEST_IP --dport $PORT -j SNAT --to-source $SOURCE_IP"
                info " Applying rule: $PREROUTING_RULE"
                eval "$PREROUTING_RULE"
                info " Applying rule: $POSTROUTING_RULE"
                eval "$POSTROUTING_RULE"
                FORWARDING_RULES+=("$PREROUTING_RULE" "$POSTROUTING_RULE")
                success "Forwarding rule for port $PORT/$PROTOCOL added."
            done
        done
    fi

    # ---------- Save config (MODIFIED) ---------------
    info "Saving configuration → $CONFIG_FILE"
    {
        echo "MAIN_INTERFACE=\"$MAIN_INTERFACE\""
        echo "LOCAL_IP=\"$LOCAL_IP\""
        echo "LOCAL_IP_SUFFIX=$LOCAL_IP_SUFFIX"
        echo "GATEWAY_IP_SUFFIX=$GATEWAY_IP_SUFFIX"
        echo "REMOTE_IPS=(${REMOTE_IPS[*]})"
        echo "INTERNAL_TUNNEL_IPS=(${INTERNAL_TUNNEL_IPS[*]})"
        # Save the masquerade rules
        printf "MASQUERADE_RULES=("
        for rule in "${MASQUERADE_RULES[@]}"; do printf "%q " "$rule"; done
        printf ")\n"
        # Save the port forwarding rules
        printf "FORWARDING_RULES=("
        for rule in "${FORWARDING_RULES[@]}"; do printf "%q " "$rule"; done
        printf ")\n"
    } > "$CONFIG_FILE"

    # ---------- Create services ----------------
    create_persistence_service
    create_monitor_service
    systemctl daemon-reload
    systemctl enable --now gre-persistence.service gre-monitor.service

    # ---------- Final Step: Optimizer (New) ----------
    run_optimizer
    success "All done! Total time: $(( $(date +%s) - SCRIPT_START )) s"
    info "Reboot may be needed for kernel optimizations to take full effect."
}

create_persistence_service() {
    info "Building persistence service..."
    cat > "$PERSISTENCE_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /etc/gre-tunnels.conf ]] || exit 0
source /etc/gre-tunnels.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Restore NAT/Masquerade rules (MODIFIED)
for rule_cmd in "${MASQUERADE_RULES[@]}"; do
    check_cmd="${rule_cmd/ -A /-C }"
    if ! eval "$check_cmd" &>/dev/null; then
        eval "$rule_cmd"
    fi
done
for i in "${!REMOTE_IPS[@]}"; do
    TUN="gre$((i+1))"
    ip link show "$TUN" &>/dev/null || ip tunnel add "$TUN" mode gre remote "${REMOTE_IPS[$i]}" local "$LOCAL_IP" ttl 255
    ip addr show dev "$TUN" | grep -q "${INTERNAL_TUNNEL_IPS[$i]}" || ip addr add "${INTERNAL_TUNNEL_IPS[$i]}" dev "$TUN"
    ip link set "$TUN" up
done
# Restore custom port forwarding rules
for rule in "${FORWARDING_RULES[@]}"; do
    check_cmd="${rule/-A /-C }"
    if ! eval "$check_cmd" &>/dev/null; then
        eval "$rule"
    fi
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
            ip link set "$TUN" up || true
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

# --- Optimizer Functions (New) ---
apply_tcp_settings() {
    info "Writing TCP-optimized settings..."
    cat > /etc/sysctl.conf <<EOF
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
    cat > /etc/sysctl.conf <<EOF
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
    echo " 1) TCP Profile (Best for VLESS, Trojan, etc.)"
    echo " 2) UDP Profile (Best for Gaming, WireGuard, etc.)"
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
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F)
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
        [[ -n $tun ]] && ip link delete "$tun" && echo " - $tun removed."
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
