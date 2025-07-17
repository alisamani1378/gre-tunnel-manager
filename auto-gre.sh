#!/bin/bash

# --- Comprehensive and Interactive GRE Tunnel Management Script ---
# This tool creates tunnels, sets up a monitoring service, and ensures their persistence after a reboot.

CONFIG_FILE="/etc/gre-tunnels.conf"
PERSISTENCE_SCRIPT="/usr/local/bin/gre-persistence.sh"
MONITOR_SCRIPT="/usr/local/bin/gre-monitor.sh"
PERSISTENCE_SERVICE="/etc/systemd/system/gre-persistence.service"
MONITOR_SERVICE="/etc/systemd/system/gre-monitor.service"

# --- Main Functions ---

function create_new_tunnels() {
    # --- Step 0: Gathering User Information ---
    echo "############################################################"
    echo "#            New GRE Tunnel Configuration                #"
    echo "############################################################"
    
    # Initial Questions
    echo "Please choose the server location:"
    echo " 1) Iran"
    echo " 2) Abroad"
    read -p "Select option (1 for Iran, 2 for Abroad, default: 2): " location_choice

    echo "Do you want to delete existing GRE tunnels first?"
    echo " 1) Yes"
    echo " 2) No"
    read -p "Select option (1 or 2, default: 1): " delete_choice

    echo "Do you want to flush all firewall rules?"
    echo " 1) Yes"
    echo " 2) No"
    read -p "Select option (1 or 2, default: 1): " flush_choice

    # Determine internal IP based on location
    if [[ "$location_choice" == "1" ]]; then
        LOCAL_IP_SUFFIX=1
        GATEWAY_IP_SUFFIX=2
        echo "✅ Server location set to Iran. Local IPs will end in .1"
    else
        LOCAL_IP_SUFFIX=2
        GATEWAY_IP_SUFFIX=1
        echo "✅ Server location set to Abroad. Local IPs will end in .2"
    fi

    # Ask for network interface with a numeric menu
    echo "--------------------------------------------------"
    echo "Please select the main public network interface:"
    mapfile -t INTERFACES < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v "lo")
    
    for i in "${!INTERFACES[@]}"; do
        echo " $((i+1))) ${INTERFACES[$i]}"
    done
    echo "--------------------------------------------------"

    while true; do
        read -p "Select an option (1-${#INTERFACES[@]}): " iface_choice
        if [[ "$iface_choice" =~ ^[0-9]+$ ]] && [ "$iface_choice" -ge 1 ] && [ "$iface_choice" -le ${#INTERFACES[@]} ]; then
            MAIN_INTERFACE=${INTERFACES[$((iface_choice-1))]}
            echo "✅ Interface '$MAIN_INTERFACE' selected."
            break
        else
            echo "❌ Invalid option. Please try again."
        fi
    done

    # Ask for remote server IPs
    echo "--------------------------------------------------"
    echo "Please enter the destination server IPs one by one."
    echo "When finished, press [ENTER] on an empty line."
    declare -a REMOTE_IPS
    while true; do
        read -p "Enter remote IP: " ip
        if [ -z "$ip" ]; then break; fi
        REMOTE_IPS+=("$ip")
    done

    if [ ${#REMOTE_IPS[@]} -eq 0 ]; then
        echo "❌ ERROR: No remote IPs were provided. Cannot create tunnels."
        exit 1
    fi

    # Ask for internal IP assignment method
    echo "--------------------------------------------------"
    echo "How do you want to assign internal tunnel IPs?"
    echo " 1) auto   - Automatically generate IPs (e.g., 10.0.0.x, 20.0.0.x)"
    echo " 2) manual - Manually enter the IP for each tunnel"
    read -p "Choose an option (1 or 2, default is 1): " mode_choice
    case "$mode_choice" in
        2) TUNNEL_IP_MODE="manual" ;;
        *) TUNNEL_IP_MODE="auto" ;;
    esac
    echo "✅ Using '$TUNNEL_IP_MODE' mode for internal IPs."
    echo "--------------------------------------------------"

    # --- Automated Process Starts ---
    
    # Step 1: Delete existing GRE tunnels (based on user response)
    if [[ "$delete_choice" != "2" ]]; then
        echo "🔍 Searching for and deleting existing GRE tunnels..."
        EXISTING_TUNNELS=$(ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1)
        if [ -n "$EXISTING_TUNNELS" ]; then
            for tunnel in $EXISTING_TUNNELS; do
                echo "   - Deleting tunnel: $tunnel"
                sudo ip link delete $tunnel
            done
            echo "✅ All existing GRE tunnels have been deleted."
        else
            echo "👍 No existing GRE tunnels found to delete."
        fi
        echo "--------------------------------------------------"
    fi

    # Step 2: Flush firewall rules (based on user response)
    if [[ "$flush_choice" != "2" ]]; then
        echo "🔥 Flushing all firewall rules..."
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -t nat -F
        sudo iptables -t mangle -F
        sudo iptables -F
        sudo iptables -X
        sudo iptables -t nat -X
        sudo iptables -t mangle -X
        echo "✅ Firewall rules flushed."
        echo "--------------------------------------------------"
    fi
    
    # Step 3: IP Detection and Network Setup
    echo "🌐 Detecting server's public IPv4 address..."
    LOCAL_IP=$(curl -4 -s icanhazip.com)
    echo "✅ Public IPv4 detected: $LOCAL_IP"
    
    echo "🚀 Enabling IP forwarding and setting up MASQUERADE..."
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE
    echo "✅ IP forwarding and NAT are configured."
    echo "--------------------------------------------------"

    # Step 4: Save Configuration for Services
    echo "💾 Saving configuration to $CONFIG_FILE..."
    sudo rm -f $CONFIG_FILE
    sudo touch $CONFIG_FILE
    sudo chmod 600 $CONFIG_FILE
    echo "MAIN_INTERFACE='${MAIN_INTERFACE}'" | sudo tee -a $CONFIG_FILE > /dev/null
    echo "LOCAL_IP='${LOCAL_IP}'" | sudo tee -a $CONFIG_FILE > /dev/null
    echo "LOCAL_IP_SUFFIX='${LOCAL_IP_SUFFIX}'" | sudo tee -a $CONFIG_FILE > /dev/null
    echo "GATEWAY_IP_SUFFIX='${GATEWAY_IP_SUFFIX}'" | sudo tee -a $CONFIG_FILE > /dev/null
    echo "REMOTE_IPS=(${REMOTE_IPS[@]})" | sudo tee -a $CONFIG_FILE > /dev/null
    
    # Step 5: Loop to Create Tunnels and Save Internal IPs
    echo "Tunnel creation process started..."
    declare -a INTERNAL_TUNNEL_IPS_ARRAY
    for i in "${!REMOTE_IPS[@]}"; do
        TUNNEL_INDEX=$(($i + 1))
        TUNNEL_NAME="gre${TUNNEL_INDEX}"
        REMOTE_IP=${REMOTE_IPS[$i]}
        
        if [ "$TUNNEL_IP_MODE" == "manual" ]; then
            read -p "Enter internal IP for tunnel to $REMOTE_IP (e.g., 10.0.0.${LOCAL_IP_SUFFIX}/24): " TUNNEL_IP
            if [ -z "$TUNNEL_IP" ]; then
                echo "⚠️ No IP entered. Using automatic mode for this tunnel."
                TUNNEL_SUBNET_PREFIX=$(( $TUNNEL_INDEX * 10 ))
                TUNNEL_IP="${TUNNEL_SUBNET_PREFIX}.0.0.${LOCAL_IP_SUFFIX}/24"
            fi
        else
            TUNNEL_SUBNET_PREFIX=$(( $TUNNEL_INDEX * 10 ))
            TUNNEL_IP="${TUNNEL_SUBNET_PREFIX}.0.0.${LOCAL_IP_SUFFIX}/24"
        fi
        INTERNAL_TUNNEL_IPS_ARRAY+=("$TUNNEL_IP")

        echo "Creating tunnel #$TUNNEL_INDEX: $TUNNEL_NAME..."
        sudo ip tunnel add $TUNNEL_NAME mode gre remote $REMOTE_IP local $LOCAL_IP ttl 255
        sudo ip addr add $TUNNEL_IP dev $TUNNEL_NAME
        sudo ip link set $TUNNEL_NAME up
        echo "✅ Tunnel $TUNNEL_NAME is UP."
    done
    echo "INTERNAL_TUNNEL_IPS=(${INTERNAL_TUNNEL_IPS_ARRAY[@]})" | sudo tee -a $CONFIG_FILE > /dev/null
    echo "--------------------------------------------------"

    # Step 6: Create Scripts and Services
    create_persistence_service
    create_monitor_service

    # Step 7: Activate and Start Services
    echo "🚀 Activating and starting services..."
    sudo systemctl daemon-reload
    sudo systemctl enable gre-persistence.service gre-monitor.service
    sudo systemctl restart gre-persistence.service gre-monitor.service
    echo "✅ All services are enabled and active."
    echo "🎉 Setup complete!"
}

function create_persistence_service() {
    echo "🛠️ Creating persistence script and service..."
    # Create script to restore tunnels and rules on boot
    sudo bash -c "cat > $PERSISTENCE_SCRIPT" <<EOF
#!/bin/bash
# This script is auto-generated to restore GRE tunnels on boot.
source $CONFIG_FILE

# Restore firewall and NAT
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o \$MAIN_INTERFACE -j MASQUERADE

# Restore tunnels
for i in "\${!REMOTE_IPS[@]}"; do
    TUNNEL_INDEX=\$((i + 1))
    TUNNEL_NAME="gre\${TUNNEL_INDEX}"
    REMOTE_IP=\${REMOTE_IPS[i]}
    TUNNEL_IP=\${INTERNAL_TUNNEL_IPS[i]}
    
    ip tunnel add \$TUNNEL_NAME mode gre remote \$REMOTE_IP local \$LOCAL_IP ttl 255
    ip addr add \$TUNNEL_IP dev \$TUNNEL_NAME
    ip link set \$TUNNEL_NAME up
done
EOF
    sudo chmod +x $PERSISTENCE_SCRIPT

    # Create persistence service file
    sudo bash -c "cat > $PERSISTENCE_SERVICE" <<EOF
[Unit]
Description=GRE Tunnels Persistence Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $PERSISTENCE_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Persistence service created."
}

function create_monitor_service() {
    echo "🛠️ Creating monitoring script and service..."
    # Create monitoring script
    sudo bash -c "cat > $MONITOR_SCRIPT" <<EOF
#!/bin/bash
# This script is auto-generated to keep tunnels alive.
source $CONFIG_FILE

while true; do
EOF
    # Add ping loop to monitoring script
    for i in "${!INTERNAL_TUNNEL_IPS_ARRAY[@]}"; do
        IP_BASE=$(echo ${INTERNAL_TUNNEL_IPS_ARRAY[$i]} | cut -d'/' -f1)
        SUBNET_BASE=$(echo $IP_BASE | cut -d'.' -f1-3)
        GATEWAY_IP="${SUBNET_BASE}.${GATEWAY_IP_SUFFIX}"
        echo "    /bin/ping -c 2 $GATEWAY_IP > /dev/null 2>&1" | sudo tee -a $MONITOR_SCRIPT > /dev/null
    done
    sudo bash -c "cat >> $MONITOR_SCRIPT" <<EOF
    sleep 10
done
EOF
    sudo chmod +x $MONITOR_SCRIPT

    # Create monitoring service file
    sudo bash -c "cat > $MONITOR_SERVICE" <<EOF
[Unit]
Description=GRE Tunnel Keep-Alive Ping Service
After=gre-persistence.service
Wants=gre-persistence.service

[Service]
ExecStart=/bin/bash $MONITOR_SCRIPT
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Monitoring service created."
}

function delete_all_tunnels() {
    echo "⚠️ This will stop and disable all related services and delete all GRE tunnels."
    read -p "Are you sure? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi

    echo "Stopping and disabling services..."
    sudo systemctl stop gre-persistence.service gre-monitor.service &>/dev/null || true
    sudo systemctl disable gre-persistence.service gre-monitor.service &>/dev/null || true
    
    echo "Deleting service files and scripts..."
    sudo rm -f $PERSISTENCE_SERVICE $MONITOR_SERVICE
    sudo rm -f $PERSISTENCE_SCRIPT $MONITOR_SCRIPT
    sudo rm -f $CONFIG_FILE
    sudo systemctl daemon-reload

    echo "Deleting GRE tunnels..."
    EXISTING_TUNNELS=$(ip -o link show type gre | awk -F': ' '{print $2}' | cut -d'@' -f1)
    if [ -n "$EXISTING_TUNNELS" ]; then
        for tunnel in $EXISTING_TUNNELS; do
            echo "   - Deleting tunnel: $tunnel"
            sudo ip link delete $tunnel
        done
    fi
    echo "✅ Cleanup complete."
}

# --- Main Menu ---
function main_menu() {
    echo "--------------------------------------------------"
    echo "              GRE Tunnel Manager Menu"
    echo "--------------------------------------------------"
    echo " 1) Create / Reconfigure Tunnels"
    echo " 2) Delete All Tunnels and Services"
    echo " 3) Exit"
    read -p "Select an option: " choice
    case $choice in
        1) create_new_tunnels ;;
        2) delete_all_tunnels ;;
        3) exit 0 ;;
        *) echo "Invalid option. Exiting."; exit 1 ;;
    esac
}

main_menu
