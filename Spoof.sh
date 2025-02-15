#!/bin/bash

# Exit immediately on command failure
set -e

# Trap Ctrl+C to restore original routing
trap ctrl_c INT
function ctrl_c() {
    echo "[!] Ctrl+C detected. Restoring original routing..."
    restore_routes
    exit 0
}

# Function to restore the original routes
function restore_routes() {
    if [ -n "${original_default_gateway}" ]; then
        echo "[+] Restoring original default route..."
        ip route del default via "${SPOOF}" || true
        ip route add default via "${original_default_gateway}" dev enp0s3
        echo "[+] Routes restored successfully."
    else
        echo "[-] No original default gateway found to restore."
    fi
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Please run as root!"
    exit 1
fi

# SPOOF IP address
SPOOF="Your-Ip"

# Enable IP forwarding to allow traffic routing
echo "Enabling IP forwarding..."
echo "1" > /proc/sys/net/ipv4/ip_forward

# Get the current default gateway
original_default_gateway=$(ip route | grep default | awk '{print $3}')
if [ -z "${original_default_gateway}" ]; then
    echo "[-] Could not determine the current default gateway. Exiting."
    exit 1
fi

# Update routing to redirect traffic to the spoof IP
echo "[+] Current default gateway: ${original_default_gateway}"
echo "[+] Changing default gateway to spoof IP: ${SPOOF}"

# Remove any existing default route
ip route del default || true
ip route add default via "${SPOOF}" dev enp0s3

# Prompt to restore the original routes
echo "Routing has been changed to direct all traffic to ${SPOOF}. Press [Enter] to restore original routing, or press Ctrl+C to exit."
read -r null

# Restore the original routing
restore_routes
echo "[+] Original routing restored."
exit 0
