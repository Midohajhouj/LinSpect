#!/bin/bash

# LinSpect - Linux Enumeration & Privilege Escalation Tool
# Author: MIDO777
# Version: 2.0
# Description: A robust tool for Linux system enumeration, privilege escalation, and exploit suggestion.

###########################################
#---------------) Colors (----------------#
###########################################

C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_CYAN='\033[1;36m'
C_PURPLE='\033[1;35m'

# Risk level colors
C_CRITICAL='\033[1;31m'  # Red for critical
C_HIGH='\033[1;35m'      # Purple for high
C_MEDIUM='\033[1;33m'    # Yellow for medium
C_LOW='\033[1;34m'       # Blue for low
C_INFO='\033[1;36m'      # Cyan for informational
C_SAFE='\033[1;32m'      # Green for safe/non-critical

###########################################
#---------------) Banner (----------------#
###########################################

function banner {
    echo -e "${C_CYAN}"
    echo -e "  ██╗     ██╗███╗   ██╗███████╗███████╗██████╗ ███████╗ ██████╗████████╗"
    echo -e "  ██║     ██║████╗  ██║██╔════╝██╔════╝██╔══██╗ ██╔════╝██╔════╝╚══██╔══╝"
    echo -e "  ██║     ██║██╔██╗ ██║█████╗  ███████╗██████╔╝███████╗██║        ██║   "
    echo -e "  ██║     ██║██║╚██╗██║██╔══╝  ╚════██║██╔═══╝ ██      ║██║        ██║   "
    echo -e "  ███████╗██║██║  ████║███████╗███████║██║     ███████║╚██████╗   ██║   "
    echo -e "  ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   "
    echo -e "${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
    echo -e "${C_BLUE}##      Linux Enumeration & Privilege Escalation       ##${C_RESET}"
    echo -e "${C_RED}###############     Coded by MIDO777              ########${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
}

###########################################
#---------------) Usage (-----------------#
###########################################

function usage {
    banner
    echo -e "${C_YELLOW}# Example: ./LinSpect.sh${C_RESET}\n"
    echo "OPTIONS:"
    echo "-h    Displays this help text"
    echo "-s    Perform a quick system scan"
    echo "-f    Perform a full system scan (includes all checks)"
    echo "-e    Perform exploit checks only"
    echo "-n    Perform network checks only"
    echo "-u    Perform user and group checks only"
    echo -e "\n"
    echo "Running with no options = all scans (default behavior)"
    echo -e "${C_GREEN}#########################################${C_RESET}"
}

###########################################
#---------------) Checks (----------------#
###########################################

function get_color {
    case $1 in
        critical) echo -e "${C_CRITICAL}" ;;
        high) echo -e "${C_HIGH}" ;;
        medium) echo -e "${C_MEDIUM}" ;;
        low) echo -e "${C_LOW}" ;;
        info) echo -e "${C_INFO}" ;;
        safe) echo -e "${C_SAFE}" ;;
        *) echo -e "${C_RESET}" ;;
    esac
}

function print_2title {
    echo -e "${C_YELLOW}### $1 ###############${C_RESET}"
}

function print_info {
    echo -e "${C_CYAN}[*] $1${C_RESET}"
}

function system_info {
    print_2title "SYSTEM INFORMATION"
    unameinfo=$(uname -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Kernel information:${C_RESET}\n$unameinfo"
    else
        echo -e "${C_RED}[!] Failed to retrieve kernel information.${C_RESET}"
    fi
    echo -e "\n"

    echo -e "$(get_color info)[-] OS Release:${C_RESET}"
    cat /etc/os-release 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve OS release information.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color safe)[-] Hostname:${C_RESET}"
    hostname 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve hostname.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color safe)[-] Uptime:${C_RESET}"
    uptime 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve uptime.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color info)[-] CPU Information:${C_RESET}"
    lscpu 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve CPU information.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color info)[-] Memory Information:${C_RESET}"
    free -h 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve memory information.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color info)[-] Disk Usage:${C_RESET}"
    df -h 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve disk usage information.${C_RESET}"
    echo -e "\n"
}

function user_info {
    print_2title "USER/GROUP INFORMATION"
    currusr=$(id 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Current user/group info:${C_RESET}\n$currusr"
    else
        echo -e "${C_RED}[!] Failed to retrieve current user/group information.${C_RESET}"
    fi
    echo -e "\n"
    
    echo -e "$(get_color high)[-] Sudo privileges:${C_RESET}"
    sudo -l 2>/dev/null || echo -e "${C_RED}[!] Failed to check sudo privileges.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color medium)[-] All users:${C_RESET}"
    cat /etc/passwd 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve user list.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color medium)[-] All groups:${C_RESET}"
    cat /etc/group 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve group list.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color high)[-] SUID/SGID files:${C_RESET}"
    find / -perm -4000 -o -perm -2000 2>/dev/null | head -n 20 || echo -e "${C_RED}[!] Failed to find SUID/SGID files.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color high)[-] World-writable files:${C_RESET}"
    find / -perm -2 -type f 2>/dev/null | head -n 20 || echo -e "${C_RED}[!] Failed to find world-writable files.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color critical)[-] Readable /etc/shadow:${C_RESET}"
    if [ -r /etc/shadow ]; then
        echo -e "${C_RED}[!] /etc/shadow is readable!${C_RESET}"
    else
        echo -e "${C_GREEN}[+] /etc/shadow is not readable.${C_RESET}"
    fi
    echo -e "\n"
}

function networking_info {
    print_2title "NETWORKING INFORMATION"
    nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color info)[-] Network and IP info:${C_RESET}\n$nicinfo"
    else
        echo -e "${C_RED}[!] Failed to retrieve network information.${C_RESET}"
    fi
    echo -e "\n"

    echo -e "$(get_color high)[-] Open ports:${C_RESET}"
    netstat -tuln 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve open ports.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color medium)[-] Routing table:${C_RESET}"
    route -n 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve routing table.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color medium)[-] ARP table:${C_RESET}"
    arp -a 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve ARP table.${C_RESET}"
    echo -e "\n"

    echo -e "$(get_color high)[-] Active connections:${C_RESET}"
    ss -tuln 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve active connections.${C_RESET}"
    echo -e "\n"
}

function check_nmap {
    if command -v nmap &> /dev/null; then
        print_2title "NMAP SCAN"
        echo -e "$(get_color critical)[+] Nmap is available. Performing a scan on the machine's IP address...${C_RESET}"
        
        ip_address=$(hostname -I | awk '{print $1}')
        if [ -z "$ip_address" ]; then
            echo -e "${C_RED}[!] Could not determine the machine's IP address.${C_RESET}"
            return
        fi

        echo -e "$(get_color info)[-] Scanning IP address: $ip_address${C_RESET}"
        nmap -sV $ip_address
    else
        print_2title "NMAP SCAN"
        echo -e "$(get_color info)[-] Nmap is not installed. Skipping Nmap scan.${C_RESET}"
    fi
}

function check_kernel_cves {
    print_2title "CHECKING CVES BASED ON KERNEL"
    echo -e "$(get_color critical)[+] Checking for known CVEs related to the current kernel...${C_RESET}"

    kernel_version=$(uname -r)
    echo -e "$(get_color info)[-] Current kernel version: $kernel_version${C_RESET}"

    echo -e "$(get_color high)[-] Searching Google and ExploitDB for kernel-related exploits...${C_RESET}"
    echo -e "${C_BLUE} Google Search: https://www.google.com/search?q=exploit+kernel+$kernel_version${C_RESET}"
    echo -e "${C_BLUE} ExploitDB Search: https://www.exploit-db.com/search?q=kernel+$kernel_version${C_RESET}"

    if [[ $kernel_version =~ "4.4" || $kernel_version =~ "4.8" || $kernel_version =~ "4.9" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2017-5753 (Spectre) vulnerability...${C_RESET}"
    fi

    if [[ $kernel_version =~ "3.8" || $kernel_version =~ "3.10" || $kernel_version =~ "4.4" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2017-1000253 (Dirty COW) vulnerability...${C_RESET}"
    fi

    if [[ $kernel_version =~ "4.19" || $kernel_version =~ "5.4" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2021-3490 (Polkit Privilege Escalation) vulnerability...${C_RESET}"
    fi

    if [[ $kernel_version =~ "5.10" || $kernel_version =~ "5.11" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2021-4034 (PwnKit) vulnerability...${C_RESET}"
    fi

    echo ""
}

function linux_exploit_suggester {
    print_2title "LINUX EXPLOIT SUGGESTER"
    
    if [ "$(command -v bash 2>/dev/null)" ] && [ -z "$MACPEAS" ]; then
        print_info "Executing Linux Exploit Suggester"
        print_info "https://github.com/mzet-/linux-exploit-suggester"

        # Define the URL for Linux Exploit Suggester
        les_url="https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"

        # Download and execute the script
        curl -fsSL "$les_url" | bash | \
            sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" | \
            grep -i "\[CVE" -A 10 | \
            grep -Ev "^\-\-$" | \
            sed -E "s/\[(CVE-[0-9]+-[0-9]+,?)+\].*/${SED_RED}/g"

        echo ""
    else
        echo -e "${C_RED}Linux Exploit Suggester cannot be executed. Either 'bash' is unavailable, or 'MACPEAS' is set.${C_RESET}"
    fi
}

###########################################
#---------------) Main (------------------#
###########################################

function main {
    banner
    system_info
    networking_info
    check_nmap
    user_info
    check_kernel_cves
    linux_exploit_suggester
}

# Parse command line options
while getopts "hsfenu" option; do
    case "${option}" in
        h) usage; exit;;
        s) quick_scan; exit;;
        f) main; exit;;
        e) linux_exploit_suggester; check_kernel_cves; exit;;
        n) networking_info; check_nmap; exit;;
        u) user_info; exit;;
        *) usage; exit;;
    esac
done

# Run the script
main
