#!/bin/bash

# Linspect - Advanced Linux Enumeration & Privilege Escalation Tool
# Author: LIONMAD
# Version: v1.0
# Description: Comprehensive tool for Linux system enumeration, privilege escalation, 
#              exploit suggestion, and security auditing with enhanced features.

###########################################
#---------------) Colors (----------------
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
    echo -e "  ██╗     ██╗███╗   ██╗███████╗███████╗██████╗ ███████╗ ██████ ████████╗  "
    echo -e "  ██║     ██║████╗  ██║██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝"
    echo -e "  ██║     ██║██╔██╗ ██║█████╗  ███████╗██████╔╝███████╗██║        ██║   "
    echo -e "  ██║     ██║██║╚██╗██║██╔══╝  ╚════██║██╔═══╝ ╚════██║██║        ██║   "
    echo -e "  ███████╗██║██║ ╚████║███████╗███████║██║     ███████║╚██████╗   ██║   "
    echo -e "  ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   "
    echo -e "${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
    echo -e "${C_BLUE}##      Advanced Linux Enumeration & PrivEsc Tool     ##${C_RESET}"
    echo -e "${C_RED}###############     Coded by LIONMAD       ##############${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
    echo -e "${C_YELLOW}# Version: 1	².0 | Last Updated: $(date +'%Y-%m-%d')${C_RESET}"
    echo -e ""
}

###########################################
#---------------) Usage (-----------------#
###########################################

function usage {
    banner
    echo -e "${C_YELLOW}Usage: ./Linspect.sh [options]${C_RESET}\n"
    echo "OPTIONS:"
    echo "-h    Display this help text"
    echo "-s    Perform a quick system scan (fast mode)"
    echo "-f    Perform a full system scan (includes all checks)"
    echo "-e    Perform exploit checks only"
    echo "-n    Perform network checks only"
    echo "-u    Perform user and group checks only"
    echo "-c    Perform configuration file checks"
    echo "-p    Perform process and service checks"
    echo "-a    Perform all checks (same as -f)"
    echo "-t    Perform thorough scans (longer runtime)"
    echo "-k    Search for a specific keyword in config/log files"
    echo "-r    Save output to a report file (specify filename)"
    echo "-o    Export findings to a directory (specify path)"
    echo "-v    Enable verbose mode (more detailed output)"
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

function print_good {
    echo -e "${C_GREEN}[+] $1${C_RESET}"
}

function print_error {
    echo -e "${C_RED}[!] $1${C_RESET}"
}

function print_waiting {
    echo -e "${C_BLUE}[~] $1${C_RESET}"
}

function print_progress {
    if [ "$verbose" == "1" ]; then
        echo -e "${C_BLUE}[~] $1${C_RESET}"
    fi
}

function check_command {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed."
        return 1
    fi
    return 0
}

###########################################
#---------------) System Info (-----------#
###########################################

function system_info {
    print_2title "SYSTEM INFORMATION"
    
    # Kernel information
    unameinfo=$(uname -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Kernel information:${C_RESET}\n$unameinfo"
    else
        print_error "Failed to retrieve kernel information."
    fi
    echo -e "\n"

    # OS Release
    echo -e "$(get_color info)[-] OS Release:${C_RESET}"
    if [ -f /etc/os-release ]; then
        cat /etc/os-release 2>/dev/null | head -n 15
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release 2>/dev/null
    elif [ -f /etc/centos-release ]; then
        cat /etc/centos-release 2>/dev/null
    else
        print_error "Failed to retrieve OS release information."
    fi
    echo -e "\n"

    # Hostname
    echo -e "$(get_color safe)[-] Hostname:${C_RESET}"
    hostname 2>/dev/null || print_error "Failed to retrieve hostname."
    echo -e "\n"

    # Uptime
    echo -e "$(get_color safe)[-] Uptime:${C_RESET}"
    uptime 2>/dev/null || print_error "Failed to retrieve uptime."
    echo -e "\n"

    # CPU Information
    if check_command "lscpu"; then
        echo -e "$(get_color info)[-] CPU Information:${C_RESET}"
        lscpu 2>/dev/null | head -n 15 || print_error "Failed to retrieve CPU information."
    else
        echo -e "$(get_color info)[-] CPU Information:${C_RESET}"
        cat /proc/cpuinfo 2>/dev/null | grep -E "model name|cores|MHz" | head -n 6
    fi
    echo -e "\n"

    # Memory Information
    echo -e "$(get_color info)[-] Memory Information:${C_RESET}"
    if check_command "free"; then
        free -h 2>/dev/null || print_error "Failed to retrieve memory information."
    else
        cat /proc/meminfo 2>/dev/null | grep -E "MemTotal|MemFree|MemAvailable" || print_error "Failed to retrieve memory information."
    fi
    echo -e "\n"

    # Disk Usage
    echo -e "$(get_color info)[-] Disk Usage:${C_RESET}"
    if check_command "df"; then
        df -h 2>/dev/null || print_error "Failed to retrieve disk usage information."
    else
        cat /proc/partitions 2>/dev/null || print_error "Failed to retrieve disk information."
    fi
    echo -e "\n"

    # Sudo Version
    echo -e "$(get_color info)[-] Sudo Version:${C_RESET}"
    sudo -V | head -n 1 2>/dev/null || print_error "Failed to retrieve sudo version."
    echo -e "\n"

    # PATH
    echo -e "$(get_color info)[-] PATH:${C_RESET}"
    echo $PATH 2>/dev/null || print_error "Failed to retrieve PATH."
    echo -e "\n"

    # Date & Time
    echo -e "$(get_color info)[-] Date & Time:${C_RESET}"
    date 2>/dev/null || print_error "Failed to retrieve date."
    echo -e "\n"

    # Unmounted File Systems
    echo -e "$(get_color info)[-] Unmounted File Systems:${C_RESET}"
    cat /etc/fstab 2>/dev/null | head -n 15 || print_error "Failed to retrieve unmounted file systems."
    echo -e "\n"

    # Disk Information
    echo -e "$(get_color info)[-] Disk Information:${C_RESET}"
    print_progress "Retrieving disk information..."
    if check_command "lsblk"; then
        lsblk 2>/dev/null || print_error "Failed to retrieve disk information."
    else
        fdisk -l 2>/dev/null | head -n 15 || print_error "Failed to retrieve disk information."
    fi
    echo -e "\n"

    # Environment Variables
    echo -e "$(get_color info)[-] Environment Variables:${C_RESET}"
    env 2>/dev/null | head -n 15 || print_error "Failed to retrieve environment variables."
    echo -e "\n"

    # Unexpected files in /opt
    echo -e "$(get_color high)[-] Unexpected files in /opt:${C_RESET}"
    ls -la /opt 2>/dev/null | head -n 15 || print_error "Failed to list /opt directory."
    echo -e "\n"

    # Unexpected files in root
    echo -e "$(get_color high)[-] Unexpected files in root:${C_RESET}"
    ls -la / | grep -E 'swapfile|initrd.img|vmlinuz' 2>/dev/null || print_error "Failed to list unexpected files in root."
    echo -e "\n"

    # Modified interesting files in the last 5 minutes
    echo -e "$(get_color high)[-] Modified interesting files in the last 5 minutes:${C_RESET}"
    print_progress "Searching for modified files..."
    find / -type f -mmin -5 \( -name "*.sh" -o -name "*.py" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" \) 2>/dev/null | head -n 15 || print_error "Failed to find modified files."
    echo -e "\n"

    # Searching for passwords in history files
    echo -e "$(get_color critical)[-] Searching for passwords in history files:${C_RESET}"
    print_progress "Searching for passwords in history files..."
    history_files=("$HOME/.bash_history" "$HOME/.zsh_history" "/root/.bash_history" "/root/.zsh_history")
    found_passwords=0
    for history_file in "${history_files[@]}"; do
        if [ -f "$history_file" ]; then
            echo -e "${C_YELLOW}Checking $history_file:${C_RESET}"
            grep -Ei 'pass|pwd|secret|token|key|credential|api' "$history_file" 2>/dev/null | while read -r line; do
                echo -e "${C_RED}[!] Potential sensitive data found:${C_RESET} $line"
                found_passwords=1
            done
        else
            print_error "History file $history_file not found."
        fi
    done
    if [ $found_passwords -eq 0 ]; then
        print_good "No sensitive data found in history files."
    fi
    echo -e "\n"

    # Check for Docker
    echo -e "$(get_color info)[-] Docker Information:${C_RESET}"
    if check_command "docker"; then
        print_good "Docker is installed"
        docker --version 2>/dev/null
        echo -e "\n[-] Docker Containers:"
        docker ps -a 2>/dev/null | head -n 5
        echo -e "\n[-] Docker Images:"
        docker images 2>/dev/null | head -n 5
    else
        print_error "Docker is not installed"
    fi
    echo -e "\n"

    # Check for Kubernetes
    echo -e "$(get_color info)[-] Kubernetes Information:${C_RESET}"
    if check_command "kubectl"; then
        print_good "kubectl is installed"
        kubectl version --short 2>/dev/null
        echo -e "\n[-] Kubernetes Pods:"
        kubectl get pods --all-namespaces 2>/dev/null | head -n 5
    else
        print_error "kubectl is not installed"
    fi
    echo -e "\n"

    # Check for LXC/LXD
    echo -e "$(get_color info)[-] LXC/LXD Information:${C_RESET}"
    if check_command "lxc"; then
        print_good "LXC is installed"
        lxc --version 2>/dev/null
        echo -e "\n[-] LXC Containers:"
        lxc list 2>/dev/null | head -n 5
    else
        print_error "LXC is not installed"
    fi
    echo -e "\n"
}

###########################################
#---------------) User Info (-------------#
###########################################

function user_info {
    print_2title "USER/GROUP INFORMATION"
    
    # Current user/group info
    currusr=$(id 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Current user/group info:${C_RESET}\n$currusr"
    else
        print_error "Failed to retrieve current user/group information."
    fi
    echo -e "\n"
    
    # Sudo privileges
    echo -e "$(get_color high)[-] Sudo privileges:${C_RESET}"
    if [ "$(whoami)" != "root" ]; then
        sudo -l 2>/dev/null || print_error "Failed to check sudo privileges."
    else
        print_info "Already root, skipping sudo checks"
    fi
    echo -e "\n"

    # All users
    echo -e "$(get_color medium)[-] All users:${C_RESET}"
    if [ -f /etc/passwd ]; then
        cat /etc/passwd 2>/dev/null | cut -d: -f1,3,7 | column -t -s: | head -n 15 || print_error "Failed to retrieve user list."
    else
        print_error "/etc/passwd not found"
    fi
    echo -e "\n"

    # All groups
    echo -e "$(get_color medium)[-] All groups:${C_RESET}"
    if [ -f /etc/group ]; then
        cat /etc/group 2>/dev/null | cut -d: -f1,3 | column -t -s: | head -n 15 || print_error "Failed to retrieve group list."
    else
        print_error "/etc/group not found"
    fi
    echo -e "\n"

    # SUID/SGID files
    echo -e "$(get_color high)[-] SUID/SGID files:${C_RESET}"
    print_progress "Searching for SUID/SGID files..."
    find / -perm -4000 -o -perm -2000 2>/dev/null | xargs -I {} ls -la {} 2>/dev/null | head -n 15 || print_error "Failed to find SUID/SGID files."
    echo -e "\n"

    # World-writable files
    echo -e "$(get_color high)[-] World-writable files:${C_RESET}"
    print_progress "Searching for world-writable files..."
    find / -perm -2 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -n 15 || print_error "Failed to find world-writable files."
    echo -e "\n"

    # Readable /etc/shadow
    echo -e "$(get_color critical)[-] Readable /etc/shadow:${C_RESET}"
    if [ -r /etc/shadow ]; then
        print_error "/etc/shadow is readable!"
        echo -e "First 5 lines of /etc/shadow:"
        head -n 5 /etc/shadow 2>/dev/null
    else
        print_good "/etc/shadow is not readable."
    fi
    echo -e "\n"

    # PGP Keys
    echo -e "$(get_color info)[-] PGP Keys:${C_RESET}"
    if check_command "gpg"; then
        gpg --list-keys 2>/dev/null | head -n 15 || print_info "No PGP keys found."
    else
        print_error "gpg not found"
    fi
    echo -e "\n"

    # Sudo Tokens
    echo -e "$(get_color info)[-] Sudo Tokens:${C_RESET}"
    if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
        ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
        if [ "$ptrace_scope" == "0" ]; then
            print_error "ptrace protection is disabled, sudo tokens could be abused."
        else
            print_good "ptrace protection is enabled."
        fi
    else
        print_info "ptrace_scope file not found"
    fi
    echo -e "\n"

    # Pkexec Policy
    echo -e "$(get_color info)[-] Pkexec Policy:${C_RESET}"
    if check_command "pkexec"; then
        pkexec --version 2>/dev/null || print_error "Pkexec not found."
    else
        print_error "pkexec not found"
    fi
    echo -e "\n"

    # Superusers
    echo -e "$(get_color info)[-] Superusers:${C_RESET}"
    grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 {print $1}' 2>/dev/null || print_error "Failed to retrieve superusers."
    echo -e "\n"

    # Users with Console
    echo -e "$(get_color info)[-] Users with Console:${C_RESET}"
    grep -E "sh$|bash$" /etc/passwd 2>/dev/null || print_error "Failed to retrieve users with console."
    echo -e "\n"

    # Recent logins
    echo -e "$(get_color info)[-] Recent logins:${C_RESET}"
    if check_command "last"; then
        last -n 10 2>/dev/null || print_error "Failed to retrieve recent logins."
    else
        print_error "last command not found"
    fi
    echo -e "\n"

    # Failed login attempts
    echo -e "$(get_color info)[-] Failed login attempts:${C_RESET}"
    if [ -f /var/log/auth.log ]; then
        grep -i "failed" /var/log/auth.log 2>/dev/null | tail -n 5 || print_info "No failed login attempts found."
    elif [ -f /var/log/secure ]; then
        grep -i "failed" /var/log/secure 2>/dev/null | tail -n 5 || print_info "No failed login attempts found."
    else
        print_error "Could not find auth log file"
    fi
    echo -e "\n"

    # SSH authorized keys
    echo -e "$(get_color info)[-] SSH authorized keys:${C_RESET}"
    find /home /root -name authorized_keys -type f 2>/dev/null | while read -r keyfile; do
        echo -e "${C_YELLOW}Found authorized_keys in $keyfile:${C_RESET}"
        cat "$keyfile" | head -n 3
    done
    echo -e "\n"

    # Password policy
    echo -e "$(get_color info)[-] Password policy:${C_RESET}"
    if [ -f /etc/login.defs ]; then
        grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs 2>/dev/null || print_info "No password policy found in login.defs."
    else
        print_error "/etc/login.defs not found"
    fi
    echo -e "\n"
}

###########################################
#---------------) Networking Info (-------#
###########################################

function networking_info {
    print_2title "NETWORKING INFORMATION"
    
    # Network and IP info
    if check_command "ip"; then
        echo -e "$(get_color info)[-] Network and IP info:${C_RESET}"
        ip a 2>/dev/null || print_error "Failed to retrieve network information."
    else
        nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo -e "$(get_color info)[-] Network and IP info:${C_RESET}\n$nicinfo"
        else
            print_error "Failed to retrieve network information."
        fi
    fi
    echo -e "\n"

    # Open ports
    echo -e "$(get_color high)[-] Open ports:${C_RESET}"
    if check_command "ss"; then
        ss -tuln 2>/dev/null | head -n 15 || print_error "Failed to retrieve open ports."
    elif check_command "netstat"; then
        netstat -tuln 2>/dev/null | head -n 15 || print_error "Failed to retrieve open ports."
    else
        print_error "Neither ss nor netstat commands found"
    fi
    echo -e "\n"

    # Routing table
    echo -e "$(get_color medium)[-] Routing table:${C_RESET}"
    if check_command "ip"; then
        ip route 2>/dev/null || print_error "Failed to retrieve routing table."
    elif check_command "route"; then
        route -n 2>/dev/null || print_error "Failed to retrieve routing table."
    else
        print_error "Neither ip nor route commands found"
    fi
    echo -e "\n"

    # ARP table
    echo -e "$(get_color medium)[-] ARP table:${C_RESET}"
    if check_command "ip"; then
        ip neigh 2>/dev/null || print_error "Failed to retrieve ARP table."
    elif check_command "arp"; then
        arp -a 2>/dev/null || print_error "Failed to retrieve ARP table."
    else
        print_error "Neither ip neigh nor arp commands found"
    fi
    echo -e "\n"

    # Active connections
    echo -e "$(get_color high)[-] Active connections:${C_RESET}"
    if check_command "ss"; then
        ss -tunp 2>/dev/null | head -n 15 || print_error "Failed to retrieve active connections."
    elif check_command "netstat"; then
        netstat -tunp 2>/dev/null | head -n 15 || print_error "Failed to retrieve active connections."
    else
        print_error "Neither ss nor netstat commands found"
    fi
    echo -e "\n"

    # Can I sniff with tcpdump?
    echo -e "$(get_color info)[-] Can I sniff with tcpdump?:${C_RESET}"
    if command -v tcpdump &> /dev/null; then
        print_good "tcpdump is available!"
        if [ "$(id -u)" == "0" ]; then
            print_error "Running as root - could sniff all traffic!"
        else
            print_info "Not running as root - sniffing capabilities may be limited"
        fi
    else
        print_error "tcpdump not found."
    fi
    echo -e "\n"

    # DNS information
    echo -e "$(get_color info)[-] DNS Information:${C_RESET}"
    if [ -f /etc/resolv.conf ]; then
        cat /etc/resolv.conf 2>/dev/null || print_error "Failed to retrieve DNS information."
    else
        print_error "/etc/resolv.conf not found"
    fi
    echo -e "\n"

    # Hosts file
    echo -e "$(get_color info)[-] Hosts file:${C_RESET}"
    if [ -f /etc/hosts ]; then
        cat /etc/hosts 2>/dev/null || print_error "Failed to retrieve hosts file."
    else
        print_error "/etc/hosts not found"
    fi
    echo -e "\n"

    # iptables rules
    echo -e "$(get_color info)[-] iptables rules:${C_RESET}"
    if check_command "iptables"; then
        iptables -L -n -v 2>/dev/null | head -n 20 || print_error "Failed to retrieve iptables rules."
    else
        print_error "iptables not found"
    fi
    echo -e "\n"

    # Check for listening services on localhost only
    echo -e "$(get_color info)[-] Services listening on localhost only:${C_RESET}"
    if check_command "ss"; then
        ss -tuln | grep '127.0.0.1' 2>/dev/null || print_info "No services listening on localhost only."
    elif check_command "netstat"; then
        netstat -tuln | grep '127.0.0.1' 2>/dev/null || print_info "No services listening on localhost only."
    fi
    echo -e "\n"

    # Check for unusual outbound connections
    echo -e "$(get_color high)[-] Unusual outbound connections:${C_RESET}"
    if check_command "ss"; then
        ss -tunp | grep -E 'ESTAB|SYN-SENT' | grep -v '127.0.0.1' 2>/dev/null || print_info "No unusual outbound connections found."
    elif check_command "netstat"; then
        netstat -tunp | grep -E 'ESTABLISHED|SYN_SENT' | grep -v '127.0.0.1' 2>/dev/null || print_info "No unusual outbound connections found."
    fi
    echo -e "\n"
}

###########################################
#---------------) Process Info (----------#
###########################################

function process_info {
    print_2title "PROCESS INFORMATION"
    
    # Running processes
    echo -e "$(get_color info)[-] Running processes:${C_RESET}"
    if check_command "ps"; then
        ps aux 2>/dev/null | head -n 15 || print_error "Failed to retrieve running processes."
    else
        print_error "ps command not found"
    fi
    echo -e "\n"

    # Cron jobs
    echo -e "$(get_color high)[-] Cron jobs:${C_RESET}"
    if [ -f /etc/crontab ]; then
        echo -e "${C_YELLOW}System crontab:${C_RESET}"
        cat /etc/crontab 2>/dev/null | head -n 15 || print_error "Failed to retrieve system crontab."
    else
        print_error "/etc/crontab not found"
    fi
    echo -e "\n"

    # User crontabs
    echo -e "$(get_color high)[-] User crontabs:${C_RESET}"
    ls -la /var/spool/cron/crontabs/ 2>/dev/null || print_info "No user crontabs found in /var/spool/cron/crontabs/"
    echo -e "\n"

    # Services
    echo -e "$(get_color info)[-] Services:${C_RESET}"
    if check_command "systemctl"; then
        systemctl list-units --type=service 2>/dev/null | head -n 15 || print_error "Failed to retrieve services."
    elif check_command "service"; then
        service --status-all 2>/dev/null | head -n 15 || print_error "Failed to retrieve services."
    else
        print_error "Neither systemctl nor service commands found"
    fi
    echo -e "\n"

    # Startup applications
    echo -e "$(get_color info)[-] Startup applications:${C_RESET}"
    ls -la /etc/init.d/ 2>/dev/null | head -n 15 || print_info "No startup applications found in /etc/init.d/"
    ls -la /etc/rc*.d/ 2>/dev/null | head -n 15 || print_info "No startup applications found in /etc/rc*.d/"
    echo -e "\n"

    # Process tree
    echo -e "$(get_color info)[-] Process tree:${C_RESET}"
    if check_command "pstree"; then
        pstree 2>/dev/null | head -n 15 || print_error "Failed to retrieve process tree."
    else
        print_error "pstree command not found"
    fi
    echo -e "\n"

    # Unusual processes
    echo -e "$(get_color high)[-] Unusual processes:${C_RESET}"
    if check_command "ps"; then
        ps aux | grep -E "cryptominer|miner|backdoor|reverse_shell|bind_shell" 2>/dev/null || print_info "No unusual processes found."
    else
        print_error "ps command not found"
    fi
    echo -e "\n"

    # Process memory usage
    echo -e "$(get_color info)[-] Process memory usage:${C_RESET}"
    if check_command "ps"; then
        ps aux --sort=-%mem 2>/dev/null | head -n 10 || print_error "Failed to retrieve process memory usage."
    else
        print_error "ps command not found"
    fi
    echo -e "\n"

    # Process CPU usage
    echo -e "$(get_color info)[-] Process CPU usage:${C_RESET}"
    if check_command "ps"; then
        ps aux --sort=-%cpu 2>/dev/null | head -n 10 || print_error "Failed to retrieve process CPU usage."
    else
        print_error "ps command not found"
    fi
    echo -e "\n"
}

###########################################
#---------------) Config Files (----------#
###########################################

function config_files {
    print_2title "CONFIGURATION FILES"
    
    # SSH config
    echo -e "$(get_color info)[-] SSH config:${C_RESET}"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "PermitRootLogin|PasswordAuthentication|Port" /etc/ssh/sshd_config 2>/dev/null || print_error "Failed to retrieve SSH config."
    else
        print_error "/etc/ssh/sshd_config not found"
    fi
    echo -e "\n"

    # Interesting config files
    echo -e "$(get_color high)[-] Interesting config files:${C_RESET}"
    interesting_files=(
        "/etc/passwd" "/etc/group" "/etc/shadow" "/etc/sudoers"
        "/etc/hosts" "/etc/resolv.conf" "/etc/fstab"
        "/etc/crontab" "/etc/cron.*/*" "/etc/init.d/*"
        "/etc/syslog.conf" "/etc/chttp.conf" "/etc/lighttpd.conf"
        "/etc/squid.conf" "/etc/snmp.conf" "/etc/rsyncd.conf"
        "/etc/motd" "/etc/issue" "/etc/redhat-release"
        "/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf"
        "/etc/nginx/nginx.conf" "/etc/my.cnf" "/etc/mysql/my.cnf"
    )
    
    for file in "${interesting_files[@]}"; do
        if [ -f "$file" ]; then
            echo -e "${C_YELLOW}Found: $file${C_RESET}"
            ls -la "$file" 2>/dev/null
            if [ "$verbose" == "1" ]; then
                head -n 5 "$file" 2>/dev/null
            fi
        fi
    done
    echo -e "\n"

    # World-writable config files
    echo -e "$(get_color critical)[-] World-writable config files:${C_RESET}"
    find /etc -perm -2 -type f 2>/dev/null | head -n 15 || print_info "No world-writable config files found."
    echo -e "\n"

    # Backup files
    echo -e "$(get_color info)[-] Backup files:${C_RESET}"
    find / -name "*~" -o -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*.swp" 2>/dev/null | head -n 15 || print_info "No backup files found."
    echo -e "\n"

    # Log files
    echo -e "$(get_color info)[-] Log files:${C_RESET}"
    find /var/log -type f -exec ls -la {} \; 2>/dev/null | head -n 15 || print_error "Failed to retrieve log files."
    echo -e "\n"

    # Recent modified files
    echo -e "$(get_color high)[-] Recently modified files (last 7 days):${C_RESET}"
    find / -type f -mtime -7 2>/dev/null | grep -vE "/proc|/sys|/dev" | head -n 15 || print_error "Failed to find recently modified files."
    echo -e "\n"

    # SSH keys
    echo -e "$(get_color info)[-] SSH keys:${C_RESET}"
    find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null | head -n 15 || print_info "No SSH keys found."
    echo -e "\n"

    # Database files
    echo -e "$(get_color info)[-] Database files:${C_RESET}"
    find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -n 15 || print_info "No database files found."
    echo -e "\n"

    # Password files
    echo -e "$(get_color critical)[-] Password files:${C_RESET}"
    find / -name "*password*" -o -name "*credential*" -o -name "*secret*" 2>/dev/null | grep -vE "/proc|/sys|/dev" | head -n 15 || print_info "No password files found."
    echo -e "\n"
}

###########################################
#---------------) Exploit Suggester (-----#
###########################################

function linux_exploit_suggester {
    print_2title "LINUX EXPLOIT SUGGESTER"
    
    if [ "$(command -v bash 2>/dev/null)" ] && [ -z "$MACPEAS" ]; then
        print_info "Executing Linux Exploit Suggester"
        print_info "https://github.com/mzet-/linux-exploit-suggester"

        # Define the URL for Linux Exploit Suggester
        les_url="https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"

        # Download and execute the script
        print_progress "Downloading Linux Exploit Suggester..."
        curl -fsSL "$les_url" 2>/dev/null | bash | \
            sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" | \
            grep -i "\[CVE" -A 10 | \
            grep -Ev "^\-\-$" | \
            sed -E "s/\[(CVE-[0-9]+-[0-9]+,?)+\].*/${C_RED}&${C_RESET}/g"

        echo ""
    else
        echo -e "${C_RED}Linux Exploit Suggester cannot be executed. Either 'bash' is unavailable, or 'MACPEAS' is set.${C_RESET}"
    fi
}

###########################################
#---------------) Quick Scan (------------#
###########################################

function quick_scan {
    print_2title "QUICK SYSTEM SCAN"
    
    # Basic system info
    echo -e "$(get_color info)[-] Basic System Info:${C_RESET}"
    uname -a 2>/dev/null || print_error "Failed to retrieve kernel information."
    cat /etc/os-release 2>/dev/null | head -n 5 || print_error "Failed to retrieve OS release information."
    echo -e "\n"

    # Current user info
    echo -e "$(get_color critical)[-] Current User Info:${C_RESET}"
    id 2>/dev/null || print_error "Failed to retrieve current user information."
    sudo -l 2>/dev/null | head -n 5 || print_error "Failed to check sudo privileges."
    echo -e "\n"

    # Network info
    echo -e "$(get_color info)[-] Network Info:${C_RESET}"
    if check_command "ip"; then
        ip a 2>/dev/null | head -n 15 || print_error "Failed to retrieve network information."
    else
        /sbin/ifconfig -a 2>/dev/null | head -n 15 || print_error "Failed to retrieve network information."
    fi
    echo -e "\n"

    # Open ports
    echo -e "$(get_color high)[-] Open Ports:${C_RESET}"
    if check_command "ss"; then
        ss -tuln 2>/dev/null | head -n 10 || print_error "Failed to retrieve open ports."
    elif check_command "netstat"; then
        netstat -tuln 2>/dev/null | head -n 10 || print_error "Failed to retrieve open ports."
    fi
    echo -e "\n"

    # SUID/SGID files
    echo -e "$(get_color high)[-] SUID/SGID Files:${C_RESET}"
    find / -perm -4000 -o -perm -2000 2>/dev/null | xargs -I {} ls -la {} 2>/dev/null | head -n 10 || print_error "Failed to find SUID/SGID files."
    echo -e "\n"

    # World-writable files
    echo -e "$(get_color high)[-] World-writable Files:${C_RESET}"
    find / -perm -2 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -n 10 || print_error "Failed to find world-writable files."
    echo -e "\n"

    # Quick exploit check
    echo -e "$(get_color critical)[-] Quick Exploit Check:${C_RESET}"
    kernel_version=$(uname -r 2>/dev/null)
    if [[ "$kernel_version" == *"4.4.0-21-generic"* ]]; then
        print_error "Vulnerable to Dirty COW (CVE-2016-5195)"
    fi
    if [ -f /etc/passwd ] && [ -w /etc/passwd ]; then
        print_error "/etc/passwd is writable!"
    fi
    if [ -f /etc/shadow ] && [ -r /etc/shadow ]; then
        print_error "/etc/shadow is readable!"
    fi
    echo -e "\n"
}

###########################################
#---------------) Keyword Search (--------#
###########################################

function keyword_search {
    local keyword=$1
    print_2title "KEYWORD SEARCH: $keyword"
    
    echo -e "$(get_color info)[-] Searching in config files:${C_RESET}"
    find /etc -type f -exec grep -l "$keyword" {} \; 2>/dev/null | head -n 15 || print_info "No matches found in config files."
    echo -e "\n"

    echo -e "$(get_color info)[-] Searching in home directories:${C_RESET}"
    find /home /root -type f -exec grep -l "$keyword" {} \; 2>/dev/null | head -n 15 || print_info "No matches found in home directories."
    echo -e "\n"

    echo -e "$(get_color info)[-] Searching in log files:${C_RESET}"
    find /var/log -type f -exec grep -l "$keyword" {} \; 2>/dev/null | head -n 15 || print_info "No matches found in log files."
    echo -e "\n"

    echo -e "$(get_color info)[-] Searching in current directory:${C_RESET}"
    grep -r "$keyword" . 2>/dev/null | head -n 15 || print_info "No matches found in current directory."
    echo -e "\n"
}

###########################################
#---------------) Export Results (--------#
###########################################

function export_results {
    local output_file=$1
    {
        banner
        system_info
        networking_info
        user_info
        process_info
        config_files
        linux_exploit_suggester
    } > "$output_file"
    print_good "Results exported to $output_file"
}

function export_to_directory {
    local output_dir=$1
    mkdir -p "$output_dir" 2>/dev/null
    
    if [ $? -ne 0 ]; then
        print_error "Failed to create output directory $output_dir"
        return 1
    fi
    
    # Export each section to separate files
    system_info > "$output_dir/system_info.txt"
    networking_info > "$output_dir/networking_info.txt"
    user_info > "$output_dir/user_info.txt"
    process_info > "$output_dir/process_info.txt"
    config_files > "$output_dir/config_files.txt"
    linux_exploit_suggester > "$output_dir/exploit_suggestions.txt"
    
    print_good "Results exported to directory $output_dir"
}

###########################################
#---------------) Main (------------------#
###########################################

function main {
    banner
    
    if [ "$thorough" == "1" ]; then
        print_info "Running in thorough mode (this will take longer)..."
    fi
    
    system_info
    
    if [ "$thorough" == "1" ]; then
        print_info "Running thorough network checks..."
        networking_info
    else
        print_info "Running basic network checks..."
        networking_info
    fi
    
    user_info
    
    if [ "$thorough" == "1" ]; then
        print_info "Running thorough process checks..."
        process_info
    else
        print_info "Running basic process checks..."
        process_info
    fi
    
    config_files
    
    if [ "$thorough" == "1" ]; then
        print_info "Running thorough exploit checks..."
        linux_exploit_suggester
    else
        print_info "Running basic exploit checks..."
        linux_exploit_suggester
    fi
    
    if [ -n "$keyword" ]; then
        keyword_search "$keyword"
    fi
    
    if [ -n "$report" ]; then
        export_results "$report"
    fi
    
    if [ -n "$export" ]; then
        export_to_directory "$export"
    fi
    
    print_good "Scan completed!"
}

# Parse command line options
while getopts "hsfenucptak:r:o:v" option; do
    case "${option}" in
        h) usage; exit;;
        s) quick_scan; exit;;
        f) thorough=1;;
        e) linux_exploit_suggester; exit;;
        n) networking_info; exit;;
        u) user_info; exit;;
        c) config_files; exit;;
        p) process_info; exit;;
        a) thorough=1;;
        t) thorough=1;;
        k) keyword=${OPTARG};;
        r) report=${OPTARG};;
        o) export=${OPTARG};;
        v) verbose=1;;
        *) usage; exit;;
    esac
done

# Run the script
main
