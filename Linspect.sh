#!/bin/bash

# Linespect - Linux Enumeration & Privilege Escalation Tool
# Author: MIDO
# Version: v1.0
# Description: A comprehensive tool for Linux system enumeration, privilege escalation, and exploit suggestion.

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
    echo -e "  ██╗     ██╗███╗   ██╗███████╗███████╗██████╗ ███████╗ ██████ ████████╗  "
    echo -e "  ██║     ██║████╗  ██║██╔════╝██╔════╝██╔═██╗ ██╔═ ═══╝██╔════╚══██╔══╝"
    echo -e "  ██║     ██║██╔██╗ ██║█████╗  ███████╗██████╔╝███████╗ ██║       ██║   "
    echo -e "  ██║     ██║██║╚██╗██║██╔══╝  ╚════██║██╔═══╝ ██      ║██║       ██║   "
    echo -e "  ███████╗██║██║  ████║███████╗███████║██║     ███████║╚██████    ██║   "
    echo -e "  ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   "
    echo -e "${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
    echo -e "${C_BLUE}##      Linux Enumeration & Privilege Escalation       ##${C_RESET}"
    echo -e "${C_RED}###############     Coded by MIDO         ########${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
}

###########################################
#---------------) Usage (-----------------#
###########################################

function usage {
    banner
    echo -e "${C_YELLOW}# Example: ./Linespect.sh${C_RESET}\n"
    echo "OPTIONS:"
    echo "-h    Displays this help text"
    echo "-s    Perform a quick system scan"
    echo "-f    Perform a full system scan (includes all checks)"
    echo "-e    Perform exploit checks only"
    echo "-n    Perform network checks only"
    echo "-u    Perform user and group checks only"
    echo "-t    Perform thorough scans (longer runtime)"
    echo "-k    Search for a specific keyword in config/log files"
    echo "-r    Save output to a report file"
    echo "-o    Export findings to a directory"
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
    echo -e "${C_BLUE}[~] $1${C_RESET}"
}

###########################################
#---------------) System Info (-----------#
###########################################

function check_command {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed."
        return 1
    fi
    return 0
}

function check_sudo_version {
    echo -e "$(get_color info)[-] Sudo Version:${C_RESET}"
    sudo -V | head -n 1 2>/dev/null || print_error "Failed to retrieve sudo version."
    echo -e "\n"
}

function check_path {
    echo -e "$(get_color info)[-] PATH:${C_RESET}"
    echo $PATH 2>/dev/null || print_error "Failed to retrieve PATH."
    echo -e "\n"
}

function system_info {
    print_2title "SYSTEM INFORMATION"
    
    # Existing checks
    unameinfo=$(uname -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Kernel information:${C_RESET}\n$unameinfo"
    else
        print_error "Failed to retrieve kernel information."
    fi
    echo -e "\n"

    echo -e "$(get_color info)[-] OS Release:${C_RESET}"
    cat /etc/os-release 2>/dev/null | head -n 15 || print_error "Failed to retrieve OS release information."
    echo -e "\n"

    echo -e "$(get_color safe)[-] Hostname:${C_RESET}"
    hostname 2>/dev/null || print_error "Failed to retrieve hostname."
    echo -e "\n"

    echo -e "$(get_color safe)[-] Uptime:${C_RESET}"
    uptime 2>/dev/null || print_error "Failed to retrieve uptime."
    echo -e "\n"

    if check_command "lscpu"; then
        echo -e "$(get_color info)[-] CPU Information:${C_RESET}"
        lscpu 2>/dev/null | head -n 15 || print_error "Failed to retrieve CPU information."
        echo -e "\n"
    fi

    echo -e "$(get_color info)[-] Memory Information:${C_RESET}"
    free -h 2>/dev/null || print_error "Failed to retrieve memory information."
    echo -e "\n"

    echo -e "$(get_color info)[-] Disk Usage:${C_RESET}"
    df -h 2>/dev/null | head -n 15 || print_error "Failed to retrieve disk usage information."
    echo -e "\n"

    # New checks
    check_sudo_version
    check_path

    echo -e "$(get_color info)[-] Date & Uptime:${C_RESET}"
    date 2>/dev/null || print_error "Failed to retrieve date."
    uptime 2>/dev/null || print_error "Failed to retrieve uptime."
    echo -e "\n"

    echo -e "$(get_color info)[-] Unmounted File Systems:${C_RESET}"
    cat /etc/fstab 2>/dev/null | head -n 15 || print_error "Failed to retrieve unmounted file systems."
    echo -e "\n"

    echo -e "$(get_color info)[-] Disk Information:${C_RESET}"
    print_progress "Retrieving disk information, this may take a moment..."
    lsblk 2>/dev/null | head -n 15 || print_error "Failed to retrieve disk information."
    echo -e "\n"

    echo -e "$(get_color info)[-] Environment Variables:${C_RESET}"
    env 2>/dev/null | head -n 15 || print_error "Failed to retrieve environment variables."
    echo -e "\n"

    # Unexpected files in /opt
    echo -e "$(get_color high)[-] Unexpected files in /opt:${C_RESET}"
    ls -la /opt 2>/dev/null | head -n 15 || print_error "Failed to list /opt directory."
    echo -e "\n"

    # Unexpected files in root
    echo -e "$(get_color high)[-] Unexpected files in root:${C_RESET}"
    ls -la / | grep -E 'swapfile|initrd.img|vmlinuz' 2>/dev/null | head -n 15 || print_error "Failed to list unexpected files in root."
    echo -e "\n"

    # Modified interesting files in the last 5 minutes
    echo -e "$(get_color high)[-] Modified interesting files in the last 5 minutes:${C_RESET}"
    print_progress "Searching for modified files, this may take a moment..."
    find / -type f -mmin -5 2>/dev/null | head -n 15 || print_error "Failed to find modified files."
    echo -e "\n"

    # Searching for passwords in history files
    echo -e "$(get_color critical)[-] Searching for passwords in history files:${C_RESET}"
    print_progress "Searching for passwords in history files, this may take a moment..."
    history_files=("$HOME/.bash_history" "$HOME/.zsh_history" "/root/.bash_history" "/root/.zsh_history")
    found_passwords=0
    for history_file in "${history_files[@]}"; do
        if [ -f "$history_file" ]; then
            echo -e "${C_YELLOW}Checking $history_file:${C_RESET}"
            grep -Ei 'pass|pwd|secret|token|key|credential' "$history_file" 2>/dev/null | while read -r line; do
                echo -e "${C_RED}[!] Potential password found:${C_RESET} $line"
                found_passwords=1
            done
        else
            print_error "History file $history_file not found."
        fi
    done
    if [ $found_passwords -eq 0 ]; then
        print_good "No passwords found in history files."
    fi
    echo -e "\n"
}

###########################################
#---------------) User Info (-------------#
###########################################

function user_info {
    print_2title "USER/GROUP INFORMATION"
    
    # Existing checks
    currusr=$(id 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Current user/group info:${C_RESET}\n$currusr"
    else
        print_error "Failed to retrieve current user/group information."
    fi
    echo -e "\n"
    
    echo -e "$(get_color high)[-] Sudo privileges:${C_RESET}"
    sudo -l 2>/dev/null | head -n 15 || print_error "Failed to check sudo privileges."
    echo -e "\n"

    echo -e "$(get_color medium)[-] All users:${C_RESET}"
    cat /etc/passwd 2>/dev/null | head -n 15 || print_error "Failed to retrieve user list."
    echo -e "\n"

    echo -e "$(get_color medium)[-] All groups:${C_RESET}"
    cat /etc/group 2>/dev/null | head -n 15 || print_error "Failed to retrieve group list."
    echo -e "\n"

    echo -e "$(get_color high)[-] SUID/SGID files:${C_RESET}"
    print_progress "Searching for SUID/SGID files, this may take a moment..."
    find / -perm -4000 -o -perm -2000 2>/dev/null | head -n 15 || print_error "Failed to find SUID/SGID files."
    echo -e "\n"

    echo -e "$(get_color high)[-] World-writable files:${C_RESET}"
    print_progress "Searching for world-writable files, this may take a moment..."
    find / -perm -2 -type f 2>/dev/null | head -n 15 || print_error "Failed to find world-writable files."
    echo -e "\n"

    echo -e "$(get_color critical)[-] Readable /etc/shadow:${C_RESET}"
    if [ -r /etc/shadow ]; then
        print_error "/etc/shadow is readable!"
    else
        print_good "/etc/shadow is not readable."
    fi
    echo -e "\n"

    # New checks
    echo -e "$(get_color info)[-] PGP Keys:${C_RESET}"
    gpg --list-keys 2>/dev/null | head -n 15 || print_error "No PGP keys found."
    echo -e "\n"

    echo -e "$(get_color info)[-] Sudo Tokens:${C_RESET}"
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    if [ "$ptrace_scope" == "0" ]; then
        print_error "ptrace protection is disabled, sudo tokens could be abused."
    else
        print_good "ptrace protection is enabled."
    fi
    echo -e "\n"

    echo -e "$(get_color info)[-] Pkexec Policy:${C_RESET}"
    pkexec --version 2>/dev/null || print_error "Pkexec not found."
    echo -e "\n"

    echo -e "$(get_color info)[-] Superusers:${C_RESET}"
    grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 {print $1}' 2>/dev/null | head -n 15 || print_error "Failed to retrieve superusers."
    echo -e "\n"

    echo -e "$(get_color info)[-] Users with Console:${C_RESET}"
    grep -E "sh$|bash$" /etc/passwd 2>/dev/null | head -n 15 || print_error "Failed to retrieve users with console."
    echo -e "\n"
}

###########################################
#---------------) Networking Info (-------#
###########################################

function networking_info {
    print_2title "NETWORKING INFORMATION"
    
    # Existing checks
    nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color info)[-] Network and IP info:${C_RESET}\n$nicinfo"
    else
        print_error "Failed to retrieve network information."
    fi
    echo -e "\n"

    echo -e "$(get_color high)[-] Open ports:${C_RESET}"
    netstat -tuln 2>/dev/null | head -n 15 || print_error "Failed to retrieve open ports."
    echo -e "\n"

    echo -e "$(get_color medium)[-] Routing table:${C_RESET}"
    route -n 2>/dev/null | head -n 15 || print_error "Failed to retrieve routing table."
    echo -e "\n"

    echo -e "$(get_color medium)[-] ARP table:${C_RESET}"
    arp -a 2>/dev/null | head -n 15 || print_error "Failed to retrieve ARP table."
    echo -e "\n"

    echo -e "$(get_color high)[-] Active connections:${C_RESET}"
    ss -tuln 2>/dev/null | head -n 15 || print_error "Failed to retrieve active connections."
    echo -e "\n"

    # New checks
    echo -e "$(get_color info)[-] Can I sniff with tcpdump?:${C_RESET}"
    if command -v tcpdump &> /dev/null; then
        print_good "You can sniff with tcpdump!"
    else
        print_error "tcpdump not found."
    fi
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

function export_results {
    local output_file=$1
    {
        system_info
        networking_info
        user_info
        linux_exploit_suggester
    } > "$output_file"
    print_good "Results exported to $output_file"
}

function main {
    banner
    system_info
    networking_info
    user_info
    linux_exploit_suggester
}

# Parse command line options
while getopts "hsfenutk:r:o:" option; do
    case "${option}" in
        h) usage; exit;;
        s) quick_scan; exit;;
        f) main; exit;;
        e) linux_exploit_suggester; exit;;
        n) networking_info; exit;;
        u) user_info; exit;;
        t) thorough=1;;
        k) keyword=${OPTARG};;
        r) report=${OPTARG};;
        o) export=${OPTARG};;
        *) usage; exit;;
    esac
done

# Run the script
main
