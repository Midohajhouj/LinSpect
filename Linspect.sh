#!/bin/bash

# Color codes
C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_WHITE='\033[1;37m'
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

# Function to get color based on risk level
function get_color {
    case $1 in
        critical) echo -e $C_CRITICAL ;;
        high) echo -e $C_HIGH ;;
        medium) echo -e $C_MEDIUM ;;
        low) echo -e $C_LOW ;;
        info) echo -e $C_INFO ;;
        safe) echo -e $C_SAFE ;;
        *) echo -e $C_RESET ;;
    esac
}

# Linspect Banner
function banner {
    echo -e "${C_CYAN}"
    echo -e "  ██╗     ██╗███╗   ██╗███████╗███████╗██████╗ ███████╗ ██████╗████████╗"
    echo -e "  ██║     ██║████╗  ██║██╔════╝██╔════╝██╔═██╗ ██╔════╝██╔════╝╚══██╔══╝"
    echo -e "  ██║     ██║██╔██╗ ██║█████╗  ███████╗██████╔╝███████╗██║        ██║   "
    echo -e "  ██║     ██║██║╚██╗██║██╔══╝  ╚════██║██╔═══╝ ██     ║██║        ██║   "
    echo -e "  ███████╗██║██║ ╚████║███████╗███████║██║     ███████║╚██████╗   ██║   "
    echo -e "  ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   "
    echo -e "${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
    echo -e "${C_BLUE}##      Linux Enumeration & Privilege Escalation       ##${C_RESET}"
    echo -e "${C_RED}############### Coded by MIDO777 #######################${C_RESET}"
    echo -e "${C_GREEN}########################################################${C_RESET}"
}

# Function to display usage
function usage {
    banner
    echo -e "${C_YELLOW}# Example: ./Linspect.sh${C_RESET}\n"
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

# Enumeration functions
function system_info {
    echo -e "${C_YELLOW}### SYSTEM INFORMATION ###############${C_RESET}"
    unameinfo=$(uname -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Kernel information:${C_RESET}\n$unameinfo"
    else
        echo -e "${C_RED}[!] Failed to retrieve kernel information.${C_RESET}"
    fi
    echo -e "\n"

    # Additional system info
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
    echo -e "${C_YELLOW}### USER/GROUP INFORMATION ###############${C_RESET}"
    currusr=$(id 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color critical)[-] Current user/group info:${C_RESET}\n$currusr"
    else
        echo -e "${C_RED}[!] Failed to retrieve current user/group information.${C_RESET}"
    fi
    echo -e "\n"
    
    # Check sudo privileges
    echo -e "$(get_color high)[-] Sudo privileges:${C_RESET}"
    sudo -l 2>/dev/null || echo -e "${C_RED}[!] Failed to check sudo privileges.${C_RESET}"
    echo -e "\n"

    # List all users
    echo -e "$(get_color medium)[-] All users:${C_RESET}"
    cat /etc/passwd 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve user list.${C_RESET}"
    echo -e "\n"

    # List all groups
    echo -e "$(get_color medium)[-] All groups:${C_RESET}"
    cat /etc/group 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve group list.${C_RESET}"
    echo -e "\n"

    # Check for SUID/SGID files
    echo -e "$(get_color high)[-] SUID/SGID files:${C_RESET}"
    find / -perm -4000 -o -perm -2000 2>/dev/null || echo -e "${C_RED}[!] Failed to find SUID/SGID files.${C_RESET}"
    echo -e "\n"
}

function networking_info {
    echo -e "${C_YELLOW}### NETWORKING INFORMATION ###############${C_RESET}"
    nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$(get_color info)[-] Network and IP info:${C_RESET}\n$nicinfo"
    else
        echo -e "${C_RED}[!] Failed to retrieve network information.${C_RESET}"
    fi
    echo -e "\n"

    # Check open ports
    echo -e "$(get_color high)[-] Open ports:${C_RESET}"
    netstat -tuln 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve open ports.${C_RESET}"
    echo -e "\n"

    # Check routing table
    echo -e "$(get_color medium)[-] Routing table:${C_RESET}"
    route -n 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve routing table.${C_RESET}"
    echo -e "\n"

    # Check ARP table
    echo -e "$(get_color medium)[-] ARP table:${C_RESET}"
    arp -a 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve ARP table.${C_RESET}"
    echo -e "\n"

    # Check active connections
    echo -e "$(get_color high)[-] Active connections:${C_RESET}"
    ss -tuln 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve active connections.${C_RESET}"
    echo -e "\n"
}

function check_nmap {
    if command -v nmap &> /dev/null; then
        echo -e "${C_YELLOW}### NMAP SCAN ###################${C_RESET}"
        echo -e "$(get_color critical)[+] Nmap is available. Performing a scan on the machine's IP address...${C_RESET}"
        
        # Get the machine's IP address
        ip_address=$(hostname -I | awk '{print $1}')
        if [ -z "$ip_address" ]; then
            echo -e "${C_RED}[!] Could not determine the machine's IP address.${C_RESET}"
            return
        fi

        echo -e "$(get_color info)[-] Scanning IP address: $ip_address${C_RESET}"
        nmap -sV $ip_address
    else
        echo -e "${C_YELLOW}### NMAP SCAN ####################${C_RESET}"
        echo -e "$(get_color info)[-] Nmap is not installed. Skipping Nmap scan.${C_RESET}"
    fi
}

# Updated Linux Exploit Suggester function with multiple download methods
function linux_exploit_suggester {
    echo -e "${C_YELLOW}### LINUX EXPLOIT SUGGESTER ##############${C_RESET}"
    echo -e "$(get_color critical)[+] Checking for known kernel vulnerabilities...${C_RESET}"

    # Define the URLs for the Linux Exploit Suggester tools
    LES_URL="https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
    LES2_URL="https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/refs/heads/master/linux-exploit-suggester-2.pl"

    # Function to download a tool using multiple methods
    function download_tool {
        url=$1
        tool_name=$2

        # Method 1: Use wget
        if command -v wget &> /dev/null; then
            echo -e "$(get_color info)[-] Downloading $tool_name using wget...${C_RESET}"
            wget -q --show-progress "$url" -O "$tool_name"
            if [[ $? -eq 0 ]]; then
                chmod +x "$tool_name"
                return 0
            else
                echo -e "${C_RED}[!] wget failed to download $tool_name.${C_RESET}"
            fi
        fi

        # Method 2: Use curl
        if command -v curl &> /dev/null; then
            echo -e "$(get_color info)[-] Downloading $tool_name using curl...${C_RESET}"
            curl -s -o "$tool_name" "$url"
            if [[ $? -eq 0 ]]; then
                chmod +x "$tool_name"
                return 0
            else
                echo -e "${C_RED}[!] curl failed to download $tool_name.${C_RESET}"
            fi
        fi

        # Method 3: Use Python
        if command -v python3 &> /dev/null; then
            echo -e "$(get_color info)[-] Downloading $tool_name using Python...${C_RESET}"
            python3 -c "import urllib.request; urllib.request.urlretrieve('$url', '$tool_name')"
            if [[ $? -eq 0 ]]; then
                chmod +x "$tool_name"
                return 0
            else
                echo -e "${C_RED}[!] Python failed to download $tool_name.${C_RESET}"
            fi
        fi

        # Method 4: Use Perl
        if command -v perl &> /dev/null; then
            echo -e "$(get_color info)[-] Downloading $tool_name using Perl...${C_RESET}"
            perl -MLWP::Simple -e "getstore('$url', '$tool_name')"
            if [[ $? -eq 0 ]]; then
                chmod +x "$tool_name"
                return 0
            else
                echo -e "${C_RED}[!] Perl failed to download $tool_name.${C_RESET}"
            fi
        fi

        # If all methods fail
        echo -e "${C_RED}[!] Failed to download $tool_name. No download methods available.${C_RESET}"
        return 1
    }

    # Download and run Linux Exploit Suggester
    echo -e "$(get_color critical)[-] Running Linux Exploit Suggester...${C_RESET}"
    if download_tool "$LES_URL" "linux-exploit-suggester.sh"; then
        ./linux-exploit-suggester.sh
        rm linux-exploit-suggester.sh
    else
        echo -e "${C_RED}[!] Skipping Linux Exploit Suggester.${C_RESET}"
    fi

    # Download and run Linux Exploit Suggester 2
    echo -e "$(get_color critical)[-] Running Linux Exploit Suggester 2...${C_RESET}"
    if download_tool "$LES2_URL" "linux-exploit-suggester-2.pl"; then
        perl linux-exploit-suggester-2.pl
        rm linux-exploit-suggester-2.pl
    else
        echo -e "${C_RED}[!] Skipping Linux Exploit Suggester 2.${C_RESET}"
    fi

    echo ""
}

function check_kernel_cves {
    echo -e "${C_YELLOW}### CHECKING CVES BASED ON KERNEL ###############${C_RESET}"
    echo -e "$(get_color critical)[+] Checking for known CVEs related to the current kernel...${C_RESET}"

    # Detect the kernel version
    kernel_version=$(uname -r)
    echo -e "$(get_color info)[-] Current kernel version: $kernel_version${C_RESET}"

    # Perform searches based on the kernel version
    echo -e "$(get_color high)[-] Searching Google and ExploitDB for kernel-related exploits...${C_RESET}"
    echo -e "${C_BLUE} Google Search: https://www.google.com/search?q=exploit+kernel+$kernel_version${C_RESET}"
    echo -e "${C_BLUE} ExploitDB Search: https://www.exploit-db.com/search?q=kernel+$kernel_version${C_RESET}"

    # Check for specific CVEs based on kernel version
    if [[ $kernel_version =~ "4.4" || $kernel_version =~ "4.8" || $kernel_version =~ "4.9" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2017-5753 (Spectre) vulnerability...${C_RESET}"
        download_tool "https://raw.githubusercontent.com/username/cve-spectre-checker/master/cve-spectre.sh" "cve-spectre.sh"
    fi

    if [[ $kernel_version =~ "3.8" || $kernel_version =~ "3.10" || $kernel_version =~ "4.4" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2017-1000253 (Dirty COW) vulnerability...${C_RESET}"
        download_tool "https://raw.githubusercontent.com/username/cve-dirty-cow-checker/master/cve-dirty-cow.sh" "cve-dirty-cow.sh"
    fi

    if [[ $kernel_version =~ "4.19" || $kernel_version =~ "5.4" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2021-3490 (Polkit Privilege Escalation) vulnerability...${C_RESET}"
        download_tool "https://raw.githubusercontent.com/username/cve-polkit-checker/master/cve-polkit.sh" "cve-polkit.sh"
    fi

    if [[ $kernel_version =~ "5.10" || $kernel_version =~ "5.11" ]]; then
        echo -e "$(get_color critical)[+] Checking CVE-2021-4034 (PwnKit) vulnerability...${C_RESET}"
        download_tool "https://raw.githubusercontent.com/username/cve-pwnkit-checker/master/cve-pwnkit.sh" "cve-pwnkit.sh"
    fi

    echo ""
}

# Function to check for common misconfigurations
function check_misconfigurations {
    echo -e "${C_YELLOW}### CHECKING FOR COMMON MISCONFIGURATIONS ###############${C_RESET}"

    # Check for .bash_history files
    echo -e "$(get_color medium)[-] Checking for .bash_history files:${C_RESET}"
    find / -name ".bash_history" 2>/dev/null || echo -e "${C_RED}[!] Failed to find .bash_history files.${C_RESET}"
    echo -e "\n"

    # Check for SSH keys
    echo -e "$(get_color medium)[-] Checking for SSH keys:${C_RESET}"
    find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pub" 2>/dev/null || echo -e "${C_RED}[!] Failed to find SSH keys.${C_RESET}"
    echo -e "\n"

    # Check for cron jobs
    echo -e "$(get_color medium)[-] Checking for cron jobs:${C_RESET}"
    crontab -l 2>/dev/null || echo -e "${C_RED}[!] Failed to retrieve cron jobs.${C_RESET}"
    ls -la /etc/cron* 2>/dev/null || echo -e "${C_RED}[!] Failed to list cron directories.${C_RESET}"
    echo -e "\n"
}

# Main function to call all enumeration functions
function main {
    banner
    system_info
    networking_info
    linux_exploit_suggester
    check_kernel_cves
    check_nmap
    check_misconfigurations
    user_info
    echo -e "${C_GREEN}##########################################${C_RESET}"
    echo -e "${C_GREEN}############## Goodbye! ##################${C_RESET}"
    echo -e "${C_GREEN}##########################################${C_RESET}"
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
