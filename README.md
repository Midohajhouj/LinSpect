# 💥 Linspect: Linux enumeration and privilege escalation.

Linspect is a powerful Linux enumeration and privilege escalation script designed to identify vulnerabilities, misconfigurations, and potential security risks. It provides detailed system, user, and network information along with kernel vulnerability checks and exploit suggestions.

---

## 🚀 Features

- **System Information**: Collects kernel, OS, CPU, memory, and disk details.
- **User and Group Enumeration**: Displays user privileges, SUID/SGID files, and sudo rights.
- **Network Scanning**: Shows IP configuration, open ports, and routing/ARP tables.
- **Kernel CVE Checks**: Links to CVEs related to the current kernel.
- **Exploit Suggestions**: Downloads and runs Linux Exploit Suggester tools.
- **Common Misconfigurations**: Identifies insecure `.bash_history`, SSH keys, and cron jobs.
- **Custom Scan Options**: Perform specific scans like quick system checks, exploit checks, or full system audits.

---

## 📜 Usage

./Linspect.sh [options]

Options:
Option	Description
-h	Display help and usage information
-s	Perform a quick system scan
-f	Perform a full system scan
-e	Perform exploit checks only
-n	Perform network checks only
-u	Perform user and group checks only

Running the script without any options defaults to a full scan.


Examples:
### Run a full system scan
./Linspect.sh -f

### Perform network checks
./Linspect.sh -n

### Display help
./Linspect.sh -h

---

## 🌟 Highlights

    Color-Coded Output: Easily distinguish critical, high, medium, and informational messages.

    Automation-Friendly: Generates detailed outputs for further analysis.

    Built-In Exploit Tools: Automatically fetches and runs popular vulnerability scanners.

## 🛠 Prerequisites

    Bash Shell: Ensure the script is executed in a bash-compatible shell.

    Required Tools: The following tools are optional but recommended for full functionality:

        wget, curl, or python3 for downloading scripts.

        nmap for advanced network scanning.

        perl for executing certain scripts.

Install missing tools via your package manager:
bash
Copy

sudo apt-get install nmap perl wget curl -y

🔒 Disclaimer

This script is intended for ethical purposes and educational use only. Always obtain permission before running scans or exploits on systems you do not own.

📃 License

This project is licensed under the MIT License. See the LICENSE file for details.


credit to <a href="https://github.com/The-Z-Labs">The-Z-Labs</a>
---

*<p align="center"> Coded by <a href="https://github.com/Midohajhouj">MIDO777</a> </p>*
