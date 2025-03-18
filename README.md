# <p align="center"> **🕵️ Linspect: Linux enumeration**
<p align="center">
  <img src="https://img.shields.io/github/v/release/Midohajhouj/Linspect?label=Version&color=a80505">
  <img src="https://img.shields.io/badge/Open%20Source-Yes-darkviolet?style=flat-square&color=a80505">
  <img src="https://img.shields.io/github/stars/Midohajhouj/Linspect?style=flat&label=Stars&color=a80505">
  <img src="https://img.shields.io/github/repo-size/Midohajhouj/Linspect?label=Size&color=a80505">
  <img src="https://img.shields.io/github/languages/top/Midohajhouj/Linspect?color=a80505">
</p>

**Linspect** is a powerful Linux enumeration and privilege escalation script designed to identify vulnerabilities, misconfigurations, and potential security risks. It provides detailed system, user, and network information along with kernel vulnerability checks and exploit suggestions.

---

## 🚀 Features

- **System Information**: Collects kernel, OS, CPU, memory, and disk details.
- **User and Group Enumeration**: Displays user privileges, SUID/SGID files, and sudo rights.
- **Network Scanning**: Shows IP configuration, open ports, and routing/ARP tables.
- **Kernel CVE Checks**: Links to CVEs related to the current kernel.
- **Exploit Suggestions**: Runs Linux Exploit Suggester tools.
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


---

## 🔒 Disclaimer

This script is intended for ethical purposes and educational use only. Always obtain permission before running scans or exploits on systems you do not own.

---

## 📃 License

This project is licensed under the MIT License. See the LICENSE file for details.
**<p align="center"> Developed by <a href="https://github.com/Midohajhouj">MIDØ</a> </p>**
