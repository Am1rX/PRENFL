# 🛡️ Linux Firewall Assistant & SOC Dashboard

A professional, interactive Python-based tool for secure and automated **IPTables** configuration and live server security monitoring (SOC).

This script is designed to simplify the Linux server hardening process and mitigate Brute-Force attacks. It also features a live monitoring dashboard that analyzes and color-codes security logs.

## ✨ Key Features

  * **📊 System Status Dashboard:** Real-time display of RAM usage, CPU Load, Disk space, and network information in the application header.
  * **🔍 Service Auto-Discovery:** Scans listening ports and detects active services (e.g., SSH, Nginx, MySQL) to suggest opening relevant ports.
  * **🛡️ Anti-Brute Force Protection:** Smart Rate Limiting capability on ports (blocks IPs after 4 failed attempts within 60 seconds).
  * **👀 SOC Dashboard (Security Operations Center):**
      * Live monitoring of attacks and firewall logs.
      * Display of failed login attempts (SSH Failed Logins).
      * Smart log coloring (Attacker IPs highlighted in red).
  * **⚡ Smart Wizard:** Step-by-step guide for firewall configuration with options for automatic or manual modes.
  * **♻️ Smart Rule Management:** Prevents rule duplication and includes the ability to fully flush the firewall before reconfiguration.

## 🚀 Prerequisites

  * **OS:** Linux (Ubuntu, Debian, CentOS, RHEL, etc.)
  * **Python:** Version 3.x
  * **Permissions:** Root access (Sudo) is required.

## 📥 Installation

1.  Clone the repository:

<!-- end list -->

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO.git
cd YOUR-REPO
```

2.  Run the script as root:

<!-- end list -->

```bash
sudo python3 firewall.py
```

## 📖 Usage Guide

Upon running the script, you will see the following menu:

1.  **Auto-Secure Server (Wizard):** Starts the automated hardening process. You can choose to reset old rules, detect running services, and apply anti-brute force protection.
2.  **View Active Rules:** Displays the current IPTables configuration.
3.  **SOC DASHBOARD:** Enters the live monitoring mode to watch for threats and failed logins.

## 💾 Persistence

IPTables rules are not persistent by default. To save your configuration after using this tool:

**Ubuntu/Debian:**

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

**CentOS/RHEL:**

```bash
sudo service iptables save
```

## ⚠️ Disclaimer

This tool manages network firewall rules. Always ensure you allow traffic on your SSH port (usually 22) to avoid locking yourself out of the server.

-----

\<div align="center"\>
Made with ❤️ and Python
\</div\>
