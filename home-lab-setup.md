# Home Lab Setup

**Date:** October 2025  
**Platform:** VirtualBox 7.0 on Windows 11 Host

---

## 1. Lab Architecture

```
                    ┌─────────────────┐
                    │   Windows 11    │
                    │   Host Machine  │
                    │  (Intel i7, 16G)│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   VirtualBox    │
                    │   (NAT Network)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼────┐ ┌──────▼──────┐ ┌────▼──────────┐
    │ Kali Linux   │ │ DVWA (Apache│ │ Windows 10    │
    │ (Attacker)   │ │ + MySQL)    │ │ (Victim VM)   │
    │ 192.168.56.10│ │ 192.168.56.20│ │ 192.168.56.30│
    └──────────────┘ └─────────────┘ └───────────────┘
```

### Network Configuration

- **Mode:** Host-only adapter (`vboxnet0`)
- **Subnet:** `192.168.56.0/24`
- **Gateway:** `192.168.56.1` (host)
- **Isolation:** No internet access for victim/target VMs

---

## 2. Virtual Machines

### 2.1 Kali Linux (Attacker)

| Setting | Value |
|---------|-------|
| OS | Kali Linux 2025.1 |
| RAM | 4 GB |
| CPU | 2 cores |
| Disk | 50 GB (dynamic) |
| Network | Host-only + NAT (for updates) |
| IP | 192.168.56.10 (static) |

**Pre-installed tools:**
- Nmap, Wireshark, Metasploit Framework
- Burp Suite Community, John the Ripper
- Hydra, SQLmap, Gobuster
- Aircrack-ng, Hashcat

### 2.2 DVWA (Target)

| Setting | Value |
|---------|-------|
| OS | Ubuntu 24.04 LTS |
| RAM | 2 GB |
| CPU | 1 core |
| Disk | 20 GB |
| Network | Host-only |
| IP | 192.168.56.20 (static) |

**Stack:** Apache 2.4 + PHP 8.2 + MySQL 8.0 + DVWA 2.2

**Setup commands:**
```bash
# Install LAMP stack
sudo apt update && sudo apt install -y apache2 mysql-server php libapache2-mod-php php-mysql php-gd

# Download and configure DVWA
cd /var/www/html
git clone https://github.com/digininja/DVWA.git
cd DVWA
cp config/config.inc.php.dist config/config.inc.php

# Create MySQL database
sudo mysql -u root -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost'; FLUSH PRIVILEGES;"
```

### 2.3 Windows 10 (Victim)

| Setting | Value |
|---------|-------|
| OS | Windows 10 Pro (eval) |
| RAM | 4 GB |
| CPU | 2 cores |
| Disk | 40 GB |
| Network | Host-only |
| IP | 192.168.56.30 (static) |

**Purpose:** Testing Windows-specific attacks (SMB, RDP, PowerShell)

---

## 3. Tools Installed & Configured

### Network Analysis
- **Wireshark:** Configured with custom display filters for lab subnet
- **Nmap:** Scripting engine (NSE) library updated
- **tcpdump:** Command-line packet capture

### Vulnerability Scanning
- **Nessus Essentials:** Free license, local scan policy configured
- **OpenVAS:** Alternative scanner for comparison
- **Nikto:** Web server vulnerability scanner

### Exploitation
- **Metasploit:** `msfdb init` completed, Postgres running
- **Burp Suite:** CA certificate installed in DVWA browser
- **SQLmap:** Automated SQL injection testing

### Password Attacks
- **John the Ripper:** Wordlists: rockyou.txt, custom lists
- **Hashcat:** GPU acceleration enabled
- **Hydra:** Online brute-force testing

---

## 4. Challenges Faced & Solutions

### Challenge 1: Network Connectivity
**Problem:** VMs could not ping each other on first setup.  
**Root cause:** VirtualBox host-only adapter was disabled.  
**Solution:** Enabled `vboxnet0` in VirtualBox → Host Network Manager, assigned static IPs.

### Challenge 2: DVWA Database Connection
**Problem:** `Access denied for user 'dvwa'@'localhost'`  
**Root cause:** MySQL 8 uses `caching_sha2_password` by default; DVWA expected `mysql_native_password`.  
**Solution:** 
```sql
ALTER USER 'dvwa'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';
```

### Challenge 3: Burp Suite Certificate
**Problem:** HTTPS sites showed certificate errors in browser.  
**Root cause:** Burp CA cert not trusted by the browser.  
**Solution:** Exported Burp CA cert from `http://burp`, imported into browser's trusted root CAs.

---

## 5. Lab Workflow

### Daily Startup
1. Start VirtualBox
2. Power on Kali Linux (attacker)
3. Power on DVWA (target)
4. Verify connectivity: `ping 192.168.56.20` from Kali
5. Launch target service: `http://192.168.56.20/DVWA`

### Session Cleanup
1. Reset DVWA: Login → Security → DVWA Security → Set to desired level → Reset/Restart
2. Clear Burp history
3. Save any captures to `/writeups/` directory
4. Snapshot VMs if needed for reproducibility

---

## 6. Expansion Plans

- [ ] Add Splunk/ELK stack for SIEM practice
- [ ] Deploy Active Directory lab (Windows Server + domain joined clients)
- [ ] Add pfSense firewall VM for network segmentation
- [ ] Configure log forwarding from all VMs to SIEM
- [ ] Set up automated vulnerability scanning with cron jobs

---

## 7. Resources

- [TryHackMe](https://tryhackme.com) — Guided rooms for practice
- [HackTheBox](https://hackthebox.com) — More advanced machines
- [OverTheWire](https://overthewire.org) — Wargames for fundamentals
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free web security training
