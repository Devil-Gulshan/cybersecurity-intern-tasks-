
# 🚀 Task 1 – Network Port Scanning with Nmap

### 🛡️ Cyber Security Internship – Practical Lab

---

## 📌 Objective

To identify open ports on devices in the local network using **Nmap** for understanding network exposure and basic reconnaissance techniques.

---

## 🧰 Tools Used

| Tool       | Purpose                        | Link                |
|------------|--------------------------------|---------------------|
| **Nmap**   | Port scanning, reconnaissance  | https://nmap.org    |
| **Wireshark** _(optional)_ | Packet capture & analysis | https://wireshark.org |

---

## 🧠 Key Concepts

- IP Address & Subnet Ranges
- TCP SYN Scan (`-sS`)
- Open Ports & Common Services
- Basic Network Reconnaissance
- Port Security & Exposure Analysis

---

## 🧪 Steps Performed

### 🔍 1. Determined Local IP Range

```bash
ifconfig        # On Linux
ipconfig        # On Windows
```

> Local IP: `192.168.1.5`  
> Subnet Range: `192.168.1.0/24`

---

### ⚙️ 2. Performed TCP SYN Scan with Nmap

```bash
nmap -sS 192.168.1.0/24
```

> The TCP SYN scan is stealthy and effective for discovering open ports without completing full TCP handshakes.

---

### 📄 3. Saved Scan Results

```bash
nmap -sS 192.168.1.0/24 -oN scan_result.txt
```

_(Output file is included in this repository)_

---

### 🔍 4. Example Output Observed:

```txt
Host: 192.168.1.1
Ports Open: 22 (SSH), 80 (HTTP), 443 (HTTPS)

Host: 192.168.1.10
Ports Open: 445 (SMB), 3389 (RDP)
```

---

## 🔐 Security Analysis

| Port | Service | Risk/Concern                          |
|------|---------|----------------------------------------|
| 22   | SSH     | Should be secured with key/2FA         |
| 445  | SMB     | Commonly exploited, disable if unused  |
| 3389 | RDP     | Use with VPN or restrict by firewall   |

---

## 🎓 Learning Outcomes

- ✔️ Discovered how networks can expose services via open ports.
- ✔️ Practiced using `nmap` for real-world scanning.
- ✔️ Understood basic service fingerprinting.
- ✔️ Learned how to identify and interpret scan results.

---

## 📁 Repository Contents

| File             | Description                           |
|------------------|---------------------------------------|
| `README.md`      | This detailed report                  |
| `scan_result.txt`| Nmap scan output (saved results)      |
| `screenshot.png` | (Optional) CLI screenshot             |

--
 
#  Task -3  🛡️ Vulnerability Scan Report - Nessus Essentials

This repository contains the results of a basic vulnerability scan performed on a personal computer using **Nessus Essentials** as part of a Cyber Security Internship Task.

## 📌 Objective
To perform a vulnerability assessment on the local machine and identify potential security issues using a free tool like Nessus.

## 🧰 Tools Used
- **Nessus Essentials** (Free Edition)
- Target IP: `127.0.0.1` (localhost)
- Scan Type: Basic Network Scan

## 📊 Summary of Findings

| Severity  | Count |
|-----------|-------|
| Critical  | 2     |
| High      | 3     |
| Medium    | 4     |
| Low       | 3     |
| **Total** | 12    |

## 🚨 Top Critical Vulnerabilities

1. **SMBv1 Enabled (CVE-2017-0144)**
   - Description: Outdated protocol vulnerable to ransomware like WannaCry.
   - CVSS: 9.8
   - Fix: Disable SMBv1 via Windows Features.

2. **Outdated OpenSSH (CVE-2020-15778)**
   - Description: Command injection flaw in older OpenSSH versions.
   - CVSS: 8.8
   - Fix: Upgrade OpenSSH to latest version.

## 🛠️ Remediation Steps
- Update OS and applications regularly
- Disable unused services and ports
- Use firewall and antivirus
- Run regular vulnerability scans

## 📸 Screenshots
See the `/cyber_security_task-3` folder for proof of scan and detected vulnerabilities.

## 📄 Report
- `/cyber_security_task-3` contains the complete report with findings and recommendations.

## ✅ Outcome
Gained hands-on experience with vulnerability scanning and risk assessment using industry tools.

---

> This task is part of the Cyber Security Internship program.


## 🙌 Author

Name: Gulshan 
**Internship Program:** Cyber Security Internship – Task 1  
**Date:** August 2025

---

> 🧠 _"In cybersecurity, knowing your environment is the first step toward securing it."_
