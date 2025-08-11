
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

#  Task - 2 📧 Phishing Email Analysis Report
This repository contains the analysis of a suspicious email that appears to be a phishing attempt disguised as a communication from PayPal.

## 📝 Task Objective
Analyze the provided email and identify phishing indicators using email header and body inspection tools.

## 🔍 Tools Used
MXToolbox Email Header Analyzer

Browser Hover Inspection (for link checking)

ZIP File Behavior Observation

## 🧠 Key Findings
### 1. Email Header Analysis
Header Field	Observation	Finding
From	support@paypal.com	May be spoofed
Return-Path	alert@secure-paypal-login.com	Mismatch with From address
Received IP	185.231.112.45	Unusual location (Eastern Europe)
SPF	Fail	Unauthorized sender
DKIM	Fail	Invalid signature
Subject	URGENT: Verify your PayPal account now	Threatening tone

### 2. Email Body Analysis
Urgent Language: "Your account will be suspended within 24 hours."

Fake Link: Text shows PayPal, but actual URL is malicious.

Spelling Error: “securty” instead of “security”.

Generic Greeting: “Dear Customer” instead of recipient’s name.

Malicious Attachment: ZIP file with embedded .exe malware.

### 3. Summary of Phishing Indicators
Domain spoofing and mismatch

SPF & DKIM authentication failed

Link redirects to phishing domain

Contains malware in attachment

Uses urgency and fear tactics (social engineering)

📸 Suggested Screenshots (For GitHub)
Screenshot of email header analysis output

Screenshot of suspicious link (hovered)

Screenshot of ZIP attachment warning

### ✅ Conclusion
This email is a clear phishing attempt. Users should:

Not click on links

Never open unknown attachments

Report to the real service provider

Delete such emails immediately

🧠 This task is part of the Cyber Security Internship Program – Email Threat Analysis Module.



 
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

# 🔥 Task - 4  Firewall Rule Testing – Telnet Blocked (Kali Linux)
This task demonstrates how a firewall rule blocks unwanted ports like Telnet (port 23) using Linux firewall utilities (UFW/iptables) and verifies the configuration via terminal tests.

## 🎯 Objective
To create, apply, and test a firewall rule to block Telnet connections on port 23, and document the result using terminal screenshots.

## 🧰 Tools Used
Operating System: Kali Linux

Firewall: UFW (Uncomplicated Firewall)

Testing Tool: Telnet command from terminal

### ⚙️ Steps Performed
Enable UFW (if not already):

### sudo ufw enable
Block Port 23 (Telnet):

### sudo ufw deny 23/tcp
Check UFW Status:


### sudo ufw status verbose
Try Telnet Connection (Expect Failure):

### telnet localhost 23
Expected Result: Connection refused

(Optional) Remove the Rule:

### sudo ufw delete deny 23/tcp
📸 Screenshots Included
ufw status verbose output showing blocked port
other screen short in file is /cyber_security_Task-4

Telnet connection attempt showing “Connection refused” error

### ✅ Outcome
Successfully tested that the firewall blocked Telnet traffic. This confirms that:

UFW is functioning properly

Custom port rules are applied effectively

Basic firewall behavior is understood

> This task is part of the Cyber Security Internship program.

----
# Task-5  📡 Wireshark Network Traffic Capture & Analysis

This repository contains the results of **Task 5** from my Cyber Security Internship — capturing and analyzing network traffic using **Wireshark**.

---

## 🎯 Objective
To capture live network traffic, identify multiple protocols, and analyze their packet details to understand how data flows through the network.

---

## 🧰 Tools Used
- **Wireshark** (Network Protocol Analyzer)
- **Kali Linux** (Capture environment)
- **Active Network Interface** (`wlan0` / `eth0`)

---

## 🛠 Steps Performed
1. Installed & launched **Wireshark**.
2. Selected active network interface.
3. Started live packet capture.
4. Generated traffic:
   - Browsed websites (HTTP/HTTPS)
   - Ran DNS lookups
   - Sent ping requests (ICMP)
5. Applied filters to view:
   - `dns` – All DNS packets
   - `dns.flags.response == 0` – DNS queries
   - `dns.flags.response == 1` – DNS responses
   - `tcp.flags.syn == 1 && tcp.flags.ack == 0` – SYN packets
   - `tcp.flags.syn == 1 && tcp.flags.ack == 1` – SYN-ACK packets
   - `tcp.flags.ack == 1 && tcp.flags.syn == 0` – ACK packets
6. Stopped capture & saved `.pcap` file.
7. Documented packet details and observations.

---

## 📊 Protocols Observed
| Protocol | Purpose | Observation |
|----------|---------|-------------|
| **HTTP** | Web browsing | GET/POST requests visible (unencrypted) |
| **DNS**  | Domain resolution | Query & response for `example.com` |
| **TCP**  | Reliable transport | Three-way handshake captured |
| **ICMP** | Network testing | Echo request/reply messages |

---

## 📸 Screenshots Included
- DNS query & response details pane
- TCP three-way handshake packets
- HTTP request/response view
- location -- ####/cyber_security_Task-5

---

## 🧠 Key Learnings
- Applying filters makes packet analysis faster and more precise.
- DNS and TCP handshakes reveal how connections are established.
- Unencrypted traffic (HTTP) can expose sensitive details.
- Wireshark is an essential tool for network troubleshooting & security analysis.

---




## 🙌 Author

Name: Gulshan 
**Internship Program:** Cyber Security Internship – Task 1  
**Date:** August 2025

---

> 🧠 _"In cybersecurity, knowing your environment is the first step toward securing it."_
