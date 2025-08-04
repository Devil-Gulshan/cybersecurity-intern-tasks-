
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

---

## 🔗 Submission Link

[Click Here to Submit](https://forms.gle/8Gm83s53KbyXs3Ne9)

---

## 🙌 Author

**Name:** _Your Name Here_  
**Internship Program:** Cyber Security Internship – Task 1  
**Date:** August 2025

---

> 🧠 _"In cybersecurity, knowing your environment is the first step toward securing it."_
