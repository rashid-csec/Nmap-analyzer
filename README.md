# Nmap Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg">
  <img src="https://img.shields.io/badge/Platform-Linux-success.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg">
</p>

<p align="center">
  <b>Transform Nmap XML scan results into a prioritized vulnerability assessment and exploitation roadmap.</b>
</p>

---

## Overview

**Nmap Analyzer** is an automated post-processing tool for Nmap XML scan results. It identifies known vulnerabilities, prioritizes findings based on CVSS severity, recommends enumeration techniques, and suggests exploitation resources including SearchSploit, Metasploit, and Nmap NSE scripts.

Rather than manually reviewing large Nmap outputs, Nmap Analyzer provides a structured roadmap to help penetration testers and security professionals focus on the highest-priority findings first.

---

## Features

* Parse Nmap XML scan results
* Detect open services and versions
* Identify known CVEs using a local vulnerability database
* Rank vulnerabilities by CVSS severity
* Generate an exploitation roadmap
* Recommend service-specific enumeration commands
* Suggest relevant Nmap NSE scripts
* Generate SearchSploit commands
* Suggest Metasploit modules (where available)
* Colorized terminal output
* Export analysis to a text report

---

## Supported Services

Current coverage includes many common enterprise services, including:

* FTP
* SSH
* Telnet
* SMTP
* DNS
* HTTP
* HTTPS
* SMB
* LDAP
* MSSQL
* MySQL
* PostgreSQL
* Oracle
* MongoDB
* Redis
* RDP
* WinRM
* VNC
* NFS
* RPC
* IMAP
* POP3

The service database is easily extendable by editing `services_db.py`.

---

## Vulnerability Detection

The included vulnerability database currently identifies high-impact vulnerabilities such as:

* EternalBlue (MS17-010)
* SMBGhost (CVE-2020-0796)
* BlueKeep (CVE-2019-0708)
* Heartbleed (CVE-2014-0160)
* Shellshock (CVE-2014-6271)
* Apache HTTP Server CVEs
* Apache Tomcat RCE
* vsFTPd Backdoor
* ProFTPD mod_copy RCE
* OpenSSH vulnerabilities
* MySQL Authentication Bypass
* PostgreSQL COPY FROM PROGRAM RCE
* Redis Unauthenticated Access
* Jenkins CLI Arbitrary File Read
* MongoDB Unauthenticated Access

More signatures can easily be added to `vulnerability_db.py`.

---

## Installation

### Clone the repository

```bash
git clone https://github.com/rashid-csec/Nmap-analyzer.git

cd Nmap-analyzer
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Step 1 — Perform an Nmap scan

```bash
nmap -sV -sC -oX scan.xml <target>
```

Example

```bash
nmap -sV -sC -Pn -oX scan.xml 192.168.1.100
```

---

### Step 2 — Analyze the results

```bash
python3 nmap_analyzer.py scan.xml
```

Save the report to a file

```bash
python3 nmap_analyzer.py scan.xml -o report.txt
```

---

## Example Output

```
Target: 192.168.1.100

Open Ports

21/tcp   FTP
22/tcp   SSH
80/tcp   HTTP
445/tcp  SMB

=============================================

[CRITICAL] EternalBlue (MS17-010)

CVSS: 9.8

Port: 445

Metasploit:

exploit/windows/smb/ms17_010_eternalblue

SearchSploit:

searchsploit smb

Recommended NSE Script:

nmap --script smb-vuln* -p445 <target>

=============================================

[INFO] HTTP Enumeration

Recommended Actions

gobuster
nikto
whatweb
curl
```

---

## Project Structure

```
Nmap-analyzer/
│
├── nmap_analyzer.py
├── services_db.py
├── vulnerability_db.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Roadmap

Planned features for future releases:

* HTML report generation
* PDF report generation
* JSON export
* CSV export
* Automatic SearchSploit lookup
* Vulners API integration
* NVD API integration
* EPSS risk scoring
* MITRE ATT&CK mapping
* Attack path visualization
* Multi-host reporting
* Docker support
* pip installation
* GitHub Actions CI/CD
* Automatic CVE database updates

---

## Contributing

Contributions are welcome.

If you would like to improve the project:

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Open a Pull Request

Bug reports, feature requests, and suggestions are appreciated.

---

## Disclaimer

This project is intended for:

* Authorized penetration testing
* Security research
* Vulnerability assessment
* Educational purposes

Do not use this software against systems you do not own or have explicit permission to test.

The author assumes no responsibility for misuse or damage caused by this software.

---

## Author

**Rashid**

Cybersecurity Researcher | Penetration Tester

GitHub:

https://github.com/rashid-csec

---

## License

This project is licensed under the MIT License.

---

## Support

If you find this project useful:

* ⭐ Star the repository
* 🍴 Fork the project
* 🐞 Report bugs
* 💡 Suggest new features
* 🤝 Contribute improvements

Your support helps improve the project for the cybersecurity community.
