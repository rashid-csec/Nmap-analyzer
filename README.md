# Nmap Analyzer — Vulnerability Assessment & Exploitation Roadmap

Parses Nmap XML scan results and produces a **criticality-ranked exploitation roadmap**.

## 🚀 How It Works

1. **Parse**: Reads Nmap XML output (`nmap -sV -sC -oX scan.xml <target>`)
2. **Analyze**: Matches services:versions against known critical CVEs
3. **Roadmap**: Ranks findings by CVSS score (Critical → High → Medium → Low → Info)
4. **Enumeration**: If no direct exploit, suggests enumeration commands (FTP anonymous, SMB shares, etc.)
5. **Commands**: Generates Searchsploit, NSE, and Metasploit commands for each finding

## 📦 Installation

```bash
pip install -r requirements.txt
