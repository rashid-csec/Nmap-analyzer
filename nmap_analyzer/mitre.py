MITRE_DB = {
    # File & Remote Administration Shell Access (Lateral Movement / Collection)
    "ftp":        {"id": "T1021.003", "name": "Remote Services: SSH/FTP", "tactic": "Lateral Movement"},
    "ssh":        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "telnet":     {"id": "T1021",     "name": "Remote Services", "tactic": "Lateral Movement"},
    "rdp":        {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "winrm":      {"id": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement"},
    "vnc":        {"id": "T1021.005", "name": "Remote Services: VNC", "tactic": "Lateral Movement"},
    
    # Web Frontends & Entry Vectors (Initial Access)
    "http":       {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "https":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    
    # Network Storage & File Access Architecture
    "smb":        {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "nfs":        {"id": "T1021",     "name": "Remote Services", "tactic": "Lateral Movement"},
    "rpc":        {"id": "T1021",     "name": "Remote Services", "tactic": "Lateral Movement"},
    
    # Directory Services, Naming & Mail Frameworks
    "ldap":       {"id": "T1087.003", "name": "Account Discovery: Email Account", "tactic": "Discovery"},
    "dns":        {"id": "T1568",     "name": "Dynamic Resolution", "tactic": "Command and Control"},
    "smtp":       {"id": "T1566",     "name": "Phishing", "tactic": "Initial Access"},
    "imap":       {"id": "T1114.002", "name": "Email Collection: Remote Email Services", "tactic": "Collection"},
    "pop3":       {"id": "T1114.002", "name": "Email Collection: Remote Email Services", "tactic": "Collection"},
    
    # Enterprise Database & NoSQL Solutions
    "mssql":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "mysql":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "postgresql": {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "oracle":     {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "mongodb":    {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "redis":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
}

def get_mitre_mapping(service_name, is_exploit=True):
    svc = service_name.lower()
    if not is_exploit:
        return {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}
    
    for key, data in MITRE_DB.items():
        if key in svc:
            return data
    return {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"}
