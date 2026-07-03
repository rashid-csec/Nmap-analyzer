MITRE_DB = {
    "ftp":       {"id": "T1021.003", "name": "Remote Services: SSH/FTP", "tactic": "Lateral Movement"},
    "ssh":       {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "http":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "https":     {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "smb":       {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "rdp":       {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "mssql":     {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "mysql":     {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "vnc":       {"id": "T1021.005", "name": "Remote Services: VNC", "tactic": "Lateral Movement"},
}

def get_mitre_mapping(service_name, is_exploit=True):
    svc = service_name.lower()
    if not is_exploit:
        return {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}
    
    for key, data in MITRE_DB.items():
        if key in svc:
            return data
    return {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"}
