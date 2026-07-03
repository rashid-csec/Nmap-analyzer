LOCAL_SERVICES_REF = {
    21:   {"service": "FTP",        "enum_scripts": ["ftp-anon", "ftp-syst"], "enum_commands": ["ftp -n $TARGET"]},
    22:   {"service": "SSH",        "enum_scripts": ["ssh-auth-methods", "ssh2-enum-algos"], "enum_commands": ["ssh -v $TARGET"]},
    23:   {"service": "Telnet",     "enum_scripts": ["telnet-ntlm-info"], "enum_commands": ["telnet $TARGET"]},
    25:   {"service": "SMTP",       "enum_scripts": ["smtp-enum-users", "smtp-commands"], "enum_commands": ["swaks --to root@$TARGET"]},
    53:   {"service": "DNS",        "enum_scripts": ["dns-zone-transfer", "dns-recursion"], "enum_commands": ["dig axfr @$TARGET"]},
    80:   {"service": "HTTP",       "enum_scripts": ["http-enum", "http-methods"], "enum_commands": ["nikto -h $TARGET"]},
    110:  {"service": "POP3",       "enum_scripts": ["pop3-capabilities", "pop3-ntlm-info"], "enum_commands": ["nc -nv $TARGET 110"]},
    135:  {"service": "RPC",        "enum_scripts": ["rpcinfo", "msrpc-enum"], "enum_commands": ["rpcinfo -p $TARGET"]},
    143:  {"service": "IMAP",       "enum_scripts": ["imap-capabilities", "imap-ntlm-info"], "enum_commands": ["nc -nv $TARGET 143"]},
    389:  {"service": "LDAP",       "enum_scripts": ["ldap-rootdse", "ldap-search"], "enum_commands": ["ldapsearch -x -h $TARGET"]},
    443:  {"service": "HTTPS",      "enum_scripts": ["ssl-enum-ciphers", "http-vuln-cve2014-0160"], "enum_commands": ["testssl.sh $TARGET"]},
    445:  {"service": "SMB",        "enum_scripts": ["smb-enum-shares", "smb-vuln-ms17-010"], "enum_commands": ["smbclient -L //$TARGET/"]},
    593:  {"service": "RPC-HTTP",   "enum_scripts": ["rpcinfo"], "enum_commands": ["rpcinfo -p $TARGET"]},
    1433: {"service": "MSSQL",      "enum_scripts": ["ms-sql-info", "ms-sql-config"], "enum_commands": ["sqsh -S $TARGET -U sa"]},
    1521: {"service": "Oracle",     "enum_scripts": ["oracle-sid-brute", "oracle-tns-version"], "enum_commands": ["odat sidguesser -s $TARGET"]},
    2049: {"service": "NFS",        "enum_scripts": ["nfs-showmount", "nfs-ls"], "enum_commands": ["showmount -e $TARGET"]},
    3306: {"service": "MySQL",      "enum_scripts": ["mysql-info", "mysql-empty-password"], "enum_commands": ["mysql -h $TARGET -u root"]},
    3389: {"service": "RDP",        "enum_scripts": ["rdp-vuln-ms12-020", "rdp-ntlm-info"], "enum_commands": ["xfreerdp /v:$TARGET"]},
    5432: {"service": "PostgreSQL", "enum_scripts": ["pgsql-brute"], "enum_commands": ["psql -h $TARGET -U postgres"]},
    5900: {"service": "VNC",        "enum_scripts": ["vnc-info", "vnc-brute"], "enum_commands": ["vncviewer $TARGET"]},
    5985: {"service": "WinRM",      "enum_scripts": ["wsman-identity"], "enum_commands": ["crackmapexec winrm $TARGET"]},
    6379: {"service": "Redis",      "enum_scripts": ["redis-info"], "enum_commands": ["redis-cli -h $TARGET"]},
    27017:{"service": "MongoDB",    "enum_scripts": ["mongodb-info", "mongodb-databases"], "enum_commands": ["mongo --host $TARGET"]}
}

def get_service_info(port, name=""):
    # Fallback to identify by parsed alphanumeric name strings if port doesn't match standard defaults
    p_int = int(port)
    if p_int in LOCAL_SERVICES_REF:
        return LOCAL_SERVICES_REF[p_int]
    
    # Strict matching across alphanumeric strings
    n_lower = name.lower()
    for _, info in LOCAL_SERVICES_REF.items():
        if info["service"].lower() in n_lower:
            return info
            
    return {"service": name or "Unknown", "enum_scripts": [], "enum_commands": ["manual deep verification"]}
