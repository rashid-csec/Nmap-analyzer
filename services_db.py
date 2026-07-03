#!/usr/bin/env python3
"""
services_db.py — Maps ports to services and their enumeration/exploitation methods.
"""

SERVICES_DB = {
    21: {
        "service": "FTP",
        "enum_scripts": ["ftp-anon", "ftp-bounce", "ftp-proftpd-backdoor", 
                         "ftp-vsftpd-backdoor", "ftp-vuln-cve2010-4221"],
        "enum_commands": [
            "ftp <TARGET>  (try anonymous:anonymous)",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<TARGET>",
            "nmap --script ftp-anon,ftp-vuln* -p 21 <TARGET>",
            "searchsploit ftp <VERSION>",
        ],
        "checks": ["anonymous login", "default credentials", "writable directory"],
    },
    22: {
        "service": "SSH",
        "enum_scripts": ["ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods"],
        "enum_commands": [
            "ssh <USER>@<TARGET>  (try default creds)",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<TARGET>",
            "nmap --script ssh-auth-methods,ssh2-enum-algos -p 22 <TARGET>",
            "searchsploit openssh <VERSION>",
        ],
        "checks": ["weak ciphers", "password auth enabled", "default credentials"],
    },
    23: {
        "service": "Telnet",
        "enum_scripts": ["telnet-ntlm-info"],
        "enum_commands": [
            "telnet <TARGET>",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://<TARGET>",
            "searchsploit telnet",
        ],
        "checks": ["cleartext communication", "default creds"],
    },
    25: {
        "service": "SMTP",
        "enum_scripts": ["smtp-commands", "smtp-enum-users", "smtp-vuln-cve2011-1764"],
        "enum_commands": [
            "nc -nv <TARGET> 25",
            "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <TARGET>",
            "nmap --script smtp-commands,smtp-enum-users -p 25 <TARGET>",
            "searchsploit sendmail <VERSION>",
        ],
        "checks": ["open relay", "user enumeration via VRFY/EXPN"],
    },
    53: {
        "service": "DNS",
        "enum_scripts": ["dns-zone-transfer", "dns-enum", "dns-brute"],
        "enum_commands": [
            "dig axfr @<TARGET> <DOMAIN>",
            "nmap --script dns-zone-transfer,dns-enum -p 53 <TARGET>",
            "dnsrecon -d <DOMAIN> -t axfr -n <TARGET>",
            "dnsenum <DOMAIN> --dnsserver <TARGET>",
        ],
        "checks": ["zone transfer", "recursive resolver"],
    },
    80: {
        "service": "HTTP",
        "enum_scripts": ["http-title", "http-headers", "http-enum", "http-webdav-scan",
                        "http-methods", "http-vuln-cve2017-5638", "http-sql-injection"],
        "enum_commands": [
            "curl -v http://<TARGET>",
            "gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "nikto -h http://<TARGET>",
            "nmap --script http-enum,http-headers,http-methods -p 80 <TARGET>",
            "whatweb http://<TARGET>",
            "searchsploit apache <VERSION> | searchsploit nginx <VERSION> | searchsploit iis <VERSION>",
        ],
        "checks": ["directory listing", "default pages", "info disclosure", "PUT method"],
    },
    110: {
        "service": "POP3",
        "enum_scripts": ["pop3-capabilities", "pop3-ntlm-info"],
        "enum_commands": [
            "nc -nv <TARGET> 110",
            "telnet <TARGET> 110",
            "hydra -l user -P /usr/share/wordlists/rockyou.txt pop3://<TARGET>",
            "nmap --script pop3-capabilities -p 110 <TARGET>",
        ],
        "checks": ["cleartext auth", "default creds"],
    },
    111: {
        "service": "RPCbind",
        "enum_scripts": ["rpcinfo"],
        "enum_commands": [
            "rpcinfo -p <TARGET>",
            "nmap --script rpcinfo -p 111 <TARGET>",
        ],
        "checks": ["NFS exports enumeration"],
    },
    135: {
        "service": "MSRPC",
        "enum_scripts": ["msrpc-enum", "epmd-info"],
        "enum_commands": [
            "rpcclient -U '' -N <TARGET>",
            "nmap --script msrpc-enum -p 135 <TARGET>",
        ],
        "checks": ["null session", "RPC enumeration"],
    },
    139: {
        "service": "NetBIOS-SSN",
        "enum_scripts": ["nbstat", "smb-enum-shares", "smb-enum-users", "smb-os-discovery"],
        "enum_commands": [
            "nbtscan <TARGET>/24",
            "nmap --script nbstat,smb-enum-shares,smb-enum-users -p 139,445 <TARGET>",
            "smbclient -L //<TARGET> -N",
            "enum4linux -a <TARGET>",
        ],
        "checks": ["null session", "share listing", "user enumeration"],
    },
    143: {
        "service": "IMAP",
        "enum_scripts": ["imap-capabilities", "imap-ntlm-info"],
        "enum_commands": [
            "nc -nv <TARGET> 143",
            "hydra -l user -P /usr/share/wordlists/rockyou.txt imap://<TARGET>",
            "nmap --script imap-capabilities -p 143 <TARGET>",
        ],
        "checks": ["cleartext auth", "default creds"],
    },
    389: {
        "service": "LDAP",
        "enum_scripts": ["ldap-search", "ldap-rootdse"],
        "enum_commands": [
            "ldapsearch -x -h <TARGET> -b 'dc=<DOMAIN>,dc=<TLD>'",
            "nmap --script ldap-search,ldap-rootdse -p 389 <TARGET>",
        ],
        "checks": ["anonymous bind", "information disclosure"],
    },
    443: {
        "service": "HTTPS",
        "enum_scripts": ["ssl-enum-ciphers", "ssl-heartbleed", "tls-nextprotoneg",
                        "http-enum", "http-headers"],
        "enum_commands": [
            "curl -k -v https://<TARGET>",
            "nmap --script ssl-enum-ciphers,ssl-heartbleed -p 443 <TARGET>",
            "sslscan <TARGET>",
            "testssl.sh <TARGET>",
            "gobuster dir -k -u https://<TARGET> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ],
        "checks": ["weak SSL/TLS ciphers", "heartbleed", "certificate issues"],
    },
    445: {
        "service": "SMB",
        "enum_scripts": ["smb-enum-shares", "smb-enum-users", "smb-os-discovery",
                        "smb-protocols", "smb-security-mode", "smb-vuln-*"],
        "enum_commands": [
            "smbclient -L //<TARGET> -N",
            "smbmap -H <TARGET>",
            "crackmapexec smb <TARGET>",
            "enum4linux-ng -A <TARGET>",
            "nmap --script smb-enum-shares,smb-enum-users,smb-vuln-* -p 445 <TARGET>",
            "hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://<TARGET>",
            "searchsploit smb <VERSION>",
        ],
        "checks": ["null session", "SMBv1 enabled", "anonymous shares", "EternalBlue"],
    },
    1433: {
        "service": "MSSQL",
        "enum_scripts": ["ms-sql-info", "ms-sql-ntlm-info", "ms-sql-brute"],
        "enum_commands": [
            "nmap --script ms-sql-info,ms-sql-ntlm-info -p 1433 <TARGET>",
            "sqsh -S <TARGET> -U sa",
            "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://<TARGET>",
            "searchsploit mssql <VERSION>",
        ],
        "checks": ["sa empty password", "default creds"],
    },
    1521: {
        "service": "Oracle DB",
        "enum_scripts": ["oracle-sid-brute", "oracle-tns-version"],
        "enum_commands": [
            "nmap --script oracle-sid-brute -p 1521 <TARGET>",
            "odat all -s <TARGET>",
            "searchsploit oracle <VERSION>",
        ],
        "checks": ["default SID", "default creds"],
    },
    2049: {
        "service": "NFS",
        "enum_scripts": ["nfs-showmount", "nfs-ls", "nfs-statfs"],
        "enum_commands": [
            "showmount -e <TARGET>",
            "mount -t nfs <TARGET>:/<SHARE> /mnt/nfs",
            "nmap --script nfs-showmount,nfs-ls -p 2049 <TARGET>",
        ],
        "checks": ["exported world-readable shares", "no_root_squash"],
    },
    3306: {
        "service": "MySQL",
        "enum_scripts": ["mysql-empty-password", "mysql-enum", "mysql-info",
                        "mysql-vuln-cve2012-2122"],
        "enum_commands": [
            "mysql -h <TARGET> -u root",
            "nmap --script mysql-empty-password,mysql-info,mysql-enum -p 3306 <TARGET>",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<TARGET>",
            "searchsploit mysql <VERSION>",
        ],
        "checks": ["root empty password", "default creds"],
    },
    3389: {
        "service": "RDP",
        "enum_scripts": ["rdp-enum-encryption", "rdp-ntlm-info", "rdp-vuln-ms12-020"],
        "enum_commands": [
            "nmap --script rdp-enum-encryption,rdp-ntlm-info -p 3389 <TARGET>",
            "crowbar -b rdp -u admin -C /usr/share/wordlists/rockyou.txt -s <TARGET>/32",
            "hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://<TARGET>",
            "searchsploit rdp <VERSION>",
        ],
        "checks": ["BlueKeep (CVE-2019-0708)", "weak creds", "NLA disabled"],
    },
    5432: {
        "service": "PostgreSQL",
        "enum_scripts": ["pgsql-enum"],
        "enum_commands": [
            "psql -h <TARGET> -U postgres",
            "nmap --script pgsql-enum -p 5432 <TARGET>",
            "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://<TARGET>",
            "searchsploit postgresql <VERSION>",
        ],
        "checks": ["postgres empty password", "default creds"],
    },
    5900: {
        "service": "VNC",
        "enum_scripts": ["vnc-info", "vnc-brute"],
        "enum_commands": [
            "nmap --script vnc-info,vnc-brute -p 5900 <TARGET>",
            "vncviewer <TARGET>",
            "searchsploit vnc <VERSION>",
        ],
        "checks": ["no password", "weak VNC auth"],
    },
    5985: {
        "service": "WinRM",
        "enum_scripts": ["http-title", "wsman-enum"],
        "enum_commands": [
            "crackmapexec winrm <TARGET> -u administrator -p /usr/share/wordlists/rockyou.txt",
            "evil-winrm -i <TARGET> -u administrator -p 'PASSWORD'",
            "nmap --script http-title -p 5985 <TARGET>",
        ],
        "checks": ["default creds", "WinRM enabled"],
    },
    6379: {
        "service": "Redis",
        "enum_scripts": ["redis-info"],
        "enum_commands": [
            "redis-cli -h <TARGET>",
            "nmap --script redis-info -p 6379 <TARGET>",
            "searchsploit redis <VERSION>",
        ],
        "checks": ["no auth", "writable /root/.ssh"],
    },
    8080: {
        "service": "HTTP-Proxy",
        "enum_scripts": ["http-title", "http-enum", "http-methods"],
        "enum_commands": [
            "curl -v http://<TARGET>:8080",
            "gobuster dir -u http://<TARGET>:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "nmap --script http-enum,http-headers -p 8080 <TARGET>",
            "searchsploit tomcat <VERSION> | searchsploit jenkins <VERSION>",
        ],
        "checks": ["default tomcat/jenkins", "manager console"],
    },
    27017: {
        "service": "MongoDB",
        "enum_scripts": ["mongodb-info"],
        "enum_commands": [
            "nmap --script mongodb-info -p 27017 <TARGET>",
            "mongo --host <TARGET>",
            "searchsploit mongodb <VERSION>",
        ],
        "checks": ["no auth", "default databases"],
    },
}

# Default catch-all for unknown ports
DEFAULT_ENUM = {
    "enum_commands": [
        "nc -nv <TARGET> <PORT>  # banner grab",
        "curl http://<TARGET>:<PORT>  # if HTTP",
        "searchsploit <SERVICE> <VERSION>",
        "nmap -sV --script vulners -p <PORT> <TARGET>",
    ],
    "checks": ["banner grab", "version-specific CVEs"],
}


def get_service_info(port, service_name=None):
    """Return service enumeration info for a given port."""
    if port in SERVICES_DB:
        return SERVICES_DB[port]
    # Try to find by service name if port not standard
    for p, info in SERVICES_DB.items():
        if service_name and service_name.lower() in info["service"].lower():
            return info
    return DEFAULT_ENUM
