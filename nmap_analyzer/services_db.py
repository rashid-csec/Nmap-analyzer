LOCAL_SERVICES_REF = {
    21: {"service": "FTP", "enum_scripts": ["ftp-anon", "ftp-syst"], "enum_commands": ["ftp -n $TARGET"]},
    22: {"service": "SSH", "enum_scripts": ["ssh-auth-methods"], "enum_commands": ["ssh -v $TARGET"]},
    80: {"service": "HTTP", "enum_scripts": ["http-enum"], "enum_commands": ["nikto -h $TARGET"]},
    443: {"service": "HTTPS", "enum_scripts": ["ssl-enum-ciphers"], "enum_commands": ["testssl.sh $TARGET"]},
    445: {"service": "SMB", "enum_scripts": ["smb-enum-shares"], "enum_commands": ["smbclient -L //$TARGET/"]}
}

def get_service_info(port, name=""):
    return LOCAL_SERVICES_REF.get(int(port), {"service": name or "Unknown", "enum_scripts": [], "enum_commands": ["manual inspection"]})
