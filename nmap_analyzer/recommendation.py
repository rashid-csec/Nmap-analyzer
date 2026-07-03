def generate_recommendations(service, version, cve=None):
    recs = []
    svc = service.lower()
    
    if cve:
        if "apache" in svc and "2.4.49" in version:
            recs.extend([
                "Update Apache HTTP Server to version 2.4.51+",
                "Disable CGI parsing modules if not explicitly required by system applications",
                "Disable dangerous HTTP methods (e.g., PUT, DELETE) within system configs",
                "Restrict DocumentRoot access directives inside httpd.conf structure"
            ])
            return recs
        else:
            recs.append(f"Update component to the latest stable patched release matching {cve}")
    else:
        recs.append(f"Review tracking patch updates for {service} ({version or 'Unknown Version'})")
        
    if "http" in svc or "nginx" in svc:
        recs.extend([
            "Disable unused modules and legacy high-risk HTTP request verbs",
            "Implement a Web Application Firewall (WAF) to block application-layer bypasses"
        ])
    elif "ssh" in svc:
        recs.extend([
            "Disable password authentication completely; enforce secure SSH public key pairs",
            "Change standard listen port 22 to an arbitrary high port to evade scanner spraying"
        ])
    elif "ftp" in svc:
        recs.extend([
            "Explicitly disable Anonymous FTP access policies unless functionally critical",
            "Force encryption encapsulation policies (FTPS/SFTP) to protect data"
        ])
        
    return recs[:4]
