import json
import csv
import os
from colorama import Fore, Style
from tabulate import tabulate
from nmap_analyzer.severity import calculate_severity, get_severity_properties
from nmap_analyzer.mitre import get_mitre_mapping
from nmap_analyzer.recommendation import generate_recommendations
from nmap_analyzer.searchsploit import execute_searchsploit

def run_analysis_pipeline(hosts, args):
    report_data = []
    for host in hosts:
        host_findings = []
        for port in host["ports"]:
            from nmap_analyzer.vulnerability_db import lookup_cves
            from nmap_analyzer.services_db import get_service_info
            
            clean_name = port["product"] if port["product"] else port["service"]
            vulns = lookup_cves(clean_name, port["version"])
            
            if vulns:
                for v in vulns:
                    sev = calculate_severity(v["cvss"])
                    mitre = get_mitre_mapping(port["service"], is_exploit=True)
                    recs = generate_recommendations(port["service"], port["version"], v["cve"])
                    
                    finding = {
                        "port": port["port"], "service": port["service"], "version": port["full_version"],
                        "type": "EXPLOIT", "severity": sev, "cvss": v["cvss"], "cve": v["cve"],
                        "name": v["name"], "module": v["module"], "probability": v["probability"],
                        "mitre_id": mitre["id"], "mitre_name": mitre["name"], "recommendations": recs
                    }
                    if args.searchsploit:
                        finding["searchsploit_data"] = execute_searchsploit(clean_name, port["version"])
                    host_findings.append(finding)
            else:
                svc_info = get_service_info(port["port"], port["service"])
                mitre = get_mitre_mapping(port["service"], is_exploit=False)
                recs = generate_recommendations(port["service"], port["version"])
                
                host_findings.append({
                    "port": port["port"], "service": port["service"], "version": port["full_version"],
                    "type": "ENUMERATE", "severity": "INFO", "cvss": 0.0, "cve": "—",
                    "name": f"{svc_info.get('service', port['service'])} Verification",
                    "module": "—", "probability": "★☆☆☆☆", "mitre_id": mitre["id"],
                    "mitre_name": mitre["name"], "recommendations": recs,
                    "enum_commands": svc_info.get("enum_commands", []),
                    "enum_scripts": svc_info.get("enum_scripts", [])
                })
        
        # Build graphical attack path
        attack_path = []
        sorted_findings = sorted(host_findings, key=lambda x: x["cvss"], reverse=True)
        for idx, item in enumerate(sorted_findings):
            if item["type"] == "EXPLOIT":
                attack_path.append(f"{item['port']} {item['service']} -> Exploit {item['cve']}")
            elif idx == 0:
                attack_path.append(f"{item['port']} {item['service']} -> Service Discovery & Enumeration")
        if attack_path:
            attack_path.append("Privilege Escalation Strategy -> Root Shell Access")
            
        report_data.append({
            "ip": host["ip"], "hostname": host["hostname"], "os": host["os"],
            "os_confidence": host["os_confidence"], "findings": sorted_findings,
            "attack_roadmap": attack_path
        })
    return report_data

def render_terminal_output(analysis_results, args):
    for host in analysis_results:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Target Asset Profile: {host['ip']} ({host['hostname'] or 'No Resolve Domain'})")
        print(f"{Fore.WHITE}{'='*85}")
        print(f"Detected OS  : {Fore.YELLOW}{host['os']}")
        print(f"Confidence   : {Fore.YELLOW}{host['os_confidence']}%")
        print(f"Architecture : {Fore.YELLOW}x64{Fore.WHITE}\n")
        
        table_rows = []
        for f in host["findings"]:
            sev_p = get_severity_properties(f["severity"])
            badge = f"{sev_p['badge']} {sev_p['color']}{f['severity']:<8}{Style.RESET_ALL} [{sev_p['range']}]" if f["type"] == "EXPLOIT" else f"{Fore.CYAN}[ENUMERATE]{Style.RESET_ALL}"
            table_rows.append([f["port"], f["service"], badge, f["cvss"], f["cve"]])
            
        print(tabulate(table_rows, headers=["Port", "Service", "Severity", "CVSS", "Identifier"], tablefmt="grid"))
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}Attack Roadmap:")
        for i, step in enumerate(host["attack_roadmap"]):
            print(f"  {step}")
            if i < len(host["attack_roadmap"]) - 1:
                print(f"    ↓")
                
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Recommendations:")
        for f in host["findings"]:
            if f["type"] == "EXPLOIT":
                print(f"  {Fore.RED}Vulnerability {f['cve']} ({f['name']}):")
                print(f"  Exploitability: {f['probability']}")
                for r in f["recommendations"]:
                    print(f"    ✔ {r}")
                if "searchsploit_data" in f:
                    print(f"  {Fore.YELLOW}Searchsploit Output:")
                    print(f"{f['searchsploit_data']}")
        
        if args.nse:
            print(f"\n{Fore.GREEN}Recommended NSE Validation Commands:")
            for f in host["findings"]:
                if f["type"] == "ENUMERATE":
                    for scr in f.get("enum_scripts", []):
                        print(f"  $ nmap --script {scr} -p {f['port']} {host['ip']}")

def export_json(analysis_results, path):
    with open(path, 'w') as f: json.dump(analysis_results, f, indent=4)
    print(f"{Fore.GREEN}[✓] Exported JSON to: {path}")

def export_csv(analysis_results, path):
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "OS", "Port", "Service", "Severity", "CVSS", "CVE", "MITRE ID"])
        for h in analysis_results:
            for f in h["findings"]:
                writer.writerow([h["ip"], h["os"], f["port"], f["service"], f["severity"], f["cvss"], f["cve"], f["mitre_id"]])
    print(f"{Fore.GREEN}[✓] Exported CSV to: {path}")

def export_html(analysis_results, path):
    html = "<html><head><style>body{font-family:sans-serif;margin:40px;background:#f8fafc;} th{background:#0f172a;color:white;padding:10px;} td{padding:10px;border-bottom:1px solid #ddd;}</style></head><body><h1>Nmap Analyzer Executive Report</h1>"
    for h in analysis_results:
        html += f"<h2>Target: {h['ip']} ({h['os']})</h2><table><tr><th>Port</th><th>Service</th><th>Severity</th><th>CVSS</th><th>CVE</th></tr>"
        for f in h["findings"]:
            html += f"<tr><td>{f['port']}</td><td>{f['service']}</td><td>{f['severity']}</td><td>{f['cvss']}</td><td>{f['cve']}</td></tr>"
        html += "</table>"
    html += "</body></html>"
    with open(path, 'w') as f: f.write(html)
    print(f"{Fore.GREEN}[✓] Exported HTML to: {path}")

def export_pdf(analysis_results, path):
    try:
        from weasyprint import HTML
        tmp = path + ".tmp.html"
        export_html(analysis_results, tmp)
        HTML(tmp).write_pdf(path)
        if os.path.exists(tmp): os.remove(tmp)
        print(f"{Fore.GREEN}[✓] Exported PDF to: {path}")
    except ImportError:
        print(f"{Fore.RED}[!] Missing 'weasyprint' framework library for native vector PDF rendering outputs.")
