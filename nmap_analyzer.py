#!/usr/bin/env python3
"""
Nmap Analyzer — Parses Nmap XML results, identifies vulnerabilities,
ranks them by criticality, and provides an exploitation roadmap.

Usage:
    python3 nmap_analyzer.py scan_results.xml
    python3 nmap_analyzer.py scan_results.xml -o report.txt
"""

import sys
import os
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from colorama import init, Fore, Back, Style
from tabulate import tabulate

from services_db import get_service_info
from vulnerability_db import lookup_cves

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.BLUE,
    "INFO": Fore.GREEN,
}

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════╗
║             Nmap Analyzer v2.0                         ║
║       Nmap Result → Vulnerability → Exploit Roadmap   ║
╚═══════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def parse_nmap_xml(xml_file):
    """Parse Nmap XML output file and extract hosts, ports, services."""
    if not os.path.exists(xml_file):
        print(f"{Fore.RED}[!] File not found: {xml_file}")
        sys.exit(1)

    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "unknown")

        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid")
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                service_product = service_el.get("product", "") if service_el is not None else ""
                service_version = service_el.get("version", "") if service_el is not None else ""
                service_extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""

                full_version = f"{service_product} {service_version}".strip()
                if not full_version:
                    full_version = service_name

                ports.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "full_version": full_version,
                    "extrainfo": service_extrainfo,
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "ports": ports,
        })

    return hosts


def search_vulnerabilities(service_name, version, port):
    """Search for known CVEs in local DB and suggest searchsploit."""
    findings = lookup_cves(service_name, version)

    # If nothing found locally, note it
    if not findings:
        return []

    return findings


def classify_severity(cvss):
    """Classify CVSS score into severity level."""
    if cvss >= 9.0:
        return "CRITICAL"
    elif cvss >= 7.0:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    elif cvss > 0:
        return "LOW"
    return "INFO"


def analyze_ports(host):
    """Analyze all open ports for a host and generate findings."""
    findings = []
    ip = host["ip"]

    for port_info in host["ports"]:
        port = port_info["port"]
        service = port_info["service"]
        version = port_info["full_version"]
        service_name_clean = port_info["product"] if port_info["product"] else service

        # Get service enum info
        svc_info = get_service_info(port, service)

        # Look up CVEs
        vulns = search_vulnerabilities(service_name_clean, version, port)

        if vulns:
            for vuln in vulns:
                severity = classify_severity(vuln["cvss"])
                findings.append({
                    "ip": ip,
                    "port": port,
                    "service": f"{service} ({version})" if version else service,
                    "type": "EXPLOIT",
                    "severity": severity,
                    "cvss": vuln["cvss"],
                    "cve": vuln["cve"],
                    "name": vuln["name"],
                    "module": vuln.get("module", ""),
                    "action": f"Run: use {vuln['module']}" if vuln.get("module") else "Manual exploitation",
                    "details": f"Target: {ip}:{port} — Version: {version} — CVE: {vuln['cve']} ({vuln['name']})",
                })
        else:
            # No direct CVE — suggest enumeration methods
            findings.append({
                "ip": ip,
                "port": port,
                "service": f"{service} ({version})" if version else service,
                "type": "ENUMERATE",
                "severity": "INFO",
                "cvss": 0,
                "cve": "—",
                "name": f"{svc_info['service'] if 'service' in svc_info else service} Enumeration",
                "module": "",
                "action": "\n".join(svc_info.get("enum_commands", [])),
                "details": f"Target: {ip}:{port} — Service: {service} v{version if version else '(unknown)'}\n"
                           f"Check: {', '.join(svc_info.get('checks', ['manual inspection']))}",
            })

    return findings


def organize_roadmap(findings):
    """Organize findings into a criticality-ranked exploitation roadmap."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda f: (severity_order.get(f["severity"], 99), -f["cvss"]))


def check_searchsploit(service_name, version=""):
    """Suggest running searchsploit for deeper analysis."""
    query = f"{service_name} {version}".strip()
    return (
        f"  searchsploit {service_name} {version}\n"
        f"  searchsploit --cve <CVE-ID>\n"
        f"  searchsploit --nmap scan.xml   (auto-parse Nmap XML)"
    )


def generate_report(hosts_data, output_file=None):
    """Generate the full analysis report."""
    output = []
    output.append(BANNER)
    output.append(f"\n{Fore.WHITE}Scan Analysis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output.append(f"{Fore.WHITE}{'='*65}\n")

    all_findings = []

    for host in hosts_data:
        ip = host["ip"]
        hostname = host["hostname"]
        label = f"{ip} ({hostname})" if hostname else ip
        output.append(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Target: {label}")
        output.append(f"{Fore.WHITE}{'-'*65}")

        if not host["ports"]:
            output.append(f"{Fore.YELLOW}  [i] No open ports found.\n")
            continue

        # Summary table
        table_data = []
        for p in host["ports"]:
            table_data.append([
                p["port"],
                p["protocol"],
                p["service"],
                p["product"],
                p["version"],
            ])

        output.append(f"\n{Fore.MAGENTA}Open Ports Summary:")
        output.append(tabulate(
            table_data,
            headers=["Port", "Proto", "Service", "Product", "Version"],
            tablefmt="grid"
        ))

        # Analyze ports
        findings = analyze_ports(host)
        all_findings.extend(findings)

        # Findings table
        if findings:
            roadmap = organize_roadmap(findings)
            output.append(f"\n{Fore.MAGENTA}{Style.BRIGHT}🔴 Exploitation Roadmap (Criticality Ordered):")
            output.append(f"{Fore.WHITE}{'='*65}")

            for i, finding in enumerate(roadmap, 1):
                severity_color = SEVERITY_COLORS.get(finding["severity"], Fore.WHITE)

                # Severity badge
                if finding["type"] == "EXPLOIT":
                    badge = f"{severity_color}[{finding['severity']:>8}]"
                else:
                    badge = f"{Fore.CYAN}[ENUM]"

                cvss_str = f"CVSS:{finding['cvss']:.1f}" if finding["cvss"] > 0 else "     —"

                output.append(f"\n  {Fore.WHITE}{Style.BRIGHT}{i}. {badge} {cvss_str} {finding['name']}")
                output.append(f"     {Fore.WHITE}Port: {finding['port']} | Service: {finding['service']}")
                if finding["type"] == "EXPLOIT":
                    output.append(f"     {Fore.WHITE}CVE: {finding['cve']}")
                    output.append(f"     {Fore.WHITE}Details: {finding['details']}")
                    if finding["module"]:
                        output.append(f"     {Fore.GREEN}Metasploit: {finding['module']}")
                    output.append(f"     {Fore.YELLOW}Searchsploit:")
                    output.append(check_searchsploit(finding["service"].split("(")[0].strip(),
                                                      finding["service"].split("(")[1].rstrip(")") if "(" in finding["service"] else ""))
                else:
                    output.append(f"     {Fore.WHITE}Details: {finding['details']}")
                    output.append(f"     {Fore.YELLOW}Actions:")
                    for line in finding["action"].split("\n"):
                        output.append(f"       {Fore.CYAN}$ {line.strip()}")

        output.append(f"\n")

    # === GLOBAL SUMMARY ===
    exploit_count = len([f for f in all_findings if f["type"] == "EXPLOIT"])
    enum_count = len([f for f in all_findings if f["type"] == "ENUMERATE"])
    critical_count = len([f for f in all_findings if f["severity"] == "CRITICAL"])
    high_count = len([f for f in all_findings if f["severity"] == "HIGH"])

    output.append(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*65}")
    output.append(f"{Fore.CYAN}{Style.BRIGHT}📊 SCAN SUMMARY")
    output.append(f"{Fore.WHITE}{'='*65}")
    output.append(f"  {Fore.RED}Critical Vulnerabilities: {critical_count}")
    output.append(f"  {Fore.RED}High Vulnerabilities:    {high_count}")
    output.append(f"  {Fore.YELLOW}Exploitable Findings:   {exploit_count}")
    output.append(f"  {Fore.CYAN}Services to Enumerate:  {enum_count}")

    # === SEARCHSPLOIT BATCH ===
    if exploit_count > 0:
        output.append(f"\n{Fore.MAGENTA}{Style.BRIGHT}🔎 SearchSploit Batch Commands:")
        output.append(f"{Fore.WHITE}{'='*65}")
        for f in all_findings:
            if f["type"] == "EXPLOIT":
                svc = f["service"].split("(")[0].strip()
                ver = ""
                if "(" in f["service"]:
                    ver = f["service"].split("(")[1].rstrip(")")
                if ver:
                    output.append(f"  {Fore.YELLOW}searchsploit {svc} {ver}")
                else:
                    output.append(f"  {Fore.YELLOW}searchsploit {svc}")
        output.append(f"  {Fore.YELLOW}searchsploit --nmap {sys.argv[1] if len(sys.argv) > 1 else '<xml_file>'}")

    # === NSE SCRIPT COMMANDS ===
    nse_commands = set()
    hosts_ips = [h["ip"] for h in hosts_data]
    for finding in all_findings:
        port = finding["port"]
        if finding["type"] == "EXPLOIT":
            nse_commands.add(f"nmap -sV --script vulners -p {port} {hosts_ips[0] if hosts_ips else '<target>'}")
        else:
            svc_info = get_service_info(port)
            for script in svc_info.get("enum_scripts", []):
                nse_commands.add(f"nmap --script {script} -p {port} {hosts_ips[0] if hosts_ips else '<target>'}")

    if nse_commands:
        output.append(f"\n{Fore.MAGENTA}{Style.BRIGHT}📡 Recommended NSE Scripts:")
        output.append(f"{Fore.WHITE}{'='*65}")
        for cmd in sorted(nse_commands):
            output.append(f"  {Fore.CYAN}$ {cmd}")

    # === FOOTER ===
    output.append(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Analysis complete")
    output.append(f"{Fore.WHITE}{'='*65}\n")

    report_text = "\n".join(output)

    if output_file:
        # Strip ANSI codes for file output
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', report_text)
        with open(output_file, 'w') as f:
            f.write(clean_text)
        print(f"{Fore.GREEN}[+] Report saved to: {output_file}")

    print(report_text)
    return report_text


def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python3 nmap_analyzer.py <nmap_output.xml> [-o report.txt]")
        print(f"\n  {Fore.WHITE}Steps:")
        print(f"    1. Run Nmap: nmap -sV -sC -oX scan.xml <target>")
        print(f"    2. Analyze:  python3 nmap_analyzer.py scan.xml")
        sys.exit(1)

    xml_file = sys.argv[1]
    output_file = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]

    print(f"{Fore.CYAN}[*] Parsing: {xml_file}")
    hosts = parse_nmap_xml(xml_file)
    print(f"{Fore.CYAN}[*] Found {len(hosts)} host(s) with open ports")

    generate_report(hosts, output_file)


if __name__ == "__main__":
    main()
