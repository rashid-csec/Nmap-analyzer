import os
import re
import xml.etree.ElementTree as ET

def detect_and_parse(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File path error: {file_path}")
        
    with open(file_path, 'r', errors='ignore') as f:
        sample = f.read(2048)
        
    if "<nmaprun" in sample or "xml version=" in sample:
        return parse_xml(file_path)
    elif "# Nmap parseable scan" in sample:
        return parse_gnmap(file_path)
    else:
        return parse_normal_nmap(file_path)

def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    hosts = []
    
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None: continue
        ip = addr_el.get("addr", "unknown")
        
        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")
                
        os_name, os_accuracy = "Unknown OS", 0
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name", "Unknown")
                os_accuracy = int(match.get("accuracy", "0"))

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid")
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open": continue
                
                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                service_product = service_el.get("product", "") if service_el is not None else ""
                service_version = service_el.get("version", "") if service_el is not None else ""
                
                full_version = f"{service_product} {service_version}".strip() or service_name
                
                ports.append({
                    "port": int(port_id), "protocol": protocol, "service": service_name,
                    "product": service_product, "version": service_version, "full_version": full_version
                })
                
        hosts.append({
            "ip": ip, "hostname": hostname, "os": os_name, "os_confidence": os_accuracy, "ports": ports
        })
    return hosts

def parse_gnmap(file_path):
    hosts = []
    with open(file_path, 'r') as f:
        for line in f:
            if "Host:" in line and "Ports:" in line:
                ip_match = re.search(r"Host:\s+([0-9.]+)", line)
                if not ip_match: continue
                ip = ip_match.group(1)
                
                hn_match = re.search(r"Host:\s+[0-9.]+\s+\(([^)]*)\)", line)
                hostname = hn_match.group(1) if hn_match else ""
                
                ports_part = line.split("Ports:")[1].strip()
                ports_list = ports_part.split(",")
                ports = []
                
                for p_info in ports_list:
                    tokens = p_info.strip().split("/")
                    if len(tokens) >= 5 and tokens[1] == "open":
                        ports.append({
                            "port": int(tokens[0]), "protocol": "tcp", "service": tokens[4],
                            "product": "", "version": "", "full_version": tokens[4]
                        })
                hosts.append({"ip": ip, "hostname": hostname, "os": "Unknown OS", "os_confidence": 0, "ports": ports})
    return hosts

def parse_normal_nmap(file_path):
    hosts = []
    current_host = None
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if "Nmap scan report for" in line:
                if current_host: hosts.append(current_host)
                tokens = line.split()
                ip = tokens[-1].strip("()")
                hn = tokens[-2] if len(tokens) > 4 else ""
                current_host = {"ip": ip, "hostname": hn if hn != "for" else "", "os": "Unknown OS", "os_confidence": 0, "ports": []}
            elif current_host and "/tcp" in line and "open" in line:
                tokens = re.split(r'\s+', line)
                port_proto = tokens[0].split('/')
                current_host["ports"].append({
                    "port": int(port_proto[0]), "protocol": "tcp", "service": tokens[2],
                    "product": tokens[2], "version": " ".join(tokens[3:]), "full_version": " ".join(tokens[2:])
                })
        if current_host: hosts.append(current_host)
    return hosts
