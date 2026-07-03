import subprocess
import shutil
import json
from colorama import Fore

def is_searchsploit_available():
    return shutil.which("searchsploit") is not None

def execute_searchsploit(service_name, version=""):
    if not is_searchsploit_available():
        return f"  {Fore.RED}[!] SearchSploit not detected in system PATH variables."
    
    query = f"{service_name} {version}".strip()
    try:
        process = subprocess.run(
            ["searchsploit", "--json", service_name, version],
            capture_output=True, text=True, timeout=10
        )
        if process.returncode != 0 or not process.stdout.strip():
            return "  No matching public functional exploit entries found."
        
        data = json.loads(process.stdout)
        results = data.get("RESULTS_EXPLOIT", [])
        
        if not results:
            return "  No direct public functional exploit payloads recovered."
            
        output_lines = []
        for item in results[:3]:
            output_lines.append(f"  [EDB-ID {item.get('EDB-ID', 'N/A')}] {item.get('Title', 'Unknown Payload')}")
        return "\n".join(output_lines)
        
    except Exception as e:
        return f"  {Fore.RED}[!] Execution interface fault: {e}"
