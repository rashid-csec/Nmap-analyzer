from colorama import Fore, Style

SEVERITY_MAP = {
    "CRITICAL": {"color": Fore.RED + Style.BRIGHT, "badge": "🔴", "range": "9.0-10.0"},
    "HIGH":     {"color": Fore.RED,                  "badge": "🟠", "range": "7.0-8.9"},
    "MEDIUM":   {"color": Fore.YELLOW,               "badge": "🟡", "range": "4.0-6.9"},
    "LOW":      {"color": Fore.BLUE,                 "badge": "🔵", "range": "0.1-3.9"},
    "INFO":     {"color": Fore.GREEN,                "badge": "🟢", "range": "0.0"}
}

def calculate_severity(cvss_score):
    try:
        score = float(cvss_score)
    except (ValueError, TypeError):
        score = 0.0
        
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "INFO"

def get_severity_properties(severity_lbl):
    return SEVERITY_MAP.get(severity_lbl, {"color": Fore.WHITE, "badge": "⚪", "range": "—"})
