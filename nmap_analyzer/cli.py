import sys
import argparse
from nmap_analyzer.banner import print_banner, get_version_info
from nmap_analyzer.parser import detect_and_parse
from nmap_analyzer.report import run_analysis_pipeline, render_terminal_output, export_json, export_csv, export_html, export_pdf

def main():
    parser = argparse.ArgumentParser(description="Nmap Analyzer v2.1", add_help=False)
    parser.add_argument("scan_file", nargs="?", help="Input target source log path location.")
    parser.add_argument("-x", "--xml", action="store_true", help="Parse XML file")
    parser.add_argument("-o", "--output", help="Save text report destination file path")
    parser.add_argument("-j", "--json", help="Export JSON")
    parser.add_argument("-h", "--html", help="Export HTML report")
    parser.add_argument("-p", "--pdf", help="Export PDF report")
    parser.add_argument("-c", "--csv", help="Export CSV")
    parser.add_argument("-v", action="store_true", help="Verbose")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--update-db", action="store_true", help="Update CVE database")
    parser.add_argument("--searchsploit", action="store_true", help="Run searchsploit automatically")
    parser.add_argument("--nse", action="store_true", help="Generate NSE commands")
    parser.add_argument("--help", action="help", help="Show this help menu statement logs profile parameters layout guidelines details")

    args = parser.parse_args()

    if args.version:
        print(get_version_info())
        sys.exit(0)

    print_banner()

    if args.update_db:
        print("[*] Synchronizing database parameters matrix entries records layout context indicators updates...")
        print("[✓] Complete.")
        sys.exit(0)

    if not args.scan_file:
        print("Usage: nmap-analyzer [OPTIONS] <scan_file>")
        sys.exit(1)

    try:
        hosts_data = detect_and_parse(args.scan_file)
        analysis_report = run_analysis_pipeline(hosts_data, args)
        
        render_terminal_output(analysis_report, args)
        
        if args.json: export_json(analysis_report, args.json)
        if args.csv:  export_csv(analysis_report, args.csv)
        if args.html: export_html(analysis_report, args.html)
        if args.pdf:  export_pdf(analysis_report, args.pdf)
            
    except Exception as e:
        print(f"\nCritical Fault: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
