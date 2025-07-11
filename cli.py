import argparse
from config_loader import load_config
from scanner import run_nmap_scan
from parser import parse_nmap_xml, compare_scans
from reporter import generate_markdown_report
from alerter import check_alerts
import os

def main():
    parser = argparse.ArgumentParser(description="Network Monitoring CLI Tool")
    parser.add_argument("--scan", action="store_true", help="Run a new network scan")
    parser.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"), help="Compare two scan results")
    parser.add_argument("--report", metavar="JSON_FILE", help="Generate a report from a parsed scan")
    parser.add_argument("--config", metavar="CONFIG_PATH", default="config.yaml", help="Path to YAML config file")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.scan:
        print("[*] Running scan...")
        output_dir = config.get("output_dir", "./logs")
        timestamp = os.popen("date +%Y-%m-%d_%H-%M-%S").read().strip()
        os.makedirs(output_dir, exist_ok=True)
        xml_path = os.path.join(output_dir, f"scan_results_{timestamp}.xml")
        run_nmap_scan(config, xml_path)
        print(f"[*] Scan saved to {xml_path}")
    
    elif args.compare:
        old, new = args.compare
        compare_scans(old, new)
    
    elif args.report:
        print(f"[*] Generating report for {args.report}")
        parsed = parse_nmap_xml(args.report)
        alert_config = config.get("alerts", {})
        alerts = check_alerts(parsed, alert_config)
        for alert in alerts:
            print(f"ALERT: {alert}")

        report_path = args.report.replace(".json", ".md")
        generate_markdown_report(parsed, report_path)
        print(f"[+] Markdown report saved to {report_path}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()