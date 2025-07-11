import argparse
from config_loader import load_config
from scanner import run_nmap_scan
from parser import parse_nmap_xml, compare_scans
from reporter import generate_markdown_report
from alerter import check_alerts
import os
import glob
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Network Visibility Tool")
    parser.add_argument("--config", metavar="CONFIG_PATH", default="config.yaml", help="Path to configuration YAML file")
    parser.add_argument("--scan", action="store_true", help="Run a new network scan")
    parser.add_argument("--compare", nargs=2, metavar=("OLD_SCAN", "NEW_SCAN"), help="Compare two scan JSON files")
    parser.add_argument("--report", metavar="SCAN_FILE", help="Generate a Markdown report from the given scan file (XML)")
    parser.add_argument("--dashboard", action="store_true", help="Launch the Flask dashboard")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.scan:
        print("[*] Running network scan...")
        output_dir = config.get("output_dir", "./logs")
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_path = os.path.join(output_dir, f"scan_results_{timestamp}.xml")

        run_nmap_scan(config, xml_path)
        print(f"[*] Scan saved to {xml_path}")

        parsed = parse_nmap_xml(xml_path)
        alert_config = config.get("alerts", {})
        alerts = check_alerts(parsed, alert_config)
        for alert in alerts:
            print(f"ALERT: {alert}")

    elif args.compare:
        old_file, new_file = args.compare
        print(f"[*] Comparing scans: {old_file} -> {new_file}")
        compare_scans(old_file, new_file)

    elif args.report:
        print(f"[*] Generating report for {args.report}")
        parsed = parse_nmap_xml(args.report)
        alert_config = config.get("alerts", {})
        alerts = check_alerts(parsed, alert_config)
        for alert in alerts:
            print(f"ALERT: {alert}")
        report_path = generate_markdown_report(parsed, "./reports")
        print(f"[+] Markdown report saved to {report_path}")

    elif args.dashboard:
        print("[*] Launching Flask dashboard...")
        import dashboard
        dashboard.app.run(debug=False)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
