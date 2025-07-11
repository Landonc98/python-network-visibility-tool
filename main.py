# Old entry point for testing - use cli.py instead
import os
import yaml
import datetime
import argparse

from config_loader import load_config
from scanner import run_nmap_scan
from parser import parse_nmap_xml
from alerter import check_alerts
from reporter import generate_markdown_report

def main():
    # Step 1: Load config
    config = load_config("config.yaml")
    alert_config = config.get("alerts", {})
    output_dir = config.get("output_dir", "./logs")

    # Step 2: Create timestamped subfolder for this run
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = os.path.join(output_dir, timestamp)
    os.makedirs(run_folder, exist_ok=True)

    # Step 3: Run Nmap scan
    print("[*] Running scan...")
    xml_path = os.path.join(run_folder, f"scan_results_{timestamp}.xml")
    run_nmap_scan(config, xml_path)

    # Step 4: Parse scan results
    print("[*] Parsing scan results...")
    parsed_results = parse_nmap_xml(xml_path)

    # Step 5: Trigger alerts
    print("[*] Checking for alerts...")
    alerts = check_alerts(parsed_results, alert_config)
    for alert in alerts:
        print(alert)
    
    # Step 6: Generate markdown report
    print("[*] Generating report...")
    report_path = os.path.join(run_folder, f"report_{timestamp}.md")
    generate_markdown_report(parsed_results, report_path)
    print(f"[+] Report saved to {report_path}")

if __name__=="__main__":
    main()