from parser import parse_nmap_xml
from reporter import generate_markdown_report

scan_file = "./logs/scan_results_20250621_173215.xml"
parsed = parse_nmap_xml(scan_file)
report_path = generate_markdown_report(parsed)

print(f"Report saved to: {report_path}")