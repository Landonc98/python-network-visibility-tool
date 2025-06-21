import os
from datetime import datetime

def generate_markdown_report(scan_data, output_dir="./reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"report_{timestamp}.md")

    with open(report_path, "w") as file:
        file.write(f"# Network Scan Report = {timestamp}\n\n")

        for host in scan_data:
            file.write(f"## Host: `{host['ip']}`\n")
            if host['open_ports']:
                for port in host ['open_ports']:
                    file.write(f"- **Port {port['port']}** - {port['service']}\n")
            
            else:
                file.write("*No open ports found.*\n")
            file.write("\n---\n\n")
    

    return report_path