from parser import parse_nmap_xml

scan_file = "./logs/scan_results_20250621_173215.xml"

data = parse_nmap_xml(scan_file)
print("Parsed scan results:")
for host in data:
    print(f"{host['ip']}:")
    for port in host['open_ports']:
        print(f" Port {port['port']} ({port['service']})")