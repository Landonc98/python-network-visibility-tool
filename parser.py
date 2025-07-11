import xmltodict
import os

def parse_nmap_xml(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Scan file not found: {file_path}")
    
    with open(file_path, 'r') as file:
        xml_content = file.read()
        try:
            parsed = xmltodict.parse(xml_content)
        except Exception as e:
            raise Exception(f"Failed to parse XML: {e}")
        
    hosts = parsed.get('nmaprun', {}).get('host', [])
    if not isinstance(hosts, list):
        hosts = [hosts] # Make it a list if it's a single host
    
    result = []
    for host in hosts:
        if host.get('status', {}).get('@state') != 'up':
            continue # skip down hosts

        address_info = host.get('address')
        ip = None
        if isinstance(address_info, list):
            for addr in address_info:
                if addr.get('@addrtype') == 'ipv4':
                    ip = addr.get('@addr')
                    break
        elif isinstance(address_info, dict):
            ip = address_info.get('@addr')
        ports = host.get('ports', {}).get('port', [])
        if not isinstance(ports, list):
            ports = [ports]
        
        open_ports = []
        for port in ports:
            if port.get('state', {}).get('@state') == 'open':
                port_id = port.get('@portid')
                service = port.get('service', {}).get('@name', 'unknown')
                open_ports.append({'port': port_id, 'service': service})
        
        result.append({'ip': ip, 'open_ports': open_ports})
    
    return result

def compare_scans(old_file, new_file):
    import json

    def load_json(path):
        with open(path, 'r') as f:
            return json.load(f)
    
    old_data = load_json(old_file)
    new_data = load_json(new_file)

    old_hosts = {host["ip"]: host for host in old_data}
    new_hosts = {host["ip"]: host for host in new_data}

    print("\n--- Scan Comparison ---\n")

    # New hosts
    new_only = [ip for ip in new_hosts if ip not in old_hosts]
    if new_only:
        print("[+] New Hosts Detected:")
        for ip in new_only:
            print(f" - {ip}")
    else:
        print("[-] No new hosts detected.")
    
    # Removed Hosts
    removed = [ip for ip in old_hosts if ip not in new_hosts]
    if removed:
        print("[!] Hosts No Longer Present:")
        for ip in removed:
            print(f" -  {ip}")
    else:
        print("[-] No hosts removed.")
    
    # Port Changes
    for ip in new_hosts:
        if ip in old_hosts:
            old_ports = set(p["port"] for p in old_hosts[ip].get("ports", []))
            new_ports = set(p["port"] for p in new_hosts[ip].get("ports", []))
            added_ports = new_ports - old_ports
            removed_ports = old_ports - new_ports
            if added_ports or removed_ports:
                print(f"\n[*] Port changes for {ip}:")
                if added_ports:
                    print(f" [+] New Ports: {', '.join(added_ports)}")
                if removed_ports:
                    print(f" [-] Removed Ports: {', '.join(removed_ports)}") 