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