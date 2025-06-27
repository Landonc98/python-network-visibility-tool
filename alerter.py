# alerter.py

def check_alerts(scan_results, alert_config):
    """
    Scan through parsed scan data and return alerts based on risky ports or services.
     
    :param scan_results: list of dicts with 'ip' and 'ports' from parsed XML scan
    :param alert_config: Dict with keys 'risky_ports' and 'risky_services'
    :return: list of alert strings
    """

    risky_ports = alert_config.get('risky_ports', [])
    risky_services = [s.lower() for s in alert_config.get('risky_services', [])]
    alerts = []

    for host in scan_results:
        ip = host.get("ip")
        for port_info in host.get("ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "").lower()

            if port in risky_ports:
                alerts.append(f"[ALERT] Host {ip} has risky port open: {port}")
            if service in risky_services:
                alerts.append(f"[ALERT] Host {ip} is running risky service: {service}")
    
    return alerts