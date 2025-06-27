from alerter import check_alerts
import yaml

# Simulate parsed scan results
scan_results = [
    {"ip": "1.2.3.4", "ports": [{"port": 23, "service": "telnet"}]}
]
   
# Load config from your actual file
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

alert_config = config.get("alerts", {})

# Run the alert check
alerts = check_alerts(scan_results, alert_config)

# Print results
print("\n".join(alerts))