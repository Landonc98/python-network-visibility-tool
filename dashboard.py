
from flask import Flask, render_template, jsonify
import json
import os
import glob

app = Flask(__name__)

def load_scan_data():
    try:
        # Look for all scan result JSON files
        scan_files = glob.glob("scan_results_*.json")
        if not scan_files:
            raise FileNotFoundError("No scan result files found.")
        
        # Get the most recent one
        latest_file = max(scan_files, key=os.path.getctime)
        print("Loading scan file:", latest_file)

        with open(latest_file, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading scan data: {e}")
        return []

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/hosts')
def hosts():
    data = load_scan_data()
    return render_template('hosts.html', hosts=data)

@app.route('/vulnerabilities')
def vulnerabilities():
    data = load_scan_data()

    # Known high-risk ports
    risky_ports = {
        21: "FTP - unencrypted",
        23: "Telnet - obsolete",
        25: "SMTP - open relay risk",
        110: "POP3 - weak auth",
        135: "MSRPC - DCOM exploits",
        139: "NetBIOS - old Windows",
        445: "SMB - EternalBlue/WannaCry",
        1433: "MSSQL - brute force",
        3306: "MySQL - default creds",
        3389: "RDP - ransomware target",
        5900: "VNC - often exposed",
        8080: "HTTP-alt - often misconfigured"
    }

    vulnerable_hosts = []
    for host in data:
        print(f"Scanning host: {host['ip']}")
        vulns = []
        for port in host.get("ports", []):
            print("Checking port:", port["port"])
            if int(port["port"]) in risky_ports:
                print("RISKY PORT FOUND")
                vulns.append({
                    "port": port["port"],
                    "service": port.get("service", ""),
                    "version": port.get("version", ""),
                    "reason": risky_ports[int(port["port"])]
                })
            if vulns:
                print(f"Adding {host['ip']} to vulnerable hosts.")
                vulnerable_hosts.append({"ip": host["ip"], "vulns": vulns})
    
    return render_template("vulnerabilities.html", vulnerable_hosts=vulnerable_hosts)

@app.route('/history')
def history():
    scan_files = sorted(glob.glob("scan_results_*.json"), key=os.path.getctime, reverse=True)
    history_data = []

    for file in scan_files:
        try:
            with open(file, "r") as f:
                data = json.load(f)
                host_count = len(data)
                history_data.append({
                    "filename": file,
                    "host_count": host_count,
                })
        except Exception as e:
            print(f"Failed to load {file}: {e}")
    
    return render_template("history.html", history=history_data)
        
    

if __name__ == '__main__':
    app.run(debug=True)
