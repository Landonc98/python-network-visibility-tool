# python-network-visibility-tool

Capstone project: A Python-based network visibility, vulnerability detection, and reporting toolkit using **Scapy**, **Nmap**, and **Flask**.

This project provides small-to-medium network environments with a modular and extensible suite for identifying devices, detecting risky services, comparing historical scan results, and viewing findings via a CLI or a web dashboard.

---

## Features

- ✅ **Active scanning** via Nmap  
- ✅ **Passive packet sniffing** via Scapy (dev/tested early)  
- ✅ **JSON-structured scan logging**  
- ✅ **Differential engine**: compares scan results over time  
- ✅ **Risk-based alerting** system (configurable ports/services)  
- ✅ **Plugin support** for custom logic  
- ✅ **Markdown report generation**  
- ✅ **Flask dashboard** with routes:  
  - `/hosts`: Detected hosts and ports  
  - `/vulnerabilities`: High-risk ports/services flagged  
  - `/history`: View of past scans  
- ✅ **YAML-based user configuration**  
- ✅ CLI integration via `cli.py`  

---

## Project Structure

```
├── cli.py                # Command-line interface
├── dashboard.py          # Flask web dashboard
├── config.yaml           # User-defined settings
├── scanner.py            # Nmap scanner
├── parser.py             # Nmap XML → JSON parser
├── alerter.py            # Alert system based on scan content
├── reporter.py           # Markdown report generator
├── templates/            # Jinja2 templates for Flask
├── logs/                 # Saved scans
├── reports/              # Generated reports
├── requirements.txt      # Python dependencies
└── README.md             # You're reading it
```

---

## How to Use

### 1. Clone the repo and create a virtual environment

```bash
git clone https://github.com/yourusername/python-network-visibility-tool.git
cd python-network-visibility-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure the tool

Edit `config.yaml`:
```yaml
output_dir: logs
alerts:
  risky_ports: [23, 21, 445, 3389]
  risky_services: ["ftp", "telnet", "smb", "rdp"]
```

### 3. Run commands from `cli.py`

#### Run a network scan:
```bash
python cli.py --scan
```

#### Generate a Markdown report:
```bash
python cli.py --report logs/scan_results_YYYY-MM-DD_HH-MM-SS.xml
```

#### Compare two past scans:
```bash
python cli.py --compare logs/old.json logs/new.json
```

#### Launch the Flask dashboard:
```bash
python cli.py --dashboard
```

Then visit: [http://localhost:5000](http://localhost:5000)

---


## License

This project was developed for educational purposes as a capstone project at Georgia Southern University.

---

## Author

**Landon Carter**  
ITW 4530 – Senior Capstone Project (Summer 2025)
