import datetime
import os
from config_loader import load_config


def run_nmap_scan(config, output_path):

    targets = config['targets']
    ports = config['ports']
    output_dir = config['output_dir']
    scan_options = config.get('scan_options' or {})

    # Build Nmap flags
    flags = ["-sS"] # default: SYN scan
    if scan_options.get("service_version"):
        flags.append("-sV")
    if scan_options.get("aggressive"):
        flags.append("-A")
    if scan_options.get("skip_host_discovery"):
        flags.append("-Pn") # Treat all hosts as up, skip ping check
    

    # Prepare targets and output path
    target_string = " ".join(targets)
    port_string = ports

    # Make sure output directory exists 
    os.makedirs(output_dir, exist_ok=True)

    # Final command
    command = [
        "nmap",
        *flags,
        "-p", port_string,
        target_string,
        "-oX", output_path # Output as XML
    ]

    print(f"[*] Running: {' '.join(command)}")
    os.system(" ".join(command))