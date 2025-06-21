import subprocess
import datetime
import os
from config_loader import load_config


def run_nmap_scan():
    # Load settings from config.yaml
    config = load_config()

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

    # Prepare targets and output path
    target_string = " ".join(targets)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"scan_results_{timestamp}.xml")

    # Make sure output directory exists 
    os.makedirs(output_dir, exist_ok=True)

    # Final command
    cmd = ["nmap", "-p", ports] + flags + ["-oX", output_file, target_string]

    print(f"Running command: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, check=True)
        print("Scan complete. Results saved to: {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error: Nmap scan failed.\n{e}")
        return None

