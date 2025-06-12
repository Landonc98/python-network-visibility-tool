# sniffer.py
# Capstone Project - Week 1
# Purpose: Basic passive packet sniffer using Scapy

# Import necessary modules
from scapy.all import sniff  # sniff() is the function that captures packets
from datetime import datetime # Used to add readable timestamps to my output
import subprocess
import xml.etree.ElementTree as ET
import json

def parse_nmap_results(xml_file):
    tree = ET.parse("scan_results.xml")
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        ip_address = host.find("address").get("addr")
        host_data = {
            "ip": ip_address,
            "ports": []
        }


        ports = host.find("ports")
        for port in ports.findall("port"):
            state = port.find("state").get("state")
            if state == "open":
                port_id = port.get("portid")
                service = port.find("service").get("name", "unknown")
                version = port.find("service").get("version", "unknown")

                host_data["ports"].append({
                    "port": port_id,
                    "service": service,
                    "version": version
                })

        results.append(host_data)

    return results

# Define Nmap scan function
def run_nmap_scan(target_subnet="192.168.0.0/24"):
    nmap_command = [
        "nmap",
        "-sV",
        "-oX", "scan_results.xml",
        target_subnet
    ]    

    print("Running Nmap scan...")
    subprocess.run(nmap_command, check=True)
    print("Scan complete.")
# Define a function that will be called for each captured packet
def process_packet(packet):
    """
    This function runs every time a packet is captured.
    It extracts and prints basic information about the packet:
    - Source IP
    - Destination IP
    - Protocol (if known)
    - Timestamp
    """

    try:
        # Extract source and destination IP addresses, if available
        # Not all packets will have IP layer; this protects against errors
        src = packet[0][1].src if hasattr(packet[0][1], 'src') else 'N/A'
        dst = packet[0][1].dst if hasattr(packet[0][1], 'dst') else 'N/A'

        #Extract protocol name (best effort - some packets may not have a 'name')
        proto = packet[0][1].name if hasattr(packet[0][1], 'name') else 'Unknown'

        # Get current timestamp for when packet was captured
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Print the formatted packet information to the console
        print(f"[{timestamp}] {proto} Packet: {src} --> {dst}")

    except Exception as e:
        # In case something unexpected happens while processing a packet
        print(f"Error processing packet: {e}")

def save_results_to_json(results, filename_prefix="scan_results"):
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f"{filename_prefix}_{timestamp}.json"

    with open(json_filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"Results saved to {json_filename}")


# Main block - this will run when we execute the script directly
if __name__=='__main__':
    choice = input("Run Nmap scan first? (y/n): ")
    if choice.lower() == 'y':
        run_nmap_scan("192.168.0.0/24")

# Parse the results
    results = parse_nmap_results("scan_results.xml")
    print(json.dumps(results, indent=4))
    save_results_to_json(results)

    # Start sniffing
    # - prn=process_packet -> call my function for each packet
    # - store=False -> do not store packets in memory (we only want live output)
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)
