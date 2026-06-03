import nmap
import json
import os
import sys
from datetime import datetime

# ==================== LAB CONFIGURATION ====================
SUBNET = "192.168.56.0/24"   # depends on your subnet
INVENTORY_FILE = "asset_inventory.json"
# ===========================================================

def run_network_scan(target_subnet):
    """Scans the network for active hosts and open ports."""
    nm = nmap.PortScanner()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[*] [{now}] NetGuard: Scanning subnet {target_subnet}...")
    
    try:
        # -Pn: Assumes hosts are up (bypasses VirtualBox ping blocks)
        # -sS: Stealth SYN scan
        # --top-ports 1000: Scans the 1,000 most common ports
        nm.scan(hosts=target_subnet, arguments="-Pn -sS --top-ports 1000")
    except nmap.PortScannerError as e:
        print(f"[X] Nmap Error: {e}")
        sys.exit(1)
        
    scan_manifest = {}
    
    for host in nm.all_hosts():
        # Direct .get() structure for MAC and Vendor details
        addresses = nm[host].get('addresses', {})
        mac_address = addresses.get('mac', 'UNKNOWN')

        hardware_vendor = nm[host].get('vendor', {})
        vendor_name = hardware_vendor.get(mac_address, 'Unknown Vendor')
        
        # Nested loops to collect open ports
        established_ports = []
        for protocol in nm[host].all_protocols():
            for port, data in nm[host][protocol].items():
                if data.get("state") == "open":
                    established_ports.append(port)
                    
        scan_manifest[host] = {
            "mac": mac_address,
            "vendor": vendor_name,
            "open_ports": sorted(established_ports),
            "last_seen": now
        }
    return scan_manifest

def read_historical_baseline():
    """Loads the saved network baseline file."""
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, 'r') as file_pointer:
                return json.load(file_pointer)
        except json.JSONDecodeError:
            print("[🚨 WARNING] Inventory file corrupted. Resetting baseline.")
            return {}
    return {}

def update_historical_baseline(updated_dataset):
    """Saves the current network state to the inventory file."""
    with open(INVENTORY_FILE, 'w') as file_pointer:
        json.dump(updated_dataset, file_pointer, indent=4)

def evaluate_network_deltas(current_state, historical_baseline):
    """Compares current scan against baseline and scores the risks."""
    print("\n======================= [ SECURITY ANALYSIS ] =======================")
    new_devices_found = 0
    modified_devices_found = 0
    
    for ip_address, network_metrics in current_state.items():
        severity = 0
        is_anomaly = False
        alert_msg = ""

        # 1. Check for a brand new device (+2 Severity)
        if ip_address not in historical_baseline:
            severity += 2
            new_devices_found += 1
            is_anomaly = True
            alert_msg += f"[⚠️ ALERT] Unknown Host Discovered: IP [{ip_address}]\n"
        else:
            # 2. Check for port changes on known devices
            past_ports = historical_baseline[ip_address].get('open_ports', [])
            if set(network_metrics['open_ports']) != set(past_ports):
                is_anomaly = True
                modified_devices_found += 1
                alert_msg += f"[🚨 WARNING] Port Change Detected on Host [{ip_address}]\n"
                alert_msg += f"    ↳ Before: {past_ports}\n"
                alert_msg += f"    ↳ Now:    {network_metrics['open_ports']}\n"

        # 3. Check for Unknown Vendor (+1 Severity)
        if network_metrics['vendor'] == "Unknown Vendor":
            severity += 1

        # 4. Check for high-risk open ports (+2 Severity for SSH/RDP)
        if 22 in network_metrics['open_ports'] or 3389 in network_metrics['open_ports']:
            severity += 2

        # Print the alert if anything suspicious is found
        if is_anomaly or severity > 0:
            if not alert_msg:  
                alert_msg = f"[💡 INFO] Risk Assessment for: [{ip_address}]\n"
            
            print(alert_msg.strip())
            print(f"    ↳ MAC Address: {network_metrics['mac']}")
            print(f"    ↳ Vendor:      {network_metrics['vendor']}")
            print(f"    ↳ Risk Score:  [{severity}]\n")

        # Sync current state into history
        historical_baseline[ip_address] = network_metrics

    print("======================================================================")
    print(f"[*] Analysis Complete. New Assets: {new_devices_found} | Anomalies: {modified_devices_found}")

def main():
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[*] Notice: Please run as root (sudo) to capture accurate MAC addresses.")
        
    active_network_state = run_network_scan(SUBNET)
    historical_baseline = read_historical_baseline()
    
    evaluate_network_deltas(active_network_state, historical_baseline)
    update_historical_baseline(historical_baseline)
    print("[*] Baseline database updated successfully.\n")

if __name__ == "__main__":
    main()