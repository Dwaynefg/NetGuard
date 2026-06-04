# DCydra

DCydra is a lightweight, automated network monitoring tool written in Python. It scans a local subnet to discover active devices and open ports, tracks changes over time against a saved inventory file, and applies a basic risk-scoring engine to flag security anomalies.

---

##  How It Works

DCydra establishes a baseline map of your network fabric and compares future scans against that blueprint to detect unauthorized changes.

1. **Network Discovery:** Uses a TCP SYN Stealth scan (-sS) across the top 1,000 common ports to identify active hosts without completing full connections.
2. **State Tracking:** Saves device profiles (IP, MAC address, Hardware Vendor, Open Ports) into a local asset_inventory.json file.
3. **Delta Analysis:** Compares the active scan against the saved history. If a new device drops in or a known device mutates its port layout, NetGuard raises an alert.
4. **Risk Triage:** Scores the overall severity of anomalies based on specific network flags:
   - Unknown Device: +2 Risk Points
   - Unidentified Hardware Vendor: +1 Risk Point
   - High-Risk Administrative Ports Open (SSH/22 or RDP/3389): +2 Risk Points

---

## Technical Stack

- **Language:** Python 3
- **Core Dependencies:** python-nmap (Wrapper for the native Nmap C-engine)
- **Data Persistence:** JSON (asset_inventory.json)
- **Testing Sandbox:** VirtualBox Environment (Kali Linux Scanner & Headless Ubuntu Server Target)

---

##  Step-by-Step Setup & Verification Guide

Follow these exact steps to deploy DCydra in your environment and verify that the intrusion detection capabilities are working correctly.

### Step 1: Install System Dependencies
On your scanning machine (Kali Linux), open a terminal and run the update and package installation command:
"sudo apt update && sudo apt install nmap python3-pip -y"
Then, install the Python Nmap abstraction wrapper using:
"pip3 install python-nmap --break-system-packages"

### Step 2: Configure the Subnet Targeting
Create a script named DCydra.py, paste your Python code inside it, and open the file to verify your target network range matches your virtual environment:
"nano DCydra.py"
Locate the SUBNET variable near the top and ensure it matches your subnet range (e.g., 192.168.56.0/24 for standard VirtualBox Host-Only setups):
SUBNET = "192.168.56.0/24"
Save and exit the file using Ctrl+O, Enter, then Ctrl+X.

### Step 3: Establish the Trusted Baseline
Run the script for the very first time. Since no prior baseline data exists, NetGuard will discover the active devices on your network, flag them as new connections, and write them into a permanent JSON registry:
"sudo python3 DCydra.py"
Note: Root privileges (sudo) are required so Nmap can build raw network sockets for stealth packet processing and capture target hardware layer properties.
Verify that the registry file has been created and populated successfully:
"cat asset_inventory.json"

### Step 4: Run a Clean Second Scan
Run the script a second time without making any network changes. Because your network layout now matches the baseline blueprint exactly, NetGuard should report completely clear states:
"sudo python3 DCydra.py"
Expected Terminal Output:
[*] Analysis Complete. New Assets: 0 | Anomalies: 0
[*] Baseline database updated successfully.

### Step 5: Simulate a Threat and Trigger an Alert
Now, let's intentionally simulate configuration drift to verify the alerting and risk-scoring engines:
1. Pivot over to your Ubuntu Server VM and use Netcat to bind a new listener on a random port (e.g., port 8888):
"sudo nc -lk 0.0.0.0 8888 &"
2. Return to your Kali Linux VM and execute the scanner once again:
"sudo python3 DCydra.py"
NetGuard's internal engine will immediately intercept the delta difference between the active state and your baseline blueprint, calculating risk flags and raising a live alert right inside your console!


Add the following configuration line to the very bottom of the scheduler registry:
0 0 * * * /usr/bin/python3 /absolute/path/to/DCydra.py >> /var/log/DCydra.log 2>&1
