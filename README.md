# DCydra

DCydra is a lightweight, automated network monitoring tool written in Python. It scans a local subnet to discover active devices and open ports, tracks changes over time against a saved inventory file, and applies a basic risk-scoring engine to flag security anomalies.

---

## How It Works

DCydra establishes a baseline map of your network fabric and compares future scans against that blueprint to detect unauthorized changes.

1. **Network Discovery:** Uses a TCP SYN Stealth scan (-sS) across the top 1,000 common ports to identify active hosts without completing full connections.  
2. **State Tracking:** Saves device profiles (IP, MAC address, Hardware Vendor, Open Ports) into a local `asset_inventory.json` file.  
3. **Delta Analysis:** Compares the active scan against the saved history. If a new device appears or a known device changes its port layout, DCydra raises an alert.  
4. **Risk Triage:** Scores anomalies based on defined risk rules:  
   - Unknown Device: +2 Risk Points  
   - Unidentified Hardware Vendor: +1 Risk Point  
   - High-Risk Administrative Ports (SSH/22 or RDP/3389): +2 Risk Points  

---

## Technical Stack

- **Language:** Python 3  
- **Core Dependencies:** python-nmap (wrapper for the Nmap engine)  
- **Data Persistence:** JSON (`asset_inventory.json`)  
- **Testing Environment:** VirtualBox (Kali Linux scanner + Ubuntu Server target)  

---

## Step-by-Step Setup & Verification Guide

### Step 1: Install System Dependencies

On your Kali Linux machine:

```bash
sudo apt update && sudo apt install nmap python3-pip -y
```

Install Python dependency:

```bash
pip3 install python-nmap --break-system-packages
```

---

### Step 2: Configure the Subnet Targeting

Create the script:

```bash
nano DCydra.py
```

Set your subnet (adjust if needed):

```python
SUBNET = "192.168.56.0/24"
```

Save and exit:
Ctrl + O → Enter → Ctrl + X

---

### Step 3: Establish the Trusted Baseline

Run DCydra for the first scan:

```bash
sudo python3 DCydra.py
```

Verify inventory file:

```bash
cat asset_inventory.json
```

---

### Step 4: Run a Clean Second Scan

Run again without making network changes:

```bash
sudo python3 DCydra.py
```

Expected output:

```
[*] Analysis Complete. New Assets: 0 | Anomalies: 0
[*] Baseline database updated successfully.
```

---

### Step 5: Simulate a Threat and Trigger an Alert

On your Ubuntu Server VM:

```bash
sudo nc -lk 0.0.0.0 8888 &
```

Then run DCydra again on Kali Linux:

```bash
sudo python3 DCydra.py
```

DCydra will detect the new open port, compare it against the baseline, and flag it as an anomaly with a risk alert in the console output.
