"""
IoT Forensic Gateway - Network Sniffer & Intrusion Detection System (IDS).
Monitors multi-port UDP industrial traffic, calculates cryptographic hashes to 
ensure data integrity, runs signature-based rule assessments, and maintains 
a persistent forensic ledger.
"""

import socket
import json
import hashlib
import select
from datetime import datetime
import sqlite3

# Define configuration constants
DB_FILE = "iot_forensic.db"
PORTS = {
    5000: "HVAC_PORTS",
    5001: "LOCK_PORTS",
    5002: "LIGHT_PORTS"
}

def init_database():
    """
    Initializes the local SQLite database forensic ledger.
    Creates the 'ledger' table schema if it does not already exist.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Create an immutable-style ledger structure tracking key network and application headers
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            device_id TEXT,
            payload TEXT,
            packet_hash TEXT,
            integrity_status TEXT
        )
    """)
    conn.commit()
    conn.close()

def calculate_sha256(data_string):
    """
    Computes a SHA-256 cryptographic checksum of the incoming raw packet string.
    Acts as a verifiable data-integrity mechanism for forensic analysis.
    """
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

def inspect_packet_security(source_ip, device_id, data_json, port):
    """
    Signature-based Intrusion Detection Engine. Evaluates packet headers and 
    payload contexts against zero-trust architectural boundaries.
    """
    # RULE 1: Network Ingestion Port vs Device Identity Verification Alignment
    if port == 5000 and "HVAC" not in device_id:
        return "CRITICAL: PORT_IDENTITY_MISMATCH"
    if port == 5001 and "Lock" not in device_id:
        return "CRITICAL: PORT_IDENTITY_MISMATCH"
    if port == 5002 and "Light" not in device_id:
        return "CRITICAL: PORT_IDENTITY_MISMATCH"

    # RULE 2: HVAC Operational Environmental Parameter Validation
    if device_id == "HVAC_Ctrl_01":
        temp = data_json.get("temp_c")
        if temp is not None:
            # Trigger alert if ambient metrics exceed safe physical plant operations
            if float(temp) > 50.0 or float(temp) < 0.0:
                return "ALERT: OUT_OF_BOUNDS_TEMP"

    # RULE 3: Smart Lock Authentication State & Force Monitoring
    if device_id == "SmartLock_Zone_02":
        lock_status = data_json.get("status")
        lock_msg = data_json.get("lock_status")
        # Evaluate for brute-force entry attempts or anomalous unauthenticated loops
        if lock_status == "CRITICAL_ALERT" or lock_msg == "ACCESS_DENIED":
            return "ALERT: BRUTE_FORCE_SUSPECTED"

    # RULE 4: Electrical Grid Load Anomalous Tracking
    if device_id == "LightCtrl_Floor_01":
        power_w = data_json.get("power_watts")
        if power_w is not None:
            # Trap power spikes indicative of hardware manipulation or electrical bypass
            if float(power_w) > 500.0:
                return "ALERT: EXCESSIVE_POWER_DRAW"

    return "VALID"

def start_multi_port_gateway():
    """
    Initializes non-blocking sockets across targeted ingestion ports and enters 
    an asynchronous monitoring loop utilizing low-level I/O select multiplexing.
    """
    init_database()
    sockets = []
    
    # Instantiate and bind UDP sockets for every asset track configuration
    for port in PORTS.keys():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        sockets.append(s)
        print(f"[+] Listening on Ingestion Port: {port}")

    print("[+] IoT Forensic Gateway Core active (SQLite Enabled). Monitoring traffic...")

    while True:
        # Utilize select.select to handle asynchronous packet arrival without thread blocking
        readable, _, _ = select.select(sockets, [], [])
        for ready_socket in readable:
            bytes_data, addr = ready_socket.recvfrom(4096)
            source_ip = addr[0]
            local_port = ready_socket.getsockname()[1]
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            try:
                decoded_str = bytes_data.decode('utf-8')
                data_json = json.loads(decoded_str)
                device_id = data_json.get("device_id", "UNKNOWN_NODE")
                
                # Execute automated analysis pipeline
                integrity_status = inspect_packet_security(source_ip, device_id, data_json, local_port)
                computed_hash = calculate_sha256(decoded_str)

                # Scope SQL connection explicitly within processing frame to ensure execution safety
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ledger (timestamp, source_ip, device_id, payload, packet_hash, integrity_status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (current_time, source_ip, device_id, decoded_str, computed_hash, integrity_status))
                conn.commit()
                conn.close()

                print(f"[*] Port {local_port} -> SQLite DB | Node: {device_id} | Status: {integrity_status}")
                
            except Exception as e:
                print(f"[-] Ingestion processing exception: {e}")

if __name__ == '__main__':
    try:
        start_multi_port_gateway()
    except KeyboardInterrupt:
        print("\n[!] Shutting down gateway cleanly.")