"""
Lubuntu End-Device Node - Industrial HVAC System Emulator.
Generates structured thermodynamic instrumentation metrics, packages them into clean 
JSON frames, and utilizes UDP transmission pipelines to report to the forensic core.
Includes automated anomaly cycling to validate active network defense mechanics.
"""

import socket
import time
import json
import random

# Core network targeting configurations
TARGET_IP = "192.168.234.128"  # Verified IP footprint of the target Kali gateway
TARGET_PORT = 5000              # Standard dedicated ingestion pathway for HVAC assets
DEVICE_ID = "HVAC_Ctrl_01"

def run_sensor_stream():
    """
    Initiates continuous telemetry communication loops, packing environment frames 
    and throwing deliberate anomaly intervals to verify forensic trigger health.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[+] HVAC Sensor Stream Active. Dispatched traffic directed to {TARGET_IP}:{TARGET_PORT}...")
    cycle = 0

    while True:
        cycle += 1
        
        # Every 5th data packet transmission cycle, inject an explicit extreme anomaly condition
        if cycle % 5 == 0:
            current_temp = 73.88  # Intentionally cross upper firewall threshold parameter boundary (>50.0°C)
            msg = "THREAT TEST CASE: SAFETY BOUNDARY SURGE DETECTION EXERCISE"
        else:
            current_temp = round(random.uniform(19.0, 24.5), 2)  # Maintain standard, safe operating metrics
            msg = "Temperature status nominal."

        # Compile structured data fields matching the validation dictionary requirements
        payload = {
            "device_id": DEVICE_ID,
            "type": "climate",
            "temp_c": current_temp,
            "humidity_pct": round(random.uniform(40.0, 55.0), 1),
            "status": "OPERATIONAL",
            "message": msg
        }

        try:
            # Flatten dictionary into a clean byte string string for transmission
            json_string = json.dumps(payload)
            client_socket.sendto(json_string.encode('utf-8'), (TARGET_IP, TARGET_PORT))
            print(f"[-] Dispatched Telemetry Frame: {json_string}")
        except Exception as e:
            print(f"[-] Transport layer failure encountered: {e}")

        # Wait exactly 3 seconds before sending the next telemetry check-in packet
        time.sleep(3)

if __name__ == '__main__':
    run_sensor_stream()