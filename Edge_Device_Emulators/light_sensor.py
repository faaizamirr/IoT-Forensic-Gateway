"""
Lubuntu End-Device Node - Smart Lighting Grid Controller Emulator.
Monitors operational load drawing patterns, formats current power tracking into
JSON arrays, and broadcasts telemetry packets over UDP channels.
Includes custom automated intervals to check hardware load overdraw protections.
"""

import socket
import time
import json
import random

# Core network configurations
TARGET_IP = "192.168.234.128"  # IP footprint of the target Kali gateway
TARGET_PORT = 5002              # Dedicated forensic ingestion port for Smart Lighting
DEVICE_ID = "LightCtrl_Floor_01"

def run_light_stream():
    """
    Main execution pipeline generating smart infrastructure asset signatures.
    Cycles electrical metrics to test system load exception routines.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[+] Lighting Controller Active. Dispatching traffic to {TARGET_IP}:{TARGET_PORT}...")
    cycle = 0

    while True:
        cycle += 1
        
        # Every 4th data transmission cycle, simulate an electrical power anomaly spike
        if cycle % 4 == 0:
            power_watts = round(random.uniform(550.0, 680.0), 2)  # Cross upper safety boundary (>500.0 W)
            msg = "THREAT TEST CASE: EXCESSIVE LOAD DRAW SURGE DETECTED"
        else:
            power_watts = round(random.uniform(45.0, 120.0), 2)   # Maintain normal operational baseline
            msg = "Lighting matrices status nominal."

        # Package data variables to maintain database schema compatibility
        payload = {
            "device_id": DEVICE_ID,
            "power_watts": power_watts,
            "active_bulbs": random.randint(15, 30),
            "message": msg
        }

        try:
            # Cast payload objects to explicit JSON strings for delivery
            json_string = json.dumps(payload)
            client_socket.sendto(json_string.encode('utf-8'), (TARGET_IP, TARGET_PORT))
            print(f"[-] Dispatched Lighting Telemetry: {json_string}")
        except Exception as e:
            print(f"[-] Transport layer failure encountered: {e}")

        # Wait 3 seconds before next cycle refresh
        time.sleep(3)

if __name__ == '__main__':
    run_light_stream()