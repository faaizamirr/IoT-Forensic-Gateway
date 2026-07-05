"""
Lubuntu End-Device Node - Smart Lock System Emulator.
Generates physical access logs, packages access state attributes into JSON frames,
and uses UDP to transmit data to the central forensic gateway.
Includes an automated exception engine to test brute-force detection rules.
"""

import socket
import time
import json
import random

# Core network configurations
TARGET_IP = "192.168.234.128"  # IP footprint of the target Kali gateway
TARGET_PORT = 5001              # Dedicated forensic ingestion port for Smart Lock assets
DEVICE_ID = "SmartLock_Zone_02"

def run_lock_stream():
    """
    Main loop running telemetry generation. Alternates between nominal states
    and threat models to validate forensic logging pipelines.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[+] Smart Lock Stream Active. Dispatching traffic to {TARGET_IP}:{TARGET_PORT}...")
    cycle = 0

    while True:
        cycle += 1
        
        # Every 6th transmission cycle, simulate a critical brute-force intrusion event
        if cycle % 6 == 0:
            status = "CRITICAL_ALERT"
            lock_status = "ACCESS_DENIED"
            msg = "THREAT TEST CASE: MULTIPLE FAILED AUTHENTICATION ATTEMPTS DETECTED"
        else:
            status = "OPERATIONAL"
            lock_status = random.choice(["LOCKED", "UNLOCKED"])
            msg = f"Access panel secure. Interlocking system state: {lock_status}."

        # Compile telemetry payload mapping to gateway inspection rules
        payload = {
            "device_id": DEVICE_ID,
            "status": status,
            "lock_status": lock_status,
            "message": msg
        }

        try:
            # Flatten context frames into a standardized byte string
            json_string = json.dumps(payload)
            client_socket.sendto(json_string.encode('utf-8'), (TARGET_IP, TARGET_PORT))
            print(f"[-] Dispatched Lock Telemetry: {json_string}")
        except Exception as e:
            print(f"[-] Transport layer failure encountered: {e}")

        # Wait 3 seconds between sensor updates
        time.sleep(3)

if __name__ == '__main__':
    run_lock_stream()