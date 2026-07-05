"""
IoT Forensic Gateway - Asynchronous Web Command Dashboard.
Spins up an HTTP interface on port 8080. Serves interactive HTML forensics 
and hosts an asynchronous internal API endpoint (/api/data) to populate layout structures 
without interrupting UI selections or user filtering entry states.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sqlite3

DB_FILE = "iot_forensic.db"

def fetch_db_logs():
    """
    Queries the forensic database file for the latest 100 captured frames.
    """
    logs = []
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, source_ip, device_id, payload, packet_hash, integrity_status FROM ledger ORDER BY id DESC LIMIT 100")
        logs = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"[-] SQLite database read error: {e}")
    return logs

def build_json_data():
    """
    Transforms raw SQLite row objects into structured JSON strings for the frontend AJAX receiver.
    """
    logs = fetch_db_logs()
    packet_list = []
    for row in logs:
        packet_list.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "device_id": row[3],
            "payload": row[4],
            "packet_hash": row[5],
            "integrity_status": row[6]
        })
    return json.dumps(packet_list)

def build_html():
    """
    Generates the core interactive interface tracking cyber forensic elements.
    Integrates an embedded JavaScript engine executing background XMLHttp/Fetch tasks.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IoT Forensic Gateway</title>
    <style>
        body { font-family: 'Consolas', 'Courier New', monospace; background-color: #121212; color: #dcdcdc; margin: 0; padding: 20px; font-size: 13px; }
        .wrapper { max-width: 100%; margin: 0 auto; display: flex; flex-direction: column; height: 93vh; }
        .main-title-container { text-align: center; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 3px solid #333333; }
        .main-title { font-family: sans-serif; font-size: 32px; font-weight: 800; color: #ffffff; letter-spacing: 2px; text-transform: uppercase; margin: 0; }
        .sub-title { font-family: sans-serif; font-size: 14px; color: #888888; margin: 5px 0 0 0; text-transform: uppercase; letter-spacing: 1px; }
        .filter-area { display: flex; gap: 15px; align-items: center; background-color: #222222; padding: 10px; border: 1px solid #333333; border-radius: 4px; margin-bottom: 15px; }
        .filter-label { font-family: sans-serif; font-size: 12px; color: #aaaaaa; font-weight: bold; text-transform: uppercase; }
        #searchBar { flex-grow: 1; background-color: #ffffff; color: #000000; border: 1px solid #555555; padding: 6px 12px; font-family: 'Consolas', monospace; font-size: 13px; font-weight: bold; }
        .packet-list-container { flex: 1; overflow-y: auto; border: 1px solid #333333; background-color: #ffffff; min-height: 300px; }
        table { width: 100%; border-collapse: collapse; }
        th { background-color: #2c2c2c; color: #ffffff; font-family: sans-serif; font-size: 12px; font-weight: bold; text-align: left; padding: 6px 8px; border-bottom: 2px solid #111111; position: sticky; top: 0; text-transform: uppercase; }
        tr.packet-row { cursor: pointer; border-bottom: 1px solid #dcdcdc; }
        tr.packet-row:hover { background-color: #b5d5ff !important; color: #000000 !important; }
        tr.selected-packet { background-color: #0056b3 !important; color: #ffffff !important; }
        .color-hvac { background-color: #e6f2ff; color: #003366; }
        .color-lock { background-color: #ffe6cc; color: #663300; }
        .color-light { background-color: #e6ffcc; color: #336600; }
        .color-threat { background-color: #ffcccc !important; color: #b30000 !important; }
        td { padding: 6px 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 450px; border-right: 1px solid #dcdcdc; font-size: 12px; font-weight: bold; }
        .packet-details-pane { height: 320px; background-color: #1a1a1a; border: 1px solid #333333; margin-top: 15px; border-radius: 4px; display: flex; flex-direction: column; }
        .details-header { background-color: #2c2c2c; color: #ffffff; font-family: sans-serif; font-size: 13px; font-weight: bold; padding: 8px 12px; text-transform: uppercase; }
        .details-content { padding: 12px; overflow-y: auto; flex: 1; font-family: 'Consolas', monospace; line-height: 1.6; color: #9cdcfe; }
        .tree-node { color: #ffffff; font-weight: bold; }
        .tree-sub { margin-left: 24px; color: #ce9178; }
        .tree-meta { margin-left: 24px; color: #6a9955; font-style: italic; }
        .tree-rule { margin-left: 24px; color: #fbcfe8; background-color: #9d174d; padding: 2px 6px; display: inline-block; font-weight: bold; margin-top: 4px; border-radius: 3px;}
        .empty-prompt { color: #666666; text-align: center; margin-top: 40px; font-family: sans-serif; }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="main-title-container">
            <h1 class="main-title">IoT Forensic Gateway</h1>
            <p class="sub-title">Intrusion Detection and Ledger Analysis Framework</p>
        </div>
        <div class="filter-area">
            <span class="filter-label">Display Filter:</span>
            <input type="text" id="searchBar" oninput="filterPackets()" placeholder="Filter entries by target IP, device...">
        </div>
        <div class="packet-list-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 60px;">Index</th>
                        <th style="width: 150px;">Timestamp</th>
                        <th style="width: 130px;">Source IP</th>
                        <th style="width: 150px;">Device Ident</th>
                        <th>Payload Context Frame</th>
                        <th style="width: 180px;">Cryptographic Hash</th>
                        <th style="width: 180px;">Security Status</th>
                    </tr>
                </thead>
                <tbody id="packetTableBody">
                    </tbody>
            </table>
        </div>
        <div class="packet-details-pane">
            <div class="details-header" id="detailsHeaderTitle">Field Dissector Framework</div>
            <div class="details-content" id="detailsWindow">
                <div class="empty-prompt">Select an ingestion line item from the grid view above to unpack metadata.</div>
            </div>
        </div>
    </div>
    <script>
        // Maintain local UI context flags across background modifications
        let currentlySelectedId = null;
        let lastInspectedData = null;

        async function updateDashboardData() {
            try {
                // Request new data frames silently from backend API path
                let response = await fetch('/api/data');
                let packets = await response.json();
                let tableBody = document.getElementById('packetTableBody');
                let rowsHtml = "";

                packets.forEach(row => {
                    let status = row.integrity_status;
                    let deviceId = row.device_id;
                    let colorClass = "color-unknown";

                    // Apply visual indicators matching the system's compliance status
                    if (status.includes('ALERT') || status.includes('CRITICAL')) {
                        colorClass = "color-threat";
                    } else if (deviceId.includes('HVAC')) {
                        colorClass = "color-hvac";
                    } else if (deviceId.toLowerCase().includes('lock')) {
                        colorClass = "color-lock";
                    } else if (deviceId.toLowerCase().includes('light')) {
                        colorClass = "color-light";
                    }

                    let isSelected = (row.id === currentlySelectedId) ? "selected-packet" : "";
                    
                    // Sanitize double/single quotes to prevent structural parsing anomalies within the DOM element
                    let safePayload = row.payload.replace(/"/g, '&quot;').replace(/'/g, '&#39;');

                    rowsHtml += `
                    <tr class="packet-row ${colorClass} ${isSelected}" id="row-${row.id}"
                        onclick="selectPacketRow(this, ${row.id}, '${row.timestamp}', '${row.source_ip}', '${row.device_id}', '${row.packet_hash}', '${status}', '${safePayload}')"
                        data-search-blob="${row.timestamp.toLowerCase()} ${row.source_ip.toLowerCase()} ${row.device_id.toLowerCase()} ${row.payload.toLowerCase()} ${status.toLowerCase()} ${row.packet_hash.toLowerCase()}"
                        data-payload="${safePayload}">
                        <td>${row.id}</td>
                        <td>${row.timestamp}</td>
                        <td>${row.source_ip}</td>
                        <td>${row.device_id}</td>
                        <td>${row.payload}</td>
                        <td>${row.packet_hash.substring(0, 20)}...</td>
                        <td style="font-weight: 900;">${status}</td>
                    </tr>
                    `;
                });

                tableBody.innerHTML = rowsHtml;
                filterPackets(); // Run text matching engine to keep search entries valid
                
                // Keep the active forensic selection highlighted when table updates
                if (currentlySelectedId && lastInspectedData) {
                    let matchingRow = document.getElementById(`row-${currentlySelectedId}`);
                    if (matchingRow) matchingRow.classList.add('selected-packet');
                }

            } catch (err) {
                console.error("Data polling error:", err);
            }
        }

        function filterPackets() {
            // Front-end high performance display sorting routine
            let input = document.getElementById('searchBar').value.toLowerCase().trim();
            let rows = document.getElementById('packetTableBody').getElementsByTagName('tr');
            for (let i = 0; i < rows.length; i++) {
                let searchBlob = rows[i].getAttribute('data-search-blob');
                if (!input || (searchBlob && searchBlob.includes(input))) { 
                    rows[i].style.display = ""; 
                } else { 
                    rows[i].style.display = "none"; 
                }
            }
        }

        function selectPacketRow(element, id, time, sourceIp, deviceId, packetHash, status, rawPayloadStr) {
            currentlySelectedId = id;
            
            // Re-convert HTML entities back into readable JSON syntax formatting strings
            let decodedPayload = rawPayloadStr.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            lastInspectedData = { id, time, sourceIp, deviceId, packetHash, status, rawPayloadStr: decodedPayload };
            
            let rows = document.getElementsByClassName('packet-row');
            for (let r of rows) { r.classList.remove('selected-packet'); }
            element.classList.add('selected-packet');
            
            inspectPacket(id, time, sourceIp, deviceId, packetHash, status, decodedPayload);
        }

        function inspectPacket(id, time, sourceIp, deviceId, packetHash, status, rawPayloadStr) {
            let formattedJsonTree = "";
            let ruleDiagnosticText = "";
            let expectedPort = deviceId.toLowerCase().includes("lock") ? "5001" : (deviceId.toLowerCase().includes("light") ? "5002" : "5000");
            
            try {
                // Parse application json strings into interactive field-dissect layouts
                let parsedJson = JSON.parse(rawPayloadStr);
                for (let key in parsedJson) {
                    formattedJsonTree += `<div class="tree-sub">  └── ${key}: <span style="color: #4fc1ff;">${parsedJson[key]}</span></div>`;
                }
                
                // Provide explanations detailing why specific signature alerts triggered
                if (status.includes("ALERT") || status.includes("CRITICAL")) {
                    if (deviceId === "HVAC_Ctrl_01" && (parsedJson["temp_c"] > 50.0 || parsedJson["temp_c"] < 0.0)) {
                        ruleDiagnosticText = `<div class="tree-rule">[!] IDS TRIP DETECTED: Rule #2 Violated. Temperature metrics value (${parsedJson["temp_c"]}°C) dropped outside boundary safety limits.</div>`;
                    } else if (deviceId === "SmartLock_Zone_02" && (parsedJson["status"] === "CRITICAL_ALERT" || parsedJson["lock_status"] === "ACCESS_DENIED")) {
                        ruleDiagnosticText = `<div class="tree-rule">[!] IDS TRIP DETECTED: Rule #3 Violated. Threat case: Multiple failed access attempts.</div>`;
                    } else if (deviceId === "LightCtrl_Floor_01" && parsedJson["power_watts"] > 500.0) {
                        ruleDiagnosticText = `<div class="tree-rule">[!] IDS TRIP DETECTED: Rule #4 Violated. System load draw surge detected (${parsedJson["power_watts"]} W).</div>`;
                    } else {
                        ruleDiagnosticText = `<div class="tree-rule">[!] IDS TRIP DETECTED: Rule #1 Violated. Security pipeline triggered a Port-to-Identity destination verification mismatch.</div>`;
                    }
                } else {
                    ruleDiagnosticText = `<div class="tree-sub" style="color: #34d399;"> ✔ Anomaly Assessment Clear: Packet parameters sit comfortably within standard operational parameters.</div>`;
                }
            } catch(e) {
                formattedJsonTree = `<div class="tree-sub">  └── Raw Data Segment: ${rawPayloadStr}</div>`;
                ruleDiagnosticText = `<div class="tree-rule">[!] CORRUPTED DATA: Failed to parse structured JSON tokens.</div>`;
            }
            
            let flagColor = (status.includes("ALERT") || status.includes("CRITICAL")) ? "#ff4444" : "#34d399";
            document.getElementById('detailsHeaderTitle').innerText = `Decoded Structure: Ingestion Frame Object #${id}`;
            document.getElementById('detailsWindow').innerHTML = `
                <div class="tree-node">[ Ingestion Layer Analysis Properties ]</div>
                <div class="tree-sub"> ├── Frame Processing System Timestamp: <span style="color: #4fc1ff;">${time}</span></div>
                <div class="tree-node">[ Transport Protocol Characteristics (UDP) ]</div>
                <div class="tree-sub"> ├── Origin Host Node Address: <span style="color: #4fc1ff;">${sourceIp}</span></div>
                <div class="tree-sub"> └── Target Gateway Entry Port: <span style="color: #4fc1ff;">${expectedPort}</span></div>
                <div class="tree-node">[ Application Layer Payload Dissection ]</div>
                <div class="tree-sub"> ├── Assigned Device Signature Group: <span style="color: #4fc1ff;">${deviceId}</span></div>
                ${formattedJsonTree}
                <div class="tree-node">[ Cryptographic Signature Check Verification ]</div>
                <div class="tree-meta"> ├── Computational SHA-256 Checksum Digest: <span style="color: #fb7185;">${packetHash}</span></div>
                <div class="tree-meta"> └── Core Ledger Database Integrity Status Flag: <span style="color: ${flagColor}; font-weight: bold;">${status}</span></div>
                <div class="tree-node">[ Forensic Rule Diagnostic Explanation ]</div>
                ${ruleDiagnosticText}
            `;
        }

        // Loop background queries every 2000 milliseconds asynchronously
        setInterval(updateDashboardData, 2000);
        window.onload = updateDashboardData;
    </script>
</body>
</html>"""

class DashboardHandler(BaseHTTPRequestHandler):
    """
    Custom router handling normal HTML browser views and AJAX background endpoints.
    """
    def do_GET(self):
        if self.path == '/api/data':
            # Send dynamic JSON data streams to frontend scripts without reloading page canvas
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(build_json_data().encode('utf-8'))
        else:
            # Deliver the core visual rendering canvas shell blueprint
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(build_html().encode('utf-8'))

if __name__ == '__main__':
    print("[+] AJAX Interactive Dashboard running on http://127.0.0.1:8080")
    server = HTTPServer(('127.0.0.1', 8080), DashboardHandler)
    server.serve_forever()