from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import nmap
import socket

app = FastAPI(title="Network Scanner & Firewall API")

# --- Models ---
class ScanRequest(BaseModel):
    target: str
    scan_type: str  # e.g., "TCP Connect", "TCP SYN", "UDP", "TCP", "SYN"
    ports: str = "1-1024"

class FirewallRule(BaseModel):
    priority: int
    action: str  # ALLOW or DENY
    ip: str      # 'ANY' or specific IP like '192.168.1.5'
    port: str    # 'ANY' or specific port like '80'
    protocol: str # TCP, UDP, ANY

class TrafficSimulation(BaseModel):
    source_ip: str
    target_port: str
    protocol: str
    rules: List[FirewallRule]

# --- Endpoints ---
@app.post("/api/scan")
def run_network_scan(request: ScanRequest):
    try:
        # Resolve hostname to IP to prevent Nmap errors
        target_ip = socket.gethostbyname(request.target)
        
        # Initialize Nmap PortScanner
        # Note: If on Windows and it fails to find nmap, uncomment and update the path below:
        # nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap\\nmap.exe',))
        nm = nmap.PortScanner()
        
        # Determine Nmap arguments based on selected scan type
        scan_args = "-v "
        scan_type_upper = request.scan_type.upper()
        
        if scan_type_upper in ["TCP CONNECT", "TCP"]:
            scan_args += "-sT"
        elif scan_type_upper in ["TCP SYN", "SYN"]:
            scan_args += "-sS"
        elif scan_type_upper == "UDP":
            scan_args += "-sU"
            
        scan_args += f" -p {request.ports}"
        
        # Execute scan (Requires Administrator privileges for SYN and UDP)
        nm.scan(hosts=target_ip, arguments=scan_args)
        
        results = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                ports = nm[target_ip][proto].keys()
                for port in sorted(ports):
                    state = nm[target_ip][proto][port]['state']
                    service = nm[target_ip][proto][port]['name']
                    results.append({
                        "ip": target_ip,
                        "port": port,
                        "protocol": proto.upper(),
                        "service": service,
                        "status": state
                    })
        return {"status": "success", "data": results}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/firewall/simulate")
def simulate_firewall(sim: TrafficSimulation):
    # Sort rules by priority (lowest number = highest priority)
    sorted_rules = sorted(sim.rules, key=lambda x: x.priority)
    
    for rule in sorted_rules:
        # Match conditions
        ip_match = rule.ip == "ANY" or rule.ip == sim.source_ip
        port_match = rule.port == "ANY" or rule.port == sim.target_port
        proto_match = rule.protocol == "ANY" or rule.protocol == sim.protocol
        
        if ip_match and port_match and proto_match:
            return {
                "decision": rule.action,
                "matched_rule_priority": rule.priority,
                "message": f"Traffic {rule.action.lower()}ed by Rule #{rule.priority}"
            }
            
    # Default drop if no rules match
    return {
        "decision": "DENY",
        "matched_rule_priority": None,
        "message": "Traffic denied by default implicit deny rule."
    }