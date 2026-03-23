
import time
from traffic_analysis import (
    get_unique_ports_count,
    get_icmp_rate,
    get_total_packets,
    get_proto_count,
)

# ====== YOUR KALI IP - EDIT THIS ======
YOUR_KALI_IP = "10.0.2.15"  # ← RUN ip a on Kali and put YOUR IP here

# ====== AGGRESSIVE THRESHOLDS (Catches Metasploitable2) ======
PORT_SCAN_PORT_THRESHOLD = 10    # 10+ ports = SCAN
PORT_SCAN_MIN_TCP_PACKETS = 20   # 20+ TCP pkts = SCAN  
ICMP_PPS_THRESHOLD = 2.0         # 2+ ICMP/sec = FLOOD
BRUTE_FORCE_THRESHOLD = 15       # 15+ login attempts
ALERT_COOLDOWN = 10              # 10 sec between alerts (DEBUG)

# ====== INTERNAL STATE ======
last_alert_time = {}
connection_attempts = {}

def _can_raise_alert(src_ip, attack_type):
    """Cooldown check - FIXED BUG"""
    now = time.time()
    key = (src_ip, attack_type)
    last_time = last_alert_time.get(key, 0)
    
    if now - last_time >= ALERT_COOLDOWN:
        last_alert_time[key] = now
        return True
    return False

def _is_trusted_source(src_ip):
    """ONLY trust YOUR Kali IP - everything else is suspicious"""
    return src_ip == YOUR_KALI_IP  # ← ONLY your Kali is safe

def _detect_port_scan(record):
    """Detects ANY port scan from non-Kali systems"""
    src_ip = record["src_ip"]
    
    if _is_trusted_source(src_ip):
        return None
    
    unique_ports = get_unique_ports_count(src_ip)
    tcp_packets = get_proto_count(src_ip, "TCP")
    
    # DEBUG: Print every check
    print(f"🔍 SCAN CHECK {src_ip}: {unique_ports} ports, {tcp_packets} TCP")
    
    if (unique_ports >= PORT_SCAN_PORT_THRESHOLD and 
        tcp_packets >= PORT_SCAN_MIN_TCP_PACKETS):
        
        if _can_raise_alert(src_ip, "PORT_SCAN"):
            alert = {
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "dst_ip": record["dst_ip"],
                "timestamp": time.time(),
                "severity": "HIGH",
                "details": {
                    "unique_ports_in_window": unique_ports,
                    "tcp_packets_in_window": tcp_packets,
                    "source_type": "NON_KALI_SCANNER"
                }
            }
            print(f"🚨 PORT SCAN ALERT: {alert}")
            return alert
    return None

def _detect_icmp_flood(record):
    """Detects ICMP flood from non-Kali systems"""
    if record["proto"] != "ICMP":
        return None
        
    src_ip = record["src_ip"]
    if _is_trusted_source(src_ip):
        return None
        
    icmp_rate = get_icmp_rate(src_ip)
    print(f"🔍 FLOOD CHECK {src_ip}: {icmp_rate:.1f} ICMP/sec")
    
    if icmp_rate >= ICMP_PPS_THRESHOLD:
        if _can_raise_alert(src_ip, "ICMP_FLOOD"):
            alert = {
                "type": "ICMP_FLOOD",
                "src_ip": src_ip,
                "dst_ip": record["dst_ip"],
                "timestamp": time.time(),
                "severity": "CRITICAL",
                "details": {
                    "icmp_packets_per_second": round(icmp_rate, 2),
                    "threshold": ICMP_PPS_THRESHOLD
                }
            }
            print(f"🚨 ICMP FLOOD ALERT: {alert}")
            return alert
    return None

def _detect_brute_force(record):
    """Detects brute force from non-Kali systems - FIXED BUG"""
    if record["proto"] != "TCP":
        return None
        
    src_ip = record["src_ip"]
    dport = record.get("dport")
    
    if dport not in {22, 21, 23, 3389}:
        return None
    
    if _is_trusted_source(src_ip):
        return None
        
    key = (src_ip, dport)
    now = time.time()
    attempts = connection_attempts.get(key, [])
    
    attempts = [t for t in attempts if now - t < 300]
    attempts.append(now)
    connection_attempts[key] = attempts
    
    if len(attempts) >= BRUTE_FORCE_THRESHOLD:
        if _can_raise_alert(src_ip, f"BRUTE_FORCE{dport}"):  # ← FIXED: was 'can_raise_alert'
            alert = {
                "type": f"BRUTE_FORCE_PORT_{dport}",
                "src_ip": src_ip,
                "dst_ip": record["dst_ip"],
                "timestamp": time.time(),
                "severity": "HIGH",
                "details": {
                    "attempts": len(attempts),
                    "service": f"Port {dport}",
                    "threshold": BRUTE_FORCE_THRESHOLD
                }
            }
            print(f"🚨 BRUTE FORCE ALERT: {alert}")
            return alert
    return None

# ====== PUBLIC API ======
def check_record(record):
    """Main detection function"""
    alerts = []
    
    ps_alert = _detect_port_scan(record)
    if ps_alert:
        alerts.append(ps_alert)
    
    icmp_alert = _detect_icmp_flood(record)
    if icmp_alert:
        alerts.append(icmp_alert)
    
    bf_alert = _detect_brute_force(record)
    if bf_alert:
        alerts.append(bf_alert)
    
    return alerts

# ====== SETUP & TEST ======
def print_config():
    """Show your exact configuration"""
    print("🎯 IDS CONFIGURATION:")
    print(f"✅ Your Kali IP (safe): {YOUR_KALI_IP}")
    print(f"🚨 Port Scan: {PORT_SCAN_PORT_THRESHOLD}+ ports & {PORT_SCAN_MIN_TCP_PACKETS}+ TCP")
    print(f"🚨 ICMP Flood: {ICMP_PPS_THRESHOLD}+ pps") 
    print(f"🚨 Brute Force: {BRUTE_FORCE_THRESHOLD}+ attempts")
    print("🔥 EVERYTHING ELSE triggers alerts!")

if __name__ == "_main_":
    print_config()
