# alert_logging.py - Fulfills "Alert system", "Log management", "Performance analysis"
import logging
import os
import json
from datetime import datetime
from collections import defaultdict

LOG_DIR = "ids_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Professional logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'ids_alerts.log')),
        logging.StreamHandler()
    ]
)

# Statistics for report
stats = defaultdict(int)
malicious_ips = set()

def log_alert(alert):
    """Log alerts + update statistics"""
    alert_type = alert['type']
    src_ip = alert['src_ip']
    
    # Update counters
    stats[alert_type] += 1
    malicious_ips.add(src_ip)
    
    # Rich formatted message
    ts_str = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    details = alert.get('details', {})
    
    msg = (f"🚨 [{alert_type}] {ts_str} | "
           f"ATTACKER: {src_ip} → VICTIM: {alert['dst_ip']} | "
           f"DETAILS: {details}")
    
    # Console (colored) + file
    print(f"\u001B[91m{msg}\u001B[0m")
    logging.critical(msg)
    
    # Save malicious IPs list
    with open(os.path.join(LOG_DIR, 'malicious_ips.txt'), 'w') as f:
        for ip in sorted(malicious_ips):
            f.write(ip + '')

def generate_report():
    """Performance analysis for report/PPT"""
    total_alerts = sum(stats.values())
    
    print("" + "="*80)
    print("📊 IDS PERFORMANCE REPORT:")
    print("="*80)
    print(f"✅ TOTAL ALERTS GENERATED: {total_alerts}")
    print(f"✅ UNIQUE MALICIOUS IPS: {len(malicious_ips)}")
    print(f"📁 LOG FILE: {os.path.join(LOG_DIR, 'ids_alerts.log')}")
    print("📈 ATTACK BREAKDOWN:")
    for attack, count in sorted(stats.items()):
        print(f"   {attack:12}: {count:3} alerts")
    print(f"🔒 MALICIOUS IPS LOG: {os.path.join(LOG_DIR, 'malicious_ips.txt')}")
    print("="*80)
    
    # Save JSON report
    report = {
        'total_alerts': total_alerts,
        'malicious_ips_count': len(malicious_ips),
        'attack_stats': dict(stats),
        'timestamp': datetime.now().isoformat()
    }
    with open(os.path.join(LOG_DIR, 'final_report.json'), 'w') as f:
        json.dump(report, f, indent=2)
