# traffic_analysis.py
#
# Traffic Analysis Module for IDS.
# Receives packet records from Packet Capture Module and
# maintains statistics over a sliding time window.

import time
from collections import defaultdict

# Analyze traffic in the last N seconds
WINDOW_SECONDS =10 #60

# ====== DATA STRUCTURES ======

# Store (timestamp, record) for recent packets
packet_history = []  # list of (ts, record)

# Total packets per source IP in window
counts_by_src = defaultdict(int)

# Protocol-wise counts per source IP in window: proto_counts_by_src[src][proto] -> count
proto_counts_by_src = defaultdict(lambda: defaultdict(int))

# Unique destination ports per source IP (for port scan detection)
# ports_by_src[src_ip] = set of destination ports contacted in window (TCP/UDP only)
ports_by_src = defaultdict(set)

# ICMP packet counts per source IP in window (for ICMP flood detection)
icmp_counts_by_src = defaultdict(int)


# ====== INTERNAL HELPERS ======

def _rebuild_stats_from_history():
    """
    Rebuild all counters from packet_history.
    Called after cleaning out old entries.
    """
    counts_by_src.clear()
    proto_counts_by_src.clear()
    ports_by_src.clear()
    icmp_counts_by_src.clear()

    for ts, rec in packet_history:
        src = rec["src_ip"]
        proto = rec["proto"]
        dport = rec["dport"]

        counts_by_src[src] += 1
        proto_counts_by_src[src][proto] += 1

        # Track unique destination ports for TCP/UDP
        if proto in ("TCP", "UDP") and dport is not None:
            ports_by_src[src].add(dport)

        # Track ICMP counts
        if proto == "ICMP":
            icmp_counts_by_src[src] += 1


def _cleanup_old_entries():
    """
    Remove entries older than WINDOW_SECONDS and rebuild statistics.
    """
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    global packet_history
    packet_history = [entry for entry in packet_history if entry[0] >= cutoff]

    _rebuild_stats_from_history()


# ====== PUBLIC API ======

def handle_packet(record):
    """
    Main entry: called for every packet record from capture module.
    Updates sliding window and statistics.
    """
    ts = record["timestamp"]
    packet_history.append((ts, record))

    # Remove old entries and update stats
    _cleanup_old_entries()

    # DEBUG / TEMP: print some live metrics for this source
    src = record["src_ip"]
    proto = record["proto"]
    total_for_src = counts_by_src[src]
    proto_for_src = proto_counts_by_src[src][proto]
    unique_ports_for_src = len(ports_by_src[src])
    icmp_for_src = icmp_counts_by_src[src]

    print(
        f"[ANALYSIS] src={src} total={total_for_src}, "
        f"{proto}={proto_for_src}, unique_ports={unique_ports_for_src}, "
        f"icmp_in_window={icmp_for_src}"
    )


def get_total_packets(src_ip):
    """
    Return total packets from src_ip in the current window.
    """
    return counts_by_src.get(src_ip, 0)


def get_proto_count(src_ip, proto):
    """
    Return packets from src_ip of specific protocol in current window.
    proto: 'TCP', 'UDP', 'ICMP', 'OTHER'
    """
    return proto_counts_by_src[src_ip].get(proto, 0)


def get_unique_ports_count(src_ip):
    """
    Return number of unique destination ports contacted by src_ip (TCP/UDP) in window.
    """
    return len(ports_by_src[src_ip])


def get_icmp_rate(src_ip):
    """
    Approximate ICMP packets per second from src_ip in current window.
    """
    icmp_count = icmp_counts_by_src.get(src_ip, 0)
    if WINDOW_SECONDS <= 0:
        return 0.0
    return icmp_count / float(WINDOW_SECONDS)
