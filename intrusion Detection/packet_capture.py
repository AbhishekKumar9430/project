
# packet_capture.py
#
# Packet Capture Module for IDS.
# Converts raw Scapy packets into structured Python dicts
# and sends them to a callback (e.g., Traffic Analysis Module).

from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

INTERFACE = "eth0"  # Replace with your actual interface


def build_record(pkt):
    """
    Convert a Scapy packet into a structured record dict
    that the rest of the IDS can use.
    """

    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    proto_name = "OTHER"
    src_port = None
    dst_port = None

    if TCP in pkt:
        proto_name = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto_name = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif ICMP in pkt:
        proto_name = "ICMP"

    ts = time.time()  # numeric timestamp (seconds since epoch)

    record = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto_name,
        "sport": src_port,
        "dport": dst_port,
        "timestamp": ts
    }

    return record


def _process_packet(pkt, packet_callback):
    """
    Internal: Scapy calls this for each packet.
    It builds a record and forwards it to the callback.
    """
    record = build_record(pkt)
    if record is not None:
        packet_callback(record)


def start_capture(packet_callback):
    """
    Start capturing packets on INTERFACE and send each
    parsed record to packet_callback(record).
    """

    print("=== IDS Packet Capture Module ===")
    print(f"Listening on interface: {INTERFACE}")
    print("Press Ctrl+C to stop.")

    sniff(
        iface=INTERFACE,
        prn=lambda pkt: _process_packet(pkt, packet_callback),
        store=False
    )


# Simple standalone test
if __name__ == "__main__":
    def demo_callback(rec):
        # For now just print the record
        print(rec)

    try:
        start_capture(demo_callback)
    except KeyboardInterrupt:
        print("Capture stopped by user.")
