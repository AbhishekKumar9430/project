# basic firewall

from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading

# rules
blocked_ips = []
blocked_ports = []

running = False

# firewall logic
def firewall(packet):
    global running

    if not running:
        return

    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            log("Packet: " + src_ip + " -> " + dst_ip)

            # block ip
            if src_ip in blocked_ips:
                log("Blocked IP: " + src_ip)
                return

            if packet.haslayer(TCP):
                dport = packet[TCP].dport

                if dport in blocked_ports:
                    log("Blocked Port: " + str(dport))
                    return

            log("Allowed")

    except:
        log("Error in packet")


# sniff thread
def start_sniffing():
    sniff(prn=firewall, store=0)


# GUI functions
def start_firewall():
    global running
    running = True
    log("Firewall Started")
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()


def stop_firewall():
    global running
    running = False
    log("Firewall Stopped")


def add_ip():
    ip = ip_entry.get()
    if ip != "":
        blocked_ips.append(ip)
        log("Added blocked IP: " + ip)
        ip_entry.delete(0, tk.END)


def add_port():
    try:
        port = int(port_entry.get())
        blocked_ports.append(port)
        log("Added blocked Port: " + str(port))
        port_entry.delete(0, tk.END)
    except:
        log("Invalid port")


def log(msg):
    log_box.insert(tk.END, msg + "\n")
    log_box.yview(tk.END)


# GUI design
root = tk.Tk()
root.title("Basic Firewall")

# IP input
tk.Label(root, text="Block IP").pack()
ip_entry = tk.Entry(root)
ip_entry.pack()

tk.Button(root, text="Add IP", command=add_ip).pack()

# Port input
tk.Label(root, text="Block Port").pack()
port_entry = tk.Entry(root)
port_entry.pack()

tk.Button(root, text="Add Port", command=add_port).pack()

# Buttons
tk.Button(root, text="Start Firewall", command=start_firewall, bg="green").pack()
tk.Button(root, text="Stop Firewall", command=stop_firewall, bg="red").pack()

# Log box
log_box = scrolledtext.ScrolledText(root, width=50, height=15)
log_box.pack()

root.mainloop()