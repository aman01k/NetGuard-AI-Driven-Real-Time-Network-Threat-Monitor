from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime
import threading

# Global DataFrame to store packet data
# We use a global variable here for simplicity in a quick project
packet_data = []

def packet_callback(packet):
    # We only care about IP packets (Internet Protocol)
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)
        
        # Determine protocol name
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        # Append to our list
        packet_data.append({
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Source": src_ip,
            "Destination": dst_ip,
            "Protocol": protocol_name,
            "Size": size
        })

        # Keep the list size manageable (last 1000 packets)
        if len(packet_data) > 1000:
            packet_data.pop(0)

def start_sniffing():
    # Start sniffing on the default interface
    # store=0 means we don't keep packets in RAM forever, we process them with callback
    sniff(prn=packet_callback, store=0)

# We run this in a separate thread so it doesn't block the Dashboard
def start_sniffer_thread():
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()