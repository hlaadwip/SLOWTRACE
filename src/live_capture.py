import os
from scapy.all import sniff, wrpcap, get_if_list, TCP

EXCLUDE_PORTS = {8501}  # port dashboard Streamlit


def list_interfaces():
    return get_if_list()


def capture_packets(iface, seconds):
    def keep(p):
        return TCP in p and p[TCP].sport not in EXCLUDE_PORTS and p[TCP].dport not in EXCLUDE_PORTS

    return list(sniff(iface=iface, timeout=seconds, lfilter=keep, store=True))


def save_pcap(path, packets):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrpcap(path, packets)
