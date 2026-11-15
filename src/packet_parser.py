import os
import pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP, ICMP


class PacketParser:
    def __init__(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"File PCAP tidak ditemukan: {pcap_path}")
        self.pcap_path = pcap_path

    def parse(self) -> pd.DataFrame:
        records = []
        with PcapReader(self.pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                timestamp = float(pkt.time)

                row = {
                    "timestamp": timestamp,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "protocol": "OTHER",
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": "",
                    "packet_size": len(pkt),
                }

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    row["protocol"] = "TCP"
                    row["src_port"] = int(tcp.sport)
                    row["dst_port"] = int(tcp.dport)
                    row["tcp_flags"] = str(tcp.flags)
                    row["seq"] = int(tcp.seq)
                    row["ack"] = int(tcp.ack)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    row["protocol"] = "UDP"
                    row["src_port"] = int(udp.sport)
                    row["dst_port"] = int(udp.dport)
                elif pkt.haslayer(ICMP):
                    row["protocol"] = "ICMP"

                records.append(row)

        df = pd.DataFrame(records)
        if not df.empty:
            df = df.sort_values(by="timestamp").reset_index(drop=True)
            # Interface loopback ('lo') bisa merekam paket yang sama dua kali.
            # Buang salinan identik (5-tuple, flag, seq, ack) yang muncul < 50 ms setelah aslinya.
            tcp_rows = df[df["protocol"] == "TCP"]
            if not tcp_rows.empty:
                key = ["src_ip", "dst_ip", "src_port", "dst_port", "tcp_flags", "seq", "ack"]
                gap = tcp_rows.groupby(key)["timestamp"].diff()
                df = df.drop(index=gap[gap < 0.05].index).reset_index(drop=True)
            df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
            df["inter_arrival_time"] = (
                df.groupby(["src_ip", "dst_ip"])["timestamp"].diff().fillna(0.0)
            )
        return df
