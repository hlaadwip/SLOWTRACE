import time
from scapy.all import IP, TCP, wrpcap


def generate_benchmark_pcap(filename="data/sample/slowtrace_benchmark.pcap"):
    packets = []
    base_time = time.time() - 5400  # Simulasi rentang 90 menit

    # Skenario 1: Normal Traffic (192.168.1.10 -> 192.168.1.50) - Akses web normal (HTTP/HTTPS)
    for i in range(12):
        port = 443 if i % 2 == 0 else 80
        pkt = IP(src="192.168.1.10", dst="192.168.1.50") / TCP(
            sport=41000 + i, dport=port, flags="PA"
        )
        pkt.time = base_time + (i * 180)
        packets.append(pkt)

    # Skenario 2: Repeated Legitimate Connection (192.168.1.25 -> 192.168.1.50) - Cron healthcheck/sync port 443 setiap 2 menit
    for i in range(15):
        pkt = IP(src="192.168.1.25", dst="192.168.1.50") / TCP(
            sport=45000 + i, dport=443, flags="PA"
        )
        pkt.time = base_time + 60 + (i * 120)
        packets.append(pkt)

    # Skenario 3: Fast Port Scan (10.0.0.44 -> 192.168.1.50) - 12 port dalam 6 detik (0.5s/paket)
    fast_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    for idx, port in enumerate(fast_ports):
        pkt = IP(src="10.0.0.44", dst="192.168.1.50") / TCP(
            sport=50000 + idx, dport=port, flags="S"
        )
        pkt.time = base_time + 600 + (idx * 0.5)
        packets.append(pkt)

    # Skenario 4: Low-and-Slow Reconnaissance (192.168.1.20 -> 192.168.1.50) - 10 port dengan jeda 15 menit (900s) / 75s
    slow_ports = [21, 22, 80, 443, 445, 3306, 5432, 6379, 8080, 8443]
    for idx, port in enumerate(slow_ports):
        pkt = IP(src="192.168.1.20", dst="192.168.1.50") / TCP(
            sport=55000 + idx, dport=port, flags="S"
        )
        pkt.time = base_time + 120 + (idx * 75)
        packets.append(pkt)

    packets.sort(key=lambda x: x.time)
    wrpcap(filename, packets)
    print(f"[+] Berhasil membuat {len(packets)} paket (4 skenario) di {filename}")


if __name__ == "__main__":
    generate_benchmark_pcap()
