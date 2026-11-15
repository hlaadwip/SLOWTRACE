import time
from scapy.all import IP, TCP, UDP, wrpcap

def create_demo_pcap(filename="data/sample_recon.pcap"):
    packets = []
    base_time = time.time() - 3600  # Simulasi dimulai 1 jam lalu

    # 1. Lalu lintas normal (User biasa akses HTTP/HTTPS/DNS)
    normal_ports = [80, 443, 53]
    for i in range(15):
        pkt = IP(src="192.168.1.10", dst="192.168.1.1") / TCP(
            sport=40000 + i, dport=normal_ports[i % 3], flags="PA"
        )
        pkt.time = base_time + (i * 120)
        packets.append(pkt)

    # 2. Serangan Low-and-Slow Vertical Port Scan (Attacker 10.0.0.66 -> Target 192.168.1.50)
    # Mengirim paket SYN setiap ~45-60 detik ke berbagai port berbeda
    target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 8080, 8443]
    for idx, port in enumerate(target_ports):
        pkt = IP(src="10.0.0.66", dst="192.168.1.50") / TCP(
            sport=51000 + idx, dport=port, flags="S"
        )
        pkt.time = base_time + 100 + (idx * 55)
        packets.append(pkt)

    # 3. Serangan Stealth Xmas Scan lambat (Attacker 10.0.0.99 -> Target 192.168.1.50)
    stealth_ports = [22, 80, 443, 8080, 9000, 9200]
    for idx, port in enumerate(stealth_ports):
        pkt = IP(src="10.0.0.99", dst="192.168.1.50") / TCP(
            sport=60000 + idx, dport=port, flags="FPU"
        )
        pkt.time = base_time + 300 + (idx * 90)
        packets.append(pkt)

    # Urutkan paket berdasarkan waktu
    packets.sort(key=lambda x: x.time)
    wrpcap(filename, packets)
    print(f"[+] Berhasil membuat {len(packets)} paket di {filename}")

if __name__ == "__main__":
    create_demo_pcap()
