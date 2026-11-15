"""Uji low-and-slow: mengetuk satu port tiap 20 detik, HANYA ke komputer sendiri (127.0.0.1)."""
import socket
import time

TARGET = "127.0.0.1"
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]
DELAY = 20

for i, p in enumerate(PORTS, 1):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((TARGET, p))
    except Exception:
        pass
    s.close()
    print(f"[{i}/{len(PORTS)}] probe ke {TARGET}:{p}", flush=True)
    time.sleep(DELAY)
print("Selesai")
