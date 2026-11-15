# SLOWTRACE

Temporal Behavioral Correlation untuk mendeteksi reconnaissance *low-and-slow*
(port scan yang sengaja diperlambat agar lolos dari deteksi berbasis ambang batas).

## Fitur
- Network Traffic Analyzer: parsing PCAP (IP, port, protokol, timestamp, TCP flags)
- Signature-Based Detection: stealth scan (FIN/NULL/Xmas) dan SYN scan
- Behavioral Anomaly Detection: port unik, host unik, frekuensi, dan interval koneksi
- Temporal Correlation Engine: korelasi aktivitas per IP lintas waktu (pembeda utama)
- Risk Scoring & Alert: skor 0-100 beserta bukti deteksi
- Response Manager: rekomendasi mitigasi dan simulasi (dry-run)
- Detection History (SQLite), Export CSV/JSON, Upload PCAP, Live Monitor

## Instalasi
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run dashboard/app.py
```

## Struktur
- `src/packet_parser.py`: parsing PCAP
- `src/detection_engine.py`: signature, behavioral, temporal, dan risk scoring
- `src/live_capture.py`: capture paket untuk Live Monitor
- `scripts/block_ip.py`: pemblokiran terkontrol (dry-run secara default, allowlist IP uji)
- `dashboard/app.py`: dashboard Streamlit

## Peta dunia (opsional)
Letakkan `GeoLite2-City.mmdb` (unduh gratis dari MaxMind) di `data/geoip/`.
Tanpa file itu, dashboard memakai topologi koneksi dan matriks port.

## Batasan
- Fokus pada trafik TCP; UDP dan ICMP belum dianalisis.
- Live Monitor di WSL2 hanya melihat trafik milik WSL.
- Pemblokiran nyata hanya lewat skrip CLI dengan allowlist; dashboard hanya simulasi.
- Gunakan hanya pada jaringan dan IP yang Anda miliki izinnya.

## Demo Live Monitor (uji low-and-slow di komputer sendiri)

Live Monitor menangkap paket TCP secara bertahap dan menganalisis ulang secara kumulatif,
sehingga pola low-and-slow baru terdeteksi setelah bukti lintas waktu cukup.

Izin capture (sekali saja, di WSL):

~~~bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
~~~

Langkah demo:
1. Jalankan dashboard, buka tab **Live Monitor**, pilih interface `lo`, durasi 60 detik, 4 siklus.
2. Klik **Mulai Live Capture**.
3. Di terminal lain jalankan `python scripts/slow_scan_test.py`
   (satu port tiap 20 detik, hanya ke 127.0.0.1).
4. Setelah sekitar 5 port terkumpul, `127.0.0.1` terdeteksi sebagai
   *Potential Low-and-Slow Reconnaissance*.

Catatan: capture di `lo` merekam paket ganda, sehingga parser membuang salinan identik (< 50 ms).
