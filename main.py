import argparse
import json
import os
from src.packet_parser import PacketParser
from src.detection_engine import SlowTraceEngine


def main():
    parser = argparse.ArgumentParser(description="SLOWTRACE CLI Network Reconnaissance Analyzer")
    parser.add_argument(
        "--pcap",
        default="data/sample/slowtrace_benchmark.pcap",
        help="Path ke file PCAP yang akan dianalisis",
    )
    args = parser.parse_args()

    print(f"[*] Menganalisis PCAP: {args.pcap}")
    pkt_parser = PacketParser(args.pcap)
    df_packets = pkt_parser.parse()
    print(f"[+] Total paket diekstrak: {len(df_packets)}")

    engine = SlowTraceEngine(df_packets)
    df_results = engine.analyze(save_history=True)

    os.makedirs("reports", exist_ok=True)
    df_results.to_csv("reports/analysis_report.csv", index=False)
    alerts = df_results[df_results["Risk Level"].isin(["High", "Medium"])]
    alerts.to_json("reports/alerts.json", orient="records", indent=2)
    with open("reports/detection_summary.json", "w") as f:
        json.dump(
            {
                "pcap_file": args.pcap,
                "total_packets": len(df_packets),
                "total_alerts": len(alerts),
            },
            f,
            indent=2,
        )

    print("\n=== HASIL KORELASI & DETEKSI SLOWTRACE ===")
    print(
        df_results[
            [
                "Source IP",
                "Destination IP",
                "Unique Ports",
                "Avg Interval (s)",
                "Detection Type",
                "Risk Score",
                "Risk Level",
            ]
        ].to_string(index=False)
    )
    print("\n[+] Laporan tersimpan di folder reports/ (analysis_report.csv, alerts.json, detection_summary.json)")


if __name__ == "__main__":
    main()
