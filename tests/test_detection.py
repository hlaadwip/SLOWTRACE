from src.packet_parser import PacketParser
from src.detection_engine import SlowTraceEngine


def test_benchmark_scenarios():
    parser = PacketParser("data/sample/slowtrace_benchmark.pcap")
    df_packets = parser.parse()
    assert not df_packets.empty, "PCAP tidak boleh kosong"

    engine = SlowTraceEngine(df_packets)
    df_res = engine.analyze(save_history=False)

    # Pastikan Low-and-Slow dari 192.168.1.20 terdeteksi High Risk
    slow_row = df_res[df_res["Source IP"] == "192.168.1.20"].iloc[0]
    assert slow_row["Detection Type"] == "Potential Low-and-Slow Reconnaissance"
    assert slow_row["Risk Level"] == "High"

    # Pastikan Normal & Repeated Legitimate tidak false positive
    normal_row = df_res[df_res["Source IP"] == "192.168.1.10"].iloc[0]
    assert normal_row["Risk Level"] == "Low"

    legit_row = df_res[df_res["Source IP"] == "192.168.1.25"].iloc[0]
    assert legit_row["Risk Level"] == "Low"
    print("[PASS] Semua 4 skenario pengujian lolos evaluasi!")


if __name__ == "__main__":
    test_benchmark_scenarios()
