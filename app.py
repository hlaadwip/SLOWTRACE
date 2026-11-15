import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile

from src.packet_parser import PacketParser
from src.detection_engine import SlowTraceEngine

st.set_page_config(
    page_title="SLOWTRACE | SOC Reconnaissance Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS untuk nuansa SOC / Cybersecurity Dark Dashboard
st.markdown(
    """
    <style>
    /* Hilangkan padding atas berlebih & sembunyikan menu Deploy bawaan */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    #MainMenu {visibility: hidden;}
    header[data-testid="stHeader"] {background: rgba(11, 15, 25, 0.85);}

    /* Banner Hero Header */
    .hero-box {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 60%, #091E2C 100%);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-left: 5px solid #00F0FF;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .hero-title {
        font-size: 2rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        background: linear-gradient(90deg, #00F0FF, #38BDF8, #818CF8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .hero-sub {
        color: #94A3B8;
        font-size: 0.95rem;
        margin-top: 0.25rem;
        margin-bottom: 0;
    }
    .badge-live {
        display: inline-block;
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(52, 211, 153, 0.4);
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-bottom: 0.4rem;
    }

    /* Kartu Metrik Custom */
    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, #111827 0%, #0F172A 100%);
        border: 1px solid #1E293B;
        border-top: 3px solid #00F0FF;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
    }
    div[data-testid="stMetricLabel"] > div {
        color: #94A3B8 !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }
    div[data-testid="stMetricValue"] > div {
        color: #F8FAFC !important;
        font-weight: 700 !important;
    }

    /* Styling Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #111827;
        padding: 6px;
        border-radius: 10px;
        border: 1px solid #1E293B;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 7px;
        padding: 8px 16px;
        color: #94A3B8;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(0, 240, 255, 0.12) !important;
        color: #00F0FF !important;
        border: 1px solid rgba(0, 240, 255, 0.35) !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Hero Header
st.markdown(
    """
    <div class="hero-box">
        <span class="badge-live">● TEMPORAL CORRELATION ENGINE ACTIVE</span>
        <h1 class="hero-title">🛡️ SLOWTRACE</h1>
        <p class="hero-sub">Temporal Behavioral Correlation for Low-and-Slow Network Reconnaissance Detection &amp; Response System</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Sidebar
st.sidebar.markdown("### ⚙️ Konfigurasi Analisis")
data_mode = st.sidebar.radio(
    "Sumber Paket Jaringan:",
    ["Sample PCAP (Simulasi Serangan)", "Upload File PCAP (.pcap / .pcapng)"],
)

pcap_path = "data/sample_recon.pcap"
if data_mode == "Upload File PCAP (.pcap / .pcapng)":
    uploaded_file = st.sidebar.file_uploader("Unggah file PCAP", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            pcap_path = tmp.name

st.sidebar.markdown("---")
st.sidebar.markdown("### 🧠 Pipeline Deteksi")
st.sidebar.markdown(
    """
    - **Stage 1:** Packet & Interval Extraction
    - **Stage 2:** Signature Flag Inspection
    - **Stage 3:** Behavioral Anomaly Profiling
    - **Stage 4:** Temporal Window Correlation
    - **Stage 5:** Risk Scoring & Containment
    """
)
st.sidebar.caption("Mode: Offline PCAP Forensic & Lab Mitigation")

try:
    parser = PacketParser(pcap_path)
    df_packets = parser.parse()

    if df_packets.empty:
        st.warning("Tidak ada paket IP valid di dalam file PCAP ini.")
        st.stop()

    engine = SlowTraceEngine(df_packets)
    df_alerts = engine.analyze()

    # KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Paket Dianalisis", f"{len(df_packets):,}", "IPv4 / Transport")
    col2.metric("Pasangan Aliran IP", len(df_alerts), "Unique Flow Pairs")
    suspicious_count = len(df_alerts[df_alerts["severity"].isin(["CRITICAL", "HIGH"])])
    col3.metric(
        "Ancaman Reconnaissance",
        f"{suspicious_count} Host",
        delta="Low-and-Slow Detected" if suspicious_count else "Clean",
        delta_color="inverse",
    )
    max_risk = int(df_alerts["risk_score"].max()) if not df_alerts.empty else 0
    col4.metric("Skor Risiko Tertinggi", f"{max_risk} / 100", "CRITICAL Threshold ≥ 75")

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "🚨 Detection & Risk Scoring",
            "⏱️ Temporal Correlation Timeline",
            "📦 PCAP Traffic Explorer",
            "🛡️ Controlled Response & Mitigation",
        ]
    )

    with tab1:
        st.markdown("#### Matriks Korelasi Ancaman & Skor Risiko")
        st.dataframe(
            df_alerts[
                [
                    "src_ip",
                    "dst_ip",
                    "severity",
                    "risk_score",
                    "unique_ports",
                    "avg_interval_sec",
                    "duration_min",
                    "signatures",
                    "temporal_correlation",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

        fig_risk = px.bar(
            df_alerts,
            x="src_ip",
            y="risk_score",
            color="severity",
            text="risk_score",
            title="Perbandingan Skor Risiko per Sumber IP",
            template="plotly_dark",
            color_discrete_map={
                "CRITICAL": "#EF4444",
                "HIGH": "#F97316",
                "MEDIUM": "#EAB308",
                "NORMAL": "#10B981",
            },
        )
        fig_risk.update_traces(textposition="outside")
        fig_risk.update_layout(
            plot_bgcolor="#0F172A",
            paper_bgcolor="#111827",
            yaxis=dict(range=[0, 115], title="Risk Score (0-100)"),
            xaxis=dict(title="Source IP Address"),
            margin=dict(t=50, b=30, l=30, r=30),
        )
        st.plotly_chart(fig_risk, use_container_width=True)

    with tab2:
        st.markdown("#### Kronologi Temporal Pemindaian Port (Low-and-Slow Pattern)")
        st.caption(
            "Setiap titik merepresentasikan paket probe terhadap port tujuan sepanjang garis waktu. Pola tangga diagonal dengan jeda panjang menandakan low-and-slow reconnaissance."
        )
        fig_timeline = px.scatter(
            df_packets.dropna(subset=["dst_port"]),
            x="datetime",
            y="dst_port",
            color="src_ip",
            symbol="tcp_flags",
            size="packet_size",
            hover_data=["dst_ip", "protocol", "inter_arrival_time"],
            title="Distribusi Temporal Akses Port Tujuan per Sumber IP",
            template="plotly_dark",
            color_discrete_sequence=["#00F0FF", "#EF4444", "#F59E0B", "#10B981"],
        )
        fig_timeline.update_layout(
            plot_bgcolor="#0F172A",
            paper_bgcolor="#111827",
            xaxis=dict(title="Waktu Kejadian (Timestamp)"),
            yaxis=dict(title="Destination Port"),
            margin=dict(t=50, b=30, l=30, r=30),
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    with tab3:
        st.markdown("#### Inspeksi Paket Jaringan & Inter-Arrival Time")
        col_f1, col_f2 = st.columns([1, 3])
        with col_f1:
            selected_ip = st.selectbox(
                "Filter Source IP:", ["Semua IP"] + sorted(df_packets["src_ip"].unique().tolist())
            )
        filtered_df = (
            df_packets
            if selected_ip == "Semua IP"
            else df_packets[df_packets["src_ip"] == selected_ip]
        )
        st.dataframe(
            filtered_df[
                [
                    "datetime",
                    "src_ip",
                    "dst_ip",
                    "protocol",
                    "src_port",
                    "dst_port",
                    "tcp_flags",
                    "inter_arrival_time",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

    with tab4:
        st.markdown("#### Rekomendasi Mitigasi & Isolasi Terkontrol (Lab Environment)")
        threats = df_alerts[df_alerts["severity"].isin(["CRITICAL", "HIGH", "MEDIUM"])]

        if threats.empty:
            st.success("Tidak ditemukan aktivitas reconnaissance yang memerlukan mitigasi.")
        else:
            for _, row in threats.iterrows():
                with st.expander(
                    f"🚨 [{row['severity']}] {row['src_ip']} ➔ {row['dst_ip']}  |  Risk Score: {row['risk_score']}/100",
                    expanded=True,
                ):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**Rentang Aktivitas:** `{row['first_seen']}` — `{row['last_seen']}`")
                        st.markdown(f"**Durasi Pemindaian:** `{row['duration_min']} menit` (Rata-rata jeda `{row['avg_interval_sec']} detik`)")
                        st.markdown(f"**Signature Terdeteksi:** `{row['signatures']}`")
                    with c2:
                        st.markdown(f"**Anomali Perilaku:** `{row['behavioral_anomaly']}`")
                        st.markdown(f"**Korelasi Temporal:** `{row['temporal_correlation']}`")

                    st.markdown("**Perintah Mitigasi Firewall (Rekomendasi):**")
                    st.code(row["mitigation_command"], language="bash")

                    if st.button(f"⚡ Eksekusi Simulasi Blokir ({row['src_ip']})", key=f"btn_{row['src_ip']}"):
                        st.warning(
                            f"[CONTROLLED RESPONSE LOG] Aturan DROP untuk {row['src_ip']} berhasil disimulasikan dan dicatat ke audit trail."
                        )

except Exception as e:
    st.error(f"Terjadi kesalahan saat memproses PCAP: {e}")
