import os
import sys
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.packet_parser import PacketParser
from src.detection_engine import SlowTraceEngine

st.set_page_config(page_title="SLOWTRACE | Security Operations Center", layout="wide", initial_sidebar_state="collapsed")

C = {"High": "#EF4444", "Medium": "#F59E0B", "Low": "#10B981"}
CY = "#00E5FF"
PAL = [CY, "#38BDF8", "#F59E0B", "#EF4444", "#10B981", "#A78BFA"]
GEO_DB = "data/geoip/GeoLite2-City.mmdb"

st.markdown(
    """
    <style>
    .block-container{padding:.8rem 1.2rem 1.2rem;max-width:100%}
    #MainMenu,footer{visibility:hidden}
    header[data-testid="stHeader"]{display:none}
    div[data-testid="stVerticalBlockBorderWrapper"]{background:#0D121D;border:1px solid #162033;border-radius:8px;padding:.3rem .5rem}
    .top{display:flex;justify-content:space-between;align-items:center;background:#0B0F19;border:1px solid #162033;border-radius:8px;padding:.6rem 1.1rem;margin-bottom:.7rem}
    .brand{display:flex;align-items:center;gap:12px}
    .brand b{font-size:1.25rem;letter-spacing:2px;color:#F8FAFC}
    .brand b span{color:#00E5FF}
    .brand small{display:block;color:#64748B;font-size:.72rem;font-family:monospace;letter-spacing:0}
    .chips{display:flex;gap:10px;align-items:center}
    .chip{border:1px solid #1E293B;background:#0D121D;color:#CBD5E1;border-radius:4px;padding:3px 10px;font-size:.72rem;font-family:monospace}
    .live{border-color:rgba(0,229,255,.4);color:#00E5FF;background:rgba(0,229,255,.08);font-weight:700;letter-spacing:1px}
    .ph{display:flex;justify-content:space-between;font-size:.95rem;font-weight:600;color:#E2E8F0;margin:.1rem 0 .3rem}
    .ph i{color:#475569;font-style:normal;letter-spacing:2px}
    .al{background:#0B0F19;border:1px solid #162033;border-left:3px solid #EF4444;border-radius:4px;padding:.45rem .65rem;margin-bottom:.4rem;font-size:.78rem;color:#E2E8F0;font-family:monospace}
    .al small{color:#7C8AA0;font-family:sans-serif}
    .stat{display:flex;gap:10px;align-items:center;padding:.55rem 0;border-bottom:1px solid #162033}
    .stat .ic{width:10px;height:34px;border-radius:3px}
    .stat b{font-size:.82rem;color:#E2E8F0}
    .stat small{color:#7C8AA0;font-family:monospace;font-size:.72rem}
    .big{text-align:center;font-family:monospace;color:#F1F5F9;font-size:1.35rem;font-weight:700}
    .big small{display:block;color:#64748B;font-size:.68rem;font-family:sans-serif;font-weight:400;letter-spacing:.8px;text-transform:uppercase}
    button[data-baseweb="tab"]{color:#94A3B8;font-size:.85rem}
    button[data-baseweb="tab"][aria-selected="true"]{color:#FFFFFF;font-weight:700}
    div[data-baseweb="tab-highlight"]{background:#00E5FF}
    div[data-baseweb="tab-border"]{background:#162033}
    </style>
    """,
    unsafe_allow_html=True,
)

SHIELD = (
    "<svg width='34' height='34' viewBox='0 0 24 24' fill='none' stroke='#00E5FF' stroke-width='1.6'>"
    "<path d='M12 2 4 5v6c0 5 3.4 9.2 8 11 4.6-1.8 8-6 8-11V5z'/><path d='M8 12l3 3 5-6'/></svg>"
)


def ph(title):
    st.markdown(f"<div class='ph'>{title}<i>...</i></div>", unsafe_allow_html=True)


def sty(fig, h, legend=False):
    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=h, margin=dict(t=8, b=8, l=8, r=8), showlegend=legend,
        legend=dict(orientation="h", y=1.18, x=0, font=dict(size=10), title=None),
    )
    fig.update_xaxes(gridcolor="#162033", title=None)
    fig.update_yaxes(gridcolor="#162033")
    return fig


def show_df(d):
    try:
        st.dataframe(d, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(d, use_container_width=True, hide_index=True)


def bk(df, n):
    span = (df["datetime"].max() - df["datetime"].min()).total_seconds()
    return df["datetime"].dt.floor(f"{max(1, int(span / n))}s")


def alert_html(r):
    c = C.get(r["Risk Level"], CY)
    return (
        f"<div class='al' style='border-left-color:{c}'><b>{r['Source IP']}</b> "
        f"<span style='color:{c}'>{r['Risk Score']}/100</span><br>"
        f"<small>{r['Detection Type']} | {r['Unique Ports']} ports | {r['Avg Interval (s)']}s</small></div>"
    )


@st.cache_data(show_spinner="Analyzing PCAP...")
def load(path, sig):
    dfp = PacketParser(path).parse()
    eng = SlowTraceEngine(dfp)
    dfr = eng.analyze(save_history=True)
    return dfp, dfr, eng.get_history()


@st.cache_data
def geo_lookup(ips):
    if not os.path.exists(GEO_DB):
        return {}
    try:
        import geoip2.database
    except ImportError:
        return {}
    out = {}
    with geoip2.database.Reader(GEO_DB) as rd:
        for ip in ips:
            try:
                r = rd.city(ip)
                if r.location.latitude is not None:
                    out[ip] = (r.location.latitude, r.location.longitude, r.country.name or "Unknown")
            except Exception:
                pass
    return out


def topology(dfp, risk_of):
    srcs = sorted(dfp["src_ip"].unique())
    dsts = sorted(dfp["dst_ip"].unique())
    ports = dfp["dst_port"].dropna().astype(int).value_counts().head(8).index.tolist()
    pos, nx, ny, nt, nc, ns = {}, [], [], [], [], []

    def add(key, x, i, n, t, c, s):
        y = 1 - (i + 0.5) / max(n, 1)
        pos[key] = (x, y)
        nx.append(x); ny.append(y); nt.append(t); nc.append(c); ns.append(s)

    for i, s in enumerate(srcs):
        add(s, 0.12, i, len(srcs), s, C.get(risk_of.get(s, "Low"), CY), 16)
    for i, d in enumerate(dsts):
        add(d, 0.55, i, len(dsts), d, CY, 22)
    for i, p in enumerate(ports):
        add(("p", p), 0.92, i, len(ports), f"TCP/{p}", "#38BDF8", 11)

    ex, ey = [], []

    def link(a, b):
        ex.extend([pos[a][0], pos[b][0], None])
        ey.extend([pos[a][1], pos[b][1], None])

    for s, d in dfp[["src_ip", "dst_ip"]].drop_duplicates().itertuples(index=False):
        link(s, d)
    for d, p in dfp[["dst_ip", "dst_port"]].dropna().drop_duplicates().itertuples(index=False):
        if ("p", int(p)) in pos:
            link(d, ("p", int(p)))

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=ex, y=ey, mode="lines", line=dict(width=1, color="rgba(56,189,248,.35)"), hoverinfo="none"))
    fig.add_trace(go.Scatter(
        x=nx, y=ny, mode="markers+text", text=nt, textposition="top center",
        textfont=dict(size=10, color="#CBD5E1"),
        marker=dict(size=ns, color=nc, line=dict(width=1.5, color="#080B12")), hoverinfo="text",
    ))
    fig.update_xaxes(visible=False, range=[0, 1.05])
    fig.update_yaxes(visible=False, range=[-0.05, 1.1])
    return fig


def geomap(dfp, geo, risk_of):
    cnt = dfp["src_ip"].value_counts()
    fig = go.Figure()
    slat, slon = os.getenv("SLOWTRACE_SENSOR_LAT"), os.getenv("SLOWTRACE_SENSOR_LON")
    if slat and slon:
        for ip, (la, lo, _) in geo.items():
            fig.add_trace(go.Scattergeo(lat=[la, float(slat)], lon=[lo, float(slon)], mode="lines",
                                        line=dict(width=1, color="rgba(0,229,255,.45)"), hoverinfo="skip"))
    fig.add_trace(go.Scattergeo(
        lat=[v[0] for v in geo.values()], lon=[v[1] for v in geo.values()], mode="markers",
        text=[f"{ip} | {v[2]} | {int(cnt.get(ip, 0))} pkts" for ip, v in geo.items()], hoverinfo="text",
        marker=dict(size=[8 + min(18, int(cnt.get(ip, 0)) ** 0.5) for ip in geo],
                    color=[C.get(risk_of.get(ip, "Low"), CY) for ip in geo], line=dict(width=1, color="#080B12")),
    ))
    fig.update_geos(projection_type="natural earth", bgcolor="rgba(0,0,0,0)", landcolor="#1A2333",
                    showcountries=True, countrycolor="#0D121D", showocean=False, coastlinecolor="#243049", showframe=False)
    return fig


# ---------------- Top bar & controls ----------------
ctrl1, ctrl2, ctrl3 = st.columns([1.4, 1.6, 2.2])
with ctrl1:
    input_source = st.selectbox(
        "Dataset",
        ["Benchmark Dataset (slowtrace_benchmark.pcap)", "Sample Dataset (sample_recon.pcap)", "Upload Custom PCAP"],
        label_visibility="collapsed",
    )

pcap_path, sig = "data/sample/slowtrace_benchmark.pcap", "benchmark"
if input_source.startswith("Sample"):
    pcap_path, sig = "data/sample_recon.pcap", "sample"
elif input_source == "Upload Custom PCAP":
    with ctrl2:
        up = st.file_uploader("Upload PCAP", type=["pcap", "pcapng"], label_visibility="collapsed")
    if up is None:
        st.info("Unggah file PCAP untuk memulai analisis.")
        st.stop()
    pcap_path, sig = "data/uploaded.pcap", f"{up.name}-{up.size}"
    with open(pcap_path, "wb") as f:
        f.write(up.getvalue())

df_packets, df_results, df_hist = load(pcap_path, sig)
if df_packets.empty or df_results.empty:
    st.warning("Tidak ada paket TCP/IP yang dapat dianalisis dari PCAP ini.")
    st.stop()

os.makedirs("reports", exist_ok=True)
df_results.to_csv("reports/analysis_report.csv", index=False)
alerts_only = df_results[df_results["Risk Level"].isin(["High", "Medium"])]
alerts_only.to_json("reports/alerts.json", orient="records", indent=2)
risk_of = dict(zip(df_results["Source IP"], df_results["Risk Level"]))

t0, t1 = df_packets["datetime"].min(), df_packets["datetime"].max()
with ctrl3:
    st.markdown(f"<div style='padding:8px 0;color:#64748B;font-size:.76rem;font-family:monospace'>{pcap_path} | Scapy + Pandas + SQLite</div>", unsafe_allow_html=True)

st.markdown(
    f"""
    <div class="top">
      <div class="brand">{SHIELD}<div><b>SLOW<span>TRACE</span> // SOC</b>
      <small>Temporal Behavioral Correlation &amp; Low-and-Slow Reconnaissance Engine</small></div></div>
      <div class="chips">
        <span class="chip">{len(df_packets):,} PKT</span>
        <span class="chip">{df_packets['src_ip'].nunique()} SRC</span>
        <span class="chip">{len(alerts_only)} ALERTS</span>
        <span class="chip">{t0:%Y-%m-%d %H:%M} &rarr; {t1:%H:%M}</span>
        <span class="chip live">SYSTEM ACTIVE</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

tabs = st.tabs(["Monitoring", "PCAP Analysis", "Detections", "Timeline", "Response & Report", "Live Monitor"])

# ================= TAB 1: MONITORING =================
with tabs[0]:
    L, M, R = st.columns([1.35, 1.2, 0.6])
    dfp = df_packets.copy()
    dfp["bucket"] = bk(dfp, 40)
    dfp["fine"] = bk(dfp, 150)

    with L:
        with st.container(border=True):
            ph("Real-Time Threat Detections")
            vol = dfp.groupby(["bucket", "src_ip"]).size().reset_index(name="probes")
            f = px.line(vol, x="bucket", y="probes", color="src_ip", markers=True, color_discrete_sequence=PAL)
            f.update_traces(line_shape="spline", line_width=1.6, marker_size=5)
            st.plotly_chart(sty(f, 230, True))
        with st.container(border=True):
            ph("Network Activity")
            act = dfp.groupby("fine").size()
            f = go.Figure(go.Scatter(x=act.index, y=act.values, fill="tozeroy", line=dict(color=CY, width=1),
                                     fillcolor="rgba(0,229,255,.25)"))
            st.plotly_chart(sty(f, 215))
        with st.container(border=True):
            b1, b2 = st.columns([1, 1.5])
            with b1:
                top = df_results.sort_values("Risk Score", ascending=False).iloc[0]
                wide = df_results.sort_values("Unique Ports", ascending=False).iloc[0]
                slow = df_results.sort_values("Avg Interval (s)", ascending=False).iloc[0]
                for t, d, c in [
                    ("Highest Risk Host", f"{top['Source IP']} | score {top['Risk Score']}", "#EF4444"),
                    ("Widest Port Sweep", f"{wide['Source IP']} | {wide['Unique Ports']} ports", "#F59E0B"),
                    ("Slowest Probe Cadence", f"{slow['Source IP']} | {slow['Avg Interval (s)']}s avg", CY),
                ]:
                    st.markdown(f"<div class='stat'><div class='ic' style='background:{c}'></div><div><b>{t}</b><br><small>{d}</small></div></div>", unsafe_allow_html=True)
            with b2:
                ph("Most Probed Destination Ports")
                pc = df_packets["dst_port"].dropna().astype(int).value_counts().head(6).reset_index()
                pc.columns = ["Port", "Hits"]
                pc["Port"] = "TCP/" + pc["Port"].astype(str)
                f = px.bar(pc.sort_values("Hits"), x="Hits", y="Port", orientation="h", color_discrete_sequence=[CY])
                f.update_yaxes(title=None)
                st.plotly_chart(sty(f, 215))

    geo = geo_lookup(tuple(df_packets["src_ip"].unique()))
    with M:
        with st.container(border=True):
            ph("Security Alerts")
            st.plotly_chart(sty(geomap(df_packets, geo, risk_of) if geo else topology(df_packets, risk_of), 360))
            a1, a2 = st.columns(2)
            for i, (_, r) in enumerate(df_results.sort_values("Risk Score", ascending=False).head(4).iterrows()):
                (a1 if i % 2 == 0 else a2).markdown(alert_html(r), unsafe_allow_html=True)
        with st.container(border=True):
            if geo:
                ph("Attack Origin by Country")
                ctry = pd.Series({ip: v[2] for ip, v in geo.items()})
                cdf = df_packets["src_ip"].map(ctry).dropna().value_counts().reset_index()
                cdf.columns = ["Country", "Packets"]
                f = px.choropleth(cdf, locations="Country", locationmode="country names", color="Packets",
                                  color_continuous_scale=[[0, "#12302F"], [1, "#14B8A6"]])
                f.update_geos(projection_type="natural earth", bgcolor="rgba(0,0,0,0)", landcolor="#1A2333",
                              showframe=False, showcountries=True, countrycolor="#0D121D", showocean=False)
                f.update_coloraxes(showscale=False)
            else:
                ph("Port Exposure Matrix (Source IP x Port)")
                tp = df_packets["dst_port"].dropna().astype(int).value_counts().head(12).index
                sub = df_packets[df_packets["dst_port"].isin(tp)].copy()
                sub["P"] = sub["dst_port"].astype(int).astype(str)
                hm = sub.pivot_table(index="src_ip", columns="P", values="dst_ip", aggfunc="count", fill_value=0)
                f = px.imshow(hm, aspect="auto", color_continuous_scale=[[0, "#0D121D"], [1, CY]])
                f.update_coloraxes(showscale=False)
            st.plotly_chart(sty(f, 300))

    with R:
        with st.container(border=True):
            ph("Network Alerts")
            flt = st.selectbox("Filter", ["All", "High", "Medium", "Low"], label_visibility="collapsed", key="flt")
            view = df_results if flt == "All" else df_results[df_results["Risk Level"] == flt]
            if view.empty:
                st.caption("Tidak ada host pada level ini.")
            for _, r in view.sort_values("Risk Score", ascending=False).iterrows():
                st.markdown(alert_html(r), unsafe_allow_html=True)
        with st.container(border=True):
            ph("System Vulnerability")
            rd = df_results["Risk Level"].value_counts().reset_index()
            rd.columns = ["Risk Level", "Hosts"]
            f = px.pie(rd, names="Risk Level", values="Hosts", hole=0.7, color="Risk Level", color_discrete_map=C)
            f.update_traces(textinfo="none", marker=dict(line=dict(color="#0D121D", width=3)))
            f.add_annotation(text=f"{int(df_results['Risk Score'].max())}<br><span style='font-size:10px;color:#94A3B8'>MAX RISK</span>",
                             showarrow=False, font=dict(size=24, color="#F8FAFC"))
            st.plotly_chart(sty(f, 230))
            s1, s2 = st.columns(2)
            s1.markdown(f"<div class='big'>{df_results['Risk Score'].mean():.1f}<small>Avg Risk</small></div>", unsafe_allow_html=True)
            s2.markdown(f"<div class='big'>{len(alerts_only) / len(df_results) * 100:.0f}%<small>Flagged</small></div>", unsafe_allow_html=True)

# ================= TAB 2: PCAP ANALYSIS =================
with tabs[1]:
    c1, c2 = st.columns(2)
    with c1:
        with st.container(border=True):
            ph("Source IP Packet Distribution")
            d = df_packets["src_ip"].value_counts().reset_index()
            d.columns = ["Source IP", "Packets"]
            st.plotly_chart(sty(px.bar(d, x="Packets", y="Source IP", orientation="h", color_discrete_sequence=[CY]), 280))
    with c2:
        with st.container(border=True):
            ph("Destination Port Hit Frequency")
            d = df_packets["dst_port"].dropna().astype(int).value_counts().head(10).reset_index()
            d.columns = ["Port", "Hits"]
            d["Port"] = d["Port"].astype(str)
            st.plotly_chart(sty(px.bar(d, x="Port", y="Hits", color_discrete_sequence=["#38BDF8"]), 280))
    with st.container(border=True):
        ph("Extracted Packet Metadata")
        show_df(df_packets[["datetime", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_flags", "inter_arrival_time"]])

# ================= TAB 3: DETECTIONS =================
with tabs[2]:
    c1, c2 = st.columns([1.2, 1])
    with c1:
        with st.container(border=True):
            ph("Risk Score per Source IP")
            f = px.bar(df_results, x="Source IP", y="Risk Score", color="Risk Level", text="Risk Score", color_discrete_map=C)
            f.update_traces(textposition="outside")
            f.update_yaxes(range=[0, 115])
            st.plotly_chart(sty(f, 330, True))
    with c2:
        with st.container(border=True):
            ph("Behavioral Matrix: Ports vs Inter-Arrival")
            f = px.scatter(df_results, x="Avg Interval (s)", y="Unique Ports", size="Risk Score", color="Detection Type",
                           hover_name="Source IP", color_discrete_sequence=PAL)
            st.plotly_chart(sty(f, 330, True))
    with st.container(border=True):
        ph("Forensic Evidence & Detection Justification")
        show_df(df_results[["Source IP", "Destination IP", "Unique Ports", "Unique Hosts", "Conn Freq (/min)", "Avg Interval (s)", "First Activity", "Last Activity",
                            "Detection Type", "Risk Score", "Risk Level", "Evidence"]])

# ================= TAB 4: TIMELINE =================
with tabs[3]:
    with st.container(border=True):
        ph("Temporal Correlation Timeline (Cross-Time Port Probing)")
        f = px.scatter(df_packets.dropna(subset=["dst_port"]), x="datetime", y="dst_port", color="src_ip",
                       symbol="tcp_flags", size="packet_size", hover_data=["dst_ip", "protocol", "inter_arrival_time"],
                       color_discrete_sequence=PAL)
        f.update_yaxes(title="Destination Port")
        st.plotly_chart(sty(f, 430, True))
    with st.container(border=True):
        ph("Chronological Event Sequence (Flagged Hosts)")
        sus = alerts_only["Source IP"].tolist()
        show_df(df_packets[df_packets["src_ip"].isin(sus)][["datetime", "src_ip", "dst_ip", "dst_port", "tcp_flags", "inter_arrival_time"]])

# ================= TAB 5: RESPONSE & REPORT =================
with tabs[4]:
    with st.container(border=True):
        ph("Export Forensic Reports")
        e1, e2, e3 = st.columns(3)
        e1.download_button("Export analysis_report.csv", df_results.to_csv(index=False).encode("utf-8"), "analysis_report.csv", "text/csv")
        e2.download_button("Export alerts.json", alerts_only.to_json(orient="records", indent=2).encode("utf-8"), "alerts.json", "application/json")
        summary = {
            "total_packets": int(len(df_packets)),
            "unique_sources": int(df_packets["src_ip"].nunique()),
            "alerts_generated": int(len(alerts_only)),
            "low_and_slow_detected": int((df_results["Detection Type"] == "Potential Low-and-Slow Reconnaissance").sum()),
        }
        e3.download_button("Export detection_summary.json", json.dumps(summary, indent=2).encode("utf-8"), "detection_summary.json", "application/json")

    with st.container(border=True):
        ph("Controlled Mitigation & Dry-Run Containment")
        for _, r in alerts_only.iterrows():
            with st.expander(f"[{r['Risk Level'].upper()}] {r['Source IP']} -> {r['Destination IP']} | {r['Detection Type']} ({r['Risk Score']}/100)", expanded=True):
                st.markdown(f"- **Activity Window:** `{r['First Activity']}` to `{r['Last Activity']}` ({r['Duration (min)']} min)")
                st.markdown(f"- **Correlation Evidence:** {r['Evidence']}")
                st.markdown(f"- **Recommended Action:** `{r['Mitigation Action']}`")
                st.code(r["Firewall Command"], language="bash")
                if st.button(f"Execute Dry-Run Block ({r['Source IP']})", key=f"dry_{r['Source IP']}"):
                    st.success(f"[DRY-RUN LOG] Firewall DROP simulation validated for {r['Source IP']} (No host network interface modified).")

    with st.container(border=True):
        ph("SQLite Detection History")
        if not df_hist.empty:
            show_df(df_hist)

# ================= TAB 6: LIVE MONITOR =================
with tabs[5]:
    from datetime import datetime
    from src.live_capture import list_interfaces, capture_packets, save_pcap

    with st.container(border=True):
        ph("Live Network Monitoring")
        ifaces = list_interfaces()
        l1, l2, l3 = st.columns(3)
        iface = l1.selectbox("Interface", ifaces, index=ifaces.index("eth0") if "eth0" in ifaces else 0)
        secs = l2.slider("Durasi per siklus (detik)", 5, 60, 20)
        cycles = l3.slider("Jumlah siklus", 1, 10, 3)
        st.caption("Paket TCP ditangkap bertahap dan dianalisis ulang secara kumulatif. Port 8501 (dashboard) dikecualikan.")
        start = st.button("Mulai Live Capture", type="primary")

    if start:
        pkts = []
        path = f"data/live/live_{datetime.now():%Y%m%d_%H%M%S}.pcap"
        prog = st.progress(0.0, text="Menyiapkan capture...")
        slot = st.empty()
        try:
            for i in range(cycles):
                prog.progress(i / cycles, text=f"Siklus {i + 1}/{cycles}: menangkap {secs} detik pada {iface}...")
                pkts.extend(capture_packets(iface, secs))
                if not pkts:
                    continue
                save_pcap(path, pkts)
                dfl = PacketParser(path).parse()
                resl = SlowTraceEngine(dfl).analyze(save_history=(i == cycles - 1))
                if resl.empty:
                    continue
                flagged = resl[resl["Risk Level"].isin(["High", "Medium"])]
                with slot.container():
                    k1, k2, k3 = st.columns(3)
                    k1.metric("Paket tertangkap", f"{len(dfl):,}")
                    k2.metric("Source IP", dfl["src_ip"].nunique())
                    k3.metric("Alert (High/Medium)", len(flagged))
                    show_df(resl[["Source IP", "Destination IP", "Unique Ports", "Unique Hosts", "Avg Interval (s)",
                                  "Detection Type", "Risk Score", "Risk Level", "Evidence"]])
                    f = px.scatter(dfl.dropna(subset=["dst_port"]), x="datetime", y="dst_port", color="src_ip",
                                   color_discrete_sequence=PAL)
                    f.update_yaxes(title="Destination Port")
                    st.plotly_chart(sty(f, 280, True), key=f"live_chart_{i}")
            prog.progress(1.0, text="Selesai")
            if pkts:
                st.success(f"{len(pkts)} paket TCP disimpan di {path}")
                with open(path, "rb") as fh:
                    st.download_button("Unduh PCAP hasil capture", fh.read(), os.path.basename(path), "application/octet-stream")
            else:
                st.warning("Tidak ada paket TCP tertangkap. Coba interface lain atau buat trafik uji.")
        except PermissionError:
            st.error("Izin capture ditolak. Jalankan di terminal WSL: sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f .venv/bin/python)\" lalu restart Streamlit.")
        except Exception as e:
            st.error(f"Capture gagal: {e}")
