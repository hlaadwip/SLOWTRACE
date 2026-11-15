import sqlite3
import os
from datetime import datetime
import pandas as pd


class SlowTraceEngine:
    def __init__(self, df: pd.DataFrame, db_path: str = "reports/slowtrace_history.db"):
        self.df = df.copy()
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                unique_ports INTEGER,
                detection_type TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                evidence TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def analyze(self, save_history: bool = True) -> pd.DataFrame:
        if self.df.empty:
            return pd.DataFrame()

        # Engine ini berfokus pada TCP; UDP/ICMP tidak dianalisis
        tcp = self.df[self.df["protocol"] == "TCP"].copy()
        if tcp.empty:
            return pd.DataFrame()
        tcp["tcp_flags"] = tcp["tcp_flags"].fillna("").astype(str)

        results = []
        # Korelasi temporal dikelompokkan per Source IP lintas waktu
        for src_ip, full in tcp.groupby("src_ip"):
            # Probe = segmen pembuka koneksi (tanpa ACK/RST): SYN, FIN, NULL, Xmas.
            # Balasan server dan sesi yang sudah berjalan tidak dihitung sebagai probe.
            probes = full[~full["tcp_flags"].str.contains("A|R", regex=True)]
            is_responder = probes.empty
            group = (full if is_responder else probes).sort_values("timestamp").copy()
            group["src_interval"] = group["timestamp"].diff().fillna(0.0)

            total_pkts = len(group)
            unique_ports = int(group["dst_port"].nunique())
            unique_hosts = int(group["dst_ip"].nunique())
            dst_ips_str = ", ".join(sorted(group["dst_ip"].unique().tolist()))
            duration_sec = float(group["timestamp"].max() - group["timestamp"].min())

            intervals = group["src_interval"].iloc[1:]
            avg_interval = float(intervals.mean()) if not intervals.empty else 0.0
            std_interval = float(intervals.std()) if len(intervals) > 1 else 0.0
            conn_freq = round(total_pkts / max(duration_sec / 60.0, 0.1), 2)

            sig_indicators, beh_indicators, temporal_indicators = [], [], []
            sig_score = beh_score = temp_score = 0

            if is_responder:
                if unique_ports <= 2 and len(full) >= 10:
                    detection_type = "Repeated Legitimate Connection"
                    temporal_indicators.append(
                        f"Consistent legitimate service access ({unique_ports} port(s), established-session traffic)"
                    )
                else:
                    detection_type = "Normal Traffic"
                    temporal_indicators.append("Response-only traffic (no connection-initiating packets)")
            else:
                # 1. Signature-Based Detection
                flags_list = group["tcp_flags"].tolist()
                syn_only = sum(1 for f in flags_list if f == "S")
                stealth_flags = sum(1 for f in flags_list if f in ["FPU", "F", ""])
                if stealth_flags > 0:
                    sig_indicators.append("Stealth TCP Flag Signature (FIN/NULL/Xmas)")
                    sig_score += 30
                if syn_only >= 4 and (syn_only / total_pkts) > 0.7:
                    sig_indicators.append("Half-Open TCP SYN Scan Signature")
                    sig_score += 25

                # 2. Behavioral Anomaly Detection
                if unique_ports >= 5:
                    beh_indicators.append(f"Multiple destination ports ({unique_ports} unique ports)")
                    beh_score += min(30, unique_ports * 2)
                if unique_hosts >= 3:
                    beh_indicators.append(f"Horizontal sweep across {unique_hosts} destination hosts")
                    beh_score += 20

                # 3. Temporal Correlation Engine
                if (unique_ports >= 5 or unique_hosts >= 3) and avg_interval >= 15.0:
                    detection_type = "Potential Low-and-Slow Reconnaissance"
                    temporal_indicators.append(
                        f"Low-and-slow cross-time correlation (avg interval {avg_interval:.1f}s over {duration_sec/60:.1f} mins)"
                    )
                    temp_score += 35
                    if std_interval < 15.0 and len(intervals) >= 3:
                        temporal_indicators.append("Periodic/automated probing interval")
                        temp_score += 10
                elif unique_ports >= 5 or unique_hosts >= 3:
                    detection_type = "Fast Port Scan"
                    temporal_indicators.append(
                        f"High-frequency burst probing (avg interval {avg_interval:.2f}s)"
                    )
                    temp_score += 20
                elif unique_ports <= 2 and len(full) >= 10:
                    detection_type = "Repeated Legitimate Connection"
                    temporal_indicators.append(
                        f"Consistent legitimate service access ({unique_ports} port(s))"
                    )
                else:
                    detection_type = "Normal Traffic"
                    temporal_indicators.append("Standard baseline traffic")

            # 4. Risk Scoring (0-29 Low, 30-59 Medium, 60-100 High)
            risk_score = min(100, sig_score + beh_score + temp_score)
            if risk_score >= 60:
                risk_level = "High"
            elif risk_score >= 30:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            all_evidence = sig_indicators + beh_indicators + temporal_indicators
            evidence_str = "; ".join(all_evidence) if all_evidence else "Normal baseline activity"

            # 5. Response Manager (Dry-Run & Controlled Mitigation)
            if risk_level == "High":
                mitigation_action = "High-Priority Alert + Controlled Dry-Run Block"
                firewall_cmd = (
                    f"# Dry-Run Mitigation Rule (Authorized Test Environment)\n"
                    f"sudo ufw deny from {src_ip} to any\n"
                    f"sudo iptables -A INPUT -s {src_ip} -j DROP"
                )
            elif risk_level == "Medium":
                mitigation_action = "Alert + Rate-Limiting & Enhanced Logging"
                firewall_cmd = f"sudo iptables -A INPUT -s {src_ip} -m limit --limit 5/min -j ACCEPT"
            else:
                mitigation_action = "Log Only (No Blocking Required)"
                firewall_cmd = "# No firewall rule required for legitimate/normal traffic"

            results.append(
                {
                    "Source IP": src_ip,
                    "Destination IP": dst_ips_str,
                    "Total Packets": len(full),
                    "Unique Ports": unique_ports,
                    "Unique Hosts": unique_hosts,
                    "Avg Interval (s)": round(avg_interval, 2),
                    "Conn Freq (/min)": conn_freq,
                    "First Activity": group["datetime"].min().strftime("%Y-%m-%d %H:%M:%S"),
                    "Last Activity": group["datetime"].max().strftime("%Y-%m-%d %H:%M:%S"),
                    "Duration (min)": round(duration_sec / 60.0, 2),
                    "Detection Type": detection_type,
                    "Risk Score": risk_score,
                    "Risk Level": risk_level,
                    "Evidence": evidence_str,
                    "Mitigation Action": mitigation_action,
                    "Firewall Command": firewall_cmd,
                }
            )

        df_res = pd.DataFrame(results).sort_values(by="Risk Score", ascending=False).reset_index(drop=True)
        if save_history and not df_res.empty:
            self._save_to_sqlite(df_res)
        return df_res

    def _save_to_sqlite(self, df_res: pd.DataFrame):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for _, r in df_res.iterrows():
            if r["Risk Level"] not in ["High", "Medium"]:
                continue
            key = (r["Source IP"], r["Destination IP"], r["Detection Type"], int(r["Risk Score"]), r["Evidence"])
            dup = cursor.execute(
                "SELECT 1 FROM detection_history WHERE src_ip=? AND dst_ip=? AND detection_type=? "
                "AND risk_score=? AND evidence=? LIMIT 1",
                key,
            ).fetchone()
            if dup:
                continue
            cursor.execute(
                """
                INSERT INTO detection_history
                (analyzed_at, src_ip, dst_ip, unique_ports, detection_type, risk_score, risk_level, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now_str, r["Source IP"], r["Destination IP"], int(r["Unique Ports"]),
                 r["Detection Type"], int(r["Risk Score"]), r["Risk Level"], r["Evidence"]),
            )
        conn.commit()
        conn.close()

    def get_history(self) -> pd.DataFrame:
        if not os.path.exists(self.db_path):
            return pd.DataFrame()
        conn = sqlite3.connect(self.db_path)
        df_hist = pd.read_sql_query("SELECT * FROM detection_history ORDER BY id DESC LIMIT 20", conn)
        conn.close()
        return df_hist
