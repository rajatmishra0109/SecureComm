"""
feature_extractor.py
Aggregate raw ARP logs into feature rows suitable for ML.
It creates data/features.csv with one row per (ip, window) or per ip summary.
"""

import pandas as pd
import numpy as np
from securecomm.utils import load_raw, ensure_dirs
import os

ensure_dirs()

RAW_CSV = "data/arp_log.csv"
OUT_F = "data/features.csv"

def build_features_per_ip(df):
    """
    Aggregates features per IP:
    - ip
    - first_seen (timestamp)
    - last_seen
    - total_claims (number of ARP packets claiming that IP)
    - distinct_mac_count
    - top_mac (most frequent)
    - top_mac_ratio (frequency ratio)
    - is_private (bool)
    NOTE: label 'is_spoof' set to 1 if >1 MAC claims same IP, 
          otherwise default to 0 (normal traffic).
    """
    rows = []
    grouped = df.groupby("ip")
    for ip, g in grouped:
        times = pd.to_datetime(g["timestamp"])
        macs = g["mac"].astype(str)

        top_mac = macs.mode().iloc[0] if not macs.mode().empty else ""
        mac_counts = macs.value_counts()
        top_ratio = mac_counts.iloc[0] / mac_counts.sum() if len(mac_counts) > 0 else 1.0
        distinct_mac_count = mac_counts.size
        total_claims = len(g)
        first_seen = times.min()
        last_seen = times.max()

        # 🚨 Spoof detection rule
        # If >1 MAC claims the same IP → likely spoofed
        if distinct_mac_count > 1:
            is_spoof_label = 1
        else:
            # Assign 0 if not spoofed
            is_spoof_label = 0

        rows.append({
            "ip": ip,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "total_claims": total_claims,
            "distinct_mac_count": distinct_mac_count,
            "top_mac": top_mac,
            "top_mac_ratio": top_ratio,
            "is_spoof": is_spoof_label
        })
    return pd.DataFrame(rows)

def main():
    if not os.path.exists(RAW_CSV):
        print(f"[!] Raw file {RAW_CSV} not found. Run collect_data.py first.")
        return
    df = load_raw(RAW_CSV)
    if df.empty:
        print("[!] No ARP records found.")
        return

    # ✅ Add default boolean column if not present
    if "is_spoof" not in df.columns:
        df["is_spoof"] = False  # Assign False to all collected entries (normal)

    feat = build_features_per_ip(df)
    feat.to_csv(OUT_F, index=False)
    print(f"[+] Features written to {OUT_F}. Rows: {len(feat)}")

if __name__ == "__main__":
    main()
