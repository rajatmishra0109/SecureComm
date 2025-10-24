#!/usr/bin/env python3
"""
live_predict.py
Load trained model and perform live predictions.
Supports both:
1. Using pre-extracted features CSV (--from-csv)
2. Live ARP sniffing (--iface, requires root on most OSes)
"""

import time
import os
from collections import Counter
import argparse
import pathlib
import sys

import pandas as pd
from joblib import load
from securecomm.utils import ensure_dirs

ensure_dirs()
MODEL_PATH = "models/mitm_detector.joblib"
FEATURE_CSV = "data/features.csv"

# Try to import scapy, handle permission error when scapy tries to cache /etc/services
SCAPY_AVAILABLE = False
sniff = None
ARP = None
try:
    from scapy.all import sniff, ARP  # type: ignore
    SCAPY_AVAILABLE = True
except PermissionError as e:
    # Common on macOS: scapy can't write to ~/.cache/scapy/services
    cache_dir = os.path.expanduser("~/.cache/scapy")
    try:
        os.makedirs(cache_dir, exist_ok=True)
        os.chmod(cache_dir, 0o700)
        # retry import
        from scapy.all import sniff, ARP  # type: ignore
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False
        print(f"[!] Scapy import failed with PermissionError and retry failed: {e}")
except Exception as e:
    # Scapy not available — ok for CSV-only mode
    SCAPY_AVAILABLE = False
    # don't print full stack; just warn
    print(f"[!] Scapy not available: {e}")

# Global in-memory map for live ARP tracking: ip -> list of macs & timestamps
ip_map = {}

# Load trained model if exists
MODEL = None
if os.path.exists(MODEL_PATH):
    try:
        MODEL = load(MODEL_PATH)
        print(f"[+] Model loaded from {MODEL_PATH}")
    except Exception as e:
        MODEL = None
        print(f"[!] Failed to load model: {e}")
else:
    print("[!] No model found. Train first with train_model.py (or run train_model to create models/mitm_detector.joblib)")

# ---------------------
# Helper Functions
# ---------------------

def aggregate_features_for_ip(ip):
    recs = ip_map.get(ip, [])  # list of {"mac":..., "ts":...}
    total_claims = len(recs)
    distinct_mac_count = len(set(r["mac"] for r in recs))
    top_ratio = 1.0
    if total_claims > 0:
        top_count = Counter(r["mac"] for r in recs).most_common(1)[0][1]
        top_ratio = top_count / total_claims
    return {
        "total_claims": total_claims,
        "distinct_mac_count": distinct_mac_count,
        "top_mac_ratio": top_ratio
    }

def predict_ip(ip):
    feat = aggregate_features_for_ip(ip)
    X = pd.DataFrame([feat])
    if MODEL is None:
        return None, feat
    try:
        prob = MODEL.predict_proba(X)[0][1] if hasattr(MODEL, "predict_proba") else None
    except Exception:
        prob = None
    try:
        pred = MODEL.predict(X)[0]
    except Exception:
        pred = None
    return {"prob": float(prob) if prob is not None else None, "pred": int(pred) if pred is not None else None}, feat

def pkt_handler(pkt):
    try:
        if not SCAPY_AVAILABLE:
            return
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ts = time.time()
            ip_map.setdefault(ip, []).append({"mac": mac, "ts": ts})
            # rolling window: keep only last 200 records per IP
            ip_map[ip] = ip_map[ip][-200:]

            pr, feat = predict_ip(ip)
            if pr is not None:
                print(f"[{ip}] feat={feat} -> pred={pr}")
            else:
                print(f"[{ip}] feat={feat} (no model)")
    except Exception as e:
        print("pkt_handler error:", e)

# ---------------------
# Predict from CSV (pre-extracted features)
# ---------------------
def predict_from_csv(csv_path=FEATURE_CSV, show_summary=True):
    if not os.path.exists(csv_path):
        print(f"[!] Feature CSV {csv_path} not found.")
        return

    df = pd.read_csv(csv_path)
    if df.empty:
        print("[!] Feature CSV is empty.")
        return

    # Ensure required columns
    for col in ["total_claims", "distinct_mac_count", "top_mac_ratio"]:
        if col not in df.columns:
            print(f"[!] Missing column '{col}' in {csv_path}. Cannot predict.")
            return

    X = df[["total_claims", "distinct_mac_count", "top_mac_ratio"]].fillna(0)
    y_true = df["is_spoof"].astype(int) if "is_spoof" in df.columns else None

    if MODEL is None:
        print("[!] No trained model available. Please run train_model.py first.")
        return

    try:
        preds = MODEL.predict(X)
    except Exception as e:
        print(f"[!] Model prediction failed: {e}")
        return

    probs = None
    if hasattr(MODEL, "predict_proba"):
        try:
            probs = MODEL.predict_proba(X)[:, 1]
        except Exception:
            probs = None

    # Print results
    for i, row in df.iterrows():
        ip_label = row.get("ip", f"row-{i}")
        feat_dict = row[["total_claims", "distinct_mac_count", "top_mac_ratio"]].to_dict()
        pred = int(preds[i]) if preds is not None else None
        prob = float(probs[i]) if (probs is not None) else None
        print(f"[{ip_label}] feat={feat_dict} -> pred={pred}, prob={prob}")

    if show_summary and y_true is not None:
        from sklearn.metrics import classification_report, accuracy_score
        try:
            print("\n=== Evaluation on provided labels ===")
            print("Accuracy:", accuracy_score(y_true, preds))
            print(classification_report(y_true, preds))
        except Exception as e:
            print("[!] Could not compute evaluation:", e)

# ---------------------
# Main Function
# ---------------------
def main(iface=None, timeout=None, from_csv=False, csv_path=FEATURE_CSV):
    if from_csv:
        predict_from_csv(csv_path=csv_path)
        return

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not available or could not be imported. Live sniffing is disabled.")
        print("Use --from-csv to predict from pre-extracted features CSV.")
        return

    print("[+] Starting live ARP sniffing for predictions...")
    try:
        sniff(filter="arp", prn=pkt_handler, store=0, iface=iface, timeout=timeout)
    except PermissionError:
        print("[!] Permission denied to sniff on this interface. Try running with sudo.")
    except Exception as e:
        print(f"[!] Sniffing error: {e}")

# ---------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live prediction for ARP spoof detection")
    parser.add_argument("--iface", type=str, help="Network interface to sniff (e.g. en0)")
    parser.add_argument("--timeout", type=int, help="Sniff duration in seconds (optional)", default=None)
    parser.add_argument("--from-csv", action="store_true", help="Predict using pre-extracted CSV instead of live sniffing")
    parser.add_argument("--csv", type=str, help="Path to features CSV (default: data/features.csv)", default=FEATURE_CSV)
    args = parser.parse_args()

    try:
        main(iface=args.iface, timeout=args.timeout, from_csv=args.from_csv, csv_path=args.csv)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(0)
