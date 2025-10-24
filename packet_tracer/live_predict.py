#!/usr/bin/env python3
"""
live_predict.py

Load trained model and perform live predictions.

Modes:
  - Live sniffing (requires scapy + root): sudo python3 live_predict.py --iface en0
  - Predict from features CSV:         python3 live_predict.py --from-csv --csv data/features.csv
  - Simulation (no root, no scapy):    python3 live_predict.py --simulate --sim-seconds 20

Behavior:
  - Maintains ip_map: ip -> list of {"mac":..., "ts":...} (rolling window)
  - On each ARP observation, computes features and calls model.predict / predict_proba (if model exists)
  - ALWAYS prints an explicit WARNING line when distinct_mac_count > 1
"""

import os
import sys
import time
import argparse
from collections import Counter
import random

import pandas as pd
from joblib import load
from securecomm.utils import ensure_dirs

# ensure project directories exist
ensure_dirs()

MODEL_PATH = "models/mitm_detector.joblib"
FEATURE_CSV = "data/features.csv"

# --- Prefer user-owned scapy cache directory to avoid permission issues on macOS ---
# Set SCAPY_CACHE_DIR to a folder we can create in the user's home
scapy_cache = os.path.expanduser("~/scapy_cache")
os.environ.setdefault("SCAPY_CACHE_DIR", scapy_cache)
try:
    os.makedirs(scapy_cache, exist_ok=True)
    os.chmod(scapy_cache, 0o700)
except Exception:
    # ignore; we'll try import anyway and handle errors
    pass

# --- Try importing scapy safely ---
SCAPY_AVAILABLE = False
sniff = None
ARP = None
try:
    from scapy.all import sniff, ARP  # type: ignore
    SCAPY_AVAILABLE = True
    print(f"[+] Scapy imported (cache: {os.environ.get('SCAPY_CACHE_DIR')})", flush=True)
except PermissionError as e:
    SCAPY_AVAILABLE = False
    print(f"[!] Scapy PermissionError: {e}", flush=True)
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"[!] Scapy not available: {e}", flush=True)

# --- Load trained model if present ---
MODEL = None
if os.path.exists(MODEL_PATH):
    try:
        MODEL = load(MODEL_PATH)
        print(f"[+] Model loaded from {MODEL_PATH}", flush=True)
    except Exception as e:
        MODEL = None
        print(f"[!] Failed to load model: {e}", flush=True)
else:
    print("[!] No model found. Train first with train_model.py to create models/mitm_detector.joblib", flush=True)

# In-memory IP map: ip -> list of {"mac":..., "ts":...}
ip_map = {}

# -------------------------
# Helper functions
# -------------------------
def aggregate_features_for_ip(ip):
    """Return feature dict for an IP using current ip_map window."""
    recs = ip_map.get(ip, [])
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
    """Return (prediction_dict_or_None, feature_dict)."""
    feat = aggregate_features_for_ip(ip)
    X = pd.DataFrame([feat])
    if MODEL is None:
        return None, feat
    prob = None
    pred = None
    try:
        if hasattr(MODEL, "predict_proba"):
            prob = MODEL.predict_proba(X)[0][1]
    except Exception:
        prob = None
    try:
        pred = MODEL.predict(X)[0]
    except Exception:
        pred = None
    return {"prob": float(prob) if prob is not None else None, "pred": int(pred) if pred is not None else None}, feat

# -------------------------
# Packet handler (Scapy)
# -------------------------
def pkt_handler(pkt):
    """Scapy packet callback: update ip_map, compute features, print prediction and warnings."""
    try:
        if not SCAPY_AVAILABLE:
            return
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ts = time.time()
            # store record
            ip_map.setdefault(ip, []).append({"mac": mac, "ts": ts})
            # keep only last 200 entries for this IP
            ip_map[ip] = ip_map[ip][-200:]

            pr, feat = predict_ip(ip)

            # Warn whenever distinct_mac_count > 1
            if feat["distinct_mac_count"] > 1:
                print(f"[!] WARNING: IP {ip} has {feat['distinct_mac_count']} distinct MACs -> {feat}", flush=True)

            # Standard output line (consistent format)
            if pr is not None:
                print(f"[{ip}] feat={feat} -> pred={pr}", flush=True)
            else:
                print(f"[{ip}] feat={feat} (no model)", flush=True)
    except Exception as e:
        print(f"[!] pkt_handler error: {e}", flush=True)

# -------------------------
# CSV prediction
# -------------------------
def predict_from_csv(csv_path=FEATURE_CSV, show_summary=True):
    """Load features CSV and run model predictions (prints results)."""
    if not os.path.exists(csv_path):
        print(f"[!] Feature CSV {csv_path} not found.", flush=True)
        return

    df = pd.read_csv(csv_path)
    if df.empty:
        print("[!] Feature CSV is empty.", flush=True)
        return

    for col in ["total_claims", "distinct_mac_count", "top_mac_ratio"]:
        if col not in df.columns:
            print(f"[!] Missing column '{col}' in {csv_path}. Cannot predict.", flush=True)
            return

    if MODEL is None:
        print("[!] No trained model available. Please run train_model.py first.", flush=True)
        return

    X = df[["total_claims", "distinct_mac_count", "top_mac_ratio"]].fillna(0)
    y_true = df["is_spoof"].astype(int) if "is_spoof" in df.columns else None

    try:
        preds = MODEL.predict(X)
    except Exception as e:
        print(f"[!] Model prediction failed: {e}", flush=True)
        return

    probs = None
    if hasattr(MODEL, "predict_proba"):
        try:
            probs = MODEL.predict_proba(X)[:, 1]
        except Exception:
            probs = None

    for i, row in df.iterrows():
        ip_label = row.get("ip", f"row-{i}")
        feat_dict = row[["total_claims", "distinct_mac_count", "top_mac_ratio"]].to_dict()
        pred = int(preds[i]) if preds is not None else None
        prob = float(probs[i]) if (probs is not None) else None

        # Print a warning line if distinct_mac_count > 1
        if feat_dict.get("distinct_mac_count", 0) > 1:
            print(f"[!] WARNING (CSV): IP {ip_label} has {feat_dict['distinct_mac_count']} distinct MACs -> {feat_dict}", flush=True)

        print(f"[{ip_label}] feat={feat_dict} -> pred={pred}, prob={prob}", flush=True)

    if show_summary and y_true is not None:
        try:
            from sklearn.metrics import classification_report, accuracy_score
            print("\n=== Evaluation on provided labels ===", flush=True)
            print("Accuracy:", accuracy_score(y_true, preds), flush=True)
            print(classification_report(y_true, preds), flush=True)
        except Exception as e:
            print(f"[!] Could not compute evaluation: {e}", flush=True)

# -------------------------
# Simulation (for debugging without root/scapy)
# -------------------------
def simulate(run_seconds=20, interval=1.0):
    """Generate synthetic ARP observations and call predict logic to exercise printing and warnings."""
    ips = [f"192.168.1.{i}" for i in range(2, 50)]
    print(f"[~] Simulation mode: running for {run_seconds}s (interval={interval}s)", flush=True)
    start = time.time()
    while time.time() - start < run_seconds:
        ip = random.choice(ips)
        # make spoof events occasional
        if random.random() < 0.2:
            mac = f"AA:BB:CC:DD:EE:{random.randint(0,255):02x}"
        else:
            mac = "AA:BB:CC:DD:EE:01"
        ts = time.time()
        ip_map.setdefault(ip, []).append({"mac": mac, "ts": ts})
        ip_map[ip] = ip_map[ip][-200:]
        pr, feat = predict_ip(ip)

        # Warning on distinct_mac_count > 1
        if feat["distinct_mac_count"] > 1:
            print(f"[!] WARNING (simulate): IP {ip} has {feat['distinct_mac_count']} distinct MACs -> {feat}", flush=True)

        if pr is not None:
            print(f"[{ip}] feat={feat} -> pred={pr}", flush=True)
        else:
            print(f"[{ip}] feat={feat} (no model)", flush=True)

        time.sleep(interval)
    print("[~] Simulation finished", flush=True)

# -------------------------
# Main
# -------------------------
def main(iface=None, timeout=None, from_csv=False, csv_path=FEATURE_CSV, simulate_mode=False, sim_seconds=20):
    if from_csv:
        predict_from_csv(csv_path=csv_path)
        return

    if simulate_mode:
        simulate(run_seconds=sim_seconds, interval=1.0)
        return

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not available or could not be imported. Live sniffing is disabled.", flush=True)
        print("    Use --simulate to test without scapy.", flush=True)
        return

    print(f"[+] Starting live ARP sniffing on iface='{iface}' (timeout={timeout})", flush=True)
    try:
        sniff(filter="arp", prn=pkt_handler, store=0, iface=iface, timeout=timeout)
    except PermissionError:
        print("[!] Permission denied to sniff on this interface. Try running with sudo.", flush=True)
    except Exception as e:
        print(f"[!] Sniffing error: {e}", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live prediction for ARP spoof detection")
    parser.add_argument("--iface", type=str, help="Network interface to sniff (e.g. en0)")
    parser.add_argument("--timeout", type=int, help="Sniff duration in seconds (optional)", default=None)
    parser.add_argument("--from-csv", action="store_true", help="Predict using pre-extracted CSV instead of live sniffing")
    parser.add_argument("--csv", type=str, help="Path to features CSV (default: data/features.csv)", default=FEATURE_CSV)
    parser.add_argument("--simulate", action="store_true", help="Run in simulation mode (no scapy/native sniff required)")
    parser.add_argument("--sim-seconds", type=int, default=20, help="Seconds to run simulate mode for")
    args = parser.parse_args()

    try:
        main(iface=args.iface, timeout=args.timeout, from_csv=args.from_csv, csv_path=args.csv,
             simulate_mode=args.simulate, sim_seconds=args.sim_seconds)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.", flush=True)
        sys.exit(0)
