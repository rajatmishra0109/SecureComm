"""
live_predict.py
Load trained model and perform live predictions based on rolling features.
It demonstrates a mapping from current ip_mac_map into feature vector and prints probability.
"""

import time
from scapy.all import sniff, ARP
from joblib import load
import pandas as pd
from securecomm.utils import ensure_dirs
import os

ensure_dirs()
MODEL_PATH = "models/mitm_detector.joblib"

# Simple in-memory map: ip -> list of macs & timestamps
ip_map = {}

# Load model if exists
MODEL = None
if os.path.exists(MODEL_PATH):
    MODEL = load(MODEL_PATH)
    print("[+] Model loaded.")
else:
    print("[!] No model found. Train first with train_model.py")

def aggregate_features_for_ip(ip):
    recs = ip_map.get(ip, [])
    total_claims = len(recs)
    distinct_mac_count = len(set(r["mac"] for r in recs))
    # ratio of top mac frequency
    if total_claims == 0:
        top_ratio = 1.0
    else:
        from collections import Counter
        top_count = Counter(r["mac"] for r in recs).most_common(1)[0][1]
        top_ratio = top_count / total_claims
    return {"total_claims": total_claims, "distinct_mac_count": distinct_mac_count, "top_mac_ratio": top_ratio}

def predict_ip(ip):
    feat = aggregate_features_for_ip(ip)
    X = pd.DataFrame([feat])
    if MODEL is None:
        return None, feat
    prob = MODEL.predict_proba(X)[0][1] if hasattr(MODEL, "predict_proba") else MODEL.predict(X)[0]
    pred = MODEL.predict(X)[0]
    return {"prob": float(prob), "pred": int(pred)}, feat

def pkt_handler(pkt):
    try:
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ts = time.time()
            ip_map.setdefault(ip, []).append({"mac": mac, "ts": ts})
            # keep only last N records per IP (rolling window)
            ip_map[ip] = ip_map[ip][-200:]
            pr, feat = predict_ip(ip)
            if pr is not None:
                print(f"[{ip}] feat={feat} -> pred={pr}")
            else:
                print(f"[{ip}] feat={feat} (no model)")
    except Exception as e:
        print("pkt_handler error:", e)

def main(iface=None, timeout=None):
    print("[+] Starting live_predict sniff")
    sniff(filter="arp", prn=pkt_handler, store=0, iface=iface, timeout=timeout)

if __name__ == "__main__":
    main()
