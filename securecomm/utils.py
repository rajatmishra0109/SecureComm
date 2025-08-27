# utils.py - shared utilities

import ipaddress
from datetime import datetime
import os
import pandas as pd

def is_private_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False

def now_iso():
    return datetime.utcnow().isoformat()

def ensure_dirs():
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)

def load_raw(path="data/arp_log.csv"):
    if not os.path.exists(path):
        return pd.DataFrame(columns=["timestamp","ip","mac","iface","note","is_spoof"])
    return pd.read_csv(path, parse_dates=["timestamp"])

def check_model_exists():
    return os.path.exists("models/mitm_detector.joblib")
