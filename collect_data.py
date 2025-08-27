"""
collect_data.py
Sniff ARP packets and append to data/arp_log.csv.
Run this with admin/root privileges:
    sudo python securecomm/collect_data.py --iface eth0 --duration 60
"""

import argparse
import csv
import os
from scapy.all import sniff, ARP
from securecomm.utils import now_iso, ensure_dirs

CSV_PATH = "data/arp_log.csv"
ensure_dirs()

def write_row(row):
    header = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(["timestamp","ip","mac","iface","note","is_spoof"])
        writer.writerow(row)

def pkt_handler(pkt, iface):
    try:
        if pkt.haslayer(ARP):
            ts = now_iso()
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            # note: default is_spoof = 0 (unknown)
            write_row([ts, ip, mac, iface or "", "", 0])
    except Exception as e:
        # ignore parse errors
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default=None, help="Network interface to sniff (e.g., eth0)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds to sniff")
    args = parser.parse_args()

    print(f"[+] Appending ARP records to {CSV_PATH} for {args.duration}s on iface={args.iface}")
    sniff(prn=lambda p: pkt_handler(p, args.iface), filter="arp", store=0, timeout=args.duration, iface=args.iface)
    print("[+] Done sniffing. You can label or inspect data/arp_log.csv")

if __name__ == "__main__":
    main()
