#!/usr/bin/env python3
"""
get_arp_table.py
Extract ARP table entries on Linux and macOS (and other Unix-like OSes).
No external dependencies.
"""

import re
import subprocess
import sys
import csv
from typing import List, Dict, Optional

def parse_proc_net_arp() -> List[Dict]:
    """Parse /proc/net/arp (Linux)."""
    out = []
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.read().strip().splitlines()
    except Exception:
        return out

    if len(lines) < 2:
        return out

    # header: IP address       HW type     Flags       HW address            Mask     Device
    for line in lines[1:]:
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 6:
            ip, hw_type, flags, hw_addr, mask, dev = parts[:6]
            state = "incomplete" if hw_addr == "00:00:00:00:00:00" else "reachable"
            out.append({"ip": ip, "mac": hw_addr, "iface": dev, "state": state})
    return out

def parse_ip_neigh(raw: str) -> List[Dict]:
    """
    Parse 'ip neigh' output formats. Examples:
    192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
    192.168.1.5 dev wlan0 INCOMPLETE
    """
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # try to capture ip, dev (<iface>), optional lladdr (mac), and state at end
        m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-f:]{17}))?.*?(\bREACHABLE\b|\bSTALE\b|\bDELAY\b|\bINCOMPLETE\b|\bFAILED\b|\bPERMANENT\b)?', line, re.IGNORECASE)
        if m:
            ip, dev, mac, state = m.groups()
            mac = mac if mac else ("<incomplete>" if (state and state.upper()=="INCOMPLETE") else None)
            out.append({"ip": ip, "mac": mac or "", "iface": dev, "state": (state or "").lower()})
    return out

def parse_arp_a(raw: str) -> List[Dict]:
    """
    Parse 'arp -a' style output.
    Example lines (macOS/BSD):
    ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
    ? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
    """
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # ip in parentheses
        m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:()incomplete]+)\s+on\s+(\S+)', line, re.IGNORECASE)
        if m:
            ip, mac, dev = m.groups()
            mac = mac.strip()
            state = "incomplete" if "incomplete" in mac else "reachable"
            # normalize mac: remove parentheses if present
            mac = "" if mac in ("(incomplete)", "incomplete") else mac
            out.append({"ip": ip, "mac": mac, "iface": dev, "state": state})
    return out

def run_cmd(cmd: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        return p.stdout
    except Exception:
        return None

def get_arp_table() -> List[Dict]:
    # 1) Try /proc/net/arp (Linux)
    entries = parse_proc_net_arp()
    if entries:
        return entries

    # 2) Try 'ip neigh' (Linux)
    out = run_cmd(["ip", "neigh"])
    if out:
        entries = parse_ip_neigh(out)
        if entries:
            return entries

    # 3) Try 'arp -a' (macOS / BSD / fallback)
    out = run_cmd(["arp", "-a"])
    if out:
        entries = parse_arp_a(out)
        if entries:
            return entries

    # nothing found
    return []

def print_table(entries: List[Dict]):
    if not entries:
        print("No ARP entries found.")
        return
    print(f"{'IP':16}  {'MAC':20}  {'IFACE':8}  {'STATE'}")
    print("-"*60)
    for e in entries:
        print(f"{e['ip']:16}  {e['mac']:20}  {e['iface']:8}  {e['state']}")

def save_csv(entries: List[Dict], path: str):
    fieldnames = ["ip", "mac", "iface", "state"]
    with open(path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            writer.writerow(e)
    print(f"Saved {len(entries)} entries to {path}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract ARP table (Linux/macOS).")
    parser.add_argument("--csv", "-c", help="Save output to CSV file")
    parser.add_argument("--monitor", "-m", action="store_true", help="Continuously monitor (prints every 2s)")
    parser.add_argument("--interval", "-i", type=float, default=2.0, help="Monitor interval in seconds (default 2)")
    args = parser.parse_args()

    if args.monitor:
        try:
            import time
            last = None
            while True:
                entries = get_arp_table()
                # simple change detection
                if entries != last:
                    print("\n[ARP TABLE] (updated)")
                    print_table(entries)
                    last = entries
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped monitoring.")
            sys.exit(0)
    else:
        entries = get_arp_table()
        print_table(entries)
        if args.csv:
            save_csv(entries, args.csv)

if __name__ == "__main__":
    main()
