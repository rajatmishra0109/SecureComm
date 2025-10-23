#!/usr/bin/env python3
"""
main.py
Periodically fetches and prints the ARP table every 10 seconds.
Also compares with the previous snapshot to detect IP→MAC changes.
"""

import time
from get_arp_table import get_arp_table

def arp_diff(old, new):
    """Compare two ARP tables and return differences."""
    old_map = {entry["ip"]: entry["mac"] for entry in old}
    new_map = {entry["ip"]: entry["mac"] for entry in new}

    added, removed, changed = [], [], []

    for ip, mac in new_map.items():
        if ip not in old_map:
            added.append((ip, mac))
        elif old_map[ip] != mac:
            changed.append((ip, old_map[ip], mac))

    for ip, mac in old_map.items():
        if ip not in new_map:
            removed.append((ip, mac))

    return added, removed, changed


def print_arp_table(table):
    """Neatly print the current ARP table."""
    if not table:
        print("[!] ARP table is empty.")
        return

    print("\n📋 Current ARP Table:")
    print(f"{'IP Address':<20} {'MAC Address':<20} {'Interface':<10} {'State':<10}")
    print("-" * 65)
    for entry in table:
        print(f"{entry['ip']:<20} {entry['mac']:<20} {entry['iface']:<10} {entry['state']:<10}")
    print("-" * 65)


def print_differences(added, removed, changed):
    """Show added, removed, or changed entries."""
    if not added and not removed and not changed:
        print("[No change detected]\n")
        return

    print("\n=== ARP Table Changes Detected ===")

    if added:
        print("\n🟢 Added:")
        for ip, mac in added:
            print(f"  {ip} → {mac}")

    if removed:
        print("\n🔴 Removed:")
        for ip, mac in removed:
            print(f"  {ip} (was {mac})")

    if changed:
        print("\n🟡 MAC Changed:")
        for ip, old_mac, new_mac in changed:
            print(f"  {ip}: {old_mac} → {new_mac}")

    print("==================================\n")


def main():
    print("🚀 Starting ARP monitor (refresh every 10s)...\n")
    previous_table = []

    while True:
        try:
            current_table = get_arp_table()
            print_arp_table(current_table)

            added, removed, changed = arp_diff(previous_table, current_table)
            print_differences(added, removed, changed)

            previous_table = current_table
            time.sleep(10)

        except KeyboardInterrupt:
            print("\n🛑 Stopping ARP monitor.")
            break
        except Exception as e:
            print(f"[Error] {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
