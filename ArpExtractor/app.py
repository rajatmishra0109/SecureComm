# app.py
import streamlit as st
import time
from get_arp_table import get_arp_table

st.set_page_config(page_title="SECURECOMM", page_icon="", layout="wide")
st.title("🛡️ SECURECOMM")
st.subheader("ARP Table Monitor")

# Placeholder for tables and logs
arp_table_placeholder = st.empty()
changes_placeholder = st.empty()

# Start/Stop buttons
if "running" not in st.session_state:
    st.session_state.running = False

def start_monitor():
    st.session_state.running = True

def stop_monitor():
    st.session_state.running = False

col1, col2 = st.columns([1, 1])
with col1:
    if st.button("🚀 Start Monitoring"):
        start_monitor()
with col2:
    if st.button("🛑 Stop Monitoring"):
        stop_monitor()

# Initialize previous table
if "previous_table" not in st.session_state:
    st.session_state.previous_table = []

def arp_diff(old, new):
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

def display_arp_table(table):
    if not table:
        arp_table_placeholder.write("[!] ARP table is empty.")
        return
    df = { "IP Address": [e["ip"] for e in table],
           "MAC Address": [e["mac"] for e in table],
           "Interface": [e["iface"] for e in table],
           "State": [e["state"] for e in table] }
    arp_table_placeholder.table(df)

def display_changes(added, removed, changed):
    changes_text = ""
    if added:
        changes_text += "🟢 **Added:**\n"
        for ip, mac in added:
            changes_text += f"  {ip} → {mac}\n"

    if removed:
        changes_text += "🔴 **Removed:**\n"
        for ip, mac in removed:
            changes_text += f"  {ip} (was {mac})\n"

    if changed:
        changes_text += "⚠️ **POSSIBLE ARP SPOOF DETECTED!**\n"
        for ip, old_mac, new_mac in changed:
            changes_text += f"  {ip}: {old_mac} → {new_mac}\n"

    if not (added or removed or changed):
        changes_text = "No change detected."

    changes_placeholder.text(changes_text)

# Monitoring loop
if st.session_state.running:
    while st.session_state.running:
        try:
            current_table = get_arp_table()
            display_arp_table(current_table)

            added, removed, changed = arp_diff(st.session_state.previous_table, current_table)
            display_changes(added, removed, changed)

            st.session_state.previous_table = current_table
            time.sleep(10)  # refresh interval
        except KeyboardInterrupt:
            st.warning("Monitoring stopped manually.")
            break
        except Exception as e:
            st.error(f"Error: {e}")
            time.sleep(10)