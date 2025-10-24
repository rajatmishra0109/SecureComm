import streamlit as st
import time
from get_arp_table import get_arp_table

# ==============================
# 🌐 Page Configuration
# ==============================
st.set_page_config(
    page_title="SecureComm - ARP Monitor",
    page_icon="🛡️",
    layout="wide",
)

# ==============================
# 🎨 Custom CSS Styling
# ==============================
st.markdown(
    """
    <style>
    /* Background gradient */
    .stApp {
        background: linear-gradient(135deg, #0a192f, #172a45);
        color: #E6F1FF;
        font-family: 'Segoe UI', sans-serif;
    }

    /* Title style */
    .main-title {
        font-size: 3rem;
        font-weight: 700;
        color: #64ffda;
        text-align: center;
        margin-top: -10px;
    }

    /* Subtitle style */
    .sub-title {
        text-align: center;
        font-size: 1.2rem;
        color: #8892b0;
        margin-bottom: 30px;
    }

    /* Button styling */
    div.stButton > button {
        background-color: #64ffda;
        color: #0a192f;
        font-weight: 600;
        border-radius: 8px;
        height: 3em;
        width: 100%;
        border: none;
        transition: 0.3s;
    }

    div.stButton > button:hover {
        background-color: #52e0c4;
        transform: scale(1.02);
    }

    /* Table style */
    table {
        border-collapse: collapse;
        width: 100%;
        color: #E6F1FF !important;
    }

    th {
        background-color: #112240 !important;
        color: #64ffda !important;
        font-weight: bold;
    }

    td {
        background-color: #0a192f !important;
    }

    /* Log text box */
    .change-log {
        background-color: #112240;
        border-radius: 10px;
        padding: 15px;
        font-size: 0.95rem;
        color: #E6F1FF;
        margin-top: 10px;
        white-space: pre-wrap;
        font-family: monospace;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ==============================
# 🧱 App Header
# ==============================
st.markdown("<h1 class='main-title'>🛡️ SecureComm</h1>", unsafe_allow_html=True)
st.markdown("<h4 class='sub-title'>Protect your network from ARP spoofing</h4>", unsafe_allow_html=True)

# ==============================
# 🖧 App Body
# ==============================
arp_table_placeholder = st.empty()
changes_placeholder = st.empty()

if "running" not in st.session_state:
    st.session_state.running = False
if "previous_table" not in st.session_state:
    st.session_state.previous_table = []

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

# ==============================
# ⚙️ Helper Functions
# ==============================
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
        arp_table_placeholder.warning("⚠️ ARP table is empty or could not be fetched.")
        return
    df = {
        "IP Address": [e["ip"] for e in table],
        "MAC Address": [e["mac"] for e in table],
        "Interface": [e["iface"] for e in table],
        "State": [e["state"] for e in table],
    }
    arp_table_placeholder.table(df)

def display_changes(added, removed, changed):
    changes_text = ""
    if added:
        changes_text += "🟢 **Added:**\n"
        for ip, mac in added:
            changes_text += f"  {ip} → {mac}\n\n"

    if removed:
        changes_text += "🔴 **Removed:**\n"
        for ip, mac in removed:
            changes_text += f"  {ip} (was {mac})\n\n"

    if changed:
        changes_text += "🟡 **MAC Changed:**\n"
        for ip, old_mac, new_mac in changed:
            changes_text += f"  {ip}: {old_mac} → {new_mac}\n\n"

    if not (added or removed or changed):
        changes_text = "No change detected."

    changes_placeholder.markdown(f"<div class='change-log'>{changes_text}</div>", unsafe_allow_html=True)

# ==============================
# 🔄 Live Monitoring Loop
# ==============================
if st.session_state.running:
    st.info("🕵️ Monitoring ARP table for suspicious changes...")
    while st.session_state.running:
        try:
            current_table = get_arp_table()
            display_arp_table(current_table)
            added, removed, changed = arp_diff(st.session_state.previous_table, current_table)
            display_changes(added, removed, changed)
            st.session_state.previous_table = current_table
            time.sleep(10)
        except KeyboardInterrupt:
            st.warning("Monitoring stopped manually.")
            break
        except Exception as e:
            st.error(f"❌ Error: {e}")
            time.sleep(10)
