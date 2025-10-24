import streamlit as st
import subprocess
import threading
import queue
import re
from datetime import datetime

st.set_page_config(
    page_title="Live ARP MITM Detector",
    page_icon="⚠️",
    layout="wide"
)

st.title("🕵️ Live ARP MITM Detection Dashboard")
st.markdown(
    "This app runs `live_predict.py` in background and displays live alerts "
    "when multiple MACs claim the same IP."
)

# --- Inputs ---
iface = st.text_input("Enter Network Interface (e.g., en0, eth0):", "en0")
start_btn = st.button("🚀 Start Detection")
stop_btn = st.button("🛑 Stop Detection")

# --- Thread-safe objects ---
output_queue = queue.Queue()
stop_event = threading.Event()  # replaces session_state.stop_flag
process = None

# Initialize Streamlit session_state
if "alerted_ips" not in st.session_state:
    st.session_state.alerted_ips = set()
if "log_lines" not in st.session_state:
    st.session_state.log_lines = []

# Regex to parse live_predict.py output
line_pattern = re.compile(
    r"\[(?P<ip>[\d\.]+)\]\s+feat=\{.*?'distinct_mac_count':\s*(?P<mac_count>\d+).*?\}\s*->"
)

# --- Thread function ---
def run_detector(iface, stop_event, output_queue):
    global process
    cmd = ["sudo", "python3", "live_predict.py", "--iface", iface]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    for line in process.stdout:
        if stop_event.is_set():
            break
        output_queue.put(line.strip())

    if process:
        process.terminate()
        process = None

# --- Start / Stop ---
if start_btn and (process is None or not process.poll() is None):
    stop_event.clear()
    threading.Thread(target=run_detector, args=(iface, stop_event, output_queue), daemon=True).start()
    st.success("✅ Started live detection...")

if stop_btn:
    stop_event.set()
    st.warning("🛑 Detection stopped.")

# --- Display containers ---
log_box = st.empty()
alert_box = st.empty()

# --- Update Streamlit display ---
def update_display():
    while not output_queue.empty():
        line = output_queue.get_nowait()
        if line:
            st.session_state.log_lines.append(line)
            # Keep last 50 lines
            if len(st.session_state.log_lines) > 50:
                st.session_state.log_lines = st.session_state.log_lines[-50:]

            # Parse for ARP spoof
            match = line_pattern.search(line)
            if match:
                ip = match.group("ip")
                mac_count = int(match.group("mac_count"))
                if mac_count > 1 and ip not in st.session_state.alerted_ips:
                    st.session_state.alerted_ips.add(ip)
                    alert_box.error(
                        f"⚠️ POSSIBLE ARP SPOOF DETECTED! IP `{ip}` has multiple MACs ({mac_count})"
                    )

    # Display last 5 log lines
    if st.session_state.log_lines:
        log_box.text("\n".join(st.session_state.log_lines[-5:]))

# --- Streamlit auto-refresh ---
update_display()
st.experimental_rerun()
