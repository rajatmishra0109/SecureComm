import streamlit as st
import subprocess
import pandas as pd
import re

# --- Page config ---
st.set_page_config(page_title="SECURECOMM", layout="wide")
st.markdown(
    "<h1 style='text-align: center; color: #1E90FF;'>🔒 SECURECOMM</h1>", 
    unsafe_allow_html=True
)
st.markdown(
    "<h3 style='text-align: center; color: gray;'>Secure your networks and devices from ARP spoofing</h3>", 
    unsafe_allow_html=True
)
st.markdown("---")

# --- Run ARP monitor once ---
def run_arp_monitor_once():
    """Run main.py once to get latest ARP table and differences."""
    try:
        result = subprocess.run(
            ["python3", "ArpExtractor/main.py", "--once"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e}"

# --- Parse latest ARP table ---
def parse_arp_table(output):
    """Extract the last ARP table from main.py output."""
    pattern = r"📋 Current ARP Table:\n(-{65})\n(.*?)(?:-{65})"
    matches = re.findall(pattern, output, re.DOTALL)
    if not matches:
        return None
    _, table_block = matches[-1]
    rows = []
    for line in table_block.strip().split("\n"):
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) == 4:
            rows.append(parts)
    if not rows:
        return None
    df = pd.DataFrame(rows, columns=["IP Address", "MAC Address", "Interface", "State"])
    return df

# --- Detect differences and alert ---
def detect_differences(output):
    alert_lines = []
    if "Added" in output:
        alert_lines.append("🟢 Added entries detected!")
    if "Removed" in output:
        alert_lines.append("🔴 Removed entries detected!")
    if "MAC Changed" in output:
        alert_lines.append("🟡 MAC address changes detected!")
    if not "Added" and not "Removed" and not"MAC Changed":
        alert_lines.append("😎 No change detected!")
    return alert_lines

# --- Button UI ---
st.markdown("<h4 style='text-align: center;'>Device Check</h4>", unsafe_allow_html=True)
if st.button("🖥️ Check Your Device", use_container_width=True):
    with st.spinner("Fetching ARP table..."):
        output = run_arp_monitor_once()
        st.code(output, language="bash")  # show raw output

        # Show parsed table
        df = parse_arp_table(output)
        if df is not None:
            st.markdown("### 📋 Latest ARP Table")
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("No ARP table found.")

        # Show alerts for differences
        alerts = detect_differences(output)
        for alert in alerts:
            st.error(f"⚠️ {alert}")

# --- Footer / network check button placeholder ---
st.markdown("---")
col1, col2 = st.columns(2)
with col1:
    st.button("🌐 Check Your Network (coming soon)", disabled=True)
with col2:
    st.markdown("<p style='text-align:right; color: gray;'>SECURECOMM © 2025</p>", unsafe_allow_html=True)
