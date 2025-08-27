import streamlit as st
import threading
import time
import os
from train_model import train_model
from detector import start_detection, stop_detection
from securecomm.utils import check_model_exists

# --- Streamlit UI ---
st.set_page_config(
    page_title="SecureComm - ARP Spoofing Detection",
    page_icon="🛡",
    layout="wide"
)

st.markdown(
    """
    <style>
    .main {background-color: #f8f9fa;}
    .stTabs [data-baseweb="tab"] {font-size: 18px;}
    .stTabs [data-baseweb="tab"]:hover {color: #0072ff;}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🛡 SecureComm - ARP Spoofing Detection System")
st.markdown("#### Protect your network from Man-in-the-Middle (MITM) attacks using ARP spoofing detection.")

tab1, tab2, tab3 = st.tabs([
    "📦 Model Management",
    "🔍 Live Detection",
    "📜 Detection Logs"
])

with tab1:
    st.subheader("Model Status")
    if check_model_exists():
        st.success("✅ Model file found! Ready for detection.")
    else:
        st.warning("⚠ No model found. Please train the model first.")

    if st.button("🎯 Train Model"):
        with st.spinner("Training model... This may take a while"):
            train_model()
        st.success("Model trained and saved successfully!")

with tab2:
    st.subheader("Live Detection")
    detection_running = st.session_state.get("detection_running", False)

    col1, col2 = st.columns([1, 2])
    with col1:
        if not detection_running:
            if st.button("▶ Start Detection"):
                st.session_state.detection_running = True
                threading.Thread(target=start_detection, args=(st,), daemon=True).start()
        else:
            if st.button("⏹ Stop Detection"):
                stop_detection()
                st.session_state.detection_running = False
                st.info("Detection stopped.")

    with col2:
        st.info("Detection will monitor ARP packets and log suspicious activity in real time.")

with tab3:
    st.subheader("Detection Logs")
    log_placeholder = st.empty()

    log_path = "logs/detection_log.txt"
    if st.session_state.get("detection_running", False):
        st.info("Live logs updating every 2 seconds...")
        for _ in range(10):  # Show updates for 20 seconds
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    logs = f.read()
                log_placeholder.text_area("Detection Log", logs, height=300)
            else:
                log_placeholder.warning("No logs found yet.")
            time.sleep(2)
    else:
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                logs = f.read()
            st.text_area("Detection Log", logs, height=300)
        else:
            st.warning("No logs found yet.")

st.markdown("---")
st.caption("© 2025 SecureComm | Built with Streamlit")
