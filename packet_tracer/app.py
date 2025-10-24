import streamlit as st
import sys
from pathlib import Path
import time
import pandas as pd
from datetime import datetime

# Add project root to Python path
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

# Add the securecomm package directory to path
SECURECOMM_DIR = BASE_DIR / "packet_tracer" / "securecomm"
if SECURECOMM_DIR.exists():
    sys.path.insert(0, str(SECURECOMM_DIR.parent))

# Try importing live_predict
try:
    # Import relative to current directory
    from live_predict import live_predict
except ImportError:
    try:
        # Import from packet_tracer package
        from packet_tracer.live_predict import live_predict
    except ImportError:
        try:
            # Last resort: direct import after adding current dir to path
            sys.path.insert(0, str(Path(__file__).parent))
            from live_predict import live_predict
        except ImportError as e:
            st.error(f"❌ Could not import live_predict module: {str(e)}")
            st.error("Please ensure you're running from the correct directory with the virtual environment activated")
            st.info("Run these commands in the terminal:")
            st.code("""
cd "/Users/shashank/Desktop/project 2/SecureComm"
source securecomm_env/Scripts/activate  # On Windows use: .\\securecomm_env\\Scripts\\activate
pip install -e .
streamlit run packet_tracer/app.py
            """)
            st.stop()

# Page config
st.set_page_config(
    page_title="Network Monitor",
    page_icon="🔒",
    layout="wide",
)

# Custom CSS
st.markdown("""
    <style>
    .main-title {
        color: #00ff88;
        font-size: 3em;
        font-weight: 700;
        text-align: center;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        margin-bottom: 1em;
    }
    
    .stApp {
        background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
    }
    
    .status-card {
        background: rgba(255,255,255,0.05);
        padding: 20px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    .alert-box {
        background: rgba(255,0,0,0.1);
        border: 2px solid #ff4444;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(255,0,0,0.4); }
        70% { box-shadow: 0 0 0 10px rgba(255,0,0,0); }
        100% { box-shadow: 0 0 0 0 rgba(255,0,0,0); }
    }
    
    .metric-card {
        background: rgba(0,255,136,0.05);
        padding: 15px;
        border-radius: 8px;
        border: 1px solid rgba(0,255,136,0.2);
        margin: 5px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown("<h1 class='main-title'>🔒 Network Security Monitor</h1>", unsafe_allow_html=True)

# Initialize session state
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'total_packets' not in st.session_state:
    st.session_state.total_packets = 0

# Control columns
col1, col2, col3 = st.columns([1,1,1])

with col1:
    if not st.session_state.monitoring:
        if st.button("▶️ Start Monitoring", use_container_width=True):
            st.session_state.monitoring = True
            st.experimental_rerun()
    else:
        if st.button("⏹️ Stop Monitoring", use_container_width=True):
            st.session_state.monitoring = False
            st.experimental_rerun()

with col2:
    if st.button("🗑️ Clear Alerts", use_container_width=True):
        st.session_state.alerts = []

# Status indicator
with col3:
    if st.session_state.monitoring:
        st.markdown("<div class='status-card'><h3>📡 Status: <span style='color:#00ff88'>ACTIVE</span></h3></div>", 
                   unsafe_allow_html=True)
    else:
        st.markdown("<div class='status-card'><h3>📡 Status: <span style='color:#ff4444'>STOPPED</span></h3></div>", 
                   unsafe_allow_html=True)

# Create placeholders for live updates
metrics_placeholder = st.empty()
alert_placeholder = st.empty()
table_placeholder = st.empty()

if st.session_state.monitoring:
    try:
        predictor = live_predict()
        
        while st.session_state.monitoring:
            try:
                # Get next prediction
                prediction = next(predictor)
                st.session_state.total_packets += 1
                
                # Update metrics
                with metrics_placeholder.container():
                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.markdown("""
                            <div class='metric-card'>
                                <h4>Total Packets</h4>
                                <h2>{}</h2>
                            </div>
                        """.format(st.session_state.total_packets), unsafe_allow_html=True)
                    with m2:
                        st.markdown("""
                            <div class='metric-card'>
                                <h4>Alerts</h4>
                                <h2>{}</h2>
                            </div>
                        """.format(len(st.session_state.alerts)), unsafe_allow_html=True)
                    with m3:
                        st.markdown("""
                            <div class='metric-card'>
                                <h4>Last Update</h4>
                                <h2>{}</h2>
                            </div>
                        """.format(datetime.now().strftime("%H:%M:%S")), unsafe_allow_html=True)

                # Check for anomalies/spoofing
                if isinstance(prediction, dict):
                    mac_count = prediction.get('distinct_mac_count', 0)
                    if mac_count > 1:
                        alert = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'ARP Spoofing Detected',
                            'details': f'Multiple MACs ({mac_count}) detected for same IP'
                        }
                        st.session_state.alerts.insert(0, alert)

                # Display alerts
                with alert_placeholder.container():
                    for alert in st.session_state.alerts[:5]:  # Show last 5 alerts
                        st.markdown(f"""
                            <div class='alert-box'>
                                <h3>⚠️ {alert['type']}</h3>
                                <p>🕒 {alert['timestamp']}</p>
                                <p>{alert['details']}</p>
                            </div>
                        """, unsafe_allow_html=True)

                # Display current packet data
                if isinstance(prediction, dict):
                    df = pd.DataFrame([prediction])
                    table_placeholder.dataframe(df, use_container_width=True)

                time.sleep(1)  # Prevent overwhelming the UI
                
            except StopIteration:
                st.warning("🔄 Prediction stream ended. Restarting...")
                predictor = live_predict()
                
    except Exception as e:
        st.error(f"❌ Error during monitoring: {str(e)}")
        st.session_state.monitoring = False

else:
    st.info("👆 Click 'Start Monitoring' to begin network surveillance")