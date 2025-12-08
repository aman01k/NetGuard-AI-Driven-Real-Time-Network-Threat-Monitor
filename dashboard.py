import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from sniffer import start_sniffer_thread, packet_data # Import our backend
from sklearn.ensemble import IsolationForest

# PAGE CONFIG
st.set_page_config(
    page_title="NetGuard Traffic Monitor",
    page_icon="🛡️",
    layout="wide",
)

# TITLE
st.title("🛡️ NetGuard: Real-Time Network Threat Monitor")

# Initialize Sniffer (Only once)
if 'sniffer_active' not in st.session_state:
    st.session_state['sniffer_active'] = True
    start_sniffer_thread()
    st.success("Network Sniffer Started... Listening for traffic.")

# Placeholder for auto-refreshing data
placeholder = st.empty()

# AI MODEL CONFIG (Simple Anomaly Detection)
# We train a model on packet sizes to find "weird" sized packets
model = IsolationForest(contamination=0.01) # 1% of data is expected to be anomalies

# ... (Everything above 'while True' stays the same) ...

# Custom Color Palette for Protocols
proto_colors = {"TCP": "#00CC96", "UDP": "#EF553B", "ICMP": "#AB63FA", "Other": "#FECB52"}

# ... (Everything above 'while True' stays the same) ...

# WE REMOVED THE CUSTOM COLOR PALETTE TO BRING BACK THE BLUES

# ... (Keep imports and setup above) ...

# Ensure time is imported (it should be, but just in case)
import time

while True:
    # 1. Capture Data
    df = pd.DataFrame(packet_data)
    
    # 2. Generate a unique ID for this second's render
    # This guarantees Streamlit never sees a "duplicate" ID
    unique_key = str(time.time())

    with placeholder.container():
        # --- KPI ROW ---
        kpi1, kpi2, kpi3 = st.columns(3)

        if not df.empty:
            kpi1.metric(
                label="Total Packets Captured", 
                value=len(df),
                delta=f"{len(df)} pkts in buffer"
            )
            
            top_proto = df['Protocol'].value_counts().idxmax()
            count_proto = df['Protocol'].value_counts().max()
            kpi2.metric(
                label="Dominant Protocol", 
                value=top_proto,
                delta=f"{count_proto} packets"
            )
            
            unique_ips = df['Source'].nunique()
            kpi3.metric(
                label="Active Source IPs", 
                value=unique_ips,
                delta="Normal" if unique_ips < 50 else "High Traffic",
                delta_color="inverse"
            )

            # --- CHARTS ---
            st.markdown("---")
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📊 Protocol Distribution")
                fig_proto = px.pie(df, names='Protocol', hole=0.5)
                fig_proto.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", 
                    plot_bgcolor="rgba(0,0,0,0)",
                    showlegend=True,
                    margin=dict(t=0, b=0, l=0, r=0),
                    height=300
                )
                # FIX: Add unique key using timestamp
                st.plotly_chart(fig_proto, use_container_width=True, key=f"proto_{unique_key}")

            with col2:
                st.subheader("🔍 Packet Size Analysis")
                fig_scatter = px.scatter(
                    df, 
                    x="Time", 
                    y="Size", 
                    color="Protocol",
                    render_mode='webgl'
                )
                fig_scatter.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)", 
                    xaxis=dict(showgrid=False, title="Capture Time"),
                    yaxis=dict(showgrid=True, gridcolor='#333333', title="Size (Bytes)"),
                    margin=dict(t=0, b=0, l=0, r=0),
                    height=300
                )
                # FIX: Add unique key using timestamp
                st.plotly_chart(fig_scatter, use_container_width=True, key=f"scatter_{unique_key}")

            # --- THREAT DETECTION ---
            st.markdown("### 🚨 Live Threat Feed")
            
            if len(df) > 20:
                features = df[['Size']]
                model.fit(features)
                df['Anomaly'] = model.predict(features)
                anomalies = df[df['Anomaly'] == -1]
                
                if not anomalies.empty:
                    st.error(f"⚠️ DETECTED {len(anomalies)} ANOMALIES")
                    st.dataframe(
                        anomalies[['Time', 'Source', 'Destination', 'Protocol', 'Size']].tail(5),
                        use_container_width=True
                    )
                else:
                    st.success("✅ System Status: Secure")
            else:
                st.info("🔄 Calibrating AI Model... (Gathering Data)")

        else:
            st.warning("Waiting for traffic... (Open a browser tab!)")

    # Refresh
    time.sleep(1)