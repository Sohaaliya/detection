import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import numpy as np
from nids import NIDS
import threading
from datetime import datetime

# Enhanced Cyberpunk CSS
cyber_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
html, body, [class*="css"]  {
    font-family: 'Orbitron', monospace !important;
    background: linear-gradient(45deg, #0a0a0a, #1a1a1a) !important;
}
.header-text {
    text-align: center; 
    color: #00FF41; 
    text-shadow: 0 0 20px #00FF41; 
    font-size: 3em; 
    font-weight: 900; 
    animation: glow 3s ease-in-out infinite;
    margin-bottom: 2rem;
}
@keyframes glow {
    0%, 100% { text-shadow: 0 0 20px #00FF41; }
    50% { text-shadow: 0 0 40px #FF0040, 0 0 60px #FF0040; }
}
.metric-glow {
    text-shadow: 0 0 15px #00FF41 !important;
    color: #00FF41 !important;
}
.status-badge {
    background: linear-gradient(45deg, #00FF41, #00D941);
    border-radius: 25px;
    padding: 1rem 2rem;
    color: #000;
    font-weight: bold;
    box-shadow: 0 0 30px #00FF41;
    font-size: 1.2em;
}
.chart-container {
    border: 2px solid #00FF41;
    border-radius: 15px;
    padding: 1rem;
    background: rgba(0,0,0,0.7);
    box-shadow: 0 0 30px rgba(0,255,65,0.3);
}
.alert-row:hover {
    background: rgba(0,255,65,0.3) !important;
    transform: scale(1.02);
    transition: all 0.3s;
}
.download-btn {
    background: linear-gradient(45deg, #FF0040, #00FF41) !important;
    border-radius: 25px !important;
    color: white !important;
    padding: 0.75rem 2rem !important;
    font-weight: bold !important;
    font-size: 1.1em !important;
    transition: all 0.3s !important;
}
.download-btn:hover {
    box-shadow: 0 0 40px #FF0040 !important;
    transform: scale(1.1) !important;
}
</style>
"""

st.markdown(cyber_css, unsafe_allow_html=True)

# Initialize NIDS
@st.cache_resource
def get_nids():
    return NIDS()

nids = get_nids()

# Initialize session state
if "nids_stats" not in st.session_state:
    st.session_state.nids_stats = nids.get_stats()
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []
if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

# Header
st.markdown('<h1 class="header-text">NETWORK INTRUSION DETECTION SYSTEM</h1>', unsafe_allow_html=True)
st.markdown("---")

# Sidebar Controls
with st.sidebar:
    st.markdown("### 🛡️ NIDS Controls")
    if st.button("🚀 Start Monitoring", key="start", use_container_width=True, type="primary"):
        if not nids.running:
            nids.start_monitoring()
            st.success("🔥 Monitoring started!")
    
    if st.button("⏹️ Stop Monitoring", key="stop", use_container_width=True):
        nids.stop_monitoring()
        st.warning("⏸️ Monitoring stopped!")
    
    st.markdown("---")
    st.markdown("### 🎯 Demo Mode")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("💥 Simulate Attack", key="simulate"):
            nids.simulate_attack()
            st.balloons()
    with col2:
        if st.button("📊 Refresh Data", key="refresh"):
            st.rerun()
    
    st.markdown("### ⚙️ Settings")
    st.session_state.auto_refresh = st.toggle("🔄 Live Updates", value=True)

# Update stats function
def update_stats():
    stats = nids.get_stats()
    st.session_state.nids_stats = stats
    return stats

# Main Metrics Row
stats = st.session_state.nids_stats
col1, col2, col3, col4, col5 = st.columns([1, 1.5, 1.5, 1.5, 1.5])

with col1:
    status = "🟢 ACTIVE" if nids.running else "🔴 OFFLINE"
    st.markdown(f'<div class="status-badge">{status}</div>', unsafe_allow_html=True)

with col2:
    st.metric("💥 Total Attacks", stats["total_attacks"], delta=f"{stats['attack_rate']}/min")
with col3:
    st.metric("🔍 Port Scans", stats["port_scans"])
with col4:
    st.metric("📡 ICMP Floods", stats["icmp_attacks"])
with col5:
    st.metric("🔨 Brute Force", stats["brute_force"])

st.markdown("---")

# Analytics Dashboard with Graphs
st.markdown("## 📊 Security Analytics")
tab1, tab2, tab3 = st.tabs(["🚨 Recent Alerts", "📈 Attack Trends", "🌐 Network Overview"])

with tab1:
    st.markdown("### Recent Alerts")
    st.markdown("---")
    if stats["alerts"]:
        df_alerts = pd.DataFrame(stats["alerts"])
        st.dataframe(
            df_alerts,
            use_container_width=True,
            hide_index=True,
            column_config={
                "attack": st.column_config.TextColumn("Attack Type"),
                "ip": st.column_config.TextColumn("IP Address"),
                "time": st.column_config.TextColumn("Time")
            }
        )
        
        csv = df_alerts.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="💾 Download Full Logs",
            data=csv,
            file_name=f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    else:
        st.info("👀 No alerts detected. Try simulating an attack!")

with tab2:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    
    # Attack Type Distribution (Pie Chart)
    if stats["alerts"]:
        df = pd.DataFrame(stats["alerts"][-50:])
        fig_pie = px.pie(df, names='attack', title="Attack Types (Last 50)")
        fig_pie.update_layout(template="plotly_dark", font_family="Orbitron")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # Attack Rate Over Time (Line Chart)
    analytics_data = nids.get_analytics_data()
    if not analytics_data["alerts_df"].empty:
        df_time = analytics_data["alerts_df"].tail(50).copy()
        df_time['time'] = pd.to_datetime(df_time['time'])
        fig_line = px.line(df_time, x='time', color='attack', 
                          title="Attack Rate Timeline (Last 50)")
        fig_line.update_layout(template="plotly_dark", font_family="Orbitron")
        st.plotly_chart(fig_line, use_container_width=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

with tab3:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    
    # Top Attackers
    if stats["top_attackers"]:
        df_top = pd.DataFrame(stats["top_attackers"])
        fig_bar = px.bar(df_top, x='ip', y='attacks', title="Top 5 Attackers")
        fig_bar.update_layout(template="plotly_dark", font_family="Orbitron")
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # Hourly Attack Heatmap
    if stats["hourly_attacks"]:
        hours = list(range(24))
        attack_counts = [stats["hourly_attacks"].get(h, 0) for h in hours]
        fig_heatmap = go.Figure(data=go.Heatmap(
            z=attack_counts,
            x=hours,
            y=['Attacks'],
            colorscale='Viridis',
            text=attack_counts,
            texttemplate="%{text}",
            textfont={"size": 15},
            hoverongaps=False
        ))
        fig_heatmap.update_layout(
            title="Hourly Attack Patterns",
            template="plotly_dark",
            font_family="Orbitron"
        )
        st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # Key Metrics
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Unique IPs", stats["unique_ips"])
    with col2: st.metric("Attack Rate", f"{stats['attack_rate']}/min")
    with col3: st.metric("Active Attackers", len([x for x in stats["top_attackers"] if x["attacks"] > 0]))
    
    st.markdown('</div>', unsafe_allow_html=True)

# Chatbot
st.markdown("---")
st.markdown("### 🤖 NIDS Security Assistant")
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []

for message in st.session_state.chat_messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask about security analytics..."):
    st.session_state.chat_messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"): st.markdown(prompt)
    
    # Enhanced responses with analytics
    responses = {
        "graph": "📊 Analytics shows pie charts (attack types), line charts (trends), bar charts (top attackers), and heatmaps (hourly patterns).",
        "top": f"🔍 Top attackers: {', '.join([f'{x['ip']}({x['attacks']})' for x in stats['top_attackers'][:3]])}",
        "trends": f"📈 Current attack rate: {stats['attack_rate']}/min. Hourly patterns show peak activity.",
        "IDS": "🛡️ NIDS monitors packets in real-time using Scapy, detects anomalies with threshold-based rules, and provides comprehensive analytics dashboards.",
        "default": f"🔥 Live stats - Total: {stats['total_attacks']} | Port Scans: {stats['port_scans']} | ICMP: {stats['icmp_attacks']} | Rate: {stats['attack_rate']}/min"
    }
    
    response = responses.get("default", "NIDS provides real-time analytics and threat intelligence.")
    for key, value in responses.items():
        if key.lower() in prompt.lower():
            response = value
            break
    
    st.session_state.chat_messages.append({"role": "assistant", "content": response})
    with st.chat_message("assistant"): st.markdown(response)

# Auto-refresh
if st.session_state.auto_refresh:
    time.sleep(2)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("*Cyberpunk NIDS Dashboard | Real-time Analytics & Threat Intelligence*")
