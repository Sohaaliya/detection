import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from datetime import datetime
from nids import NIDS

# -------------------- PAGE CONFIG --------------------
st.set_page_config(
    page_title="Cyberpunk NIDS",
    page_icon="🛡️",
    layout="wide"
)

# -------------------- CYBERPUNK CSS --------------------
cyber_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');

html, body, [class*="css"] {
    font-family: 'Orbitron', monospace !important;
    background: linear-gradient(45deg, #0a0a0a, #1a1a1a) !important;
}

.header-text {
    text-align: center;
    color: #00FF41;
    text-shadow: 0 0 20px #00FF41;
    font-size: 3em;
    font-weight: 900;
}

.status-badge {
    background: linear-gradient(45deg, #00FF41, #00D941);
    border-radius: 25px;
    padding: 1rem 2rem;
    color: black;
    font-weight: bold;
    box-shadow: 0 0 30px #00FF41;
}
</style>
"""
st.markdown(cyber_css, unsafe_allow_html=True)

# -------------------- NIDS INIT --------------------
@st.cache_resource
def load_nids():
    return NIDS()

nids = load_nids()

# -------------------- SESSION STATE --------------------
if "stats" not in st.session_state:
    st.session_state.stats = nids.get_stats()

if "chat" not in st.session_state:
    st.session_state.chat = []

if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

# -------------------- HEADER --------------------
st.markdown(
    '<h1 class="header-text">NETWORK INTRUSION DETECTION SYSTEM</h1>',
    unsafe_allow_html=True
)
st.divider()

# -------------------- SIDEBAR --------------------
with st.sidebar:
    st.markdown("### 🛡️ Controls")

    if st.button("🚀 Start Monitoring"):
        if not nids.running:
            nids.start_monitoring()
            st.success("Monitoring started")

    if st.button("⏹️ Stop Monitoring"):
        nids.stop_monitoring()
        st.warning("Monitoring stopped")

    st.divider()

    if st.button("💥 Simulate Attack"):
        nids.simulate_attack()
        st.balloons()

    st.session_state.auto_refresh = st.toggle("🔄 Live Updates", True)

# -------------------- UPDATE STATS --------------------
stats = nids.get_stats()
st.session_state.stats = stats

# -------------------- METRICS --------------------
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(
        f'<div class="status-badge">{"🟢 ACTIVE" if nids.running else "🔴 OFFLINE"}</div>',
        unsafe_allow_html=True
    )

with col2:
    st.metric("Total Attacks", stats["total_attacks"], f"{stats['attack_rate']}/min")

with col3:
    st.metric("Port Scans", stats["port_scans"])

with col4:
    st.metric("ICMP Floods", stats["icmp_attacks"])

with col5:
    st.metric("Brute Force", stats["brute_force"])

st.divider()

# -------------------- TABS --------------------
tab1, tab2, tab3 = st.tabs(["🚨 Alerts", "📈 Trends", "🌐 Network"])

# ---------- TAB 1 : ALERTS ----------
with tab1:
    if stats["alerts"]:
        df = pd.DataFrame(stats["alerts"])
        st.dataframe(df, use_container_width=True)

        st.download_button(
            label="💾 Download Logs",
            data=df.to_csv(index=False),
            file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No alerts detected")

# ---------- TAB 2 : TRENDS ----------
with tab2:
    if stats["alerts"]:
        df = pd.DataFrame(stats["alerts"][-50:])
        fig = px.pie(df, names="attack", title="Attack Distribution")
        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

# ---------- TAB 3 : NETWORK ----------
with tab3:
    if stats["top_attackers"]:
        df = pd.DataFrame(stats["top_attackers"])
        fig = px.bar(df, x="ip", y="attacks", title="Top Attackers")
        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

# -------------------- CHATBOT --------------------
st.divider()
st.markdown("### 🤖 NIDS Assistant")

for msg in st.session_state.chat:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

prompt = st.chat_input("Ask about attacks, trends, or stats")

if prompt:
    st.session_state.chat.append({"role": "user", "content": prompt})

    # SAFE STRING BUILDING (NO f-string ERROR)
    if stats["top_attackers"]:
        top_attackers = ", ".join(
            "{} ({})".format(x["ip"], x["attacks"])
            for x in stats["top_attackers"][:3]
        )
    else:
        top_attackers = "No attackers yet"

    response = (
        f"Total attacks: {stats['total_attacks']}\n"
        f"Attack rate: {stats['attack_rate']}/min\n"
        f"Top attackers: {top_attackers}"
    )

    st.session_state.chat.append({"role": "assistant", "content": response})

    with st.chat_message("assistant"):
        st.markdown(response)

# -------------------- AUTO REFRESH --------------------
if st.session_state.auto_refresh:
    time.sleep(2)
    st.rerun()

st.divider()
st.markdown("*Cyberpunk NIDS Dashboard – Real-time Threat Intelligence*")
