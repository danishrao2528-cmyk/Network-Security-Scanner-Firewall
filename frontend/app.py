import streamlit as st
import requests
import pandas as pd
import time

# --- Configuration ---
st.set_page_config(page_title="Network Security Command Center", page_icon="🛡️", layout="wide")
API_BASE_URL = "http://127.0.0.1:8000"

# Initialize session state for dynamic firewall rules
if 'firewall_rules' not in st.session_state:
    st.session_state.firewall_rules = []

# --- Custom CSS for Styling ---
st.markdown("""
    <style>
    .main { background-color: #0E1117; }
    h1, h2, h3 { color: #4DB6AC; }
    .stAlert { border-radius: 10px; }
    div[data-testid="stForm"] { border: 1px solid #4DB6AC; padding: 20px; border-radius: 10px;}
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ 🌐 Network Security Command Center 🚀")
st.markdown("---")

# --- Tabs ---
tab1, tab2, tab3 = st.tabs([
    "🚀 Network Scanner 🔍", 
    "🧱 Dynamic Firewall Policy & Simulation 🛡️", 
    "📊 Threat Analytics 📈"
])

# ==========================================
# TAB 1: NETWORK SCANNER (Unchanged, functioning well)
# ==========================================
with tab1:
    st.header("⚙️ Target Configuration")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        target = st.text_input("🎯 Target (IP, Hostname, or CIDR)", value="127.0.0.1")
    with col2:
        scan_method = st.selectbox("⚡ Scan Method", ["TCP Connect", "TCP SYN", "UDP"])
    with col3:
        port_range = st.text_input("🚪 Port Range", value="1-1024")
        
    if st.button("▶️ Launch Scan Engine 🚀", type="primary", use_container_width=True):
        with st.spinner("Initializing Scan Engine and analyzing target..."):
            try:
                payload = {"target": target, "scan_type": scan_method, "ports": port_range}
                response = requests.post(f"{API_BASE_URL}/api/scan", json=payload, timeout=30)
                
                if response.status_code == 200:
                    st.success("✔️ Scan Complete!")
                    data = response.json().get("data", [])
                    df_analytics = pd.DataFrame(data)
                    
                    if not df_analytics.empty and 'status' in df_analytics.columns:
                        open_ports_df = df_analytics[df_analytics['status'] == 'open']
                        
                        if not open_ports_df.empty:
                            st.subheader(f"🔴 Open Ports Discovered on {target}")
                            m1, m2 = st.columns(2)
                            m1.metric("Total Ports Scanned", len(df_analytics))
                            m2.metric("Open Vulnerable Ports", len(open_ports_df))
                            
                            st.dataframe(
                                open_ports_df.style.applymap(
                                    lambda x: 'background-color: #ff4b4b; color: white' if x == 'open' else '',
                                    subset=['status']
                                ), 
                                use_container_width=True
                            )
                        else:
                            st.info(f"Ports were scanned on {target}, but all are closed or filtered.")
                            st.dataframe(df_analytics, use_container_width=True)
                    elif not df_analytics.empty:
                        st.dataframe(df_analytics, use_container_width=True)
                    else:
                        st.info(f"Scan complete. No open or responsive ports were detected on target: {target}.")
                else:
                    st.error(f"Backend API Error: {response.text}")
                    
            except requests.exceptions.ConnectionError:
                st.error("🚨 Failed to connect to the backend. Ensure FastAPI (Uvicorn) is running on port 8000.")
            except Exception as e:
                st.error(f"🚨 An unexpected error occurred: {str(e)}")

# ==========================================
# TAB 2: DYNAMIC FIREWALL POLICY & SIMULATION
# ==========================================
with tab2:
    st.header("🧱 Dynamic Firewall Rule Simulation")
    st.write("Build your own security policies and test simulated packets against them.")
    
    # --- RULE BUILDER ---
    st.subheader("1. Configure Security Policies")
    with st.form("rule_builder_form"):
        rc1, rc2, rc3, rc4, rc5 = st.columns(5)
        with rc1:
            new_priority = st.number_input("Priority (Lower = First)", min_value=1, value=1)
        with rc2:
            new_action = st.selectbox("Action", ["ALLOW", "DENY"])
        with rc3:
            new_ip = st.text_input("Source IP", value="ANY", help="Use 'ANY' or a specific IP")
        with rc4:
            new_port = st.text_input("Target Port", value="ANY", help="Use 'ANY' or a specific Port")
        with rc5:
            new_protocol = st.selectbox("Protocol", ["ANY", "TCP", "UDP", "ICMP"])
            
        if st.form_submit_button("➕ Add Rule to Policy"):
            st.session_state.firewall_rules.append({
                "priority": new_priority,
                "action": new_action,
                "ip": new_ip,
                "port": new_port,
                "protocol": new_protocol
            })
            st.success("Rule added successfully!")

    # --- DISPLAY ACTIVE RULES ---
    if st.session_state.firewall_rules:
        # Sort rules by priority before displaying
        sorted_display_rules = sorted(st.session_state.firewall_rules, key=lambda x: x['priority'])
        df_rules = pd.DataFrame(sorted_display_rules)
        st.write("**Active Access Control List (ACL)**")
        st.table(df_rules)
        
        if st.button("🗑️ Clear All Rules"):
            st.session_state.firewall_rules = []
            st.rerun()
    else:
        st.info("No custom rules defined. All traffic will be blocked by the implicit deny rule.")

    st.markdown("---")

    # --- TRAFFIC SIMULATOR ---
    st.subheader("2. Test Incoming Traffic")
    with st.form("firewall_sim_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            src_ip = st.text_input("Simulated Source IP", "192.168.1.15")
        with c2:
            tgt_port = st.text_input("Simulated Target Port", "80")
        with c3:
            protocol = st.selectbox("Simulated Protocol", ["TCP", "UDP", "ICMP"])
            
        if st.form_submit_button("🚀 Launch Traffic Simulation", type="primary"):
            sim_payload = {
                "source_ip": src_ip,
                "target_port": tgt_port,
                "protocol": protocol,
                "rules": st.session_state.firewall_rules  # Sends dynamic rules instead of mock data
            }
            
            with st.spinner("Analyzing packet against rule matrix..."):
                time.sleep(0.5) 
                try:
                    res = requests.post(f"{API_BASE_URL}/api/firewall/simulate", json=sim_payload)
                    if res.status_code == 200:
                        result = res.json()
                        decision = result.get('decision', 'DENY')
                        
                        if decision == "ALLOW":
                            st.success(f"✅ **ACCESS GRANTED:** {result['message']}")
                        else:
                            st.error(f"🚫 **ACCESS BLOCKED:** {result['message']}")
                    else:
                        st.error(f"Simulation failed: {res.text}")
                except requests.exceptions.ConnectionError:
                    st.error("🚨 Failed to connect to the backend server.")

# ==========================================
# TAB 3: THREAT ANALYTICS
# ==========================================
with tab3:
    st.header("📊 Threat Analytics Dashboard")
    st.write("Visualizations based on active firewall rules.")
    
    if st.session_state.firewall_rules:
        df = pd.DataFrame(st.session_state.firewall_rules)
        action_counts = df['action'].value_counts()
        st.bar_chart(action_counts, color="#4DB6AC")
    else:
        st.info("Add firewall rules in Tab 2 to generate analytics.")