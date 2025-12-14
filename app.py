import streamlit as st
import pandas as pd
import queue
import time
import atexit
import uuid
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from multiprocessing import freeze_support

from flow_sniffer import FlowSniffer, INTERFACE_NAME, FLOW_TIMEOUT_SECONDS
from flow_processor import FlowProcessor

st.set_page_config(
    page_title="AI Network Security Analyzer",
    layout="wide",
    initial_sidebar_state="expanded"
)

def init_session_state():
    if 'sniffer' not in st.session_state:
        st.session_state.flow_queue = queue.Queue()
        st.session_state.sniffer = FlowSniffer(
            output_queue=st.session_state.flow_queue,
            interface=INTERFACE_NAME
        )
        st.session_state.sniffer.start()
        atexit.register(stop_sniffer)
    
    if 'all_flows' not in st.session_state:
        st.session_state.all_flows = []
    
    if 'analyzed_flows' not in st.session_state:
        st.session_state.analyzed_flows = []
    
    if 'flow_processor' not in st.session_state:
        st.session_state.flow_processor = FlowProcessor()
    
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []
    
    if 'expander_counter' not in st.session_state:
        st.session_state.expander_counter = 0

def stop_sniffer():
    """Stops the sniffer when the app exits."""
    if 'sniffer' in st.session_state:
        st.session_state.sniffer.stop()

init_session_state()

with st.sidebar:
    st.title("⚙️ Settings")
    
    st.subheader("Model Selection")
    model_type = st.selectbox(
        "ML Model",
        ["RandomForest", "XGBoost", "GradientBoosting", "NeuralNetwork", "KNN"],
        index=0,
        key="model_select"
    )
    
    if st.button("🔄 Switch Model", key="switch_model"):
        st.session_state.flow_processor = FlowProcessor(model_type)
        st.success(f"Switched to {model_type} model")
        st.rerun()
    
    st.subheader("Analysis Settings")
    confidence_threshold = st.slider(
        "LLM Analysis Threshold",
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        help="Confidence below which flows are sent to LLM",
        key="confidence_slider"
    )
    
    st.subheader("Statistics")
    st.metric("Total Flows", len(st.session_state.all_flows))
    st.metric("Analyzed Flows", len(st.session_state.analyzed_flows))
    llm_analyzed = len([f for f in st.session_state.analyzed_flows if f.get('needs_llm', False)])
    st.metric("LLM Analyses", llm_analyzed)
    
    if st.button("🗑️ Clear History", key="clear_history"):
        st.session_state.analyzed_flows = []
        st.session_state.alerts = []
        st.session_state.expander_counter = 0
        st.rerun()

st.title("🛡️ AI Network Security Analyzer")
st.markdown(f"""
**Interface**: `{INTERFACE_NAME}` | **Flow Timeout**: `{FLOW_TIMEOUT_SECONDS}s` | **Active Model**: `{model_type}`
""")

tab1, tab2, tab3, tab4 = st.tabs(["📊 Live Dashboard", "🚨 Threat Alerts", "📈 Analytics", "📋 Flow Details"])

with tab1:
    col1, col2, col3, col4 = st.columns(4)
    
    processed_count = 0
    while not st.session_state.flow_queue.empty():
        try:
            raw_flow = st.session_state.flow_queue.get_nowait()
            st.session_state.all_flows.append(raw_flow)
            
            analyzed_flow = st.session_state.flow_processor.process_flow(raw_flow)
            st.session_state.analyzed_flows.append(analyzed_flow)
            processed_count += 1
            
            if analyzed_flow.get('final_prediction') != 'BENIGN':
                alert = {
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'flow_id': analyzed_flow.get('Flow ID', 'Unknown'),
                    'src_ip': analyzed_flow.get('Src IP', 'Unknown'),
                    'dst_ip': analyzed_flow.get('Dst IP', 'Unknown'),
                    'threat': analyzed_flow.get('final_prediction', 'Unknown'),
                    'confidence': analyzed_flow.get('ml_confidence', 0),
                    'analyzer': 'LLM' if analyzed_flow.get('needs_llm') else 'ML'
                }
                st.session_state.alerts.append(alert)
                
        except queue.Empty:
            break
    
    if processed_count > 0:
        st.info(f"📥 Processed {processed_count} new flow(s)")
    
    with col1:
        if st.session_state.analyzed_flows:
            benign = len([f for f in st.session_state.analyzed_flows if f.get('final_prediction') == 'BENIGN'])
            st.metric("✅ Benign Flows", benign)
    
    with col2:
        if st.session_state.analyzed_flows:
            malicious = len([f for f in st.session_state.analyzed_flows if f.get('final_prediction') != 'BENIGN'])
            st.metric("🚨 Malicious Flows", malicious, delta=None)
    
    with col3:
        st.metric("🤖 LLM Analyses", llm_analyzed)
    
    with col4:
        if st.session_state.analyzed_flows:
            avg_conf = sum([f.get('ml_confidence', 0) for f in st.session_state.analyzed_flows]) / len(st.session_state.analyzed_flows)
            st.metric("📊 Avg Confidence", f"{avg_conf:.2%}")
    
    st.subheader("🔍 Recent Flow Analysis")
    if st.session_state.analyzed_flows:
        recent_flows = st.session_state.analyzed_flows[-10:]  
        df_recent = pd.DataFrame(recent_flows)
        
        display_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Protocol', 
                       'final_prediction', 'ml_confidence', 'needs_llm']
        
        available_cols = [col for col in display_cols if col in df_recent.columns]
        df_display = df_recent[available_cols]
        
        def color_prediction(val):
            if val == 'BENIGN':
                return 'background-color: #d4edda; color: #155724; font-weight: bold'
            elif val == 'ERROR':
                return 'background-color: #fff3cd; color: #856404; font-weight: bold'
            else:
                return 'background-color: #f8d7da; color: #721c24; font-weight: bold'
        
        df_formatted = df_display.copy()
        if 'ml_confidence' in df_formatted.columns:
            df_formatted['ml_confidence'] = df_formatted['ml_confidence'].apply(lambda x: f"{x:.2%}")
        if 'needs_llm' in df_formatted.columns:
            df_formatted['needs_llm'] = df_formatted['needs_llm'].apply(lambda x: '✅' if x else '❌')
        
        styled_df = df_formatted.style.applymap(color_prediction, subset=['final_prediction'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        error_count = len([f for f in recent_flows if f.get('final_prediction') == 'ERROR'])
        if error_count > 0:
            st.warning(f"⚠️ {error_count} flow(s) had prediction errors. Check your ML model training.")
    else:
        st.info("Waiting for flows to analyze...")

with tab2:
    st.subheader("🚨 Threat Alerts")
    
    if st.session_state.alerts:
        alerts_df = pd.DataFrame(st.session_state.alerts[-20:]) 
        
        def alert_color(row):
            if row['analyzer'] == 'LLM':
                return ['background-color: #ffebee'] * len(row)
            else:
                return ['background-color: #fff3e0'] * len(row)
        
        styled_alerts = alerts_df.style.apply(alert_color, axis=1)
        st.dataframe(styled_alerts, use_container_width=True, hide_index=True)
        
        if st.button("Clear All Alerts", key="clear_alerts_btn"):
            st.session_state.alerts = []
            st.rerun()
    else:
        st.success("🎉 No threats detected!")

with tab3:
    st.subheader("📊 Analytics Dashboard")
    
    if st.session_state.analyzed_flows:
        df = pd.DataFrame(st.session_state.analyzed_flows)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if 'final_prediction' in df.columns:
                threat_counts = df['final_prediction'].value_counts()
                fig = px.pie(values=threat_counts.values, 
                           names=threat_counts.index,
                           title="Threat Distribution",
                           color_discrete_sequence=px.colors.qualitative.Set3)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if 'Protocol' in df.columns:
                protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP'}
                df['Protocol_Name'] = df['Protocol'].map(protocol_map).fillna('Other')
                protocol_counts = df['Protocol_Name'].value_counts()
                fig2 = px.bar(x=protocol_counts.index, y=protocol_counts.values,
                            title="Protocol Distribution",
                            color=protocol_counts.index,
                            color_discrete_sequence=px.colors.qualitative.Set2)
                st.plotly_chart(fig2, use_container_width=True)
        
        st.subheader("Model Confidence Distribution")
        if 'ml_confidence' in df.columns:
            fig3 = px.histogram(df, x='ml_confidence', nbins=20,
                              title="Confidence Scores Distribution",
                              labels={'ml_confidence': 'Confidence Score'},
                              color_discrete_sequence=['#636EFA'])
            st.plotly_chart(fig3, use_container_width=True)
        
        if 'final_prediction' in df.columns:
            error_df = df[df['final_prediction'] == 'ERROR']
            if not error_df.empty:
                st.warning(f"⚠️ Found {len(error_df)} flow(s) with ERROR predictions")
                st.write("Common protocols in error flows:")
                if 'Protocol' in error_df.columns:
                    error_protocols = error_df['Protocol'].value_counts()
                    st.bar_chart(error_protocols)
    else:
        st.info("No analytics data available yet. Waiting for flows...")

with tab4:
    st.subheader("📋 Detailed Flow Information")
    
    if st.session_state.analyzed_flows:
        col1, col2, col3 = st.columns(3)
        with col1:
            show_only_malicious = st.checkbox("Show only malicious flows", value=False, key="filter_malicious_tab4")
        with col2:
            show_only_llm = st.checkbox("Show only LLM-analyzed flows", value=False, key="filter_llm_tab4")
        with col3:
            sort_order = st.selectbox("Sort by", ["Most Recent", "Oldest", "Highest Confidence", "Lowest Confidence"], 
                                     key="sort_order_tab4")
        
        filtered_flows = st.session_state.analyzed_flows.copy()
        
        if show_only_malicious:
            filtered_flows = [f for f in filtered_flows if f.get('final_prediction') not in ['BENIGN', 'ERROR']]
        
        if show_only_llm:
            filtered_flows = [f for f in filtered_flows if f.get('needs_llm', False)]
        
        if sort_order == "Most Recent":
            filtered_flows.sort(key=lambda x: x.get('Timestamp', 0), reverse=True)
        elif sort_order == "Oldest":
            filtered_flows.sort(key=lambda x: x.get('Timestamp', 0))
        elif sort_order == "Highest Confidence":
            filtered_flows.sort(key=lambda x: x.get('ml_confidence', 0), reverse=True)
        elif sort_order == "Lowest Confidence":
            filtered_flows.sort(key=lambda x: x.get('ml_confidence', 0))
        
        st.write(f"Showing {len(filtered_flows)} flow(s)")
        
        if filtered_flows:
            flow_data = []
            for flow in filtered_flows[:50]: 
                flow_data.append({
                    "Flow ID": flow.get('Flow ID', 'Unknown'),
                    "Source IP": flow.get('Src IP', 'N/A'),
                    "Dest IP": flow.get('Dst IP', 'N/A'),
                    "Protocol": flow.get('Protocol', 'N/A'),
                    "Prediction": flow.get('final_prediction', 'N/A'),
                    "Confidence": f"{flow.get('ml_confidence', 0):.2%}",
                    "LLM Used": '✅' if flow.get('needs_llm') else '❌'
                })
            
            df_flows = pd.DataFrame(flow_data)
            
            def highlight_predictions(val):
                if val == 'BENIGN':
                    return 'background-color: #d4edda; color: #155724'
                elif val == 'ERROR':
                    return 'background-color: #fff3cd; color: #856404'
                else:
                    return 'background-color: #f8d7da; color: #721c24'
            
            styled_flows = df_flows.style.applymap(highlight_predictions, subset=['Prediction'])
            st.dataframe(styled_flows, use_container_width=True, hide_index=True)
            
            st.subheader("View Flow Details")
            selected_flow_id = st.selectbox(
                "Select a flow to view details:",
                options=[flow.get('Flow ID', 'Unknown') for flow in filtered_flows[:50]],
                key="flow_selector"
            )
            
            if selected_flow_id:
                selected_flow = next((f for f in filtered_flows if f.get('Flow ID') == selected_flow_id), None)
                if selected_flow:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Flow Information**")
                        st.write(f"**Flow ID:** {selected_flow.get('Flow ID', 'N/A')}")
                        st.write(f"**Source IP:** `{selected_flow.get('Src IP', 'N/A')}`")
                        st.write(f"**Destination IP:** `{selected_flow.get('Dst IP', 'N/A')}`")
                        st.write(f"**Source Port:** {selected_flow.get('Src Port', 'N/A')}")
                        st.write(f"**Destination Port:** {selected_flow.get('Dst Port', 'N/A')}")
                        st.write(f"**Protocol:** {selected_flow.get('Protocol', 'N/A')}")
                        st.write(f"**Duration:** {selected_flow.get('Flow Duration', 'N/A'):.2f} ms")
                        st.write(f"**Total Bytes:** {selected_flow.get('Tot Bytes', 'N/A'):,}")
                        st.write(f"**Total Packets:** {selected_flow.get('Tot Pkts', 'N/A'):,}")
                    
                    with col2:
                        st.markdown("**Analysis Results**")
                        
                        prediction = selected_flow.get('final_prediction', 'N/A')
                        confidence = selected_flow.get('ml_confidence', 0)
                        
                        if prediction == 'BENIGN':
                            st.success(f"**Prediction:** {prediction}")
                        elif prediction == 'ERROR':
                            st.warning(f"**Prediction:** {prediction}")
                        else:
                            st.error(f"**Prediction:** {prediction}")
                        
                        st.write(f"**Confidence:** {confidence:.2%}")
                        st.write(f"**ML Model:** {selected_flow.get('ml_model', 'N/A')}")
                        
                        if selected_flow.get('needs_llm'):
                            st.markdown("---")
                            st.markdown("**LLM Analysis**")
                            st.write(f"**LLM Prediction:** {selected_flow.get('llm_prediction', 'N/A')}")
                            st.write(f"**Attack Type:** {selected_flow.get('llm_attack_type', 'N/A')}")
                            st.write(f"**LLM Confidence:** {selected_flow.get('llm_confidence', 'N/A')}")
                            
                            explanation = selected_flow.get('llm_explanation', '')
                            if explanation:
                                with st.expander("LLM Explanation"):
                                    st.write(explanation)
                    
                    with st.expander("View Raw Flow Data"):
                        st.json({k: v for k, v in selected_flow.items() if not k.startswith('_')})
        else:
            st.info("No flows match the selected filters.")
    else:
        st.info("No flows analyzed yet. Waiting for network traffic...")

st.divider()
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.caption(f"📊 Total Flows: {len(st.session_state.all_flows)}")
with col2:
    st.caption(f"🤖 ML Analyses: {len(st.session_state.analyzed_flows)}")
with col3:
    st.caption("AI Network Security Analyzer v1.0")

if st.button("🔄 Refresh Data", key="refresh_data"):
    st.rerun()

auto_refresh = st.checkbox("Auto-refresh (5s)", value=True, key="auto_refresh_toggle")
if auto_refresh:
    time.sleep(5)
    st.rerun()

if __name__ == '__main__':
    freeze_support()