import sys
from pathlib import Path

# Ensure root import resolution for Streamlit Cloud
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from app.mock_data import MOCK_APP_LOGS
from app.models import AppLog
from app.engine import evaluate_app_security

st.set_page_config(page_title="CloudEagle Shadow AI Governance Copilot", layout="wide", page_icon="🦅")

st.title("🦅 CloudEagle Shadow AI & Security Governance Copilot")
st.caption("Automated SaaS Discovery, Unvetted LLM Risk Scoring & IT Remediation Playbooks")

# Sidebar - Manager Controls & Log Scanner
st.sidebar.header("⚙️ Governance Controls")
risk_filter = st.sidebar.multiselect("Filter Apps by Risk Level", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])

st.sidebar.markdown("---")
st.sidebar.header("🔍 Scan Unvetted App / Log")
st.sidebar.caption("Audit a newly detected application log or browser extension telemetry.")

with st.sidebar.form("scan_app_form"):
    app_name = st.text_input("App / Extension Name", value="DeepWrite AI Assistant")
    category = st.selectbox("Category", ["Generative AI / Copywriting", "Developer Tools / Code Gen", "Data Analytics", "Document Processing"])
    dept = st.selectbox("Department", ["Engineering", "Finance & Accounting", "Marketing", "Sales", "Legal & HR"])
    users = st.number_input("Detected Active Users", value=12, step=1)
    sensitivity = st.selectbox("Data Sensitivity Level", ["High", "Medium", "Low"])
    sso = st.checkbox("SSO Integrated (Okta/Azure AD)", value=False)
    spend = st.number_input("Monthly Spend ($)", value=360.0, step=50.0)
    log_text = st.text_area("Log Snippet / Telemetry Detail", height=100, value="Employees submitting proprietary source code to external public API endpoint.")
    
    submit_scan = st.form_submit_button("⚡ Run Security Governance Scan")

if submit_scan:
    new_log = AppLog(
        app_id="APP-SCAN",
        app_name=app_name,
        category=category,
        user_department=dept,
        active_users=int(users),
        data_sensitivity=sensitivity,
        sso_integrated=sso,
        monthly_spend=float(spend),
        raw_log_snippet=log_text,
        additional_notes="Scanned via CloudEagle Real-Time Telemetry Parser"
    )
    with st.spinner("Analyzing Security & Compliance Risk..."):
        assessment = evaluate_app_security(new_log)
        st.session_state["selected_app"] = new_log.model_dump()
        st.session_state["selected_eval"] = assessment.model_dump()
        st.sidebar.success(f"Audit complete for {app_name}!")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📋 Detected SaaS & Shadow AI Stack")
    for app_dict in MOCK_APP_LOGS:
        log = AppLog(**app_dict)
        assessment = evaluate_app_security(log)
        eval_dict = assessment.model_dump()
        risk_lvl = eval_dict.get("risk_level", "Medium")
        
        if risk_lvl in risk_filter:
            with st.expander(f"**{log.app_name}** | {log.user_department} | Risk: {eval_dict.get('risk_score', 50)}/100 ({risk_lvl})"):
                st.write(f"**Category:** {log.category}")
                st.write(f"**Active Users:** {log.active_users} | **Monthly Spend:** ${log.monthly_spend:,.2f}")
                st.write(f"**SSO Integrated:** {'✅ Yes' if log.sso_integrated else '❌ No (Unvetted Access)'}")
                st.write(f"**Telemetry:** *\"{log.raw_log_snippet}\"*")
                if st.button(f"Inspect Governance Playbook", key=log.app_id):
                    st.session_state["selected_app"] = log.model_dump()
                    st.session_state["selected_eval"] = eval_dict

with col2:
    st.subheader("⚡ IT Governance & Remediation Playbook")
    if "selected_eval" in st.session_state:
        eval_data = st.session_state["selected_eval"]
        app_data = st.session_state.get("selected_app", {})
        
        st.markdown(f"### Application: **{eval_data.get('app_name', 'Unknown')}**")
        st.caption(f"Department: **{app_data.get('user_department', 'N/A')}** | Users: **{app_data.get('active_users', 0)}**")
        
        st.metric(
            label="Calculated Security Risk Score",
            value=f"{eval_data.get('risk_score', 0)} / 100",
            delta=eval_data.get('risk_level', 'Low'),
            delta_color="inverse"
        )
        
        st.write("#### 🛑 Identified Threat Vectors:")
        for threat in eval_data.get("identified_threats", []):
            st.error(f"• {threat}")
            
        st.write("#### 🛡️ Compliance Framework Gaps:")
        for gap in eval_data.get("compliance_framework_gaps", []):
            st.warning(f"⚠️ {gap}")
            
        st.write("#### 🛠️ IT Admin Remediation Steps:")
        for step in eval_data.get("remediation_steps", []):
            st.info(f"✔ {step}")
            
        st.write("#### 💡 Recommended Immediate Action:")
        st.success(eval_data.get("recommended_action", "Proceed with standard procurement audit."))
            
        st.write("#### ✉️ Automated Advisory Draft (IT Security to Department Head):")
        st.code(eval_data.get("department_notification_draft", ""), language="text")
    else:
        st.info("Select an application from the inventory on the left or scan a new tool in the sidebar to inspect the remediation playbook.")