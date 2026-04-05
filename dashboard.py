import streamlit as st
import os
import tempfile
import pandas as pd
import json
import base64
import altair as alt
from backend.scanner import scan_apk  # السكريبت تبعك


# Page Config & Branding

st.set_page_config(page_title="HalaScan", layout="wide")
st.image("logo.png", width=150)
st.title("🔐 HalaScan Security Dashboard")
st.markdown("---")

# Sidebar
st.sidebar.image("logo.png", width=120)
st.sidebar.title("HalaScan")
st.sidebar.markdown("**Web Vulnerability Scanner**")
st.sidebar.markdown("---")


# Custom Dark Theme

st.markdown("""
<style>
body { background: linear-gradient(135deg, #0e1117, #1e1e2f); color: white; }
h1, h2, h3 { color: #00ADB5; }
.card { background:#1e1e1e; padding:10px; border-radius:12px; margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)


# Upload APK Files

st.subheader("Upload APK Files")
uploaded_files = st.file_uploader("Choose APK files", type=["apk"], accept_multiple_files=True)

results_table = []

if uploaded_files:
    for uploaded_file in uploaded_files:
        # Save temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded_file.read())
            temp_path = tmp.name

        # Scan APK
        apk_result = scan_apk(temp_path)

        # App Name
        st.markdown(f"##  {apk_result['name']}")

        # Risk Score
        score = apk_result.get("risk_score", 0)
        st.subheader("Risk Score")
        st.progress(min(score, 100))
        verdict = apk_result.get("verdict", "LOW RISK")
        if score >= 50:
            st.error(f"{verdict}  ({score}/100)")
        else:
            st.success(f"{verdict}  ({score}/100)")

        # Risk Summary Chart
        st.subheader("📊 Risk Summary Chart")
        df_chart = pd.DataFrame({
            'Type': ['High Risk', 'Low Risk'],
            'Score': [score, 100 - score]
        })
        chart = alt.Chart(df_chart).mark_bar().encode(
            x='Type', y='Score', color='Type'
        )
        st.altair_chart(chart, use_container_width=True)

        # Permissions
        st.subheader(" Permissions")
        st.json(apk_result.get("permissions", []))

        # Findings
        st.subheader(" Findings")
        findings = apk_result.get("findings", [])
        if findings:
            for f in findings:
                if isinstance(f, dict):
                    perm = f.get("permission", "")
                    fix = f.get("ai_fix", "")
                    st.markdown(f"<div class='card'> <b>{perm}</b><br> {fix}</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='card'> {f}</div>", unsafe_allow_html=True)
        else:
            st.info("No high-risk issues found ")

        st.markdown("---")

        # Append to summary table
        results_table.append({
            "App": apk_result["name"],
            "Risk Score": score,
            "Verdict": verdict
        })

        # Download JSON report
        json_str = json.dumps(apk_result, indent=4)
        b64 = base64.b64encode(json_str.encode()).decode()
        href = f'<a href="data:file/json;base64,{b64}" download="{uploaded_file.name}_report.json">📥 Download JSON Report</a>'
        st.markdown(href, unsafe_allow_html=True)

# Summary Table
if results_table:
    st.subheader(" Summary Table")
    st.dataframe(pd.DataFrame(results_table))
