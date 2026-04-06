import streamlit as st
import os
import pandas as pd
from halasec_scan import scan_apk, save_reports
import plotly.express as px
import time

# ----------- PAGE STATE -----------
if "page" not in st.session_state:
    st.session_state.page = "landing"

# ----------- GLOBAL STYLE ----------
st.set_page_config(page_title="HALA-SCAN", page_icon="logo.png", layout="wide")

st.markdown("""
<style>
.stApp {
    background: linear-gradient(140deg, #0a0a0a, #1a1a1a, #2b1f3d, #5a3ea1);
    color: #d8cfff;
    font-family: 'Segoe UI', sans-serif;
}
h1, h2, h3 {
    color: #cbb6ff !important;
}
.card {
    background: rgba(20,20,20,0.85);
    padding: 20px;
    border-radius: 18px;
    margin-bottom: 20px;
    border: 1px solid rgba(122,95,199,0.2);
    box-shadow: 0 0 15px rgba(122,95,199,0.2);
    transition: 0.3s;
}
.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 0 30px rgba(122,95,199,0.6);
}
.progress {
    height: 6px;
    border-radius: 10px;
    background: #222;
}
.fill {
    height: 100%;
    border-radius: 10px;
}
.tip {
    background: rgba(122,95,199,0.08);
    border-left: 3px solid #7a5fc7;
    padding: 10px;
    margin: 6px 0;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

# =========================================================
# 🎬 LANDING PAGE CINEMATIC
# =========================================================
if st.session_state.page == "landing":

    st.markdown("""
    <style>
    .center {
        text-align: center;
        margin-top: 120px;
        animation: fadeIn 2s ease-in;
    }
    @keyframes fadeIn {
        from {opacity:0; transform: translateY(20px);}
        to {opacity:1; transform: translateY(0);}
    }
    .logo {
        filter: drop-shadow(0 0 20px rgba(122,95,199,0.9));
    }
    .title {
        font-size: 50px;
        color: #cbb6ff;
        margin-top: 10px;
    }
    .typing {
        font-size: 18px;
        color: #d8cfff;
        border-right: 2px solid #cbb6ff;
        white-space: nowrap;
        overflow: hidden;
        width: 0;
        margin: auto;
        animation: typing 3s steps(40,end) forwards, blink 0.7s infinite;
    }
    @keyframes typing { from {width:0} to {width:380px} }
    @keyframes blink { 50% {border-color: transparent} }
    </style>

    <div class="center">
        <img src="logo.png" width="200" class="logo">
        <div class="title">HALA-SCAN</div>
        <div class="typing">
        Scan your apps. Detect vulnerabilities. Stay secure.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🚀 Start Scanning"):
        st.session_state.page = "dashboard"
        st.rerun()

# =========================================================
# 🚀 DASHBOARD
# =========================================================
if st.session_state.page == "dashboard":

    st.image("logo.png", width=120)
    st.title("HALA-SCAN Dashboard")

    uploaded_files = st.file_uploader(
        "Upload APK files",
        type=["apk"],
        accept_multiple_files=True
    )

    results = []
    permissions_list = []

    if uploaded_files:
        with st.spinner("🔄 Scanning..."):
            time.sleep(1)

            for file in uploaded_files:
                path = os.path.join("temp", file.name)
                os.makedirs("temp", exist_ok=True)

                with open(path, "wb") as f:
                    f.write(file.getbuffer())

                res, err = scan_apk(path)
                if err:
                    st.error(err)
                    continue

                save_reports(res, path)
                results.append(res)

                if "Permissions" in res:
                    permissions_list.extend(res["Permissions"])

    # ----------- RESULTS -----------
    if results:
        df = pd.DataFrame(results).sort_values(by="Risk Score", ascending=False)

        for _, row in df.iterrows():
            risk = row["Risk Level"]
            score = row["Risk Score"]

            if risk == "HIGH":
                color = "#ff4d6d"
            elif risk == "MEDIUM":
                color = "#facc15"
            else:
                color = "#4ade80"

            st.markdown(f"""
            <div class="card">
                <h3>📱 {row['APK Name']}</h3>
                <p style="color:{color}; font-weight:bold;">
                    {risk} — {score}/100
                </p>
                <div class="progress">
                    <div class="fill" style="width:{score}%; background:{color};"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Tips
            if risk == "HIGH":
                tips = ["Critical vulnerabilities", "Avoid risky permissions", "Do full audit"]
            elif risk == "MEDIUM":
                tips = ["Review permissions", "Update libs", "Monitor behavior"]
            else:
                tips = ["Good security", "Maintain practices", "Keep testing"]

            for tip in tips:
                st.markdown(f"<div class='tip'>💡 {tip}</div>", unsafe_allow_html=True)

        # ----------- CHART -----------
        st.markdown("---")
        st.subheader("📊 Risk Scores")
        st.bar_chart(df.set_index("APK Name")["Risk Score"])

    # ----------- PIE -----------
    if permissions_list:
        st.markdown("---")
        st.subheader("📌 Permissions")

        p = pd.DataFrame(permissions_list, columns=["Permission"])
        p = p["Permission"].value_counts().reset_index()
        p.columns = ["Permission", "Count"]

        fig = px.pie(
            p,
            names="Permission",
            values="Count",
            color_discrete_sequence=px.colors.sequential.Purples
        )
        st.plotly_chart(fig)
