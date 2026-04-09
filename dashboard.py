import streamlit as st
import os
import pandas as pd
import time
import plotly.express as px
import subprocess
import shutil
from datetime import datetime


def scan_apk(path):
    try:
        from halasec_scan import scan_apk as analyze_apk
        res = analyze_apk(path)
        if not res:
            return None, "Failed to analyze APK"
        return {
            "APK Name": res.get("name", os.path.basename(path)),
            "Risk Score": res.get("risk_score", 0),
            "Risk Level": res.get("verdict", "UNKNOWN"),
            "Permissions": res.get("permissions", []),
            "Vulnerabilities": res.get("findings", [])
        }, None
    except Exception as e:
        return None, str(e)


def dynamic_analysis(apk_path, timeout_sec=60):
    decoded_dir = f"temp/decoded_{os.path.basename(apk_path)}"
    if os.path.exists(decoded_dir):
        shutil.rmtree(decoded_dir)

    try:
        cmd = ["java", "-jar", "apktool.jar", "d", apk_path, "-o", decoded_dir, "-f"]
        subprocess.run(cmd, timeout=timeout_sec, capture_output=True)
    except subprocess.TimeoutExpired:
        return [{"file": "Error", "line": f"Command timed out after {timeout_sec} seconds", "severity": "LOW"}]
    except Exception as e:
        return [{"file": "Error", "line": str(e), "severity": "LOW"}]

    findings = []
    keywords = {
        "HIGH": ["password", "secret", "api_key", "token", "private", "access_token", "android:exported=\"true\"", "android:debuggable=\"true\"", "allowBackup=\"true\""],
        "MEDIUM": ["http://", "https://", "ftp://", "ws://"],
        "LOW": ["debug", "log", "print"]
    }

    for root, dirs, files in os.walk(decoded_dir):
        for file in files:
            if file.endswith((".xml", ".smali", ".txt")):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_lower = line.lower()
                            for severity, keys in keywords.items():
                                for k in keys:
                                    if k in line_lower:
                                        findings.append({
                                            "file": file,
                                            "line": line.strip()[:120],
                                            "severity": severity
                                        })
                                        break
                except:
                    continue
    
    shutil.rmtree(decoded_dir, ignore_errors=True)
    return findings or [{"file": "Info", "line": "No suspicious behavior detected", "severity": "LOW"}]


if "page" not in st.session_state:
    st.session_state.page = "landing"
    st.session_state.results = []
    st.session_state.permissions_list = []
    st.session_state.scan_complete = False


st.set_page_config(page_title="HALA-SCAN", layout="wide")
st.markdown("""
<style>
.stApp {background: linear-gradient(140deg,#0a0a0a,#1a1a1a,#2b1f3d,#5a3ea1); color:#d8cfff; font-family:'Segoe UI', sans-serif;}
h1,h2,h3{color:#cbb6ff !important;}
.card{background:rgba(20,20,20,0.85);padding:20px;border-radius:18px;margin-bottom:20px;border:1px solid rgba(122,95,199,0.2);box-shadow:0 0 15px rgba(122,95,199,0.2);transition:0.3s;}
.card:hover{transform:translateY(-5px);box-shadow:0 0 30px rgba(122,95,199,0.6);}
.progress{height:6px;border-radius:10px;background:#222;}
.fill{height:100%;border-radius:10px;}
.tip{background: rgba(122,95,199,0.08); border-left:3px solid #7a5fc7; padding:10px;margin:6px 0;border-radius:8px;}
.loader{border:6px solid #f3f3f3;border-top:6px solid #7a5fc7;border-radius:50%;width:60px;height:60px;animation:spin 1s linear infinite;margin:auto;margin-top:50px;}
@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}
.fadein{animation: fadeIn 1.5s ease-in;}
@keyframes fadeIn{from{opacity:0;}to{opacity:1};}
.typing{border-right:2px solid #cbb6ff; white-space: nowrap; overflow: hidden; display:inline-block; animation: typing 2s steps(40,end) forwards, blink 0.7s infinite;}
@keyframes typing{from{width:0} to{width:380px}}
@keyframes blink{50%{border-color:transparent}}
.scrollable {max-height: 150px; overflow-y: auto; padding-right: 5px;}
</style>
""", unsafe_allow_html=True)


if st.session_state.page == "landing":
    st.markdown("""
    <div style='text-align:center; margin-top:150px;' class='fadein'>
        <h1 style='font-size:50px; color:#cbb6ff;'>Welcome to HALA-SCAN!</h1>
        <p class='typing' style='font-size:18px; margin:auto;'>Let's make your apps safer! 🚀</p>
    </div>
    """, unsafe_allow_html=True)

    if st.button(" Start Scanning"):
        st.session_state.page = "dashboard"
        st.session_state.results = []
        st.session_state.permissions_list = []
        st.session_state.scan_complete = False
        st.rerun()


if st.session_state.page == "dashboard":
    st.image("logo.png", width=120)
    st.title("HALA-SCAN Dashboard")

    
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    with col_btn1:
        export_pdf_clicked = st.button("📊 Export PDF Report", use_container_width=True)
    with col_btn2:
        show_cicd = st.button("🎯 CI/CD Integration", use_container_width=True)

    if show_cicd:
        st.markdown("""
        <div style='background:rgba(122,95,199,0.15); padding:15px; border-radius:12px; margin-bottom:20px;'>
            <b>🔧 GitHub Actions Workflow:</b><br><br>
            <code style='background:#1a1a1a; padding:10px; display:block; border-radius:8px;'>
            name: HALA Security Scan<br><br>
            on: [push, pull_request]<br><br>
            jobs:<br>
            &nbsp;&nbsp;security-scan:<br>
            &nbsp;&nbsp;&nbsp;&nbsp;runs-on: ubuntu-latest<br>
            &nbsp;&nbsp;&nbsp;&nbsp;steps:<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- uses: actions/checkout@v3<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- name: Setup Python<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;uses: actions/setup-python@v4<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;with:<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python-version: '3.9'<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- name: Install dependencies<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;run: pip install androguard reportlab<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- name: Run HALA Scan<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;run: |<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python halasec_scan.py ./apks/<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if grep -q "HIGH RISK" reports/scan_results.json; then<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;exit 1<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;fi<br>
            </code>
        </div>
        """, unsafe_allow_html=True)

    uploaded_files = st.file_uploader("Upload APKs", type=["apk"], accept_multiple_files=True)

    if uploaded_files and not st.session_state.scan_complete:
        loader = st.empty()
        loader.markdown("<div class='loader'></div>", unsafe_allow_html=True)
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

            findings = dynamic_analysis(path)
            res["findings"] = findings
            st.session_state.results.append(res)
            st.session_state.permissions_list.extend(res.get("Permissions", []))

        loader.empty()
        st.session_state.scan_complete = True
        st.rerun()

    
    def format_items(items, max_len=80):
        if not items:
            return "None found"
        formatted = "<div class='scrollable'>"
        for i in items:
            line = i.get('line', str(i))
            if len(line) > max_len:
                line = line[:max_len] + "…"
            file_name = i.get('file', 'unknown')
            formatted += f"📄 <b>{file_name}</b> ➜ {line}<br>"
        formatted += "</div>"
        return formatted

    
    for app in st.session_state.results:
        risk = app["Risk Level"]
        score = app["Risk Score"]
        findings = app.get("findings", [])

        color = "#ff4d6d" if risk.upper() == "HIGH" else "#facc15" if risk.upper() == "MEDIUM" else "#4ade80"

        high = [f for f in findings if f.get("severity", "").upper() == "HIGH"]
        medium = [f for f in findings if f.get("severity", "").upper() == "MEDIUM"]
        low = [f for f in findings if f.get("severity", "").upper() == "LOW"]

        st.markdown(f"""
        <div class='card fadein'>
            <h3>📱 {app['APK Name']}</h3>
            <p style='color:{color}; font-weight:bold; font-size:18px;'>{risk} — {score}/100</p>
            <div class='progress'><div class='fill' style='width:{score}%; background:{color}'></div></div>
            <div class='tip'><b>🔴 High Risk:</b><br>{format_items(high)}</div>
            <div class='tip'><b>🟡 Medium Risk:</b><br>{format_items(medium)}</div>
            <div class='tip'><b>🟢 Low Risk:</b><br>{format_items(low)}</div>
        </div>
        """, unsafe_allow_html=True)

    
    if export_pdf_clicked and st.session_state.results:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            for idx, app in enumerate(st.session_state.results):
                pdf_name = f"hala_report_{app['APK Name'].replace('.apk','')}.pdf"
                doc = SimpleDocTemplate(pdf_name, pagesize=A4)
                story = []
                
                styles = getSampleStyleSheet()
                title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#5a3ea1'), spaceAfter=30)
                
                story.append(Paragraph(f"HALA Security Report", title_style))
                story.append(Paragraph(f"<b>App:</b> {app['APK Name']}", styles['Normal']))
                story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))
                
                risk_text = app['Risk Level']
                risk_color = '#ff4d6d' if 'HIGH' in risk_text else '#facc15' if 'MEDIUM' in risk_text else '#4ade80'
                story.append(Paragraph(f"<b>Risk Score:</b> {app['Risk Score']}/100 - <font color='{risk_color}'>{risk_text}</font>", styles['Normal']))
                story.append(Spacer(1, 0.3 * inch))
                
                findings_data = [['Finding', 'Details']]
                for f in app.get('findings', [])[:20]:
                    if 'line' in f:
                        findings_data.append([f.get('file', 'unknown'), f.get('line', '')[:60]])
                    elif 'permission' in f:
                        findings_data.append([f.get('permission', 'unknown'), f.get('ai_fix', '')[:60]])
                
                if len(findings_data) > 1:
                    table = Table(findings_data, colWidths=[1.8*inch, 3.2*inch])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ]))
                    story.append(table)
                
                doc.build(story)
                
                with open(pdf_name, "rb") as f:
                    st.download_button(
                        label=f"📥 Download PDF - {app['APK Name']}",
                        data=f,
                        file_name=pdf_name,
                        mime="application/pdf",
                        key=f"pdf_{idx}"
                    )
        except ImportError:
            st.warning(" لتوليد PDF الرجاء تثبيت: pip install reportlab")
        except Exception as e:
            st.error(f"PDF Error: {e}")

    
    if st.session_state.results:
        df = pd.DataFrame(st.session_state.results).sort_values(by="Risk Score", ascending=False)
        st.markdown("---")
        st.subheader(" Risk Scores Overview")
        st.bar_chart(df.set_index("APK Name")["Risk Score"])

    if st.session_state.permissions_list:
        st.markdown("---")
        st.subheader("Permissions Distribution")

        p = pd.DataFrame(st.session_state.permissions_list, columns=["Permission"])
        p = p["Permission"].value_counts().reset_index()
        p.columns = ["Permission", "Count"]

        fig = px.pie(p, names="Permission", values="Count",
                     color_discrete_sequence=px.colors.sequential.Purples)

        st.plotly_chart(fig)
    

    if st.button("🏠 Back to Home"):
        st.session_state.page = "landing"
        st.rerun()
