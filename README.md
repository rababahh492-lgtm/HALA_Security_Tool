HALA-SCAN 🚀

Your friendly Android security buddy

Hey there,,  HALA-SCAN is a tool I built to help you quickly check Android apps (APKs) for security issues. It looks at app permissions, scans for possible security risks, highlights potential vulnerabilities, and even gives you easy tips to fix them. Perfect for developers, security enthusiasts, or anyone curious about app safety.

--  What HALA-SCAN Does
Scan APKs – Upload one or multiple APK files and let HALA-SCAN do the magic.
Risk Score – Find out if an app is HIGH, MEDIUM, or LOW risk.
Vulnerability Analysis – Detailed breakdown including:
Name of the finding
Type (permissions, secrets, network, logging)
Severity (High / Medium / Low)
Suggested fix
Interactive Dashboard – Streamlit interface with:
Fun loading animations while scanning
Typing effect welcome message
Fade-in effects on results
Scrollable cards for each finding
Visual Charts – Risk score bar chart & permissions distribution pie chart
PDF Reports – Download full reports for each app
API Ready – Optional FastAPI backend to integrate scanning in other tools
-- How to Run
Clone the repo:
git clone https://github.com/rababahh492-lgtm/HALA_Security_Tool.git
cd HALA_Security_Tool
Set up a virtual environment & install dependencies:
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
Run the Streamlit dashboard:
streamlit run dashboard.py
Upload APK files
Wait a few seconds for the analysis
View results and download PDF reports
Optional CLI scanning:
python halasec_scan.py test_files
Optional FastAPI backend:
uvicorn api:app --reload
Send a POST request to /scan/ with an APK file and get a JSON report
-- How HALA-SCAN Works:
Static Analysis – Checks APK permissions and calculates a risk score.
Dynamic-like Analysis – Scans the app’s smali/XML files for:
Hardcoded secrets (API keys, passwords, tokens)
Insecure HTTP connections
Debug logs or print statements
Insecure storage usage
Full Analysis – Combines everything and gives a verdict: HIGH RISK or LOW RISK
-- Example Output:
{
  "app": "InsecureBankv2.apk",
  "risk_score": 55,
  "verdict": "HIGH RISK",
  "permissions": ["SEND_SMS", "READ_CONTACTS", "INTERNET"],
  "findings": [
    {"type": "EXPOSED_SECRET", "severity": "HIGH", "detail": "Hardcoded API key found"},
    {"type": "REAL_NETWORK_RISK", "severity": "HIGH", "detail": "App uses HTTP with INTERNET permission"}
  ]
}
---- Disclaimer :

HALA-SCAN is for educational and ethical purposes only.
Do not use it to hack apps without the owner’s permission.

-- Future Improvements
Real runtime analysis using emulator or sandbox
AI-based predictions for unknown vulnerabilities
Support for iOS IPA files
