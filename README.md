🔐 HalaScan - Mobile Security Scanner

HalaScan is a simple security tool I built to analyze Android APK files and check for potential vulnerabilities.
The idea behind it is to make APK analysis easier and more understandable, especially for students or beginners in cybersecurity.


-- What it does: 

Scans APK files
Checks permissions and app components
Detects some common security issues
Gives a risk score (Low / Medium / High)
Generates reports (TXT, JSON, PDF)
Shows results in a simple dashboard 

---

-- How it works

Basically:

APK file → Scanner → Report → Dashboard


-- Tools I used:

Python
Streamlit (for the dashboard)
Androguard (for APK analysis)


-- How to run it:

1- Install the requirements:
pip install -r requirements.txt

2- Run the scanner:
python run_halascan.py

3-Run the dashboard:
streamlit run dashboard.py

 
-- Output example

After scanning, you will see:

Risk level (Low / Medium / High)
List of findings (if any)
Generated reports saved in the reports/ folder


-- Project structure (simplified)

backend/ → core logic
reports/ → scan results
test_files/ → sample APKs
uploads/ → dashboard uploads
dashboard.py → UI
halasec_scan.py → scanner


-- Future ideas:
Improve detection accuracy
Add more vulnerability checks
Maybe integrate AI later
