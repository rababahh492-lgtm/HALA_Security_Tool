# HalaScan – Android Security Scanner 🛡️

**HalaScan** is a comprehensive tool for scanning Android applications (APKs) and detecting security vulnerabilities safely and efficiently. It comes with an attractive **Dashboard** to display results instantly without excessive console output.

---

## 🚀 Key Features

- Upload APKs and run automatic analysis without excessive output  
- Detect dangerous permissions with AI-based recommendations  
- Calculate **Risk Score** for each APK with verdict (LOW/HIGH RISK)  
- Beautiful Dashboard with colors, progress bars, and results table  
- Support for scanning **multiple APKs at once**  
- Export reports to TXT, JSON, PDF  
- GitHub-friendly: avoids committing large APK files (>100MB)  

---

## 📂 Project Structure
HALA_Security_Tool/
├─ backend/ # Scanning scripts
├─ frontend/ # Dashboard & Streamlit interface
├─ test_files/ # APK test files (large files excluded)
├─ uploads/ # Uploaded APKs for analysis
├─ reports/ # Scan results
├─ .venv/ # Python virtual environment
├─ dashboard.py # Streamlit dashboard interface
├─ halasec_scan.py # APK scanning script
├─ requirements.txt # Required Python packages
└─ README.md


---

## 🛠️ Requirements

1. Python 3.10 or newer  
2. Install dependencies:

```bash
pip install -r requirements.txt

How to Run
1️⃣ Launch the Dashboard:
streamlit run dashboard.py

Open the URL provided by Streamlit (usually http://localhost:8501)
Upload your APK and the scan starts automatically
Results are displayed instantly without extra console output

2️⃣ Run the Scan Script Directly:
python halasec_scan.py test_files

Generates reports for each APK in the reports/ folder
Includes TXT, JSON, PDF formats

Developer Notes:
Avoid committing large APK files to GitHub (>100MB)
Keep the .venv updated to prevent package issues
You can extend the Dashboard with additional charts or progress bars



