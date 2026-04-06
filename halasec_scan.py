import os
from datetime import datetime
from androguard.core.bytecodes.apk import APK
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import json

REPORTS_DIR = "reports"

def scan_apk(apk_path):
    
    try:
        apk = APK(apk_path)
    except Exception as e:
        return None, f"Invalid APK file: {str(e)}"

   
    try:
        version = apk.get_androidversion_name() or "Unknown"
    except KeyError:
        version = "Unknown"

    apk_info = {
        "APK Name": apk.get_app_name() or "Unknown",
        "Package Name": apk.get_package() or "Unknown",
        "Version": version,
        "Permissions": apk.get_permissions(),
        "Activities": apk.get_activities(),
        "Services": apk.get_services(),
        "Receivers": apk.get_receivers(),
        "Providers": apk.get_providers(),
        "Scan Date": datetime.now().strftime("%Y-%m-%d"),
        "Scan Time": datetime.now().strftime("%H:%M:%S"),
        "Risk Score": min(len(apk.get_permissions()) * 5, 100),
        "Risk Level": "HIGH" if len(apk.get_permissions()) > 5 else "LOW"
    }

    return apk_info, None

def save_reports(apk_info, apk_path):
    
    if not apk_info:
        return None

    apk_name = apk_info.get("APK Name", "Unknown").replace(" ", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = os.path.join(REPORTS_DIR, f"{apk_name}_{timestamp}")
    os.makedirs(output_folder, exist_ok=True)

    # TXT
    txt_path = os.path.join(output_folder, f"{apk_name}_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for k, v in apk_info.items():
            f.write(f"{k}: {v}\n")

    # JSON
    json_path = os.path.join(output_folder, f"{apk_name}_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(apk_info, f, indent=4)

    # PDF
    pdf_path = os.path.join(output_folder, f"{apk_name}_report.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"HALA-SCAN SECURITY REPORT - {apk_name}")
    y -= 30
    for k, v in apk_info.items():
        if isinstance(v, list):
            v = ", ".join(v)
        c.drawString(50, y, f"{k}: {v}")
        y -= 20
        if y < 50:
            c.showPage()
            y = height - 50
    c.save()

    print(f">>> Scan completed: {apk_info['Risk Level']} ({apk_info['Risk Score']}/100) <<<")
    print(f"Report saved in: {output_folder}")
    return output_folder

def main(folder="test_files"):
    if not os.path.exists(folder):
        print(f"Folder {folder} does not exist!")
        return

    files = [f for f in os.listdir(folder) if f.endswith(".apk")]
    if not files:
        print("No APK files found in the folder.")
        return

    for file_name in files:
        file_path = os.path.join(folder, file_name)
        apk_result, error = scan_apk(file_path)
        if error:
            print(f"Missing AndroidManifest.xml or invalid APK: {file_name}")
        save_reports(apk_result, file_path)

if __name__ == "__main__":
    main("test_files") 
