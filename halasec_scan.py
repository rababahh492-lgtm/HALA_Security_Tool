

import os
from androguard.core.bytecodes.apk import APK

# قائمة الصلاحيات الخطرة مع أوزانها
CRITICAL_PERMISSIONS = {
    "READ_SMS": {"weight": 45, "reason": "يقرأ رسائلك المصرفية و OTPs"},
    "SEND_SMS": {"weight": 40, "reason": "يرسل رسائل إلى أرقام مدفوعة"},
    "RECEIVE_SMS": {"weight": 35, "reason": "يعترض رسائل التحقق"},
    "READ_CONTACTS": {"weight": 25, "reason": "يسرق جهات الاتصال"},
    "CAMERA": {"weight": 15, "reason": "يصور الشاشات والمستندات"},
    "RECORD_AUDIO": {"weight": 20, "reason": "يسجل المكالمات"},
    "ACCESS_FINE_LOCATION": {"weight": 20, "reason": "يتتبع موقعك"},
    "READ_PHONE_STATE": {"weight": 15, "reason": "يقرأ رقم هاتفك و IMEI"},
    "WRITE_EXTERNAL_STORAGE": {"weight": 10, "reason": "يكتب ملفات"},
    "SYSTEM_ALERT_WINDOW": {"weight": 30, "reason": "يعرض نوافذ فوق التطبيقات (overlay attack)"}
}

def scan_manifest_flags(apk):
    """فحص AndroidManifest.xml"""
    findings = []
    try:
        manifest = apk.get_android_manifest_xml()
        if manifest is not None:
            app_tag = manifest.find("application")
            if app_tag is not None:
                allow_backup = app_tag.get("{http://schemas.android.com/apk/res/android}allowBackup")
                if allow_backup == "true":
                    findings.append({
                        "permission": "android:allowBackup=true",
                        "risk": 25,
                        "ai_fix": "ضعه على false في AndroidManifest.xml"
                    })
                
                debuggable = app_tag.get("{http://schemas.android.com/apk/res/android}debuggable")
                if debuggable == "true":
                    findings.append({
                        "permission": "android:debuggable=true",
                        "risk": 30,
                        "ai_fix": "أزله من إصدارات الإنتاج"
                    })
    except:
        pass
    return findings

def scan_apk(file_path: str):
    """تحليل APK"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"APK file not found: {file_path}")

    try:
        apk = APK(file_path)
        permissions = apk.get_permissions() or []
    except Exception:
        permissions = []

    findings = []
    risk_score = 0

    # فحص الصلاحيات
    for perm, data in CRITICAL_PERMISSIONS.items():
        for p in permissions:
            if perm.lower() in p.lower():
                findings.append({
                    "permission": p,
                    "risk": data["weight"],
                    "ai_fix": data["reason"]
                })
                risk_score += data["weight"]

    # فحص manifest
    manifest_findings = scan_manifest_flags(apk)
    for f in manifest_findings:
        findings.append(f)
        risk_score += f["risk"]

    if not findings:
        findings.append({"info": "No issues found"})

    risk_score = min(risk_score, 100)

    if risk_score >= 40:
        verdict = "HIGH RISK"
    elif risk_score >= 20:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "name": os.path.basename(file_path),
        "risk_score": risk_score,
        "permissions": permissions,
        "findings": findings,
        "verdict": verdict
    }

def main(folder_path: str):
    results = []

    if not os.path.exists(folder_path):
        raise FileNotFoundError("Folder not found!")

    for filename in os.listdir(folder_path):
        if filename.endswith(".apk"):
            file_path = os.path.join(folder_path, filename)
            try:
                result = scan_apk(file_path)
                results.append(result)
                print(f"Scanned: {filename} → {result['verdict']} ({result['risk_score']}/100)")
            except Exception as e:
                print(f"Failed to scan: {filename} - {e}")
                continue

    os.makedirs("reports", exist_ok=True)
    
    import json
    with open("reports/scan_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\nAll APKs scanned! Full details saved in reports/scan_results.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python halasec_scan.py <folder_with_apks>")
    else:
        main(sys.argv[1])
