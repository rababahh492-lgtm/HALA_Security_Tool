import os
import re
import subprocess
import shutil

def dynamic_analysis(apk_path):
    findings = []

    decoded_dir = f"temp_dynamic/{os.path.basename(apk_path)}"

    
    if os.path.exists(decoded_dir):
        shutil.rmtree(decoded_dir)

    os.makedirs("temp_dynamic", exist_ok=True)

    
    try:
        subprocess.run(
            ["java", "-jar", "apktool.jar", "d", apk_path, "-o", decoded_dir, "-f"],
            timeout=120,
            capture_output=True
        )
    except Exception as e:
        return [{"type": "ERROR", "detail": str(e), "severity": "LOW"}]

    
    patterns = {
        "HARDCODED_SECRET": {
            "regex": r'(?i)(api_key|token|secret|password)[^\\n]{0,40}',
            "severity": "HIGH"
        },
        "INSECURE_HTTP": {
            "regex": r'http://',
            "severity": "MEDIUM"
        },
        "LOGGING": {
            "regex": r'Log\.(d|e|i|v)',
            "severity": "LOW"
        },
        "INSECURE_STORAGE": {
            "regex": r'getSharedPreferences|openFileOutput',
            "severity": "MEDIUM"
        }
    }

    
    for root, dirs, files in os.walk(decoded_dir):
        for file in files:
            if file.endswith((".xml", ".smali", ".txt")):
                fpath = os.path.join(root, file)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                        for vuln_type, rule in patterns.items():
                            matches = re.findall(rule["regex"], content)

                            if matches:
                                findings.append({
                                    "type": vuln_type,
                                    "file": file,
                                    "count": len(matches),
                                    "severity": rule["severity"]
                                })

                except:
                    continue

    
    shutil.rmtree(decoded_dir, ignore_errors=True)

    if not findings:
        findings.append({
            "type": "SAFE",
            "detail": "No suspicious patterns found",
            "severity": "LOW"
        })

    return findings
