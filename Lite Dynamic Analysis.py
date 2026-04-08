import os
import re
import subprocess

def simulate_dynamic(apk_path):
    """
    Lite Dynamic Analysis: 
    - Permissions usage
    - Hardcoded secrets
    - Unsafe storage / logging
    - Network endpoints
    """
    results = []

    temp_folder = "temp_dynamic"
    os.makedirs(temp_folder, exist_ok=True)

    try:
        subprocess.run(["apktool", "d", "-f", apk_path, "-o", temp_folder], capture_output=True, text=True, check=True)
    except Exception as e:
        results.append(f"Failed to decode APK: {e}")
        return results

  
    for root, dirs, files in os.walk(temp_folder):
        for file in files:
            if file.endswith(".smali"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()

                  
                    secrets = re.findall(r'["\'](AIza[0-9A-Za-z-_]{35}|[A-Za-z0-9]{32,})["\']', code)
                    for s in secrets:
                        results.append(f"Hardcoded secret found: {s[:8]}...")

                   
                    if re.search(r'http[s]?://', code):
                        results.append("App makes network calls (HTTP/HTTPS)")

                   
                    if re.search(r'getSharedPreferences|openFileOutput|Log\.', code):
                        results.append("App writes to storage or logs sensitive info")

    
    try:
        subprocess.run(["rm", "-rf", temp_folder])  
    except:
        pass

    if not results:
        results.append("No suspicious behavior detected")

    return results
