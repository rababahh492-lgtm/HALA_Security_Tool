import subprocess
import json

def get_ai_analysis(app_info):
   
    prompt = f"Analyze the following Android app for security risks:\n"
    prompt += f"App Name: {app_info.get('APK Name')}\n"
    prompt += f"Permissions: {', '.join(app_info.get('Permissions', []))}\n"
    prompt += f"Known Vulnerabilities: {', '.join([v['Name'] for v in app_info.get('Vulnerabilities', [])])}\n"
    prompt += "Provide AI-based prediction of potential security issues."

    try:
     
        result = subprocess.run(
            ["ollama", "run", "tinyllama", "--prompt", prompt],
            capture_output=True, text=True, timeout=30
        )
        ai_response = result.stdout.strip()
        return ai_response if ai_response else "No AI response"
    except Exception as e:
        return f"AI Error: {e}"
