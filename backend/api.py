from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.scanner import scan_apk  
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("test_files", exist_ok=True)

@app.post("/scan/")
async def scan_apk_file(file: UploadFile = File(...)):
    
    temp_path = f"test_files/{file.filename}"
    with open(temp_path, "wb") as f:
        f.write(await file.read())

    result = scan_apk(temp_path)  
    return result
