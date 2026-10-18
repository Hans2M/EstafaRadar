import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .schemas import ScanRequest, ScanResult
from .engine import analyze_url, analyze_qr, analyze_message

app = FastAPI(title="EstafaRadar API", version="0.1.0", description="Analizador estático; no visita URLs ni verifica pagos.")
origins = [v.strip() for v in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if v.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "external_fetch": True, "safe_inspection": True, "store_analyses": False}

@app.post("/api/v1/analyze/url", response_model=ScanResult)
def url_scan(data: ScanRequest):
    return analyze_url(data.value)

@app.post("/api/v1/analyze/qr", response_model=ScanResult)
def qr_scan(data: ScanRequest):
    return analyze_qr(data.value)

@app.post("/api/v1/analyze/message", response_model=ScanResult)
def message_scan(data: ScanRequest):
    return analyze_message(data.value)
