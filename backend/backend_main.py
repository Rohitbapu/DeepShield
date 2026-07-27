# ============================================================
# DEEPSHIELD DLP V4.5 - OPTIMIZED 3-LAYER SECURITY ENGINE
# Layer 1: Google Safe Browsing v4 (API)
# Layer 2: Local PyTorch ML Engine (GPU / AVX Accelerated CPU)
# Layer 3: Gemini 2.5 Flash (Production Fast Inference)
# ============================================================

import os
import json
import logging
import asyncio
import requests
import torch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

# ---------- LOGGING CONFIGURATION ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger("DeepShieldEngine")

load_dotenv()

# ---------- ENVIRONMENT VARIABLES ----------
# Note: Google Gen AI SDK automatically picks up GEMINI_API_KEY or GOOGLE_API_KEY
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

# Default Production Model (Fastest latency for real-time security scanning)
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-flash")

# ---------- FASTAPI INITIALIZATION ----------
app = FastAPI(
    title="DeepShield DLP Enterprise API",
    version="4.5.0",
    description="Multi-layered threat analysis backend integrating Google Safe Browsing, Local PyTorch ML, and Gemini Flash."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- GLOBAL ENGINE STATE ----------
ml_detector = None
gemini_client = None
gemini_active = False
safe_browsing_active = False

# ============================================================
# ENGINE INITIALIZATION ON STARTUP
# ============================================================

@app.on_event("startup")
async def initialize_security_layers():
    global ml_detector, gemini_client, gemini_active, safe_browsing_active
    logger.info("⚡ Initializing DeepShield Security Pipeline...")

    # Layer 1: Google Safe Browsing API Check
    if SAFE_BROWSING_API_KEY and SAFE_BROWSING_API_KEY != "your_google_cloud_api_key_here":
        safe_browsing_active = True
        logger.info("✅ Layer 1: Google Safe Browsing API configured.")
    else:
        logger.warning("⚠️ Layer 1: SAFE_BROWSING_API_KEY missing. Safe Browsing skipped.")

    # Layer 2: Local PyTorch ML Model Check
    try:
        from phishing_detection_py import PhishingDetector
        ml_detector = PhishingDetector()
        if torch.cuda.is_available():
            ml_detector.model_pipeline.model.to('cuda:0')
            ml_detector.model_pipeline.device = torch.device('cuda:0')
            logger.info("✅ Layer 2: PyTorch ML Model loaded on CUDA (GPU Active).")
        else:
            logger.info("✅ Layer 2: PyTorch ML Model loaded on CPU (AVX Accelerated).")
    except Exception as e:
        logger.error(f"❌ Layer 2 initialization failed: {e}")

    # Layer 3: Google Gen AI SDK Initialization
    try:
        from google import genai
        # Client automatically reads GEMINI_API_KEY / GOOGLE_API_KEY from environment
        gemini_client = genai.Client()
        gemini_active = True
        logger.info(f"✅ Layer 3: Gemini Client initialized (Target Model: {DEFAULT_GEMINI_MODEL}).")
    except Exception as e:
        logger.error(f"❌ Layer 3 initialization failed (Check API Key environment variable): {e}")

    logger.info("🚀 All security systems online and ready for traffic.")

# ============================================================
# LAYER 1: GOOGLE SAFE BROWSING VERIFICATION
# ============================================================

def check_google_safe_browsing(url: str) -> dict:
    if not safe_browsing_active:
        return {"flagged": False, "threat_types": [], "status": "SKIPPED"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "deepshield-dlp", "clientVersion": "4.5.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=3.0)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data and len(data["matches"]) > 0:
                threats = [match["threatType"] for match in data["matches"]]
                logger.warning(f"🚨 Safe Browsing Flagged: {threats}")
                return {"flagged": True, "threat_types": threats, "status": "FLAGGED"}
            return {"flagged": False, "threat_types": [], "status": "CLEAN"}
        return {"flagged": False, "threat_types": [], "status": f"API_ERROR_{response.status_code}"}
    except Exception as e:
        logger.error(f"Safe Browsing Connection Error: {e}")
        return {"flagged": False, "threat_types": [], "status": "TIMEOUT_OR_ERROR"}

# ============================================================
# LAYER 2: LOCAL PYTORCH ML MODEL VERIFICATION
# ============================================================

def check_local_ml_model(url: str) -> dict:
    if ml_detector is None:
        return {"is_phishing": False, "confidence": 0.0, "status": "UNAVAILABLE"}

    try:
        safe_url = url[:500]
        result = ml_detector.predict(safe_url)
        prediction = result["prediction"][0]
        
        is_phish = (prediction["label"].lower() == 'phishing')
        confidence = float(prediction["score"])

        return {
            "is_phishing": is_phish,
            "confidence": confidence,
            "status": "SUCCESS"
        }
    except Exception as e:
        logger.error(f"Local ML inference error: {e}")
        return {"is_phishing": False, "confidence": 0.0, "status": "ERROR"}

# ============================================================
# LAYER 3: GEMINI AI REASONING & FORENSIC SYNTHESIS
# ============================================================

def generate_ai_explanation(url: str, safe_browsing_res: dict, ml_res: dict, composite_score: int) -> dict:
    if not gemini_active or gemini_client is None:
        return {
            "short": f"Risk Score: {composite_score}/100",
            "detailed": f"Evaluated by heuristic models. Risk score set to {composite_score}%.",
            "indicators": ["Local ML analysis completed", "Safe Browsing check finished"]
        }

    prompt = f"""
You are DeepShield DLP, an advanced cyber threat detection AI.
Target URL: {url}
Calculated Composite Threat Score: {composite_score}/100

Input Security Diagnostics:
1. Google Safe Browsing: {'FLAGGED (' + str(safe_browsing_res['threat_types']) + ')' if safe_browsing_res['flagged'] else 'CLEAN / UNFLAGGED'}
2. Local PyTorch Transformer: {'PHISHING' if ml_res['is_phishing'] else 'SAFE'} (Confidence: {ml_res['confidence']:.1%})

Task:
Perform a rapid diagnostic evaluation of the URL structure and security checks.

Return STRICT JSON matching this format:
{{
  "short": "Short summary title under 70 characters (e.g., 🚨 Suspicious Login Page Detected)",
  "detailed": "2-3 technical sentences detailing threat mechanics or verification factors.",
  "indicators": [
    "Observation 1 (e.g., Domain uses character substitution to impersonate brand)",
    "Observation 2 (e.g., Verified clean on Google Safe Browsing threat database)"
  ]
}}
"""

    try:
        response = gemini_client.models.generate_content(
            model=DEFAULT_GEMINI_MODEL,
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "temperature": 0.1,
                "max_output_tokens": 350,
            }
        )
        parsed = json.loads(response.text.strip())
        return {
            "short": parsed.get("short", f"Threat Level: {composite_score}%"),
            "detailed": parsed.get("detailed", "Diagnostic analysis completed."),
            "indicators": parsed.get("indicators", [])
        }
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return {
            "short": f"Evaluated Threat Score: {composite_score}/100",
            "detailed": f"Local ML score: {ml_res['confidence']:.1%}. Safe Browsing status: {safe_browsing_res['status']}.",
            "indicators": ["Fallback diagnostic active"]
        }

# ============================================================
# DATA SCHEMAS
# ============================================================

class ScanRequest(BaseModel):
    url: str

    @field_validator('url')
    def validate_url_format(cls, v):
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        return v

class LayerResults(BaseModel):
    google_safe_browsing: dict
    local_ml_engine: dict

class ScanResponse(BaseModel):
    url: str
    risk_score: int
    threat_level: str
    short_explanation: str
    detailed_analysis: str
    key_indicators: list[str]
    layer_diagnostics: LayerResults

# ============================================================
# PRIMARY SCAN ENDPOINT
# ============================================================

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url_pipeline(payload: ScanRequest):
    url = payload.url
    logger.info(f"🔍 [SCAN START] Target: {url}")

    # Run Layer 1 and Layer 2 concurrently
    sb_task = asyncio.to_thread(check_google_safe_browsing, url)
    ml_task = asyncio.to_thread(check_local_ml_model, url)
    
    sb_result, ml_result = await asyncio.gather(sb_task, ml_task)

    # Risk Score Calculation Algorithm
    composite_risk = 0

    if sb_result.get("flagged"):
        composite_risk += 60

    if ml_result.get("is_phishing"):
        ml_weight = int(ml_result.get("confidence", 0.0) * 40)
        composite_risk += max(ml_weight, 25)
    else:
        if ml_result.get("confidence", 1.0) < 0.70 and not sb_result.get("flagged"):
            composite_risk += 15

    composite_risk = min(max(composite_risk, 0), 100)

    # Categorization
    if composite_risk >= 70:
        threat_level = "CRITICAL"
    elif composite_risk >= 40:
        threat_level = "WARNING"
    elif composite_risk >= 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"

    # Layer 3 Gemini Inference
    ai_xai = generate_ai_explanation(url, sb_result, ml_result, composite_risk)

    return ScanResponse(
        url=url,
        risk_score=composite_risk,
        threat_level=threat_level,
        short_explanation=ai_xai["short"],
        detailed_analysis=ai_xai["detailed"],
        key_indicators=ai_xai["indicators"],
        layer_diagnostics=LayerResults(
            google_safe_browsing=sb_result,
            local_ml_engine=ml_result
        )
    )

@app.get("/health")
async def health_check():
    return {
        "status": "DeepShield Engine Online",
        "active_gemini_model": DEFAULT_GEMINI_MODEL,
        "layers": {
            "google_safe_browsing": safe_browsing_active,
            "local_pytorch_ml": ml_detector is not None,
            "gemini_api": gemini_active
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run("backend_main:app", host="0.0.0.0", port=port, reload=True)
