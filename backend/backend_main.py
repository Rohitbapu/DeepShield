# ============================================================
# DEEPSHIELD V2.16 - FINAL: ML + GEMINI (IF AVAILABLE)
# ============================================================

import os
import sys
import json
import logging
import traceback
import torch
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------- INIT FASTAPI ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- ATTEMPT TO LOAD GEMINI ----------
gemini_available = False
gemini_client = None
try:
    from google import genai
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_key_here":
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        gemini_available = True
        logger.info("✅ Gemini client initialized")
    else:
        logger.warning("⚠️ GEMINI_API_KEY not set or invalid. Gemini disabled.")
except ImportError as e:
    logger.error(f"❌ Gemini import error: {e}")
except Exception as e:
    logger.error(f"❌ Gemini init error: {e}")
    logger.error(traceback.format_exc())


# ---------- ATTEMPT TO LOAD ML MODEL IN BACKGROUND ----------
# Initialize the global variable, but do not load the model yet!
detector = None

@app.on_event("startup")
async def load_ml_model():
    global detector
    logger.info("⏳ Server bound to port. Loading ML Model in background...")
    try:
        from phishing_detection_py import PhishingDetector
        detector = PhishingDetector()
        if torch.cuda.is_available():
            detector.model_pipeline.model.to('cuda:0')
            detector.model_pipeline.device = torch.device('cuda:0')
            logger.info("🚀 GPU Active: PhishGuard Engine Ready")
        else:
            logger.info("💻 CPU Mode: PhishGuard Engine Running")
    except Exception as e:
        logger.error(f"❌ ML model load failed: {e}")
        logger.error(traceback.format_exc())


# ---------- EXPLANATION GENERATOR ----------
def generate_explanation(url: str, is_phish: bool, ml_score: float):
    if not gemini_available or gemini_client is None:
        # Fallback: basic explanation with ML score
        if is_phish:
            short = f"🚨 Phishing ({ml_score:.0%} confidence)"
            detailed = f"This URL is classified as phishing with {ml_score:.1%} confidence by the ML model."
        else:
            short = f"✅ Safe ({ml_score:.0%} confidence)"
            detailed = f"This URL is classified as safe with {ml_score:.1%} confidence by the ML model."
        return {"short": short, "detailed": detailed}

    # Try Gemini
    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

URL: {url}
ML Model Confidence: {ml_score:.1%}
Classification: {'PHISHING' if is_phish else 'SAFE'}

TASK: Write a concise explanation for this URL.
Return JSON: {{"short": "one sentence for badge (max 80 chars)", "detailed": "2-3 sentence analysis"}}

Guidelines:
- If phishing: Be clear and alarming.
- If safe: Be reassuring.
- Keep it professional and concise.

OUTPUT FORMAT (STRICT JSON):
"""
    try:
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "temperature": 0.0,
                "max_output_tokens": 300,
            }
        )
        raw = response.text.strip()
        # Clean markdown if present
        if raw.startswith("```json"):
            raw = raw.replace("```json", "").replace("```", "").strip()
        elif raw.startswith("```"):
            raw = raw.replace("```", "").strip()
        result = json.loads(raw)
        return {
            "short": result.get("short", "🚨 Phishing" if is_phish else "✅ Safe"),
            "detailed": result.get("detailed", f"ML confidence: {ml_score:.1%}")
        }
    except Exception as e:
        logger.error(f"Gemini generation error: {e}")
        # Fallback
        if is_phish:
            return {"short": f"🚨 Phishing ({ml_score:.0%})", "detailed": f"ML confidence: {ml_score:.1%}. Gemini unavailable."}
        else:
            return {"short": f"✅ Safe ({ml_score:.0%})", "detailed": f"ML confidence: {ml_score:.1%}. Gemini unavailable."}

# ============================================================
# API MODELS
# ============================================================

class ScanRequest(BaseModel):
    url: str
    @field_validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        return v

class ScanResponse(BaseModel):
    url: str
    risk_score: int
    threat_level: str
    short_explanation: str
    detailed_analysis: str
    ml_confidence: float

# ============================================================
# API ENDPOINT
# ============================================================

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    if detector is None:
        raise HTTPException(status_code=503, detail="ML model is still loading. Please try again in a few seconds.")

    url = payload.url
    logger.info(f"🔍 Scanning: {url[:60]}...")

    try:
        safe_url = url[:500]
        result = detector.predict(safe_url)
        pred = result["prediction"][0]
        is_phish = (pred["label"] == 'phishing')
        ml_score = pred["score"]

        logger.info(f"ML Result: {'Phishing' if is_phish else 'Safe'} | Confidence: {ml_score:.2%}")

        if is_phish:
            risk_score = int(ml_score * 100)
            risk_score = max(risk_score, 60)
        else:
            risk_score = int((1 - ml_score) * 15)
            risk_score = min(risk_score, 20)

        if risk_score > 60:
            threat_level = "CRITICAL"
        elif risk_score > 35:
            threat_level = "WARNING"
        elif risk_score > 15:
            threat_level = "CAUTION"
        else:
            threat_level = "SAFE"

        xai = generate_explanation(url, is_phish, ml_score)

        return ScanResponse(
            url=url,
            risk_score=risk_score,
            threat_level=threat_level,
            short_explanation=xai["short"],
            detailed_analysis=xai["detailed"],
            ml_confidence=ml_score
        )

    except Exception as e:
        logger.error(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health_check():
    return {
        "status": "DeepShield V2.16 Online",
        "engine": "phishing-detection-py ML",
        "gemini_available": gemini_available,
        "model_loaded": detector is not None,
        "gpu_available": torch.cuda.is_available() if detector else False
    }

@app.get("/")
async def root():
    return {
        "status": "DeepShield V2.16 Online",
        "endpoints": {
            "scan": "POST /api/v1/scan",
            "health": "GET /health"
        }
    }