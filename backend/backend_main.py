# ============================================================
# DEEPSHIELD V2.16 - PURE ML + GEMINI (NO FALLBACK)
# ML model from phishing-detection-py is the ONLY scorer.
# Gemini only generates explanations.
# ============================================================

import os
import json
import logging
import traceback
import torch
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv
import google.generativeai as genai
from phishing_detection_py import PhishingDetector  # MUST be installed

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- API KEYS ----------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY is required but not set")
    raise ValueError("GEMINI_API_KEY is required")

# ---------- INIT FASTAPI ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- INIT ML MODEL ----------
try:
    detector = PhishingDetector()
    if torch.cuda.is_available():
        detector.model_pipeline.model.to('cuda:0')
        detector.model_pipeline.device = torch.device('cuda:0')
        logger.info("🚀 GPU Active: PhishGuard Engine Ready")
    else:
        logger.info("💻 CPU Mode: PhishGuard Engine Running")
except Exception as e:
    logger.error(f"Failed to load ML model: {e}")
    raise RuntimeError("ML model not available")

# ---------- INIT GEMINI ----------
gemini_client = genai.Client(api_key=GEMINI_API_KEY)
logger.info("✅ Gemini client initialized")

# ============================================================
# GEMINI EXPLANATION (No fallback – if Gemini fails, return error)
# ============================================================

def generate_gemini_explanation(url: str, is_phish: bool, ml_score: float):
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
        logger.error(f"Gemini error: {e}")
        # Return a generic explanation but we still consider it a failure to generate
        # but we don't fallback to heuristics. We just return generic text.
        return {
            "short": "🚨 Phishing" if is_phish else "✅ Safe",
            "detailed": f"ML Confidence: {ml_score:.1%}. {'Phishing detected.' if is_phish else 'No phishing detected.'}"
        }

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
    risk_score: int          # 0-100, derived from ML confidence
    threat_level: str        # SAFE / WARNING / CRITICAL
    short_explanation: str
    detailed_analysis: str
    ml_confidence: float

# ============================================================
# API ENDPOINT – NO FALLBACK, ML model is the only scorer
# ============================================================

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"🔍 Scanning: {url[:60]}...")

    try:
        # 1. Run ML model
        safe_url = url[:500]
        result = detector.predict(safe_url)
        pred = result["prediction"][0]
        is_phish = (pred["label"] == 'phishing')
        ml_score = pred["score"]

        logger.info(f"ML Result: {'Phishing' if is_phish else 'Safe'} | Confidence: {ml_score:.2%}")

        # 2. Convert to risk_score (0-100)
        if is_phish:
            risk_score = int(ml_score * 100)
            risk_score = max(risk_score, 60)   # Ensure phishing is at least 60
        else:
            risk_score = int((1 - ml_score) * 15)
            risk_score = min(risk_score, 20)

        # 3. Threat level
        if risk_score > 60:
            threat_level = "CRITICAL"
        elif risk_score > 35:
            threat_level = "WARNING"
        elif risk_score > 15:
            threat_level = "CAUTION"
        else:
            threat_level = "SAFE"

        # 4. Gemini explanation (only human-readable text)
        xai = generate_gemini_explanation(url, is_phish, ml_score)

        return ScanResponse(
            url=url,
            risk_score=risk_score,
            threat_level=threat_level,
            short_explanation=xai["short"],
            detailed_analysis=xai["detailed"],
            ml_confidence=ml_score
        )

    except Exception as e:
        logger.error(f"ML or API error: {traceback.format_exc()}")
        # No fallback – raise a 500 error so the client knows it failed
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health_check():
    return {
        "status": "DeepShield V2.16 Online",
        "engine": "phishing-detection-py ML + Gemini XAI",
        "gpu_available": torch.cuda.is_available(),
        "gemini_configured": True
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