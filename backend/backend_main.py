# ============================================================
# DEEPSHIELD DLP V2.1 - BACKEND (VirusTotal + Groq XAI)
# Deploy on Render.com
# Run: uvicorn backend_main:app --host 0.0.0.0 --port 10000
# ============================================================

import os
import re
import json
import time
import logging
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv
import requests
from groq import Groq

# ---------- CONFIG ----------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

if not GROQ_API_KEY:
    logger.error("GROQ_API_KEY missing! Set it in .env")
if not VT_API_KEY:
    logger.error("VT_API_KEY missing! Set it in .env")

# ---------- INIT APP ----------
app = FastAPI(title="DeepShield DLP API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- GROQ CLIENT ----------
groq_client = Groq(api_key=GROQ_API_KEY)

# ---------- VIRUSTOTAL RATE LIMITER ----------
_last_vt_call = 0
_vt_cache = {}

def get_vt_score(url: str) -> int:
    """
    Query VirusTotal API for a URL.
    Returns a risk score (0-100).
    Handles 4-lookups-per-minute rate limit.
    """
    global _last_vt_call

    # Check cache first
    if url in _vt_cache:
        logger.info(f"VT Cache hit for {url}")
        return _vt_cache[url]

    # Enforce 15-second gap (60s / 4 = 15s)
    now = time.time()
    diff = now - _last_vt_call
    if diff < 15:
        wait_time = 15 - diff
        logger.info(f"VT rate limit: waiting {wait_time:.1f}s")
        time.sleep(wait_time)

    _last_vt_call = time.time()

    try:
        # Step 1: Submit URL for scanning
        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post(vt_url, headers=headers, data={"url": url})

        if response.status_code != 200:
            logger.error(f"VT submission failed: {response.status_code}")
            return None

        scan_id = response.json()["data"]["id"]

        # Step 2: Get analysis report
        report_res = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers
        )

        if report_res.status_code != 200:
            logger.error(f"VT report fetch failed: {report_res.status_code}")
            return None

        stats = report_res.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 1)

        total = malicious + suspicious + undetected
        score = int(((malicious + suspicious) / max(total, 1)) * 100)

        # Cache the result
        _vt_cache[url] = score
        logger.info(f"VT score for {url}: {score}%")
        return score

    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return None

# ---------- GROQ XAI ENGINE ----------
def get_groq_explanation(url: str, vt_score: int) -> dict:
    """
    Generates a human-readable explanation using Groq Llama-3.
    Returns: { "short": "...", "detailed": "..." }
    """
    if vt_score is None:
        vt_score = 50  # Unknown / fallback

    # Build the prompt
    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

URL: {url}
VirusTotal Malicious Probability: {vt_score}%

**TASK:**
Write a JSON response with two fields:
1. "short": A single, punchy sentence for a browser badge tooltip (max 60 characters).
2. "detailed": A 2-3 sentence technical analysis for a security team, explaining WHY the URL is risky.

**GUIDELINES:**
- If score > 60: Warn clearly. Use words like "phishing", "malicious", "dangerous".
- If score 30-60: Say "suspicious" or "caution".
- If score < 30: Say it looks safe.
- Keep the tone professional and authoritative.

**OUTPUT FORMAT (STRICT JSON):**
{{"short": "...", "detailed": "..."}}
"""
    try:
        response = groq_client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=200,
            response_format={"type": "json_object"}
        )
        raw = response.choices[0].message.content.strip()
        result = json.loads(raw)
        return {
            "short": result.get("short", "Suspicious link detected"),
            "detailed": result.get("detailed", "No detailed analysis available.")
        }
    except Exception as e:
        logger.error(f"Groq error: {e}")
        return {
            "short": "Suspicious link detected",
            "detailed": f"VirusTotal score: {vt_score}%. AI explanation unavailable."
        }

# ---------- API MODELS ----------
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
    threat_level: str          # SAFE / WARNING / CRITICAL
    short_explanation: str     # For extension badge
    detailed_analysis: str     # For landing page deep-dive

# ---------- API ENDPOINT ----------
@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"Scanning: {url}")

    # 1. Get VirusTotal score
    vt_score = get_vt_score(url)

    # If VT fails, default to 60 (triggers a warning)
    if vt_score is None:
        logger.warning(f"VT failed for {url}, using default score 60")
        vt_score = 60

    # 2. Get Groq explanation
    xai = get_groq_explanation(url, vt_score)

    # 3. Determine threat level
    if vt_score > 60:
        threat_level = "CRITICAL"
    elif vt_score > 30:
        threat_level = "WARNING"
    else:
        threat_level = "SAFE"

    return ScanResponse(
        url=url,
        risk_score=vt_score,
        threat_level=threat_level,
        short_explanation=xai.get("short", "Suspicious link detected"),
        detailed_analysis=xai.get("detailed", "No detailed analysis available.")
    )

# ---------- HEALTH CHECK ----------
@app.get("/")
async def health_check():
    return {
        "status": "DeepShield DLP V2.1 Online",
        "engines": {
            "virustotal": "active" if VT_API_KEY else "inactive",
            "groq_xai": "active" if GROQ_API_KEY else "inactive"
        }
    }

# ---------- OPTIONAL: FORCE CACHE CLEAR ----------
@app.post("/api/v1/clear-cache")
async def clear_cache():
    global _vt_cache
    _vt_cache = {}
    return {"status": "Cache cleared"}