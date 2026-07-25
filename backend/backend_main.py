# ============================================================
# DEEPSHIELD DLP V2.7 - GEMINI-ONLY EDITION
# Optimized for free tier: deterministic scoring + Gemini explanation
# ============================================================

import os
import re
import math
import json
import logging
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv
from google import genai

# ---------- CONFIG ----------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY missing! Set it in .env")
    raise ValueError("GEMINI_API_KEY environment variable is required")

# ---------- INIT APP ----------
app = FastAPI(title="DeepShield DLP - Gemini AI", version="2.7")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- GEMINI CLIENT ----------
client = genai.Client(api_key=GEMINI_API_KEY)

# ---------- DETERMINISTIC SCORING ENGINE ----------
def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for randomness detection."""
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def get_deterministic_score_and_flags(url: str) -> tuple:
    """
    Returns (risk_score 0-100, list_of_flags) based on fixed rules.
    This is 100% consistent and never changes for the same URL.
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_name = domain.split('.')[0] if '.' in domain else domain

    score = 0
    flags = []

    # 1. Entropy (max +20)
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        score += 20
        flags.append(f"High entropy ({entropy:.2f}) suggests algorithmic generation (DGA)")

    # 2. IP address (max +30)
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 30
        flags.append("Uses raw IP address instead of domain name (bypasses DNS filters)")

    # 3. Suspicious TLDs (max +20)
    suspicious_tlds = ['.top', '.xyz', '.click', '.download', '.review', '.loan', 
                       '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 20
        tld = domain.split('.')[-1]
        flags.append(f"Suspicious TLD (.{tld}) commonly used for phishing")

    # 4. Suspicious keywords (max +15)
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 
                'paypal', 'auth', 'confirm', 'signin', 'reset', 'password']
    found = [kw for kw in keywords if kw in url.lower()]
    if found:
        score += min(15, len(found) * 5)
        flags.append(f"Contains deceptive keywords: {', '.join(found[:3])}")

    # 5. Subdomain count (max +15)
    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if num_subdomains > 2:
        score += min(15, num_subdomains * 5)
        flags.append(f"Excessive subdomains ({num_subdomains}) - masquerading attempt")

    # 6. URL length (max +10)
    if len(url) > 100:
        score += 10
        flags.append("Unusually long URL - likely obfuscated")

    # Cap at 100
    score = min(score, 100)

    # If no flags, add a safe note
    if not flags:
        flags.append("No suspicious patterns detected")

    return score, flags

# ---------- GEMINI EXPLANATION GENERATOR ----------
def generate_gemini_explanation(url: str, risk_score: int, flags: list) -> dict:
    """
    Uses Gemini to generate human-readable explanation.
    Falls back to heuristic-only if Gemini fails.
    """
    
    flag_text = "\n".join([f"  - {f}" for f in flags])

    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

URL: {url}
Deterministic Risk Score: {risk_score}/100 (computed from structural flags)

Technical Flags Detected:
{flag_text}

TASK: Write a human-readable explanation for this URL.
Return a JSON with two fields:
1. "short": A single, punchy sentence for a browser badge (max 80 characters).
2. "detailed": A 2-3 sentence technical analysis explaining why the URL is risky or safe.

Guidelines:
- If score > 60: be clearly alarming, mention specific flags.
- If score 30-60: express caution.
- If score < 30: reassure safety, explain why it's safe.
- Base your explanation strictly on the flags above.
- Keep tone professional and authoritative.

OUTPUT FORMAT (STRICT JSON):
{{"short": "...", "detailed": "..."}}
"""
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",  # Fast, efficient, free
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "temperature": 0.0,    # Consistent output
                "max_output_tokens": 300,
            }
        )
        
        raw = response.text.strip()
        logger.info(f"Gemini response: {raw[:200]}...")
        
        # Clean markdown if present
        if raw.startswith("```json"):
            raw = raw.replace("```json", "").replace("```", "").strip()
        elif raw.startswith("```"):
            raw = raw.replace("```", "").strip()
            
        result = json.loads(raw)
        return {
            "short": result.get("short", f"Risk score: {risk_score}%"),
            "detailed": result.get("detailed", f"Risk score: {risk_score}%. Flags: {', '.join(flags)}")
        }
        
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        # Fallback: use heuristic-only explanation
        return {
            "short": f"Risk score: {risk_score}%",
            "detailed": f"Risk score: {risk_score}%. Technical flags: {', '.join(flags)}"
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
    threat_level: str
    short_explanation: str
    detailed_analysis: str
    heuristics_flagged: list

# ---------- API ENDPOINT ----------
@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"🔍 Scanning: {url}")

    # 1. Deterministic scoring (always consistent)
    risk_score, flags = get_deterministic_score_and_flags(url)

    # 2. Threat level
    if risk_score > 60:
        threat_level = "CRITICAL"
    elif risk_score > 30:
        threat_level = "WARNING"
    else:
        threat_level = "SAFE"

    # 3. Gemini explanation (with fallback)
    xai = generate_gemini_explanation(url, risk_score, flags)

    return ScanResponse(
        url=url,
        risk_score=risk_score,
        threat_level=threat_level,
        short_explanation=xai["short"],
        detailed_analysis=xai["detailed"],
        heuristics_flagged=flags
    )

# ---------- HEALTH CHECK ----------
@app.get("/")
async def health_check():
    return {
        "status": "DeepShield DLP V2.7 Online",
        "engine": "Google Gemini 2.5 Flash",
        "api_key_configured": "Yes" if GEMINI_API_KEY else "No",
        "score_method": "rule-based (consistent, deterministic)",
        "fallback_enabled": "Yes"
    }

# ---------- DEBUG ENDPOINT ----------
@app.post("/api/v1/debug")
async def debug_url(payload: ScanRequest):
    """Debug endpoint to see raw flags without Gemini call."""
    url = payload.url
    score, flags = get_deterministic_score_and_flags(url)
    return {
        "url": url,
        "risk_score": score,
        "heuristics_flagged": flags,
        "note": "This is only the heuristic analysis, not the AI explanation."
    }