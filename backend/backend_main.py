# ============================================================
# DEEPSHIELD V2.5 - NVIDIA NIM (Gemma 2 27B) + Deterministic Scoring
# Uses NVIDIA's free API with Gemma 2 27B for explanations
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
import requests

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- CONFIG ----------
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

if not NVIDIA_API_KEY:
    logger.warning("NVIDIA_API_KEY not set! Using fallback.")

app = FastAPI(title="DeepShield DLP - NVIDIA NIM", version="2.5")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------- DETERMINISTIC SCORING ENGINE ----------
def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def get_deterministic_score_and_flags(url: str) -> tuple:
    """Returns (risk_score 0-100, list_of_flags) based on fixed rules."""
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_name = domain.split('.')[0] if '.' in domain else domain

    score = 0
    flags = []

    # 1. Entropy (max +20)
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        score += 20
        flags.append(f"High entropy ({entropy:.2f}) indicates algorithmic generation (DGA)")

    # 2. IP address (max +30)
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 30
        flags.append("Uses raw IP address instead of domain name")

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
        flags.append(f"Excessive subdomains ({num_subdomains})")

    # 6. URL length (max +10)
    if len(url) > 100:
        score += 10
        flags.append("Unusually long URL")

    # Cap at 100
    score = min(score, 100)

    # If no flags, add a safe note
    if not flags:
        flags.append("No suspicious patterns detected")

    return score, flags

# ---------- NVIDIA NIM EXPLANATION GENERATOR ----------
def generate_nvidia_explanation(url: str, risk_score: int, flags: list) -> dict:
    """Uses NVIDIA NIM (Gemma 2 27B) to generate explanation."""
    
    if not NVIDIA_API_KEY:
        return {
            "short": f"Risk score: {risk_score}%",
            "detailed": f"Risk score: {risk_score}%. Flags: {', '.join(flags)}"
        }

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
- If score > 60: be clearly alarming.
- If score 30-60: express caution.
- If score < 30: reassure safety.
- Base your explanation strictly on the flags above.
- Keep tone professional and authoritative.

OUTPUT FORMAT (STRICT JSON):
{{"short": "...", "detailed": "..."}}
"""
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "google/gemma-2-27b-it",
        "messages": [
            {"role": "system", "content": "You are DeepShield. Always respond with valid JSON only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 300,
        "top_p": 0.95,
        "stream": False
    }

    try:
        response = requests.post(NVIDIA_URL, headers=headers, json=payload, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            raw = data["choices"][0]["message"]["content"].strip()
            
            # Try to parse JSON (handle markdown if present)
            if raw.startswith("```json"):
                raw = raw.replace("```json", "").replace("```", "").strip()
            elif raw.startswith("```"):
                raw = raw.replace("```", "").strip()
            
            result = json.loads(raw)
            return {
                "short": result.get("short", f"Risk score: {risk_score}%"),
                "detailed": result.get("detailed", f"Risk score: {risk_score}%. Flags: {', '.join(flags)}")
            }
        else:
            logger.error(f"NVIDIA API error: {response.status_code} - {response.text}")
            return {
                "short": f"Risk score: {risk_score}%",
                "detailed": f"Risk score: {risk_score}%. NVIDIA API unavailable. Flags: {', '.join(flags)}"
            }
            
    except requests.exceptions.Timeout:
        logger.error("NVIDIA API timeout")
        return {
            "short": f"Risk score: {risk_score}%",
            "detailed": f"Risk score: {risk_score}%. Explanation timeout."
        }
    except Exception as e:
        logger.error(f"NVIDIA API error: {e}")
        return {
            "short": f"Risk score: {risk_score}%",
            "detailed": f"Risk score: {risk_score}%. Error: {str(e)[:100]}"
        }

# ---------- API ----------
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

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"Scanning: {url}")

    # 1. Deterministic scoring (always the same for the same URL)
    risk_score, flags = get_deterministic_score_and_flags(url)

    # 2. Threat level
    if risk_score > 60:
        threat_level = "CRITICAL"
    elif risk_score > 30:
        threat_level = "WARNING"
    else:
        threat_level = "SAFE"

    # 3. NVIDIA explanation
    xai = generate_nvidia_explanation(url, risk_score, flags)

    return ScanResponse(
        url=url,
        risk_score=risk_score,
        threat_level=threat_level,
        short_explanation=xai["short"],
        detailed_analysis=xai["detailed"],
        heuristics_flagged=flags
    )

@app.get("/")
async def health_check():
    return {
        "status": "DeepShield V2.5 Online",
        "engine": "NVIDIA NIM (Gemma 2 27B)",
        "nvidia_api_configured": "Yes" if NVIDIA_API_KEY else "No",
        "score_method": "rule-based (consistent)"
    }