# ============================================================
# DEEPSHIELD V2.10 - HYBRID: GOOGLE SAFE BROWSING + GEMINI
# Safe Browsing provides real-time threat intelligence.
# Gemini provides human-readable explanations.
# ============================================================

import os
import re
import math
import json
import logging
import base64
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv
from google import genai
import requests

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- API KEYS ----------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY is required")
if not SAFE_BROWSING_API_KEY:
    raise ValueError("SAFE_BROWSING_API_KEY is required")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = genai.Client(api_key=GEMINI_API_KEY)

# ---------- SAFE DOMAIN WHITELIST ----------
SAFE_DOMAINS = {
    'google.com', 'google.co.in', 'gmail.com', 'youtube.com', 'github.com',
    'stackoverflow.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'spotify.com', 'twitter.com', 'facebook.com',
    'instagram.com', 'linkedin.com', 'reddit.com', 'wikipedia.org',
    'bbc.com', 'cnn.com', 'nytimes.com', 'medium.com', 'dev.to',
    'vercel.com', 'netlify.com', 'render.com', 'heroku.com',
    'tailwindcss.com', 'reactjs.org', 'python.org', 'docker.com'
}

def is_safe_domain(url: str) -> bool:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain in SAFE_DOMAINS

# ---------- GOOGLE SAFE BROWSING CHECK ----------
def check_safe_browsing(url: str) -> dict:
    """
    Check URL against Google Safe Browsing API.
    Returns: { "malicious": bool, "threats": list, "score": int }
    """
    API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "deepshield-dlp",
            "clientVersion": "2.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data and data["matches"]:
                threats = [m["threatType"] for m in data["matches"]]
                return {
                    "malicious": True,
                    "threats": threats,
                    "score": 85 + min(len(threats) * 5, 15)  # 85-100
                }
        return {"malicious": False, "threats": [], "score": 0}
    except Exception as e:
        logger.error(f"Safe Browsing error: {e}")
        return {"malicious": False, "threats": [], "score": 0}

# ---------- HEURISTIC FLAGS ----------
def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def extract_heuristic_flags(url: str) -> list:
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_name = domain.split('.')[0] if '.' in domain else domain
    path = parsed.path

    flags = []

    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        flags.append(f"High domain entropy ({entropy:.2f}) – algorithmic generation")

    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        flags.append("Uses raw IP address – bypasses DNS filters")

    suspicious_tlds = ['.top', '.xyz', '.click', '.download', '.review', '.loan',
                       '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            flags.append(f"Suspicious TLD ({tld}) – often used in phishing")
            break

    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'facebook']
    found_brands = [b for b in brands if b in url.lower()]
    if found_brands:
        flags.append(f"Brand impersonation: {', '.join(found_brands[:2])}")

    keywords = ['login', 'verify', 'update', 'secure', 'account', 'auth', 'confirm', 'signin', 'reset', 'password']
    found_keywords = [kw for kw in keywords if kw in url.lower()]
    if found_keywords:
        flags.append(f"Deceptive keywords: {', '.join(found_keywords[:3])}")

    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if num_subdomains > 2:
        flags.append(f"Excessive subdomains ({num_subdomains})")

    if len(url) > 100:
        flags.append(f"Unusually long URL ({len(url)} chars)")

    if not flags:
        flags.append("No obvious structural anomalies detected")

    return flags

# ---------- GEMINI EXPLANATION ----------
def generate_gemini_explanation(url: str, risk_score: int, flags: list, sb_result: dict) -> dict:
    flag_text = "\n".join([f"  - {f}" for f in flags])
    threat_text = ", ".join(sb_result.get("threats", [])) if sb_result.get("malicious") else "None detected"

    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

**URL:** {url}
**Risk Score:** {risk_score}/100
**Safe Browsing Threats:** {threat_text}

**Technical Flags:**
{flag_text}

**TASK:** Write a concise explanation.
Return JSON: {{"short": "one sentence for badge (max 80 chars)", "detailed": "2-3 sentence technical analysis"}}

**Guidelines:**
- Score 0-15: SAFE – reassuring, no threats
- Score 16-40: CAUTION – some concerns
- Score 41-100: DANGEROUS – clear phishing/malware

**OUTPUT FORMAT (STRICT JSON):**
"""
    try:
        response = client.models.generate_content(
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
            "short": result.get("short", f"Risk: {risk_score}%"),
            "detailed": result.get("detailed", "Analysis unavailable.")
        }
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return {
            "short": f"Risk: {risk_score}%",
            "detailed": f"Risk score: {risk_score}%. Flags: {', '.join(flags)}"
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
    safe_browsing_threats: list

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"Scanning: {url}")

    # 1. Check whitelist
    if is_safe_domain(url):
        return ScanResponse(
            url=url,
            risk_score=0,
            threat_level="SAFE",
            short_explanation="✅ Known safe domain.",
            detailed_analysis="This domain is whitelisted as a trusted service.",
            heuristics_flagged=[],
            safe_browsing_threats=[]
        )

    # 2. Extract heuristic flags
    flags = extract_heuristic_flags(url)

    # 3. Google Safe Browsing check (REAL threat intelligence)
    sb_result = check_safe_browsing(url)

    # 4. Calculate FINAL score
    if sb_result["malicious"]:
        # Safe Browsing says it's malicious – HIGH SCORE
        final_score = sb_result["score"]
    else:
        # Not in Safe Browsing – use heuristic estimate (conservative)
        flags_count = len([f for f in flags if "suspicious" in f.lower() or "entropy" in f.lower() or "impersonation" in f.lower()])
        if flags_count >= 3:
            final_score = 60
        elif flags_count >= 2:
            final_score = 45
        elif flags_count >= 1:
            final_score = 25
        else:
            final_score = 5

    # 5. Determine threat level
    if final_score > 60:
        threat_level = "CRITICAL"
    elif final_score > 35:
        threat_level = "WARNING"
    elif final_score > 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"

    # 6. Gemini explanation
    xai = generate_gemini_explanation(url, final_score, flags, sb_result)

    return ScanResponse(
        url=url,
        risk_score=final_score,
        threat_level=threat_level,
        short_explanation=xai["short"],
        detailed_analysis=xai["detailed"],
        heuristics_flagged=flags,
        safe_browsing_threats=sb_result.get("threats", [])
    )

@app.get("/")
async def health_check():
    return {
        "status": "DeepShield V2.10 Online",
        "engine": "Google Safe Browsing + Gemini AI",
        "whitelist": "Active",
        "features": [
            "Real-time Safe Browsing checks",
            "Heuristic analysis",
            "Gemini explanation"
        ]
    }