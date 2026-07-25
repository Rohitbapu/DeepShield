# ============================================================
# DEEPSHIELD DLP V2.8 - UPDATED SCORING ENGINE
# Fixed: Properly detects brand impersonation + phishing patterns
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

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY is required")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = genai.Client(api_key=GEMINI_API_KEY)

# ---------- UPDATED SCORING ENGINE ----------

def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

# Brand keywords to detect phishing impersonation
BRAND_KEYWORDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 
    'spotify', 'facebook', 'instagram', 'twitter', 'linkedin',
    'bank', 'banking', 'chase', 'wells fargo', 'boa', 'hsbc',
    'docusign', 'dropbox', 'adobe', 'outlook', 'office365'
]

# Generic deceptive keywords
DECEPTIVE_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'auth', 
    'confirm', 'signin', 'reset', 'password', 'validate',
    'authenticate', 'recover', 'unlock', 'alert', 'notice'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.top', '.xyz', '.click', '.download', '.review', '.loan', 
                   '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf', 
                   '.work', '.date', '.party', '.racing', '.online']

def get_deterministic_score_and_flags(url: str) -> tuple:
    """Enhanced scoring with brand detection."""
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_name = domain.split('.')[0] if '.' in domain else domain
    path = parsed.path

    score = 0
    flags = []
    severity = "LOW"  # Track overall severity

    # ---------- 1. ENTROPY (DGA detection) ----------
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        score += 15
        flags.append(f"High entropy ({entropy:.2f}) - possible algorithmic generation (DGA)")
        severity = "HIGH"

    # ---------- 2. IP ADDRESS ----------
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 35  # Increased from 30
        flags.append("Uses raw IP address - bypasses DNS filters")
        severity = "CRITICAL"

    # ---------- 3. BRAND IMPERSONATION (NEW - CRITICAL) ----------
    brand_found = []
    for brand in BRAND_KEYWORDS:
        if brand in url.lower():
            brand_found.append(brand)
    
    if brand_found:
        score += 35  # Major penalty for brand impersonation
        flags.append(f"Brand impersonation detected: {', '.join(brand_found[:3])}")
        severity = "HIGH"

    # ---------- 4. SUSPICIOUS TLD ----------
    tld_found = None
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            tld_found = tld
            score += 25  # Increased from 20
            flags.append(f"Suspicious TLD ({tld}) - widely used for phishing")
            severity = "HIGH"
            break

    # ---------- 5. DECEPTIVE KEYWORDS ----------
    deceptive_found = []
    for kw in DECEPTIVE_KEYWORDS:
        if kw in url.lower():
            deceptive_found.append(kw)
    
    if deceptive_found:
        score += min(15, len(deceptive_found) * 5)
        flags.append(f"Contains deceptive keywords: {', '.join(deceptive_found[:3])}")
        if len(deceptive_found) > 2:
            severity = "HIGH"

    # ---------- 6. SUBDOMAINS ----------
    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if num_subdomains > 2:
        score += min(20, num_subdomains * 5)  # Increased from 15
        flags.append(f"Excessive subdomains ({num_subdomains}) - masquerading attempt")

    # ---------- 7. URL LENGTH ----------
    if len(url) > 100:
        score += 10
        flags.append("Unusually long URL - likely obfuscated")

    # ---------- 8. URL PATH DEPTH (NEW) ----------
    if path:
        path_depth = path.count('/')
        if path_depth > 4:
            score += 10
            flags.append(f"Deep URL path ({path_depth} levels) - suspicious nesting")

    # ---------- 9. HYPHEN COUNT (NEW) ----------
    hyphen_count = url.count('-')
    if hyphen_count > 4:
        score += 10
        flags.append(f"Excessive hyphens ({hyphen_count}) - attempts to evade detection")

    # ---------- 10. BRAND + TLD COMBINATION (NEW - CRITICAL) ----------
    if brand_found and tld_found:
        score += 15  # Bonus penalty for the combination
        flags.append("⚠️ Brand impersonation on suspicious TLD - confirmed phishing pattern")
        severity = "CRITICAL"

    # ---------- 11. SPECIAL CHARACTERS (NEW) ----------
    special_chars = len(re.findall(r'[^a-zA-Z0-9\-\.\/:]', url))
    if special_chars > 5:
        score += 10
        flags.append(f"Excessive special characters ({special_chars}) - obfuscation attempt")

    # ---------- FINAL SCORE ----------
    # Cap at 100
    score = min(score, 100)

    # Set severity level
    if score > 60:
        severity = "CRITICAL"
    elif score > 35:
        severity = "HIGH"
    elif score > 15:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # If no flags detected
    if not flags:
        flags.append("No suspicious patterns detected")

    # Add severity summary
    flags.insert(0, f"⚠️ Overall Severity: {severity}")

    return score, flags

# ---------- GEMINI EXPLANATION ----------

def generate_gemini_explanation(url: str, risk_score: int, flags: list) -> dict:
    """Generate human-readable explanation with Gemini."""
    
    flag_text = "\n".join([f"  - {f}" for f in flags if not f.startswith("⚠️")])
    severity = "CRITICAL" if risk_score > 60 else "WARNING" if risk_score > 35 else "CAUTION" if risk_score > 15 else "SAFE"

    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

URL: {url}
Risk Score: {risk_score}/100
Overall Severity: {severity}

Technical Flags:
{flag_text}

TASK: Write a JSON response:
1. "short": One sentence for a browser badge (max 80 characters)
2. "detailed": A 3-4 sentence technical explanation

Guidelines:
- Score > 60: Clearly alarming, mention specific threats
- Score 35-60: Express caution, explain suspicious elements
- Score 15-35: Low risk, explain why
- Score < 15: Reassuring
- Focus on the most severe flags

OUTPUT FORMAT (STRICT JSON):
{{"short": "...", "detailed": "..."}}
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
            "detailed": result.get("detailed", f"Flags: {', '.join(flags)}")
        }
        
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return {
            "short": f"Risk: {risk_score}%",
            "detailed": f"Technical flags: {', '.join(flags)}"
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

    # Get deterministic score
    risk_score, flags = get_deterministic_score_and_flags(url)

    # Determine threat level
    if risk_score > 60:
        threat_level = "CRITICAL"
    elif risk_score > 35:
        threat_level = "WARNING"
    elif risk_score > 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"

    # Get Gemini explanation
    xai = generate_gemini_explanation(url, risk_score, flags)

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
        "status": "DeepShield V2.8 Online",
        "engine": "Enhanced Deterministic Scoring + Gemini AI",
        "score_method": "rule-based with brand detection",
        "features": [
            "Brand impersonation detection",
            "Suspicious TLD scoring",
            "Deceptive keyword detection",
            "Entropy analysis",
            "Path depth analysis",
            "Special character detection"
        ]
    }