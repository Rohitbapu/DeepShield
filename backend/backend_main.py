# ============================================================
# DEEPSHIELD DLP V2.3 - PURE GROQ AI (No External APIs)
# Run: uvicorn backend_main:app --host 0.0.0.0 --port 10000
# ============================================================

import os
import re
import math
import json
import logging
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv
from groq import Groq

# ---------- CONFIG ----------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    logger.error("CRITICAL: GROQ_API_KEY missing!")
    raise ValueError("GROQ_API_KEY environment variable is required")

# ---------- INIT APP ----------
app = FastAPI(title="DeepShield DLP - Pure Groq AI", version="2.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- GROQ CLIENT ----------
groq_client = Groq(api_key=GROQ_API_KEY)

# ---------- HELPER: Calculate Entropy ----------
def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for domain randomness detection."""
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

# ---------- HELPER: Extract Heuristic Flags ----------
def extract_heuristic_flags(url: str) -> list:
    """
    Extract heuristic flags for the Groq prompt.
    These are NOT used for scoring - only as context for Groq.
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    flags = []

    # 1. Entropy check
    domain_name = domain.split('.')[0] if '.' in domain else domain
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        flags.append(f"High domain entropy ({entropy:.2f}) - suggests algorithmic generation (DGA)")

    # 2. IP address check
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        flags.append("Uses raw IP address instead of domain name - bypasses DNS filters")

    # 3. Suspicious TLDs
    suspicious_tlds = ['.top', '.xyz', '.click', '.download', '.review', '.loan', 
                       '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            flags.append(f"Suspicious TLD ({tld}) - commonly used for phishing")
            break

    # 4. Suspicious keywords
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 
                'paypal', 'auth', 'confirm', 'signin', 'reset', 'password']
    found_keywords = [kw for kw in keywords if kw in url.lower()]
    if found_keywords:
        flags.append(f"Contains deceptive keywords: {', '.join(found_keywords[:3])}")

    # 5. Subdomain count
    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if num_subdomains > 2:
        flags.append(f"Excessive subdomains ({num_subdomains}) - masquerading attempt")

    # 6. URL length
    if len(url) > 100:
        flags.append("Unusually long URL - likely obfuscated")

    if not flags:
        flags.append("No obvious structural anomalies detected")

    return flags

# ---------- THE GROQ AI PROMPT ----------
def build_ai_prompt(url: str, flags: list) -> str:
    flag_text = "\n".join([f"  - {f}" for f in flags])

    prompt = f"""
You are DeepShield, a strict enterprise-grade cybersecurity AI.

**YOUR TASK:** Analyze this URL for phishing or malicious activity:
{url}

**TECHNICAL TELEMETRY (Structural Analysis):**
{flag_text}

**INSTRUCTIONS:**
1. Based on the telemetry above, determine if this URL is phishing/malicious.
2. Return ONLY a JSON object with these exact keys. No other text.

**OUTPUT FORMAT:**
{{
  "risk_score": "integer 0-100",
  "threat_level": "SAFE or WARNING or CRITICAL",
  "short_explanation": "A single sentence for a browser badge (max 80 characters)",
  "detailed_analysis": "A 2-3 sentence technical report for a security team"
}}

**SCORING GUIDELINES:**
- 0-25: SAFE - No suspicious indicators, legitimate domain
- 26-55: WARNING - Some anomalies, exercise caution
- 56-100: CRITICAL - Strong evidence of phishing/malware

**RULES:**
- Be conservative. When in doubt, give a lower score.
- Base your score on the flags above, not external knowledge.
- If there are no flags, score 0-10 (SAFE).
- Never guess. Only use the telemetry provided.
"""
    return prompt

# ---------- GROQ ANALYSIS FUNCTION ----------
def analyze_with_groq(url: str) -> dict:
    """Call Groq for URL analysis and return structured result."""
    
    # 1. Extract heuristic flags
    flags = extract_heuristic_flags(url)
    logger.info(f"Extracted flags for {url}: {flags}")

    # 2. Build prompt
    prompt = build_ai_prompt(url, flags)

    # 3. Call Groq
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are DeepShield, a cybersecurity AI. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low temperature for deterministic output
            max_tokens=300,
            response_format={"type": "json_object"}
        )

        raw = response.choices[0].message.content.strip()
        logger.info(f"Groq response: {raw[:200]}...")

        # 4. Parse JSON
        result = json.loads(raw)

        # 5. Validate and sanitize
        risk_score = int(result.get("risk_score", 50))
        if risk_score < 0 or risk_score > 100:
            risk_score = 50

        threat_level = result.get("threat_level", "WARNING")
        if threat_level not in ["SAFE", "WARNING", "CRITICAL"]:
            threat_level = "WARNING"

        return {
            "risk_score": risk_score,
            "threat_level": threat_level,
            "short_explanation": result.get("short_explanation", "Suspicious link detected"),
            "detailed_analysis": result.get("detailed_analysis", "No detailed analysis available."),
            "heuristics_flagged": flags
        }

    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error: {e}")
        return {
            "risk_score": 50,
            "threat_level": "WARNING",
            "short_explanation": "Analysis unavailable",
            "detailed_analysis": f"AI response was not valid JSON: {raw[:100] if 'raw' in locals() else 'Unknown error'}",
            "heuristics_flagged": flags
        }

    except Exception as e:
        logger.error(f"Groq API error: {e}")
        return {
            "risk_score": 30,
            "threat_level": "WARNING",
            "short_explanation": "Analysis temporarily unavailable",
            "detailed_analysis": f"Groq API error: {str(e)}",
            "heuristics_flagged": flags
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

    # Analyze with Groq
    result = analyze_with_groq(url)

    return ScanResponse(
        url=url,
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        short_explanation=result["short_explanation"],
        detailed_analysis=result["detailed_analysis"],
        heuristics_flagged=result["heuristics_flagged"]
    )

# ---------- HEALTH CHECK ----------
@app.get("/")
async def health_check():
    return {
        "status": "DeepShield DLP V2.3 Online",
        "engine": "Groq Llama-3 (Pure AI)",
        "api_key_configured": "Yes" if GROQ_API_KEY else "No"
    }

# ---------- OPTIONAL: DEBUG ENDPOINT ----------
@app.post("/api/v1/debug")
async def debug_url(payload: ScanRequest):
    """Debug endpoint to see raw flags without Groq call."""
    url = payload.url
    flags = extract_heuristic_flags(url)
    return {
        "url": url,
        "heuristics_flagged": flags,
        "note": "This is only the heuristic analysis, not the AI score."
    }