# ============================================================
# DEEPSHIELD V2.9 - GEMINI SCORING + SAFE DOMAIN WHITELIST
# Gemini generates both risk score AND explanation.
# Heuristics are only used as context, not for scoring.
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

# ---------- SAFE DOMAIN WHITELIST ----------
SAFE_DOMAINS = {
    'google.com', 'google.co.in', 'gmail.com', 'youtube.com', 'github.com',
    'stackoverflow.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'spotify.com', 'twitter.com', 'facebook.com',
    'instagram.com', 'linkedin.com', 'reddit.com', 'wikipedia.org',
    'bbc.com', 'cnn.com', 'nytimes.com', 'medium.com', 'dev.to',
    'vercel.com', 'netlify.com', 'render.com', 'heroku.com'
}

def is_safe_domain(url: str) -> bool:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain in SAFE_DOMAINS

# ---------- HEURISTIC EXTRACTOR (NO SCORING) ----------
def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def extract_heuristic_flags(url: str) -> list:
    """Extract flags WITHOUT scoring. These are fed to Gemini."""
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_name = domain.split('.')[0] if '.' in domain else domain
    path = parsed.path

    flags = []

    # 1. Entropy
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        flags.append(f"High domain entropy ({entropy:.2f}) – algorithmic generation possible")

    # 2. IP address
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        flags.append("Uses raw IP address instead of domain name – bypasses DNS filters")

    # 3. Suspicious TLD
    suspicious_tlds = ['.top', '.xyz', '.click', '.download', '.review', '.loan',
                       '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            flags.append(f"Suspicious TLD ({tld}) – often used in phishing")
            break

    # 4. Brand impersonation
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'facebook']
    found_brands = [b for b in brands if b in url.lower()]
    if found_brands:
        flags.append(f"Brand impersonation: {', '.join(found_brands[:2])}")

    # 5. Deceptive keywords
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'auth', 'confirm', 'signin', 'reset', 'password']
    found_keywords = [kw for kw in keywords if kw in url.lower()]
    if found_keywords:
        flags.append(f"Deceptive keywords: {', '.join(found_keywords[:3])}")

    # 6. Subdomain count
    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
    if num_subdomains > 2:
        flags.append(f"Excessive subdomains ({num_subdomains}) – possible masquerading")

    # 7. URL length & path depth
    if len(url) > 100:
        flags.append(f"Unusually long URL ({len(url)} chars)")
    path_depth = path.count('/')
    if path_depth > 4:
        flags.append(f"Deep URL path ({path_depth} levels) – suspicious nesting")

    if not flags:
        flags.append("No obvious structural anomalies detected")

    return flags

# ---------- GEMINI SCORING + EXPLANATION ----------
def analyze_with_gemini(url: str, flags: list) -> dict:
    """Gemini generates risk_score, threat_level, short, detailed."""
    flag_text = "\n".join([f"  - {f}" for f in flags])

    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

**URL:** {url}

**Technical Telemetry (Structural Analysis):**
{flag_text}

**TASK:** Assess the phishing/malicious risk of this URL.
- Return a JSON with these keys:
  - "risk_score": integer 0-100 (0 = completely safe, 100 = highly malicious)
  - "threat_level": "SAFE" or "WARNING" or "CRITICAL"
  - "short_explanation": one sentence for a browser badge (max 80 chars)
  - "detailed_analysis": 2-3 sentences explaining your reasoning

**SCORING GUIDELINES:**
- Score 0-15: SAFE – legitimate, well-known domain, no suspicious indicators.
- Score 16-40: WARNING – some anomalies but not clearly malicious.
- Score 41-100: CRITICAL – clear signs of phishing/malware.

**IMPORTANT:**
- Be conservative. If the URL is a well-known safe domain (google.com, github.com), score 0-5.
- Base your score on the flags above. Use them as evidence.
- Do not guess. Only use the provided telemetry.

**OUTPUT FORMAT (STRICT JSON):**
{{"risk_score": 0, "threat_level": "SAFE", "short_explanation": "...", "detailed_analysis": "..."}}
"""
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "temperature": 0.0,
                "max_output_tokens": 350,
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
            "risk_score": int(result.get("risk_score", 20)),
            "threat_level": result.get("threat_level", "WARNING"),
            "short_explanation": result.get("short_explanation", "Suspicious link"),
            "detailed_analysis": result.get("detailed_analysis", "No analysis available.")
        }
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        # Conservative fallback: use low score
        return {
            "risk_score": 10,
            "threat_level": "SAFE",
            "short_explanation": "Analysis unavailable – treated as safe.",
            "detailed_analysis": f"Gemini API error. Flags: {', '.join(flags)}"
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

    # 1. Extract heuristic flags (no scoring)
    flags = extract_heuristic_flags(url)

    # 2. Check safe domain whitelist
    if is_safe_domain(url):
        logger.info(f"URL is in safe domain whitelist: {url}")
        return ScanResponse(
            url=url,
            risk_score=0,
            threat_level="SAFE",
            short_explanation="✅ This is a well-known safe domain.",
            detailed_analysis="The domain is whitelisted as a trusted, legitimate service. No further analysis needed.",
            heuristics_flagged=flags
        )

    # 3. Gemini AI scoring + explanation
    ai_result = analyze_with_gemini(url, flags)

    return ScanResponse(
        url=url,
        risk_score=ai_result["risk_score"],
        threat_level=ai_result["threat_level"],
        short_explanation=ai_result["short_explanation"],
        detailed_analysis=ai_result["detailed_analysis"],
        heuristics_flagged=flags
    )

@app.get("/")
async def health_check():
    return {
        "status": "DeepShield V2.9 Online",
        "engine": "Gemini 2.5 Flash (scoring + explanation)",
        "whitelist": "Active",
        "fallback": "Conservative (score=10 if AI fails)"
    }