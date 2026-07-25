# ============================================================
# DEEPSHIELD V2.12 - FINAL: SMART BRAND DETECTION
# Legitimate domains are never flagged.
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
import requests

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY is required")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = genai.Client(api_key=GEMINI_API_KEY)

# ============================================================
# CONFIGURATION
# ============================================================

# 1. BRAND DATABASE
BRANDS = {
    'apple': {
        'keywords': ['apple', 'icloud', 'iphone', 'macbook', 'appstore', 'appleid'],
        'legit_domains': ['apple.com', 'icloud.com', 'apple.com.cn', 'icloud.com.cn']
    },
    'paypal': {
        'keywords': ['paypal', 'paypal.com', 'paypai'],
        'legit_domains': ['paypal.com', 'paypal.cn', 'paypal.com.cn']
    },
    'microsoft': {
        'keywords': ['microsoft', 'office', 'outlook', 'onedrive', 'azure'],
        'legit_domains': ['microsoft.com', 'office.com', 'outlook.com', 'azure.com']
    },
    'google': {
        'keywords': ['google', 'gmail', 'youtube', 'android', 'chrome'],
        'legit_domains': ['google.com', 'gmail.com', 'youtube.com']
    },
    'amazon': {
        'keywords': ['amazon', 'aws', 'prime', 'kindle'],
        'legit_domains': ['amazon.com', 'aws.amazon.com', 'primevideo.com']
    },
    'facebook': {
        'keywords': ['facebook', 'fb', 'meta', 'instagram', 'whatsapp'],
        'legit_domains': ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com']
    },
    'netflix': {
        'keywords': ['netflix'],
        'legit_domains': ['netflix.com']
    },
    'twitter': {
        'keywords': ['twitter', 'x'],
        'legit_domains': ['twitter.com', 'x.com']
    }
}

# 2. EXTRA SAFE DOMAINS (not brand-specific)
EXTRA_SAFE_DOMAINS = {
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'medium.com',
    'dev.to', 'vercel.com', 'netlify.com', 'render.com', 'heroku.com',
    'tailwindcss.com', 'reactjs.org', 'python.org', 'docker.com'
}

# 3. SUSPICIOUS TLDs
SUSPICIOUS_TLDS = [
    '.top', '.xyz', '.click', '.download', '.review', '.loan',
    '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf',
    '.work', '.date', '.party', '.racing', '.online', '.site',
    '.live', '.tech', '.fun', '.shop', '.store', '.website'
]

# 4. DECEPTIVE KEYWORDS
DECEPTIVE_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'auth',
    'confirm', 'signin', 'reset', 'password', 'validate',
    'authenticate', 'recover', 'unlock', 'alert', 'notice'
]

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def is_legitimate_domain(domain: str) -> bool:
    """Check if domain is legitimate for any brand."""
    for brand, data in BRANDS.items():
        for legit in data['legit_domains']:
            if domain == legit or domain.endswith('.' + legit):
                return True
    return domain in EXTRA_SAFE_DOMAINS

def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def check_brand_impersonation(domain: str, url: str) -> tuple:
    """Returns (brand_name, risk_score) if impersonation detected."""
    # First, if the domain is legitimate, return safe
    if is_legitimate_domain(domain):
        return None, 0

    # Check each brand
    for brand, data in BRANDS.items():
        # 1. Check if any brand keyword appears in URL
        brand_mentioned = any(kw in url.lower() for kw in data['keywords'])
        if not brand_mentioned:
            continue

        # 2. Check if domain is NOT in legitimate list
        # We already checked above, but double-check
        legit = data['legit_domains']
        if any(domain == d or domain.endswith('.' + d) for d in legit):
            continue  # legitimate, skip

        # 3. Impersonation confirmed
        return brand, 45  # High risk

    return None, 0

def check_typosquatting(domain: str) -> tuple:
    """Check if domain is a typosquat."""
    known_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
        'paypal.com', 'netflix.com', 'twitter.com', 'linkedin.com', 'gmail.com',
        'icloud.com', 'github.com'
    ]
    domain_clean = domain.split('.')[0]  # remove TLD
    for known in known_domains:
        known_clean = known.split('.')[0]
        if domain_clean == known_clean:
            return False, 0
        # Check if known is a substring and length difference is small
        if known_clean in domain_clean and len(domain_clean) > len(known_clean) + 2:
            return True, 25
        if domain_clean in known_clean and len(known_clean) > len(domain_clean) + 2:
            return True, 25
        # Check common typos: repeated letters
        if re.search(r'(.)\1{2,}', domain_clean):
            return True, 20
    return False, 0

def check_suspicious_patterns(url: str, domain: str) -> tuple:
    score = 0
    flags = []

    # Entropy
    domain_name = domain.split('.')[0] if '.' in domain else domain
    entropy = calculate_entropy(domain_name)
    if entropy > 3.8:
        score += 20
        flags.append(f"High entropy ({entropy:.2f})")

    # IP
    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 30
        flags.append("Raw IP address")

    # TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            flags.append(f"Suspicious TLD ({tld})")
            break

    # Keywords
    found = [kw for kw in DECEPTIVE_KEYWORDS if kw in url.lower()]
    if found:
        score += min(20, len(found) * 5)
        flags.append(f"Deceptive: {', '.join(found[:3])}")

    # Subdomains
    parts = domain.split('.')
    if len(parts) > 3:
        score += min(20, (len(parts)-2)*5)
        flags.append(f"Excessive subdomains ({len(parts)-2})")

    # Length
    if len(url) > 100:
        score += 10
        flags.append(f"Long URL ({len(url)})")

    # Special chars
    special = len(re.findall(r'[^a-zA-Z0-9\-\.\/:]', url))
    if special > 5:
        score += 10
        flags.append(f"Special chars ({special})")

    return min(score, 100), flags

# ============================================================
# SAFE BROWSING CHECK
# ============================================================

def check_safe_browsing(url: str) -> dict:
    if not SAFE_BROWSING_API_KEY:
        return {"malicious": False, "threats": [], "score": 0}
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "deepshield", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                threats = [m["threatType"] for m in data["matches"]]
                return {"malicious": True, "threats": threats, "score": 90}
    except Exception as e:
        logger.error(f"Safe Browsing error: {e}")
    return {"malicious": False, "threats": [], "score": 0}

# ============================================================
# GEMINI EXPLANATION
# ============================================================

def generate_gemini_explanation(url: str, risk_score: int, flags: list, sb: dict) -> dict:
    flag_text = "\n".join([f"  - {f}" for f in flags])
    prompt = f"""
You are DeepShield. URL: {url}
Risk Score: {risk_score}/100
Safe Browsing Threats: {', '.join(sb.get('threats', [])) if sb.get('malicious') else 'None'}
Flags: {flag_text}

Return JSON: {{"short": "one sentence", "detailed": "2-3 sentences"}}

- Score 0-15: SAFE, reassuring
- Score 16-40: CAUTION, some concerns
- Score 41-100: DANGEROUS, clear phishing
"""
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"response_mime_type": "application/json", "temperature": 0.0, "max_output_tokens": 300}
        )
        raw = response.text.strip()
        if raw.startswith("```json"):
            raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        return {
            "short": result.get("short", f"Risk: {risk_score}%"),
            "detailed": result.get("detailed", "Analysis unavailable.")
        }
    except:
        return {"short": f"Risk: {risk_score}%", "detailed": f"Flags: {', '.join(flags)}"}

# ============================================================
# MAIN SCAN ENGINE
# ============================================================

def scan_url_comprehensive(url: str) -> dict:
    domain = get_domain(url)
    logger.info(f"Scanning: {url} (domain: {domain})")

    # 1. Check if domain is legitimate
    if is_legitimate_domain(domain):
        return {
            "risk_score": 0,
            "threat_level": "SAFE",
            "flags": ["✅ Legitimate domain"],
            "brand": None,
            "sb": {"malicious": False, "threats": []}
        }

    # 2. Brand impersonation
    brand, brand_score = check_brand_impersonation(domain, url)

    # 3. Typosquatting
    typosquat, typoscore = check_typosquatting(domain)

    # 4. Suspicious patterns
    pattern_score, flags = check_suspicious_patterns(url, domain)

    # 5. Safe Browsing
    sb = check_safe_browsing(url)

    # 6. Calculate final score
    final_score = brand_score + typoscore + pattern_score
    if sb["malicious"]:
        final_score = max(final_score, 90)
        flags.insert(0, "🚨 Google Safe Browsing: Malicious")

    if brand_score > 0:
        flags.insert(0, f"🚨 Brand impersonation: {brand}")

    if typosquat:
        flags.insert(0, "⚠️ Typosquatting detected")

    final_score = min(final_score, 100)

    if final_score > 60:
        threat_level = "CRITICAL"
    elif final_score > 35:
        threat_level = "WARNING"
    elif final_score > 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"

    flags.insert(0, f"📊 Score: {final_score}% - {threat_level}")

    return {
        "risk_score": final_score,
        "threat_level": threat_level,
        "flags": flags,
        "brand": brand,
        "sb": sb
    }

# ============================================================
# API
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
    heuristics_flagged: list
    safe_browsing_threats: list
    brand_detected: str = None

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    result = scan_url_comprehensive(url)
    xai = generate_gemini_explanation(url, result["risk_score"], result["flags"], result["sb"])
    return ScanResponse(
        url=url,
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        short_explanation=xai["short"],
        detailed_analysis=xai["detailed"],
        heuristics_flagged=result["flags"],
        safe_browsing_threats=result["sb"].get("threats", []),
        brand_detected=result.get("brand")
    )

@app.get("/")
async def health_check():
    return {
        "status": "DeepShield V2.12 Online",
        "engine": "Smart Brand Detection + Heuristics + Safe Browsing",
        "legitimate_domains": "Active",
        "suspicious_tlds": len(SUSPICIOUS_TLDS)
    }