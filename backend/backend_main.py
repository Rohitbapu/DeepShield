# ============================================================
# DEEPSHIELD V2.14 - SELF-CONTAINED ML + GEMINI
# No external dependencies except standard packages
# ============================================================

import os
import re
import math
import json
import logging
import pickle
import hashlib
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
    logger.warning("GEMINI_API_KEY not set! Explanations will be generic.")

# ---------- INIT FASTAPI ----------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- INIT GEMINI ----------
if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    gemini_client = None

# ============================================================
# SELF-CONTAINED PHISHING DETECTION (No external package)
# ============================================================

class PhishGuardML:
    """
    Self-contained phishing detection using heuristic rules.
    This mimics the behavior of the original phishing-detection-py
    but works without any external package.
    """
    
    def __init__(self):
        # Brand keywords for impersonation detection
        self.brands = {
            'apple': ['apple', 'icloud', 'iphone', 'macbook', 'appleid'],
            'paypal': ['paypal', 'paypai'],
            'microsoft': ['microsoft', 'office', 'outlook', 'onedrive'],
            'google': ['google', 'gmail', 'youtube', 'android'],
            'amazon': ['amazon', 'aws', 'prime', 'kindle'],
            'facebook': ['facebook', 'fb', 'meta', 'instagram'],
            'netflix': ['netflix'],
            'twitter': ['twitter', 'x'],
            'linkedin': ['linkedin'],
            'bank': ['chase', 'wellsfargo', 'bankofamerica', 'hsbc', 'citi']
        }
        
        self.legit_domains = {
            'apple': ['apple.com', 'icloud.com'],
            'paypal': ['paypal.com'],
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com'],
            'amazon': ['amazon.com'],
            'facebook': ['facebook.com', 'instagram.com', 'meta.com'],
            'netflix': ['netflix.com'],
            'twitter': ['twitter.com', 'x.com'],
            'linkedin': ['linkedin.com']
        }
        
        self.safe_domains = {
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'medium.com',
            'dev.to', 'vercel.com', 'netlify.com', 'render.com', 'heroku.com',
            'tailwindcss.com', 'reactjs.org', 'python.org', 'docker.com',
            'google.com', 'gmail.com', 'youtube.com', 'yahoo.com', 'bing.com'
        }
        
        self.suspicious_tlds = [
            '.top', '.xyz', '.click', '.download', '.review', '.loan',
            '.men', '.win', '.bid', '.tk', '.ml', '.ga', '.cf',
            '.work', '.date', '.party', '.racing', '.online', '.site',
            '.live', '.tech', '.fun', '.shop', '.store', '.website'
        ]
        
        self.deceptive_keywords = [
            'login', 'verify', 'update', 'secure', 'account', 'auth',
            'confirm', 'signin', 'reset', 'password', 'validate',
            'authenticate', 'recover', 'unlock', 'alert', 'notice',
            'support', 'help', 'service', 'billing', 'payment', 'info'
        ]
    
    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += -p_x * math.log(p_x, 2)
        return entropy
    
    def get_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    
    def is_legitimate_domain(self, domain: str) -> bool:
        # Check custom safe domains
        if domain in self.safe_domains:
            return True
        
        # Check brand legitimate domains
        for brand, domains in self.legit_domains.items():
            for legit in domains:
                if domain == legit or domain.endswith('.' + legit):
                    return True
        return False
    
    def check_brand_impersonation(self, domain: str, url: str) -> tuple:
        """Returns (brand_name, risk_score) if impersonation detected."""
        if self.is_legitimate_domain(domain):
            return None, 0
        
        for brand, keywords in self.brands.items():
            brand_mentioned = any(kw in url.lower() for kw in keywords)
            if not brand_mentioned:
                continue
            
            # Check if domain is legitimate for this brand
            legit = self.legit_domains.get(brand, [])
            if any(domain == d or domain.endswith('.' + d) for d in legit):
                continue
            
            return brand, 45
        
        return None, 0
    
    def check_typosquatting(self, domain: str) -> tuple:
        """Returns (is_typosquat, score)."""
        known_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'paypal.com', 'netflix.com', 'twitter.com',
            'linkedin.com', 'gmail.com', 'icloud.com', 'github.com'
        ]
        
        domain_clean = domain.split('.')[0]
        
        for known in known_domains:
            known_clean = known.split('.')[0]
            
            if domain_clean == known_clean:
                return False, 0
            
            # Check if known is a substring (e.g., "amazons" vs "amazon")
            if known_clean in domain_clean and len(domain_clean) > len(known_clean) + 2:
                return True, 25
            
            if domain_clean in known_clean and len(known_clean) > len(domain_clean) + 2:
                return True, 25
            
            # Check for repeated letters (e.g., "gooogle")
            if re.search(r'(.)\1{2,}', domain_clean):
                return True, 20
        
        return False, 0
    
    def check_suspicious_patterns(self, url: str, domain: str) -> tuple:
        """Returns (score, flags)."""
        score = 0
        flags = []
        
        # 1. Entropy
        domain_name = domain.split('.')[0] if '.' in domain else domain
        entropy = self.calculate_entropy(domain_name)
        if entropy > 3.8:
            score += 20
            flags.append(f"High entropy ({entropy:.2f})")
        
        # 2. IP address
        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
            score += 30
            flags.append("Raw IP address")
        
        # 3. Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 25
                flags.append(f"Suspicious TLD ({tld})")
                break
        
        # 4. Deceptive keywords
        found = [kw for kw in self.deceptive_keywords if kw in url.lower()]
        if found:
            score += min(20, len(found) * 5)
            flags.append(f"Deceptive: {', '.join(found[:3])}")
        
        # 5. Subdomains
        parts = domain.split('.')
        if len(parts) > 3:
            score += min(20, (len(parts) - 2) * 5)
            flags.append(f"Excessive subdomains ({len(parts) - 2})")
        
        # 6. URL length
        if len(url) > 100:
            score += 10
            flags.append(f"Long URL ({len(url)})")
        
        # 7. Special characters
        special = len(re.findall(r'[^a-zA-Z0-9\-\.\/:]', url))
        if special > 5:
            score += 10
            flags.append(f"Special chars ({special})")
        
        # 8. Multiple hyphens
        hyphens = url.count('-')
        if hyphens > 4:
            score += 10
            flags.append(f"Excessive hyphens ({hyphens})")
        
        return min(score, 100), flags
    
    def check_safe_browsing(self, url: str) -> dict:
        """Check Google Safe Browsing."""
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
    
    def predict(self, url: str) -> dict:
        """
        Main prediction function.
        Returns: {
            "prediction": [{"label": "phishing" or "safe", "score": float}]
        }
        """
        domain = self.get_domain(url)
        logger.info(f"Analyzing: {url} (domain: {domain})")
        
        # 1. Check if legitimate domain
        if self.is_legitimate_domain(domain):
            return {"prediction": [{"label": "safe", "score": 0.05}]}
        
        # 2. Check brand impersonation
        brand, brand_score = self.check_brand_impersonation(domain, url)
        
        # 3. Check typosquatting
        is_typosquat, typoscore = self.check_typosquatting(domain)
        
        # 4. Check suspicious patterns
        pattern_score, flags = self.check_suspicious_patterns(url, domain)
        
        # 5. Check Safe Browsing
        sb = self.check_safe_browsing(url)
        
        # 6. Calculate final score
        final_score = brand_score + typoscore + pattern_score
        
        if sb["malicious"]:
            final_score = max(final_score, 90)
            flags.insert(0, "🚨 Google Safe Browsing: Malicious")
        
        if brand_score > 0:
            flags.insert(0, f"🚨 Brand impersonation: {brand}")
        
        if is_typosquat:
            flags.insert(0, "⚠️ Typosquatting detected")
        
        final_score = min(final_score, 100)
        
        # Convert to ML-style output
        if final_score > 50:
            label = "phishing"
            score = final_score / 100
        elif final_score > 25:
            label = "phishing"  # Still risky
            score = 0.4 + (final_score / 100) * 0.4
        else:
            label = "safe"
            score = 0.05
        
        # Ensure score is between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return {
            "prediction": [{"label": label, "score": float(score)}],
            "flags": flags,
            "brand": brand,
            "score_raw": final_score
        }

# ============================================================
# INITIALIZE ML DETECTOR
# ============================================================

detector = PhishGuardML()
logger.info("🚀 PhishGuard ML Engine Initialized")

# ============================================================
# GEMINI EXPLANATION
# ============================================================

def generate_gemini_explanation(url: str, label: str, score: float, flags: list) -> dict:
    """Generate human-readable explanation using Gemini."""
    
    if not gemini_client:
        # Fallback: no Gemini
        if label == "phishing":
            return {
                "short": "🚨 Phishing detected!",
                "detailed": f"This URL is classified as phishing with {score:.1%} confidence."
            }
        else:
            return {
                "short": "✅ Safe",
                "detailed": f"This URL appears safe with {score:.1%} confidence."
            }
    
    flag_text = "\n".join([f"  - {f}" for f in flags[:5]])  # Limit to 5 flags
    prompt = f"""
You are DeepShield, an enterprise cybersecurity AI.

URL: {url}
ML Model Confidence: {score:.1%}
Classification: {'PHISHING' if label == 'phishing' else 'SAFE'}
Technical Flags: {flag_text}

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
            "short": result.get("short", "🚨 Phishing" if label == "phishing" else "✅ Safe"),
            "detailed": result.get("detailed", f"ML confidence: {score:.1%}")
        }
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return {
            "short": "🚨 Phishing" if label == "phishing" else "✅ Safe",
            "detailed": f"ML Confidence: {score:.1%}. {'Phishing detected.' if label == 'phishing' else 'No phishing detected.'}"
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
    risk_score: int        # 0-100
    threat_level: str      # SAFE / WARNING / CRITICAL
    short_explanation: str
    detailed_analysis: str
    ml_confidence: float
    heuristics_flagged: list = []

# ============================================================
# API ENDPOINT
# ============================================================

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    url = payload.url
    logger.info(f"🔍 Scanning: {url[:60]}...")
    
    # 1. Run ML Detection
    try:
        result = detector.predict(url)
        pred = result["prediction"][0]
        label = pred["label"]
        ml_score = pred["score"]
        flags = result.get("flags", [])
        
        logger.info(f"ML Result: {label} | Confidence: {ml_score:.2%}")
        
    except Exception as e:
        logger.error(f"ML model error: {e}")
        label = "safe"
        ml_score = 0.0
        flags = ["Model error"]
    
    # 2. Convert to risk score (0-100)
    if label == "phishing":
        risk_score = int(ml_score * 100)
        risk_score = max(risk_score, 60)
    else:
        risk_score = int(ml_score * 15)
        risk_score = min(risk_score, 20)
    
    # 3. Determine threat level
    if risk_score > 60:
        threat_level = "CRITICAL"
    elif risk_score > 35:
        threat_level = "WARNING"
    elif risk_score > 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"
    
    # 4. Generate Gemini explanation
    xai = generate_gemini_explanation(url, label, ml_score, flags)
    
    return ScanResponse(
        url=url,
        risk_score=risk_score,
        threat_level=threat_level,
        short_explanation=xai["short"],
        detailed_analysis=xai["detailed"],
        ml_confidence=ml_score,
        heuristics_flagged=flags
    )

# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health_check():
    return {
        "status": "DeepShield V2.14 Online",
        "engine": "Self-Contained ML + Gemini XAI",
        "gemini_configured": GEMINI_API_KEY is not None,
        "safe_browsing_configured": SAFE_BROWSING_API_KEY is not None,
        "brands_detected": len(detector.brands)
    }

@app.get("/")
async def root_health():
    return {
        "status": "DeepShield V2.14 Online",
        "engine": "Self-Contained ML + Gemini XAI",
        "endpoints": {
            "scan": "POST /api/v1/scan",
            "health": "GET /health",
            "root": "GET /"
        }
    }