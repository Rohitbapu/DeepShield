# ============================================================
# DEEPSHIELD DLP V5.1 - GEMINI + GROQ HYBRID XAI
# ============================================================

import os
import json
import logging
import asyncio
import re
import urllib.parse
from contextlib import asynccontextmanager
import requests
import torch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

# ---------- LOGGING ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger("DeepShieldEngine")

load_dotenv()

# ---------- ENVIRONMENT VARIABLES ----------
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL_ID", "gemini-2.5-flash")
DEFAULT_GROQ_MODEL = os.getenv("GROQ_MODEL_ID", "llama-3.1-8b-instant")

# ---------- GLOBAL ALLOWLIST ----------
GLOBAL_ALLOWLIST = {
    "google.com", "google.co.in", "gemini.google.com", "youtube.com", "gmail.com",
    "microsoft.com", "office.com", "live.com", "bing.com", "azure.com",
    "apple.com", "icloud.com", "amazon.com", "aws.amazon.com",
    "github.com", "gitlab.com", "stackoverflow.com", "huggingface.co",
    "cloudflare.com", "trycloudflare.com", "render.com", "vercel.app",
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    "whatsapp.com", "telegram.org", "discord.com", "reddit.com",
    "wikipedia.org", "wikimedia.org", "paypal.com", "stripe.com"
}

# ---------- GLOBAL STATE ----------
ml_detector = None
gemini_client = None
groq_client = None
gemini_active = False
groq_active = False
safe_browsing_active = False

# ============================================================
# FASTAPI LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_detector, gemini_client, groq_client, gemini_active, groq_active, safe_browsing_active
    logger.info("⚡ Initializing DeepShield Security Pipeline...")

    # Safe Browsing
    if SAFE_BROWSING_API_KEY and SAFE_BROWSING_API_KEY != "your_google_cloud_api_key_here":
        safe_browsing_active = True
        logger.info("✅ Layer 1: Google Safe Browsing API active.")
    else:
        logger.warning("⚠️ Layer 1: SAFE_BROWSING_API_KEY missing.")

    # PyTorch ML
    try:
        from phishing_detection_py import PhishingDetector
        ml_detector = PhishingDetector()
        if torch.cuda.is_available():
            ml_detector.model_pipeline.model.to('cuda:0')
            ml_detector.model_pipeline.device = torch.device('cuda:0')
            logger.info("✅ Layer 2: PyTorch ML Model on CUDA.")
        else:
            logger.info("✅ Layer 2: PyTorch ML Model on CPU.")
    except Exception as e:
        logger.error(f"❌ ML init failed: {e}")

    # Gemini
    try:
        from google import genai
        if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
            gemini_client = genai.Client(api_key=GEMINI_API_KEY)
            gemini_active = True
            logger.info(f"✅ Gemini Client active (model: {DEFAULT_GEMINI_MODEL}).")
        else:
            logger.warning("⚠️ GEMINI_API_KEY missing or invalid.")
    except Exception as e:
        logger.error(f"❌ Gemini init error: {e}")

    # Groq
    try:
        from groq import Groq
        if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
            groq_client = Groq(api_key=GROQ_API_KEY)
            groq_active = True
            logger.info(f"✅ Groq Client active (model: {DEFAULT_GROQ_MODEL}).")
        else:
            logger.warning("⚠️ GROQ_API_KEY missing or invalid.")
    except Exception as e:
        logger.error(f"❌ Groq init error: {e}")

    logger.info("🚀 Security Engine fully initialized.")
    yield
    logger.info("🛑 Shutting down...")

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# ANALYSIS ENGINES
# ============================================================

def is_trusted_allowlist(url: str) -> bool:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        for allowed in GLOBAL_ALLOWLIST:
            if domain == allowed or domain.endswith('.' + allowed):
                return True
        return False
    except Exception:
        return False

def analyze_lexical_heuristics(url: str) -> dict:
    flags = []
    penalty = 0
    try:
        parsed = urllib.parse.urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.lower()

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            flags.append("Host is a raw IP address")
            penalty += 35

        if domain.endswith(('.xyz', '.top', '.work', '.click', '.gq', '.ml', '.cf', '.tk', '.cc')):
            flags.append(f"Suspicious TLD detected ({domain.split('.')[-1]})")
            penalty += 25

        brand_targets = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'netflix', 'bankofamerica']
        for brand in brand_targets:
            if brand in url.lower() and not domain.endswith(f"{brand}.com"):
                flags.append(f"Possible brand spoofing attempt targeting '{brand}'")
                penalty += 30
                break

        if domain.count('.') > 3:
            flags.append("Abnormally nested subdomain structure")
            penalty += 15

    except Exception as e:
        logger.error(f"Heuristics error: {e}")
    return {"flags": flags, "penalty": penalty}

def check_google_safe_browsing(url: str) -> dict:
    if not safe_browsing_active:
        return {"flagged": False, "threat_types": [], "status": "SKIPPED"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "deepshield-dlp", "clientVersion": "5.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=3.0)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data and len(data["matches"]) > 0:
                threats = [match["threatType"] for match in data["matches"]]
                return {"flagged": True, "threat_types": threats, "status": "FLAGGED"}
            return {"flagged": False, "threat_types": [], "status": "CLEAN"}
        return {"flagged": False, "threat_types": [], "status": f"API_ERROR_{response.status_code}"}
    except Exception:
        return {"flagged": False, "threat_types": [], "status": "TIMEOUT_OR_ERROR"}

def check_local_ml_model(url: str) -> dict:
    if ml_detector is None:
        return {"is_phishing": False, "confidence": 0.0, "status": "UNAVAILABLE"}
    try:
        result = ml_detector.predict(url[:500])
        prediction = result["prediction"][0]
        return {
            "is_phishing": (prediction["label"].lower() == 'phishing'),
            "confidence": float(prediction["score"]),
            "status": "SUCCESS"
        }
    except Exception:
        return {"is_phishing": False, "confidence": 0.0, "status": "ERROR"}

# ============================================================
# EXPLANATION GENERATOR (GEMINI + GROQ FALLBACK)
# ============================================================

def generate_ai_explanation(url: str, sb_res: dict, ml_res: dict, heuristics: dict, composite_score: int) -> dict:
    prompt = f"""
You are DeepShield DLP, an enterprise threat intelligence system.
Target URL: {url}
Calculated Threat Score: {composite_score}/100

Input Security Diagnostics:
1. Google Safe Browsing: {'FLAGGED (' + str(sb_res['threat_types']) + ')' if sb_res.get('flagged') else 'CLEAN'}
2. Local PyTorch ML: {'PHISHING' if ml_res.get('is_phishing') else 'SAFE'} (Confidence: {ml_res.get('confidence', 0.0):.1%})
3. Lexical Anomalies: {heuristics['flags'] if heuristics['flags'] else 'None'}

Return STRICT JSON matching this format:
{{
  "short": "Headline summary under 65 characters",
  "detailed": "2 technical sentences detailing structural mechanics.",
  "indicators": ["Observation 1", "Observation 2"]
}}
"""
    # Try Gemini first
    if gemini_active and gemini_client is not None:
        try:
            response = gemini_client.models.generate_content(
                model=DEFAULT_GEMINI_MODEL,
                contents=prompt,
                config={"response_mime_type": "application/json", "temperature": 0.1, "max_output_tokens": 300}
            )
            parsed = json.loads(response.text.strip())
            logger.info("✅ Gemini explanation generated.")
            return {
                "short": parsed.get("short", f"Threat Level: {composite_score}%"),
                "detailed": parsed.get("detailed", "Diagnostic synthesis completed."),
                "indicators": parsed.get("indicators", heuristics["flags"])
            }
        except Exception as e:
            logger.warning(f"⚠️ Gemini failed: {e}. Falling back to Groq.")
            # Fall through to Groq

    # Fallback: Groq
    if groq_active and groq_client is not None:
        try:
            completion = groq_client.chat.completions.create(
                model=DEFAULT_GROQ_MODEL,
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst. Always output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=300,
                response_format={"type": "json_object"}
            )
            raw = completion.choices[0].message.content.strip()
            parsed = json.loads(raw)
            logger.info("✅ Groq explanation generated (fallback).")
            return {
                "short": parsed.get("short", f"Threat Level: {composite_score}%"),
                "detailed": parsed.get("detailed", "Diagnostic synthesis completed."),
                "indicators": parsed.get("indicators", heuristics["flags"])
            }
        except Exception as e:
            logger.error(f"❌ Groq also failed: {e}")
            # Final fallback: heuristic-only
            return {
                "short": f"Risk Score: {composite_score}/100 (ML Verified)",
                "detailed": "Evaluated by local heuristic and PyTorch Transformer models. AI reasoning fallback active due to API rate limits.",
                "indicators": heuristics["flags"] if heuristics["flags"] else ["Local ML verification complete"]
            }
    else:
        # No AI engine available
        return {
            "short": f"Risk Score: {composite_score}/100",
            "detailed": f"Evaluated via heuristic and machine learning models. Risk score set to {composite_score}%.",
            "indicators": heuristics["flags"] or ["Local analysis completed cleanly."]
        }

# ============================================================
# API SCHEMAS
# ============================================================

class ScanRequest(BaseModel):
    url: str

    @field_validator('url')
    def validate_url_format(cls, v):
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        return v

class LayerResults(BaseModel):
    google_safe_browsing: dict
    local_ml_engine: dict

class ScanResponse(BaseModel):
    url: str
    risk_score: int
    threat_level: str
    short_explanation: str
    detailed_analysis: str
    heuristics_flagged: list[str]
    layer_diagnostics: LayerResults

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
async def root():
    return {"status": "DeepShield DLP Security API Online", "docs": "/docs", "health": "/health"}

@app.get("/health")
async def health_check():
    return {
        "status": "DeepShield Engine Online",
        "active_gemini_model": DEFAULT_GEMINI_MODEL,
        "active_groq_model": DEFAULT_GROQ_MODEL,
        "layers": {
            "google_safe_browsing": safe_browsing_active,
            "local_pytorch_ml": ml_detector is not None,
            "gemini_api": gemini_active,
            "groq_api": groq_active
        }
    }

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url_pipeline(payload: ScanRequest, explain: bool = False):  # <-- new flag
    url = payload.url
    logger.info(f"🔍 [SCAN START] Target: {url}")

    # Allowlist fast path
    if is_trusted_allowlist(url):
        logger.info(f"✅ Allowlist Hit: {url}")
        return ScanResponse(
            url=url, risk_score=0, threat_level="SAFE",
            short_explanation="✅ Verified Enterprise Domain",
            detailed_analysis="This domain is a verified, highly-trusted service on the global allowlist.",
            heuristics_flagged=[],
            layer_diagnostics=LayerResults(
                google_safe_browsing={"flagged": False, "status": "ALLOWLIST_BYPASS"},
                local_ml_engine={"is_phishing": False, "confidence": 0.0, "status": "ALLOWLIST_BYPASS"}
            )
        )

    # Heuristics
    heuristics = analyze_lexical_heuristics(url)

    # Safe Browsing + ML in parallel
    sb_task = asyncio.to_thread(check_google_safe_browsing, url)
    ml_task = asyncio.to_thread(check_local_ml_model, url)
    sb_result, ml_result = await asyncio.gather(sb_task, ml_task)

    # Composite risk
    composite_risk = heuristics["penalty"]
    if sb_result.get("flagged"):
        composite_risk += 70
    if ml_result.get("is_phishing"):
        ml_conf = ml_result.get("confidence", 0.0)
        if not sb_result.get("flagged") and len(heuristics["flags"]) == 0:
            composite_risk += int(ml_conf * 10)
        else:
            composite_risk += int(ml_conf * 30)
    composite_risk = min(max(composite_risk, 0), 100)

    # Threat level
    if composite_risk >= 70:
        threat_level = "CRITICAL"
    elif composite_risk >= 40:
        threat_level = "WARNING"
    elif composite_risk >= 15:
        threat_level = "CAUTION"
    else:
        threat_level = "SAFE"

    # ---------- Explanation: Conditional based on 'explain' flag ----------
    if explain:
        # Full AI explanation (Gemini + Groq)
        xai = generate_ai_explanation(url, sb_result, ml_result, heuristics, composite_risk)
        short = xai["short"]
        detailed = xai["detailed"]
        indicators = xai["indicators"]
    else:
        # Quick explanation (no AI call)
        if composite_risk >= 70:
            short = f"🚨 CRITICAL ({composite_risk}%)"
            detailed = f"Risk score {composite_risk}% based on ML and heuristics."
        elif composite_risk >= 40:
            short = f"⚠️ WARNING ({composite_risk}%)"
            detailed = f"Risk score {composite_risk}% – suspicious indicators detected."
        elif composite_risk >= 15:
            short = f"⚡ CAUTION ({composite_risk}%)"
            detailed = f"Risk score {composite_risk}% – minor anomalies."
        else:
            short = f"✅ SAFE ({composite_risk}%)"
            detailed = "No threats detected by ML or heuristics."
        indicators = heuristics["flags"] if heuristics["flags"] else ["Clean scan"]

    return ScanResponse(
        url=url,
        risk_score=composite_risk,
        threat_level=threat_level,
        short_explanation=short,
        detailed_analysis=detailed,
        heuristics_flagged=indicators,
        layer_diagnostics=LayerResults(
            google_safe_browsing=sb_result,
            local_ml_engine=ml_result
        )
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)