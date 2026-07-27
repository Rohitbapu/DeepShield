```markdown
# 🛡️ DeepShield DLP v5.0 – Enterprise Threat Intelligence Engine

Enterprise-grade, privacy-first DLP & phishing detection engine combining local PyTorch transformers, lexical heuristics, Google Safe Browsing, and Gemini AI for explainable threat analysis.

**DeepShield DLP** is an advanced, multi-layered data loss prevention and phishing detection platform. Built with a privacy-first local architecture, it combines real-time lexical heuristic analysis, calibrated local machine learning models, and large language models to deliver instant threat scoring alongside detailed, human-explainable security diagnostics.

---

## ✨ Key Features

* **Multi-Layer Analysis Pipeline:** Combines global allowlisting, real-time threat APIs, local ML transformer inference, and LLM synthesis.
* **Explainable AI (XAI):** Generates concise, technical threat explanations detailing exact risk factors and structural anomalies.
* **Privacy-First Hybrid Architecture:** Executes primary heuristic and ML checks locally before optional cloud enrichment.
* **Full-Stack Ecosystem:** Includes a high-performance FastAPI backend, Manifest V3 Chrome Extension for real-time in-page hyperlink scanning, and an interactive landing dashboard.

---

## 📐 System Architecture & Analysis Pipeline

DeepShield processes target URLs through a 4-Layered Sequential Analysis Pipeline to maximize detection accuracy while minimizing latency and external API dependency:

```text
[ Target URL Input ]
         │
         ├──► Layer 0: Global Domain Allowlist (Fast-Path Filter) ──► [ INSTANT SAFE PASS ]
         │
         ├──► Layer 1: Google Safe Browsing API ──────────────────┐
         │                                                        │
         ├──► Layer 2: Lexical Heuristics + PyTorch Transformer ───┼──► Composite Risk Aggregator (0–100%)
         │                                                        │
         └──► Layer 3: Google Gemini AI (Explainable Synthesis) ──┘

```

**Layer 0: Global Domain Allowlist (Fast-Path Filter)**
Instantly validates verified, high-trust domains (e.g., google.com, github.com) to bypass heavy ML/API processing and achieve near-zero-latency scans.

**Layer 1: Google Safe Browsing API**
Queries global threat databases in real-time for known malware, social engineering, and unwanted software distribution targets.

**Layer 2: Lexical Heuristics & Local PyTorch ML**
The Lexical Engine extracts structural anomalies like raw IP hostnames, suspicious TLDs, deep subdomain nesting, and brand spoofing patterns. Simultaneously, the PyTorch Transformer Model evaluates semantic features locally on hardware (CPU AVX / CUDA GPU) without exposing user browsing activity.

**Layer 3: Google Gemini AI (Explainable Threat Synthesis)**
Synthesizes diagnostic signals into plain-language, technical summaries explaining exactly why a link is dangerous, backed by automated quota fallback logic for rate-limit resilience.

---

## 🛠️ Repository Structure

```text
DeepShield/
├── backend/
│   ├── backend_main.py          # FastAPI application & security pipeline
│   ├── phishing_detection_py.py # PyTorch model loader & inference pipeline
│   ├── .env                     # API keys and environment configuration
│   └── requirements.txt         # Python backend dependencies
├── extension/
│   ├── manifest.json            # Chrome Extension Manifest V3 configuration
│   ├── background.js            # Service worker CORS fetch proxy
│   ├── content.js               # Page DOM link extraction & visual highlighting
│   ├── popup.html               # Extension control popup UI
│   ├── popup.js                 # Popup UI event handling & health checks
│   └── styles.css               # Injected DOM threat highlighting styles
├── landing/
│   └── index.html               # Interactive dashboard & manual URL scanner
└── README.md

```

---

## 🚀 Quick Start & Installation Guide

### Prerequisites

* **Python:** 3.10+
* **Browser:** Google Chrome or any Chromium-based browser (Brave, Edge)
* **Cloud Tunnels (Optional):** Cloudflare Tunnel (`cloudflared`) or Ngrok for remote background worker pairing.

### 1. Backend Setup

Clone the Repository and navigate to the backend directory:

```bash
git clone [https://github.com/rohitbapu/DeepShield.git](https://github.com/rohitbapu/DeepShield.git)
cd DeepShield/backend

```

Create a Virtual Environment & Install Dependencies:

```bash
# Initialize Virtual Environment
python -m venv venv

# Activate on Windows:
.\venv\Scripts\activate

# Activate on Linux/macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

```

Configure Environment Variables by creating a `.env` file in the `backend/` root directory:

```env
SAFE_BROWSING_API_KEY=your_google_cloud_safe_browsing_api_key
GEMINI_API_KEY=your_google_gemini_api_key
GEMINI_MODEL_ID=gemini-2.5-flash
PORT=10000

```

Launch the Engine:

```bash
python backend_main.py

```

### 2. Chrome Extension Setup

* Open Chrome and navigate to `chrome://extensions`.
* Enable **Developer mode** in the top right corner.
* Click **Load unpacked** and select the `extension/` directory.
* Verify the active endpoint in `extension/background.js`, `extension/popup.js`, and `landing/index.html` matches your backend or Cloudflare tunnel URL.

### 3. Landing Dashboard Setup

Open `landing/index.html` in any browser or host it via GitHub Pages. Ensure the configuration variables at the bottom of the HTML file point to your active server instance.

---

## 📡 API Specification

### Health Check

`GET /health`

**Response:**

```json
{
  "status": "DeepShield Engine Online",
  "active_gemini_model": "gemini-2.5-flash",
  "layers": {
    "google_safe_browsing": true,
    "local_pytorch_ml": true,
    "gemini_api": true
  }
}

```

### URL Scan Endpoint

`POST /api/v1/scan`

**Payload:**

```json
{
  "url": "[http://paypal-verification.xyz/login](http://paypal-verification.xyz/login)"
}

```

**Response:**

```json
{
  "url": "[http://paypal-verification.xyz/login](http://paypal-verification.xyz/login)",
  "risk_score": 85,
  "threat_level": "CRITICAL",
  "short_explanation": "🚨 Brand Spoofing & Suspicious TLD Detected",
  "detailed_analysis": "The domain utilizes a high-risk .xyz TLD paired with brand spoofing targeting 'paypal'. Structural features indicate credential harvesting.",
  "heuristics_flagged": [
    "Suspicious TLD detected (xyz)",
    "Possible brand spoofing attempt targeting 'paypal'"
  ],
  "layer_diagnostics": {
    "google_safe_browsing": { "flagged": false, "status": "CLEAN" },
    "local_ml_engine": { "is_phishing": true, "confidence": 0.94, "status": "SUCCESS" }
  }
}

```

---

## 👥 Project Team

* **Rohit Bapu** – Lead Backend & Security Architecture
* **Muhammed Ibrahim** – Machine Learning Pipeline & Threat Analytics
* **K Siddharth** – Frontend Engineering & Browser Integration

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

```

```
