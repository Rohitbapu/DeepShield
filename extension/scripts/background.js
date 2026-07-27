// ============================================================
// DEEPSHIELD V5.0 - BACKGROUND SERVICE WORKER (CORS PROXY)
// ============================================================

const BASE_URL = "https://communities-artists-management-cyber.trycloudflare.com";
const API_URL = `${BASE_URL}/api/v1/scan`;
const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";

// Internal scan memory cache (5-minute TTL)
const scanCache = new Map();

async function executeBackendScan(url) {
    if (scanCache.has(url)) {
        const cached = scanCache.get(url);
        if (Date.now() - cached.timestamp < 300000) {
            return cached.data;
        }
        scanCache.delete(url);
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Bypass-Tunnel-Remainder': 'true'
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        scanCache.set(url, { data, timestamp: Date.now() });
        return data;

    } catch (error) {
        console.error("[DeepShield Background] Scan error for", url, error.message);
        return null;
    }
}

function openDeepDive(url) {
    chrome.tabs.create({ url: `${LANDING_PAGE}?url=${encodeURIComponent(url)}` });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // 1. Proxy scan request from Content Script (Bypasses Content Script CORS)
    if (request.action === "scan_url_proxy") {
        executeBackendScan(request.targetUrl).then(data => {
            if (data) {
                sendResponse({ success: true, data });
            } else {
                sendResponse({ success: false, error: "Service unavailable or offline" });
            }
        });
        return true;
    }

    // 2. Open Deep Dive report in landing page
    if (request.action === "open_report") {
        openDeepDive(request.url);
        sendResponse({ status: "opened" });
        return true;
    }
});