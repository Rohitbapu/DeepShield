// ============================================================
// DEEPSHIELD V2.1 - BACKGROUND SERVICE WORKER
// Routes API calls, manages deduping, opens Landing Page
// ============================================================

const API_URL = "https://YOUR-RENDER-URL.onrender.com/api/v1/scan";
const LANDING_PAGE = "https://YOUR-LANDING-PAGE.vercel.app";

// Simple in-memory deduping cache (prevents duplicate scans within 5 minutes)
const scanCache = new Map();

// ---------------------- SCAN SINGLE URL ----------------------
async function scanUrl(url, tabId) {
    // Check cache
    if (scanCache.has(url)) {
        const cached = scanCache.get(url);
        if (Date.now() - cached.timestamp < 300000) { // 5 minutes
            chrome.tabs.sendMessage(tabId, {
                action: "display_result",
                url: url,
                data: cached.data
            });
            return;
        } else {
            scanCache.delete(url);
        }
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        // Cache the result
        scanCache.set(url, { data, timestamp: Date.now() });

        // Send result to content script
        chrome.tabs.sendMessage(tabId, {
            action: "display_result",
            url: url,
            data: data
        });

    } catch (error) {
        console.error("Scan failed for", url, error);
        // Optionally send error back to content script
        chrome.tabs.sendMessage(tabId, {
            action: "display_result",
            url: url,
            error: "Service unavailable"
        });
    }
}

// ---------------------- BATCH SCAN (Active Scan) ----------------------
function batchScan(urls, tabId) {
    // Filter out duplicates and process sequentially with a small delay
    const uniqueUrls = [...new Set(urls)];
    uniqueUrls.forEach((url, index) => {
        // Add a slight delay between each to avoid overwhelming the backend
        setTimeout(() => {
            scanUrl(url, tabId);
        }, index * 300); // 300ms gap between requests
    });
}

// ---------------------- OPEN LANDING PAGE (Deep-Dive) ----------------------
function openDeepDive(url) {
    chrome.tabs.create({ url: `${LANDING_PAGE}?url=${encodeURIComponent(url)}` });
}

// ---------------------- MESSAGE ROUTER ----------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const tabId = sender.tab ? sender.tab.id : null;

    // 1. Passive check (single URL from content script)
    if (request.action === "check_url") {
        if (tabId) {
            scanUrl(request.url, tabId);
        }
        sendResponse({ status: "queued" });
        return true;
    }

    // 2. Active batch scan (from popup)
    if (request.action === "active_scan") {
        if (tabId && request.urls && request.urls.length > 0) {
            batchScan(request.urls, tabId);
        }
        sendResponse({ status: "batch_started" });
        return true;
    }

    // 3. Open detailed report (from content script badge click)
    if (request.action === "open_report") {
        openDeepDive(request.url);
        sendResponse({ status: "opened" });
        return true;
    }

    // 4. Clear cache (optional, for debugging)
    if (request.action === "clear_cache") {
        scanCache.clear();
        sendResponse({ status: "cache_cleared" });
        return true;
    }
});