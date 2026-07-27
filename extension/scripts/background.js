// ============================================================
// DEEPSHIELD V2.7 - BACKGROUND SERVICE WORKER
// ============================================================

const API_URL = "https://receiving-tower-treasurer-paste.trycloudflare.com/api/v1/scan";
const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";

// Cache to avoid duplicate scans
const scanCache = new Map();

async function scanUrl(url, tabId) {
    // Check cache (5 minutes)
    if (scanCache.has(url)) {
        const cached = scanCache.get(url);
        if (Date.now() - cached.timestamp < 300000) {
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

        scanCache.set(url, { data, timestamp: Date.now() });

        chrome.tabs.sendMessage(tabId, {
            action: "display_result",
            url: url,
            data: data
        });

    } catch (error) {
        console.error("Scan failed for", url, error);
        chrome.tabs.sendMessage(tabId, {
            action: "display_result",
            url: url,
            error: "Service unavailable"
        });
    }
}

function batchScan(urls, tabId) {
    const uniqueUrls = [...new Set(urls)];
    uniqueUrls.forEach((url, index) => {
        setTimeout(() => {
            scanUrl(url, tabId);
        }, index * 300);
    });
}

function openDeepDive(url) {
    chrome.tabs.create({ url: `${LANDING_PAGE}?url=${encodeURIComponent(url)}` });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const tabId = sender.tab ? sender.tab.id : null;

    if (request.action === "check_url") {
        if (tabId) scanUrl(request.url, tabId);
        sendResponse({ status: "queued" });
        return true;
    }

    if (request.action === "active_scan") {
        if (tabId && request.urls && request.urls.length > 0) {
            batchScan(request.urls, tabId);
        }
        sendResponse({ status: "batch_started" });
        return true;
    }

    if (request.action === "open_report") {
        openDeepDive(request.url);
        sendResponse({ status: "opened" });
        return true;
    }
});