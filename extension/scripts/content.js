// ============================================================
// DEEPSHIELD DLP - CONTENT SCRIPT (PAGE-WIDE LINK SCANNER)
// ============================================================

const BASE_URL = "https://communities-artists-management-cyber.trycloudflare.com";
const API_URL = `${BASE_URL}/api/v1/scan`;

// Cache scanned URLs to avoid duplicate API requests on the same page
const scannedUrlCache = new Map();

/**
 * Sends a single URL to the DeepShield backend for threat analysis
 */
async function scanSingleUrl(targetUrl) {
  // Normalize URL string
  if (!targetUrl || typeof targetUrl !== 'string') return null;
  targetUrl = targetUrl.trim();

  // Skip non-http links (mailto:, javascript:, tel:, fragment links)
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    return null;
  }

  // Check cache first
  if (scannedUrlCache.has(targetUrl)) {
    return scannedUrlCache.get(targetUrl);
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Bypass-Tunnel-Remainder": "true", // Bypass Cloudflare trycloudflare interstitial splash
        "ngrok-skip-browser-warning": "true"
      },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      console.warn(`[DeepShield] Backend error HTTP ${response.status} for ${targetUrl}`);
      return null;
    }

    const data = await response.json();
    scannedUrlCache.set(targetUrl, data);
    return data;

  } catch (error) {
    console.error(`[DeepShield] Connection error scanning ${targetUrl}:`, error.message);
    return null;
  }
}

/**
 * Applies visual threat indicators to matching <a> elements on the web page
 */
function highlightSuspiciousLinks(url, scanData) {
  if (!scanData || scanData.risk_score < 40) return;

  // Query all anchor tags matching or referencing this URL
  const anchorElements = document.querySelectorAll(`a[href="${CSS.escape(url)}"], a[href="${CSS.escape(url)}/"]`);

  anchorElements.forEach(anchor => {
    // Determine severity styling
    const isCritical = scanData.risk_score >= 70;
    const borderColor = isCritical ? '#dc2626' : '#d97706';
    const bgColor = isCritical ? '#fef2f2' : '#fffbeb';
    const textColor = isCritical ? '#dc2626' : '#b45309';

    // Apply inline visual warning highlights
    anchor.style.border = `2px solid ${borderColor}`;
    anchor.style.backgroundColor = bgColor;
    anchor.style.color = textColor;
    anchor.style.fontWeight = "bold";
    anchor.style.borderRadius = "4px";
    anchor.style.padding = "2px 4px";
    anchor.style.transition = "all 0.3s ease";
    
    // Add threat warning tooltip
    anchor.title = `🚨 DeepShield Threat Flag (${scanData.risk_score}% Risk - ${scanData.threat_level}): ${scanData.short_explanation || 'Phishing/Suspicious structural features detected.'}`;
  });
}

/**
 * Collects all hyperlinks on the page and scans them
 */
async function scanAllPageLinks() {
  console.log("[DeepShield] Starting page-wide link scan...");

  // Check if real-time protection is disabled in local storage
  const storageData = await new Promise(resolve => chrome.storage.local.get(['filterDisabled'], resolve));
  if (storageData.filterDisabled) {
    console.log("[DeepShield] Protection is currently OFF in popup settings.");
    return;
  }

  // Extract all unique anchor URLs on the active page
  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter((value, index, self) => self.indexOf(value) === index);

  if (links.length === 0) {
    console.log("[DeepShield] No valid links found on this page.");
    return;
  }

  console.log(`[DeepShield] Found ${links.length} unique links. Dispatching analysis requests...`);

  // Process links sequentially or in small batches to respect rate limits
  for (const linkUrl of links) {
    const scanData = await scanSingleUrl(linkUrl);
    if (scanData && scanData.risk_score >= 40) {
      highlightSuspiciousLinks(linkUrl, scanData);
      console.warn(`🚨 [DeepShield Flagged] ${linkUrl} -> Score: ${scanData.risk_score}% (${scanData.threat_level})`);
    }
  }

  console.log("[DeepShield] Page scan complete.");
}

// ============================================================
// MESSAGE LISTENER (COMMUNICATION WITH POPUP.JS)
// ============================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "trigger_active_scan") {
    console.log("[DeepShield] Manual scan requested from popup.");
    scanAllPageLinks();
    sendResponse({ status: "Scan initiated" });
  }
  return true; // Keeps async response channel open
});

// Auto-run scanner when page loads
if (document.readyState === 'complete') {
  scanAllPageLinks();
} else {
  window.addEventListener('load', scanAllPageLinks);
}