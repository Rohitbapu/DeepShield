// ============================================================
// DEEPSHIELD DLP - CONTENT SCRIPT (PAGE LINK SCANNER)
// ============================================================

const scannedUrlCache = new Map();

/**
 * Delegates URL scanning to background.js proxy
 */
function scanSingleUrl(targetUrl) {
  return new Promise((resolve) => {
    if (!targetUrl || typeof targetUrl !== 'string') return resolve(null);
    targetUrl = targetUrl.trim();

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      return resolve(null);
    }

    if (scannedUrlCache.has(targetUrl)) {
      return resolve(scannedUrlCache.get(targetUrl));
    }

    chrome.runtime.sendMessage(
      { action: "scan_url_proxy", targetUrl: targetUrl },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn("[DeepShield] Messaging error:", chrome.runtime.lastError.message);
          return resolve(null);
        }

        if (response && response.success) {
          scannedUrlCache.set(targetUrl, response.data);
          resolve(response.data);
        } else {
          resolve(null);
        }
      }
    );
  });
}

/**
 * Highlights suspicious links on the page
 */
function highlightSuspiciousLinks(url, scanData) {
  if (!scanData || scanData.risk_score < 40) return;

  try {
    const selector = `a[href="${CSS.escape(url)}"], a[href="${CSS.escape(url)}/"]`;
    const anchorElements = document.querySelectorAll(selector);

    anchorElements.forEach(anchor => {
      const isCritical = scanData.risk_score >= 70;
      anchor.classList.add(isCritical ? 'ds-danger' : 'ds-warning');
      anchor.title = `🚨 DeepShield Threat Flag (${scanData.risk_score}% Risk - ${scanData.threat_level}): ${scanData.short_explanation || 'Suspicious structural features detected.'}`;
    });
  } catch (e) {
    console.error("[DeepShield] Highlighting error:", e);
  }
}

/**
 * Collects and scans all page links
 */
async function scanAllPageLinks() {
  console.log("[DeepShield] Gathering links for analysis...");

  const storageData = await new Promise(resolve => chrome.storage.local.get(['filterDisabled', 'allowlist'], resolve));
  if (storageData.filterDisabled) {
    console.log("[DeepShield] Real-time protection is OFF.");
    return;
  }

  const allowlist = storageData.allowlist || [];
  const currentHostname = window.location.hostname.replace('www.', '');
  if (allowlist.includes(currentHostname)) {
    console.log("[DeepShield] Site is in user allowlist. Skipping scan.");
    return;
  }

  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter((value, index, self) => self.indexOf(value) === index);

  if (links.length === 0) return;

  console.log(`[DeepShield] Analyzing ${links.length} unique links...`);

  for (const linkUrl of links) {
    const scanData = await scanSingleUrl(linkUrl);
    if (scanData && scanData.risk_score >= 40) {
      highlightSuspiciousLinks(linkUrl, scanData);
      console.warn(`🚨 [DeepShield Flagged] ${linkUrl} (${scanData.risk_score}%)`);
    }
  }
}

// Listen for popup trigger
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "trigger_active_scan") {
    scanAllPageLinks();
    sendResponse({ status: "Scan initiated" });
  }
  return true;
});

// Auto-run on document idle
if (document.readyState === 'complete') {
  scanAllPageLinks();
} else {
  window.addEventListener('load', scanAllPageLinks);
}