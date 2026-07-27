// ============================================================
// DEEPSHIELD V5.1 - CONTENT SCRIPT (DIRECT API + CLICK BLOCK)
// ============================================================

const API_URL = "https://regions-organizations-hand-highly.trycloudflare.com/api/v1/scan";
const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";

const scannedCache = new Map();
let blockListenersAttached = false;

console.log("[DeepShield] Content script loaded.");

function scanSingleUrl(targetUrl) {
  return new Promise((resolve) => {
    targetUrl = targetUrl.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      resolve(null);
      return;
    }

    if (scannedCache.has(targetUrl)) {
      resolve(scannedCache.get(targetUrl));
      return;
    }

    fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    })
    .then(response => {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    })
    .then(data => {
      scannedCache.set(targetUrl, data);
      resolve(data);
    })
    .catch(error => {
      console.warn('[DeepShield] Scan error:', error);
      resolve(null);
    });
  });
}

function highlightLink(anchor, scanData) {
  if (!scanData || scanData.risk_score < 40) return;

  const isCritical = scanData.risk_score >= 70;
  anchor.classList.add(isCritical ? 'ds-danger' : 'ds-warning');
  anchor.title = '🚨 DeepShield: ' + scanData.risk_score + '% - ' + (scanData.short_explanation || 'Suspicious');

  // Badge for deep-dive report
  var badge = document.createElement('span');
  badge.className = 'ds-badge ' + (isCritical ? 'ds-badge-danger' : 'ds-badge-warning');
  badge.textContent = isCritical ? '🚨' : '⚠️';
  badge.title = 'Click for full report';
  badge.style.marginLeft = '6px';
  badge.style.cursor = 'pointer';
  badge.addEventListener('click', function(e) {
    e.stopPropagation();
    e.preventDefault();
    chrome.runtime.sendMessage({ action: "open_report", url: anchor.href });
  });
  anchor.parentNode.insertBefore(badge, anchor.nextSibling);

  // Attach click blocker if not already done
  if (!blockListenersAttached) {
    attachClickBlockers();
  }
}

function attachClickBlockers() {
  // Use event delegation to catch clicks on dangerous links
  document.addEventListener('click', function(e) {
    let target = e.target.closest('a.ds-danger, a.ds-warning');
    if (target) {
      // Only block if the click is not on the badge (already handled)
      if (e.target.closest('.ds-badge')) return;
      e.preventDefault();
      e.stopPropagation();
      // Send the blocked link to background (tab ID is captured automatically)
      chrome.runtime.sendMessage({ action: "block_link", url: target.href });
    }
  }, true); // capture phase to intercept before navigation
  blockListenersAttached = true;
}

function scanAllPageLinks() {
  chrome.storage.local.get(['filterDisabled', 'allowlist'], function(storage) {
    if (storage.filterDisabled) {
      console.log('[DeepShield] Protection disabled.');
      return;
    }

    var hostname = window.location.hostname.replace('www.', '');
    var allowlist = storage.allowlist || [];
    if (allowlist.indexOf(hostname) !== -1) {
      console.log('[DeepShield] Site is in allowlist, skipping.');
      return;
    }

    var anchors = document.querySelectorAll('a[href]');
    var urls = [];
    anchors.forEach(function(a) {
      var href = a.href;
      if (href && href.startsWith('http')) {
        if (urls.indexOf(href) === -1) urls.push(href);
      }
    });

    if (urls.length === 0) return;
    console.log('[DeepShield] Scanning ' + urls.length + ' links...');

    urls.forEach(function(url) {
      scanSingleUrl(url).then(function(data) {
        if (data && data.risk_score >= 40) {
          var selector = 'a[href="' + url.replace(/"/g, '\\"') + '"]';
          document.querySelectorAll(selector).forEach(function(anchor) {
            highlightLink(anchor, data);
          });
          console.warn('[DeepShield] Flagged: ' + url + ' (' + data.risk_score + '%)');
        }
      });
    });
  });
}

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "trigger_active_scan") {
    scanAllPageLinks();
    sendResponse({ status: "done" });
  }
  return true;
});

if (document.readyState === 'complete') {
  scanAllPageLinks();
} else {
  window.addEventListener('load', scanAllPageLinks);
}