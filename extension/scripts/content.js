// ============================================================
// DEEPSHIELD V2.9 - CONTENT SCRIPT (SILENT FOR SAFE URLS)
// Only highlights and badges for dangerous URLs.
// ============================================================

const BADGE_CLASS = 'ds-badge';
const DANGER_CLASS = 'ds-danger';
const THRESHOLD = 40; // Only show badges if risk_score > 40

let processedUrls = new Set();

// ---------- CHECK PROTECTION ----------
function isProtectionActive() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['filterDisabled', 'allowlist'], (data) => {
            if (data.filterDisabled === true) {
                resolve({ active: false, reason: 'disabled' });
                return;
            }
            try {
                const domain = window.location.hostname.replace('www.', '');
                if (data.allowlist && data.allowlist.includes(domain)) {
                    resolve({ active: false, reason: 'allowlisted' });
                    return;
                }
            } catch (e) { /* ignore */ }
            resolve({ active: true });
        });
    });
}

// ---------- INJECT BADGE (ONLY IF DANGEROUS) ----------
function injectBadge(anchor, riskData) {
    const url = anchor.href;
    const score = riskData.risk_score || 0;

    // 🔴 IMPORTANT: If score <= THRESHOLD, do NOTHING
    if (score <= THRESHOLD) {
        console.log(`DeepShield: Safe URL – no action taken (${score}%)`, url);
        return;
    }

    // If already processed, skip
    if (processedUrls.has(url)) return;

    const isDanger = score > 60;
    const isWarning = score > 40 && score <= 60;
    const tooltip = riskData.short_explanation || "Suspicious link detected";

    // Find all anchors with this exact URL
    const allMatchingAnchors = document.querySelectorAll(`a[href="${url}"]`);
    
    // Highlight all matching anchors
    allMatchingAnchors.forEach(a => {
        if (isDanger) {
            a.classList.add(DANGER_CLASS);
        } else if (isWarning) {
            a.style.border = '2px solid #facc15';
            a.style.backgroundColor = 'rgba(250, 204, 21, 0.08)';
            a.style.borderRadius = '4px';
        }
    });

    // Only inject badge on the FIRST anchor to avoid clutter
    if (anchor !== allMatchingAnchors[0]) {
        processedUrls.add(url);
        return;
    }

    processedUrls.add(url);

    // Create badge
    const badge = document.createElement('span');
    badge.className = `ds-badge ${isDanger ? 'ds-badge-danger' : 'ds-badge-warning'}`;
    const emoji = isDanger ? '🚨' : '⚠️';
    badge.textContent = `${emoji} ${score}%`;
    badge.title = tooltip;
    
    // Click handler: opens deep-dive report
    badge.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        chrome.runtime.sendMessage({ action: "open_report", url: url });
    });

    // Insert badge after the anchor
    anchor.parentNode.insertBefore(badge, anchor.nextSibling);
}

// ---------- PROCESS SINGLE URL ----------
async function processSingleUrl(url) {
    const status = await isProtectionActive();
    if (!status.active) return;
    if (url && url.startsWith('http') && !processedUrls.has(url)) {
        chrome.runtime.sendMessage({ action: "check_url", url: url });
    }
}

// ---------- LISTENER FOR RESULTS ----------
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === "display_result") {
        const { url, data, error } = msg;
        if (error) {
            console.warn("DeepShield error for", url, error);
            return;
        }

        // 🔴 IMPORTANT: Only proceed if risk_score > THRESHOLD
        if (data.risk_score <= THRESHOLD) {
            console.log(`DeepShield: Safe URL – no action taken (${data.risk_score}%)`, url);
            return;
        }

        const anchors = document.querySelectorAll(`a[href="${url}"]`);
        if (anchors.length > 0) {
            injectBadge(anchors[0], data);
        }
    }
});

// ---------- SCAN EXISTING LINKS ----------
async function scanExistingLinks() {
    const status = await isProtectionActive();
    if (!status.active) return;

    const anchors = document.querySelectorAll('a[href]');
    const urls = new Set();
    anchors.forEach(a => {
        const href = a.href;
        if (href && href.startsWith('http')) {
            urls.add(href);
        }
    });
    urls.forEach(url => {
        chrome.runtime.sendMessage({ action: "check_url", url: url });
    });
}

// ---------- ACTIVE SCAN (from popup) ----------
async function triggerActiveScan() {
    const status = await isProtectionActive();
    if (!status.active) {
        showFloatingToast('⚠️ Protection is disabled or site is allowlisted.', 'warning');
        return;
    }

    const anchors = document.querySelectorAll('a[href]');
    const urls = new Set();
    anchors.forEach(a => {
        const href = a.href;
        if (href && href.startsWith('http')) {
            urls.add(href);
        }
    });
    const uniqueUrls = Array.from(urls);
    if (uniqueUrls.length === 0) {
        showFloatingToast('No external links found on this page.', 'info');
        return;
    }

    chrome.runtime.sendMessage({ action: "active_scan", urls: uniqueUrls });
    showFloatingToast(`🔄 Scanning ${uniqueUrls.length} links...`, 'loading');
}

// ---------- FLOATING TOAST ----------
function showFloatingToast(message, type) {
    let toast = document.getElementById('ds-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'ds-toast';
        toast.style.cssText = `
            position: fixed; bottom: 20px; right: 20px; z-index: 999999;
            background: #1e293b; color: white; padding: 12px 24px;
            border-radius: 12px; font-family: system-ui; font-size: 14px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.8); border: 1px solid #334155;
            transition: opacity 0.3s; max-width: 400px; pointer-events: none;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.display = 'block';
    toast.style.opacity = '1';
    
    const bgColors = { loading: '#1e3a8a', warning: '#7f1d1d', info: '#1e293b', success: '#14532d' };
    toast.style.background = bgColors[type] || '#1e293b';
    
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => { 
        toast.style.opacity = '0';
        setTimeout(() => { toast.style.display = 'none'; }, 300);
    }, 6000);
}

// ---------- LISTEN FOR ACTIVE SCAN ----------
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === "trigger_active_scan") {
        triggerActiveScan();
    }
});

// ---------- INITIALIZATION ----------
setTimeout(scanExistingLinks, 1500);

const observer = new MutationObserver((mutations) => {
    mutations.forEach(m => {
        m.addedNodes.forEach(node => {
            if (node.nodeType === 1) {
                const links = node.tagName === 'A' ? [node] : node.querySelectorAll('a[href]');
                links.forEach(a => {
                    if (a.href && a.href.startsWith('http')) {
                        processSingleUrl(a.href);
                    }
                });
            }
        });
    });
});
observer.observe(document.body, { childList: true, subtree: true });