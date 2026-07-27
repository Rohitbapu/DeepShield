// ============================================================
// DEEPSHIELD V5.1 - BACKGROUND (REPORT OPENER + BLOCK HANDLER)
// ============================================================

const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";
const BLOCKED_PAGE = chrome.runtime.getURL("blocked.html");

// Open deep-dive report on landing page
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "open_report") {
    chrome.tabs.create({ url: LANDING_PAGE + '?url=' + encodeURIComponent(request.url) });
    sendResponse({ status: "opened" });
    return true;
  }

  // Block a dangerous link and show the blocked page
  if (request.action === "block_link") {
    const url = request.url;
    // Open blocked page with the URL as parameter
    chrome.tabs.create({ url: BLOCKED_PAGE + '?url=' + encodeURIComponent(url) });
    sendResponse({ status: "blocked" });
    return true;
  }

  // Open the landing page dashboard
  if (request.action === "open_dashboard") {
    chrome.tabs.create({ url: LANDING_PAGE });
    sendResponse({ status: "opened" });
    return true;
  }
});