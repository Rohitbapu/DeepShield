// ============================================================
// DEEPSHIELD V5.0 - BACKGROUND (REPORT OPENER)
// ============================================================

const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "open_report") {
    chrome.tabs.create({ url: LANDING_PAGE + '?url=' + encodeURIComponent(request.url) });
    sendResponse({ status: "opened" });
  }
  return true;
});