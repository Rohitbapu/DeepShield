// ============================================================
// DEEPSHIELD V5.1 - BACKGROUND (REPORT OPENER + BLOCK HANDLER)
// ============================================================

const LANDING_PAGE = "https://rohitbapu.github.io/DeepShield";
const BLOCKED_PAGE = chrome.runtime.getURL("blocked.html");

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "open_report") {
    chrome.tabs.create({ url: LANDING_PAGE + '?url=' + encodeURIComponent(request.url) });
    sendResponse({ status: "opened" });
    return true;
  }

  if (request.action === "block_link") {
    const url = request.url;
    const tabId = sender.tab.id;
    chrome.tabs.create({ url: BLOCKED_PAGE + '?url=' + encodeURIComponent(url) + '&tabId=' + tabId });
    sendResponse({ status: "blocked" });
    return true;
  }

  if (request.action === "open_dashboard") {
    chrome.tabs.create({ url: LANDING_PAGE });
    sendResponse({ status: "opened" });
    return true;
  }
});