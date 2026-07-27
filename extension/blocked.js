// ============================================================
// DEEPSHIELD - BLOCKED PAGE LOGIC
// ============================================================

(function() {
  console.log('[DeepShield] Blocked page script loaded.');

  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url');
  const originalTabId = parseInt(params.get('tabId'));

  const urlDisplay = document.getElementById('blockedUrl');
  const addBtn = document.getElementById('addSafeBtn');
  const goBackBtn = document.getElementById('goBackBtn');
  const successMsg = document.getElementById('successMessage');

  // Display the URL
  if (blockedUrl) {
    urlDisplay.textContent = blockedUrl;
    try {
      const parsed = new URL(blockedUrl);
      const domain = parsed.hostname.replace('www.', '');
      addBtn.dataset.domain = domain;
      console.log('[DeepShield] Domain:', domain);
    } catch (e) {
      console.error('[DeepShield] Invalid URL:', e);
      addBtn.disabled = true;
      addBtn.textContent = 'Invalid URL';
    }
  } else {
    urlDisplay.textContent = 'No URL provided.';
    addBtn.disabled = true;
    addBtn.textContent = 'No URL';
  }

  // "Add to Safe List" button
  addBtn.addEventListener('click', function() {
    const domain = this.dataset.domain;
    if (!domain) {
      alert('No domain to add.');
      return;
    }
    console.log('[DeepShield] Adding to safe list:', domain);

    chrome.storage.local.get(['allowlist'], function(data) {
      const list = data.allowlist || [];
      if (!list.includes(domain)) {
        list.push(domain);
        chrome.storage.local.set({ allowlist: list }, function() {
          console.log('[DeepShield] Added:', domain);

          // Show success
          addBtn.style.display = 'none';
          successMsg.style.display = 'block';

          // Reload original tab
          if (originalTabId && !isNaN(originalTabId)) {
            chrome.tabs.reload(originalTabId, function() {
              console.log('[DeepShield] Reloaded tab:', originalTabId);
            });
          } else {
            // Fallback: reload previous tab
            chrome.tabs.query({ active: false, currentWindow: true }, function(tabs) {
              for (var i = 0; i < tabs.length; i++) {
                if (tabs[i].url && !tabs[i].url.includes('blocked.html')) {
                  chrome.tabs.reload(tabs[i].id);
                  console.log('[DeepShield] Reloaded fallback tab:', tabs[i].url);
                  break;
                }
              }
            });
          }

          // Close blocked page
          setTimeout(function() {
            chrome.tabs.getCurrent(function(tab) {
              if (tab && tab.id) chrome.tabs.remove(tab.id);
            });
          }, 1500);
        });
      } else {
        addBtn.textContent = '✅ Already in Safe List';
        addBtn.disabled = true;
        setTimeout(function() {
          chrome.tabs.getCurrent(function(tab) {
            if (tab && tab.id) chrome.tabs.remove(tab.id);
          });
        }, 1500);
      }
    });
  });

  // "Go Back" – closes the tab
  goBackBtn.addEventListener('click', function() {
    chrome.tabs.getCurrent(function(tab) {
      if (tab && tab.id) chrome.tabs.remove(tab.id);
    });
  });
})();