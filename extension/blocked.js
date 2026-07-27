document.addEventListener('DOMContentLoaded', function() {
  console.log('[DeepShield] Blocked page loaded.');

  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url');
  const urlDisplay = document.getElementById('blockedUrl');
  const addBtn = document.getElementById('addSafeBtn');
  const goBackBtn = document.getElementById('goBackBtn');

  console.log('[DeepShield] Blocked URL param:', blockedUrl);

  if (blockedUrl) {
    urlDisplay.textContent = blockedUrl;
    try {
      const parsed = new URL(blockedUrl);
      const domain = parsed.hostname.replace('www.', '');
      addBtn.dataset.domain = domain;
      console.log('[DeepShield] Domain extracted:', domain);
    } catch (e) {
      console.error('[DeepShield] Invalid URL:', e);
      addBtn.disabled = true;
      addBtn.textContent = 'Invalid URL';
    }
  } else {
    urlDisplay.textContent = 'No URL provided.';
    addBtn.disabled = true;
  }

  // Add to Safe List button
  addBtn.addEventListener('click', function() {
    const domain = this.dataset.domain;
    console.log('[DeepShield] Add to safe list clicked, domain:', domain);
    if (!domain) {
      alert('No domain to add.');
      return;
    }
    chrome.storage.local.get(['allowlist'], function(data) {
      const list = data.allowlist || [];
      if (!list.includes(domain)) {
        list.push(domain);
        chrome.storage.local.set({ allowlist: list }, function() {
          console.log('[DeepShield] Domain added to allowlist:', domain);
          addBtn.textContent = '✅ Added!';
          addBtn.disabled = true;
          setTimeout(function() {
            window.close();
          }, 1500);
        });
      } else {
        addBtn.textContent = '✅ Already in Safe List';
        addBtn.disabled = true;
        setTimeout(window.close, 1500);
      }
    });
  });

  // Go Back button
  goBackBtn.addEventListener('click', function() {
    window.history.back();
  });
});