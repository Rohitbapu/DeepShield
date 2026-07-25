document.addEventListener('DOMContentLoaded', () => {
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const scanBtn = document.getElementById('activeScanBtn');
  const allowlistBtn = document.getElementById('allowlistBtn');
  const toggleBtn = document.getElementById('toggleProtectionBtn');

  const API_URL = 'https://deepshield-p6ux.onrender.com'; // REPLACE

  // ---------- CHECK BACKEND ----------
  fetch(`${API_URL}/health`)
    .then(() => {
      statusDot.classList.add('online');
      statusText.textContent = 'Online';
    })
    .catch(() => {
      statusText.textContent = 'Offline';
    });

  // ---------- ACTIVE SCAN ----------
  scanBtn.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "trigger_active_scan" });
        scanBtn.textContent = '⏳ Scanning...';
        scanBtn.disabled = true;
        setTimeout(() => {
          scanBtn.textContent = '🔍 Scan This Page';
          scanBtn.disabled = false;
          window.close();
        }, 3000);
      }
    });
  });

  // ---------- TOGGLE PROTECTION ----------
  chrome.storage.local.get(['filterDisabled'], (data) => {
    const disabled = data.filterDisabled || false;
    toggleBtn.textContent = disabled ? '🛡️ Protection: OFF' : '🛡️ Protection: ON';
    toggleBtn.classList.toggle('btn-danger', disabled);
    toggleBtn.classList.toggle('btn-secondary', !disabled);
  });

  toggleBtn.addEventListener('click', () => {
    chrome.storage.local.get(['filterDisabled'], (data) => {
      const newState = !data.filterDisabled;
      chrome.storage.local.set({ filterDisabled: newState }, () => {
        toggleBtn.textContent = newState ? '🛡️ Protection: OFF' : '🛡️ Protection: ON';
        toggleBtn.classList.toggle('btn-danger', newState);
        toggleBtn.classList.toggle('btn-secondary', !newState);
      });
    });
  });

  // ---------- ALLOWLIST ----------
  function updateAllowlistButton(domain) {
    chrome.storage.local.get(['allowlist'], (data) => {
      const list = data.allowlist || [];
      if (list.includes(domain)) {
        allowlistBtn.textContent = '✅ Already Safe';
        allowlistBtn.classList.add('btn-success');
        allowlistBtn.classList.remove('btn-secondary');
        allowlistBtn.disabled = true;
      } else {
        allowlistBtn.textContent = '+ Add Current Site to Safe List';
        allowlistBtn.classList.remove('btn-success');
        allowlistBtn.classList.add('btn-secondary');
        allowlistBtn.disabled = false;
      }
    });
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      try {
        const domain = new URL(tabs[0].url).hostname.replace('www.', '');
        updateAllowlistButton(domain);
        allowlistBtn.dataset.domain = domain;
      } catch (e) {
        allowlistBtn.textContent = '⚠️ No site detected';
        allowlistBtn.disabled = true;
      }
    }
  });

  allowlistBtn.addEventListener('click', () => {
    const domain = allowlistBtn.dataset.domain;
    if (!domain) return;
    chrome.storage.local.get(['allowlist'], (data) => {
      const list = data.allowlist || [];
      if (!list.includes(domain)) {
        list.push(domain);
        chrome.storage.local.set({ allowlist: list }, () => {
          allowlistBtn.textContent = '✅ Added to Safe List!';
          allowlistBtn.classList.add('btn-success');
          allowlistBtn.classList.remove('btn-secondary');
          allowlistBtn.disabled = true;
          setTimeout(() => window.close(), 1500);
        });
      }
    });
  });
});