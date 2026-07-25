document.addEventListener('DOMContentLoaded', () => {
    const dot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const toggleBtn = document.getElementById('main-toggle');
    const allowBtn = document.getElementById('add-allowlist');
    const scanBtn = document.getElementById('active-scan-btn');

    const API_URL = "https://YOUR-RENDER-URL.onrender.com";

    // 1. Check Backend Health
    fetch(`${API_URL}/`, { method: "GET" })
        .then(() => {
            dot.classList.add('online');
            statusText.innerText = "CONNECTED";
        })
        .catch(() => {
            statusText.innerText = "OFFLINE";
            dot.style.background = '#f43f5e';
        });

    // 2. Toggle Protection
    chrome.storage.local.get(['filterDisabled'], (res) => {
        let disabled = res.filterDisabled || false;
        toggleBtn.innerText = disabled ? "Protection: OFF" : "Protection: ON";
        if (disabled) toggleBtn.classList.add('active');
    });

    toggleBtn.addEventListener('click', () => {
        chrome.storage.local.get(['filterDisabled'], (res) => {
            const newState = !res.filterDisabled;
            chrome.storage.local.set({ filterDisabled: newState }, () => {
                toggleBtn.innerText = newState ? "Protection: OFF" : "Protection: ON";
                toggleBtn.classList.toggle('active');
            });
        });
    });

    // 3. Active Scan Button
    scanBtn.addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, { action: "trigger_active_scan" });
                scanBtn.innerText = "⏳ Scanning...";
                scanBtn.disabled = true;
                setTimeout(() => {
                    scanBtn.innerText = "🔍 Scan This Page Now";
                    scanBtn.disabled = false;
                }, 5000);
                setTimeout(() => window.close(), 800);
            }
        });
    });

    // 4. Add to Allowlist
    allowBtn.addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            try {
                const domain = new URL(tabs[0].url).hostname.replace('www.', '');
                chrome.storage.local.get(['allowlist'], (res) => {
                    const list = res.allowlist || [];
                    if (!list.includes(domain)) {
                        list.push(domain);
                        chrome.storage.local.set({ allowlist: list }, () => {
                            allowBtn.innerText = "✅ Added!";
                            setTimeout(() => location.reload(), 1200);
                        });
                    } else {
                        allowBtn.innerText = "⏳ Already Safe";
                        setTimeout(() => location.reload(), 1200);
                    }
                });
            } catch (e) {
                allowBtn.innerText = "⚠️ Error";
            }
        });
    });
});