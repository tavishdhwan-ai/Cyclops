document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('demo-protection-toggle');
  const statusTitle = document.getElementById('status-title');
  const statusDesc = document.getElementById('status-desc');
  const statusDot = document.getElementById('status-dot');
  const btnTestDemo = document.getElementById('btn-test-demo');
  const feedbackMsg = document.getElementById('demo-feedback-msg');

  // Load persisted protection state (default to true)
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get({ demoProtectionEnabled: true }, (res) => {
      const isEnabled = res.demoProtectionEnabled !== false;
      toggle.checked = isEnabled;
      toggle.setAttribute('aria-checked', isEnabled.toString());
      updateUIState(isEnabled);
    });
  } else {
    // Fallback if chrome.storage is missing during standalone preview
    updateUIState(toggle.checked);
  }

  // Handle toggle changes
  toggle.addEventListener('change', (e) => {
    const isEnabled = e.target.checked;
    toggle.setAttribute('aria-checked', isEnabled.toString());
    updateUIState(isEnabled);

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ demoProtectionEnabled: isEnabled }, () => {
        if (chrome.runtime && chrome.runtime.lastError) {
          console.error('[SentinelAI Popup] Storage error:', chrome.runtime.lastError);
        }
      });
    }
  });

  // Accessible Keyboard controls for toggle
  toggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggle.checked = !toggle.checked;
      toggle.dispatchEvent(new Event('change'));
    }
  });

  // Handle "Test Demo Email" button click
  btnTestDemo.addEventListener('click', () => {
    const targetUrl = 'http://localhost:3000/emails';

    showFeedback('Opening local SentinelAI demo route...', 'info');

    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: targetUrl }, (tab) => {
        if (chrome.runtime && chrome.runtime.lastError) {
          showFeedback('Failed to open tab automatically. Please open http://localhost:3000/emails', 'error');
        } else {
          showFeedback('Opened SentinelAI Email Demo in a new tab.', 'success');
        }
      });
    } else {
      // Fallback preview action
      try {
        window.open(targetUrl, '_blank');
        showFeedback('Opened demo route: ' + targetUrl, 'success');
      } catch (err) {
        showFeedback('Local demo route: http://localhost:3000/emails', 'info');
      }
    }
  });

  // Accessible keyboard Enter/Space support on Test Demo Email button
  btnTestDemo.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      btnTestDemo.click();
    }
  });

  function updateUIState(isEnabled) {
    if (isEnabled) {
      statusTitle.textContent = 'Protection Active';
      statusDesc.textContent = 'Gmail threat detection is active.';
      statusDot.className = 'sentinel-status-indicator active';
    } else {
      statusTitle.textContent = 'Protection Paused';
      statusDesc.textContent = 'Protection disabled. No panels will be injected.';
      statusDot.className = 'sentinel-status-indicator paused';
    }
  }

  function showFeedback(text, type = 'info') {
    feedbackMsg.style.display = 'block';
    feedbackMsg.textContent = text;
    feedbackMsg.className = `sentinel-feedback-msg ${type}`;
    setTimeout(() => {
      if (feedbackMsg) feedbackMsg.style.display = 'none';
    }, 4000);
  }
});
