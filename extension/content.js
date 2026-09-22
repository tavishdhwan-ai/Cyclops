/**
 * SentinelAI Gmail Security Guard - Content Script
 * Phase 3A Implementation: FastAPI Backend Integration & Extension Connection
 */

(function () {
  // Prevent duplicate content script injection
  if (window.__SENTINEL_AI_CONTENT_SCRIPT_LOADED__) {
    return;
  }
  window.__SENTINEL_AI_CONTENT_SCRIPT_LOADED__ = true;

  // Debugging toggle
  const DEBUG = false;

  function debugLog(...args) {
    if (DEBUG) {
      console.log('[SentinelAI]', ...args);
    }
  }

  // Constants & State
  const PANEL_ID = 'sentinel-ai-panel';
  const BACKEND_URL = 'http://127.0.0.1:8000/scan-email';
  const THEME_STORAGE_KEY = 'sentinelai-theme';
  const POSITION_STORAGE_KEY = 'sentinelai-panel-position';
  
  let isProtectionEnabled = true;
  let isCollapsed = false;
  let isScanning = false;
  let scanProgress = 0;
  let scanStep = 'Initializing scan...';
  let scanTimer = null;
  let reviewStatus = 'pending'; // 'pending' | 'reviewed'
  let expandedFindingId = null;
  let currentEmailKey = null;
  let observer = null;
  let debounceTimeout = null;

  // Theme & Drag state
  let currentTheme = 'dark';
  let isDragging = false;
  let dragStartX = 0;
  let dragStartY = 0;
  let initialPanelX = 0;
  let initialPanelY = 0;
  let rafId = null;

  // Theme Helpers
  function getSavedTheme() {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') {
        return saved;
      }
    } catch (e) {}
    return 'dark';
  }

  function saveTheme(theme) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch (e) {}
  }

  function applyTheme(panelEl, theme) {
    if (!panelEl) return;
    if (theme === 'light') {
      panelEl.classList.add('sentinel-theme-light');
      panelEl.classList.remove('sentinel-theme-dark');
    } else {
      panelEl.classList.add('sentinel-theme-dark');
      panelEl.classList.remove('sentinel-theme-light');
    }
  }

  function updateThemeToggleButton(panelEl, theme) {
    const themeBtn = panelEl.querySelector('#sentinel-toggle-theme');
    if (!themeBtn) return;
    const isLight = theme === 'light';
    themeBtn.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
    themeBtn.setAttribute('title', isLight ? 'Switch to dark mode' : 'Switch to light mode');
    themeBtn.innerHTML = isLight ? `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/></svg>
    ` : `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
    `;
  }

  // Position & Viewport Clamping Helpers
  function getSavedPosition() {
    try {
      const saved = localStorage.getItem(POSITION_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed.x === 'number' && typeof parsed.y === 'number' && !isNaN(parsed.x) && !isNaN(parsed.y)) {
          return { x: parsed.x, y: parsed.y };
        }
      }
    } catch (e) {}
    return null;
  }

  function savePosition(x, y) {
    try {
      localStorage.setItem(POSITION_STORAGE_KEY, JSON.stringify({ x: Math.round(x), y: Math.round(y) }));
    } catch (e) {}
  }

  function clampPosition(x, y, panelWidth, panelHeight) {
    const margin = 12;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    const pWidth = panelWidth || 420;
    const pHeight = panelHeight || 300;

    const minX = margin;
    const maxX = Math.max(margin, vw - pWidth - margin);
    const minY = margin;
    const maxY = Math.max(margin, vh - pHeight - margin);

    const clampedX = Math.min(Math.max(x, minX), maxX);
    const clampedY = Math.min(Math.max(y, minY), maxY);

    return { x: clampedX, y: clampedY };
  }

  function applyPanelPosition(panelEl, pos) {
    if (!panelEl) return;
    const rect = panelEl.getBoundingClientRect();
    const panelWidth = rect.width || 420;
    const panelHeight = rect.height || 300;

    let targetX, targetY;
    if (pos && typeof pos.x === 'number' && typeof pos.y === 'number') {
      targetX = pos.x;
      targetY = pos.y;
    } else {
      targetX = Math.max(12, window.innerWidth - panelWidth - 24);
      targetY = 80;
    }

    const clamped = clampPosition(targetX, targetY, panelWidth, panelHeight);
    panelEl.style.left = `${clamped.x}px`;
    panelEl.style.top = `${clamped.y}px`;
    panelEl.style.right = 'auto';
    panelEl.style.bottom = 'auto';
  }

  // Drag Engine using Pointer Events
  function initDrag(panelEl) {
    if (panelEl.__sentinel_drag_initialized) return;
    panelEl.__sentinel_drag_initialized = true;

    const onPointerDown = (e) => {
      if (e.button !== undefined && e.button !== 0) return;

      const dragArea = e.target.closest('.sentinel-draggable');
      if (!dragArea) return;

      // Ignore clicks on interactive controls inside or near drag area
      if (e.target.closest('button, a, input, select, textarea, .sentinel-icon-btn, [role="button"]')) {
        return;
      }

      e.preventDefault();

      const rect = panelEl.getBoundingClientRect();
      isDragging = true;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
      initialPanelX = rect.left;
      initialPanelY = rect.top;

      panelEl.classList.add('sentinel-dragging');

      window.addEventListener('pointermove', onPointerMove);
      window.addEventListener('pointerup', onPointerUp);
      window.addEventListener('pointercancel', onPointerUp);
    };

    const onPointerMove = (e) => {
      if (!isDragging) return;

      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        const deltaX = e.clientX - dragStartX;
        const deltaY = e.clientY - dragStartY;

        const newX = initialPanelX + deltaX;
        const newY = initialPanelY + deltaY;

        const rect = panelEl.getBoundingClientRect();
        const clamped = clampPosition(newX, newY, rect.width, rect.height);

        panelEl.style.left = `${clamped.x}px`;
        panelEl.style.top = `${clamped.y}px`;
        panelEl.style.right = 'auto';
      });
    };

    const onPointerUp = () => {
      if (!isDragging) return;
      isDragging = false;
      panelEl.classList.remove('sentinel-dragging');

      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('pointercancel', onPointerUp);

      const rect = panelEl.getBoundingClientRect();
      const clamped = clampPosition(rect.left, rect.top, rect.width, rect.height);
      panelEl.style.left = `${clamped.x}px`;
      panelEl.style.top = `${clamped.y}px`;
      panelEl.style.right = 'auto';
      savePosition(clamped.x, clamped.y);
    };

    panelEl.addEventListener('pointerdown', onPointerDown);
  }

  // Backend connection state
  let isBackendLive = false;
  let backendErrorMessage = null;
  let scanResults = null;

  // Local fallback findings catalog matching schema requirements
  const localFallbackResults = {
    scan_id: 'local-fallback-demo',
    mode: 'demo',
    status: 'completed',
    threat_score: 8.7,
    risk_level: 'CRITICAL',
    summary: 'Demo analysis detected several suspicious indicators.',
    findings: [
      {
        type: 'sender_impersonation',
        severity: 'high',
        title: 'Possible sender impersonation',
        description: 'The display name references Microsoft, but the sender domain does not appear related to Microsoft.'
      },
      {
        type: 'suspicious_link',
        severity: 'high',
        title: 'Suspicious link detected',
        description: 'Link uses an IP address host (198.51.100.10) instead of a domain name.'
      },
      {
        type: 'credential_request',
        severity: 'critical',
        title: 'Credential request',
        description: 'The message requests account, password, login, or identity information ("verify your password").'
      },
      {
        type: 'urgency',
        severity: 'medium',
        title: 'Urgency-based language',
        description: 'Email uses high-urgency language ("within 10 minutes") to create pressure to act quickly.'
      }
    ],
    attachments: [],
    recommendation: 'Do not click links or open attachments until the sender and request are verified through an out-of-band channel.'
  };

  // Initialize Extension State
  function init() {
    debugLog('Extension content script initialized.');
    
    // Load theme setting
    currentTheme = getSavedTheme();

    // Restore collapse state for current session
    try {
      const storedCollapse = sessionStorage.getItem('sentinel_panel_collapsed');
      if (storedCollapse !== null) {
        isCollapsed = storedCollapse === 'true';
      }
    } catch (e) {
      // Ignore session storage errors
    }

    // Check extension enabled/disabled state from chrome.storage.local
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get({ demoProtectionEnabled: true }, (res) => {
        isProtectionEnabled = res.demoProtectionEnabled !== false;
        debugLog('Protection enabled state loaded:', isProtectionEnabled);
        handleStateChange();
      });

      // Listen for runtime setting changes
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === 'local' && changes.demoProtectionEnabled) {
          isProtectionEnabled = changes.demoProtectionEnabled.newValue !== false;
          debugLog('Extension enabled/disabled setting changed:', isProtectionEnabled);
          handleStateChange();
        }
      });
    } else {
      handleStateChange();
    }

    // Window resize handler to keep panel clamped to viewport
    let resizeTimeout = null;
    window.addEventListener('resize', () => {
      if (resizeTimeout) clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        const panelEl = document.getElementById(PANEL_ID);
        if (panelEl) {
          const rect = panelEl.getBoundingClientRect();
          const clamped = clampPosition(rect.left, rect.top, rect.width, rect.height);
          panelEl.style.left = `${clamped.x}px`;
          panelEl.style.top = `${clamped.y}px`;
          panelEl.style.right = 'auto';
          savePosition(clamped.x, clamped.y);
        }
      }, 100);
    });

    // Setup SPA DOM Observer with debouncing
    setupMutationObserver();
  }

  function handleStateChange() {
    if (!isProtectionEnabled) {
      debugLog('Extension disabled - removing panel');
      removePanel();
    } else {
      checkGmailAndInject();
    }
  }

  // Setup DOM Observer with debouncing for Gmail SPA navigation
  function setupMutationObserver() {
    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver(() => {
      if (debounceTimeout) clearTimeout(debounceTimeout);
      debounceTimeout = setTimeout(() => {
        if (isProtectionEnabled) {
          checkGmailAndInject();
        }
      }, 250);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // Detect Gmail Email View & Extract Details Safely
  function findGmailEmailView() {
    const selectors = [
      '[role="main"] .h7',
      '[role="main"] .gE',
      '[role="main"] .adn',
      '.AO .h7',
      '.ha',
      '[role="main"] .a3s'
    ];

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el) {
        return el.closest('.h7') || el.closest('.gE') || el.closest('.adn') || el.closest('[role="main"]') || el;
      }
    }
    return null;
  }

  // Safely extract email details (sender, subject, body snippet, links, attachment names)
  function extractEmailContext(emailContainer) {
    try {
      let sender = '';
      let subject = '';
      let bodyText = '';
      let links = [];
      let attachments = [];
      let attachmentCount = 0;

      // Extract Sender safely
      const senderEl = document.querySelector('.gD[email]') || 
                       document.querySelector('[email]') || 
                       document.querySelector('.gD') ||
                       document.querySelector('span.gD');
      if (senderEl) {
        const emailAttr = senderEl.getAttribute('email');
        const nameText = senderEl.textContent || '';
        if (emailAttr) {
          sender = nameText ? `${nameText.trim()} <${emailAttr.trim()}>` : emailAttr.trim();
        } else if (nameText) {
          sender = nameText.trim();
        }
      }

      // Extract Subject safely
      const subjectEl = document.querySelector('.hP') || 
                        document.querySelector('h2[data-thread-perm-id]') ||
                        document.querySelector('h2.hP');
      if (subjectEl && subjectEl.textContent) {
        subject = subjectEl.textContent.trim();
      }

      // Extract Body Text Snippet & Links safely (max 1000 chars for body)
      const bodyEl = document.querySelector('.a3s') || document.querySelector('.ii.gt') || document.querySelector('[role="main"] .a3s');
      if (bodyEl) {
        bodyText = (bodyEl.textContent || '').trim().substring(0, 1000);

        const anchorEls = bodyEl.querySelectorAll('a[href]');
        anchorEls.forEach((a) => {
          const href = a.getAttribute('href');
          if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
            if (!links.includes(href) && links.length < 10) {
              links.push(href);
            }
          }
        });
      }

      // Detect Attachment Metadata safely
      const attachmentEls = document.querySelectorAll('.aQy, div[aria-label*="Attachment"], .aZo, [aria-label*="attachment"]');
      attachmentCount = attachmentEls ? attachmentEls.length : 0;
      attachmentEls.forEach((attEl) => {
        const attName = (attEl.textContent || attEl.getAttribute('aria-label') || '').trim();
        if (attName && !attachments.some(a => a.name === attName) && attachments.length < 10) {
          attachments.push({ name: attName, file_type: 'file', size_bytes: null });
        }
      });

      const isReliable = Boolean(sender || subject);

      return {
        isReliable,
        sender: sender || 'Sender email unavailable',
        subject: subject || 'Subject unavailable',
        body: bodyText,
        links,
        attachments,
        attachmentCount,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
    } catch (err) {
      debugLog('Error parsing Gmail details:', err);
      return {
        isReliable: false,
        sender: 'Email details unavailable',
        subject: 'Email details unavailable',
        body: '',
        links: [],
        attachments: [],
        attachmentCount: 0,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
    }
  }

  // Main injection check
  function checkGmailAndInject() {
    if (!isProtectionEnabled) return;

    const emailView = findGmailEmailView();
    if (!emailView) {
      if (currentEmailKey !== null) {
        debugLog('Left email view - removing panel');
        currentEmailKey = null;
        removePanel();
      }
      return;
    }

    const newEmailKey = getEmailUniqueKey(emailView);
    const existingPanel = document.getElementById(PANEL_ID);

    if (existingPanel && currentEmailKey === newEmailKey) {
      return;
    }

    currentEmailKey = newEmailKey;
    debugLog('Gmail email view detected:', currentEmailKey);

    startScanSequence(emailView);
  }

  function getEmailUniqueKey(emailView) {
    const subjectEl = document.querySelector('.hP');
    if (subjectEl && subjectEl.textContent) {
      return subjectEl.textContent.trim();
    }
    return emailView.id || emailView.className || 'default-email';
  }

  // Fetch scan response from local FastAPI backend with timeout
  async function fetchBackendScan(emailContext) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000); // 4 sec timeout

    const payload = {
      sender: emailContext.sender !== 'Sender email unavailable' ? emailContext.sender : null,
      subject: emailContext.subject !== 'Subject unavailable' ? emailContext.subject : null,
      body: emailContext.body || null,
      links: emailContext.links || [],
      attachments: emailContext.attachments || []
    };

    try {
      const response = await fetch(BACKEND_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }

      const data = await response.json();
      if (!data || typeof data.threat_score !== 'number' || !Array.isArray(data.findings)) {
        throw new Error('Invalid backend response payload');
      }

      return { success: true, data };
    } catch (err) {
      clearTimeout(timeoutId);
      debugLog('Backend fetch error:', err);
      return {
        success: false,
        error: 'Backend unavailable — showing demo fallback.'
      };
    }
  }

  // Execute scan sequence with backend query and progress loading state
  async function startScanSequence(emailView) {
    if (scanTimer) clearInterval(scanTimer);
    isScanning = true;
    scanProgress = 15;
    scanStep = 'Checking sender & connecting to FastAPI backend...';
    reviewStatus = 'pending';
    scanResults = null; // Clear stale results from previous email

    renderOrUpdatePanel(emailView);

    // Progress bar animation while requesting backend
    const progressInterval = setInterval(() => {
      if (scanProgress < 85) {
        scanProgress += 15;
        if (scanProgress === 45) {
          scanStep = 'Analyzing email body & links against threat models...';
        } else if (scanProgress === 75) {
          scanStep = 'Evaluating security findings & recommendation...';
        }
        renderOrUpdatePanel(emailView);
      }
    }, 150);

    const emailContext = extractEmailContext(emailView);
    const result = await fetchBackendScan(emailContext);

    clearInterval(progressInterval);
    scanProgress = 100;

    if (result.success) {
      isBackendLive = true;
      backendErrorMessage = null;
      scanResults = result.data;
      debugLog('Backend scan successful:', scanResults);
    } else {
      isBackendLive = false;
      backendErrorMessage = result.error;
      scanResults = localFallbackResults;
      debugLog('Backend fetch failed - utilizing fallback:', backendErrorMessage);
    }

    isScanning = false;
    renderOrUpdatePanel(emailView);
  }

  // Remove existing panel safely
  function removePanel() {
    const existing = document.getElementById(PANEL_ID);
    if (existing) {
      existing.remove();
      debugLog('Panel removed');
    }
  }

  // Determine optimal DOM placement or fallback positioning
  function injectPanelIntoDOM(panelEl) {
    panelEl.className = 'sentinel-panel sentinel-overlay-panel';
    if (!panelEl.parentNode) {
      document.body.appendChild(panelEl);
      debugLog('Panel injected as fixed floating overlay panel');
    }
  }

  // Render or Update the Panel DOM
  function renderOrUpdatePanel(emailView) {
    if (!isProtectionEnabled) {
      removePanel();
      return;
    }

    const emailContext = extractEmailContext(emailView);
    let panelEl = document.getElementById(PANEL_ID);
    const isNew = !panelEl;
    currentTheme = getSavedTheme();

    if (isNew) {
      panelEl = document.createElement('div');
      panelEl.id = PANEL_ID;
      panelEl.setAttribute('role', 'region');
      panelEl.setAttribute('aria-label', 'SentinelAI Security Analysis Overlay');
    }

    // Current active findings and scan metrics
    const currentResults = scanResults || localFallbackResults;
    const riskScore = typeof currentResults.threat_score === 'number' ? currentResults.threat_score.toFixed(1) : '8.7';
    const riskLevelText = currentResults.risk_level || 'HIGH';
    const riskRecommendation = currentResults.recommendation || 'Recommended: Do not click links or open attachments until verified.';
    const findingsList = currentResults.findings || [];

    const isLightTheme = currentTheme === 'light';

    // HTML Structure
    panelEl.innerHTML = `
      <div class="sentinel-panel-inner ${isCollapsed ? 'sentinel-collapsed' : ''}">
        <!-- Header Strip -->
        <div class="sentinel-panel-header">
          <div class="sentinel-header-drag-area sentinel-draggable" tabIndex="-1" title="Drag to move panel">
            <div class="sentinel-drag-grip" aria-hidden="true" title="Drag handle">
              <svg width="10" height="14" viewBox="0 0 10 14" fill="currentColor">
                <circle cx="2" cy="2" r="1.2"/>
                <circle cx="8" cy="2" r="1.2"/>
                <circle cx="2" cy="7" r="1.2"/>
                <circle cx="8" cy="7" r="1.2"/>
                <circle cx="2" cy="12" r="1.2"/>
                <circle cx="8" cy="12" r="1.2"/>
              </svg>
            </div>
            <div class="sentinel-header-left">
              <div class="sentinel-header-logo" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <path d="m9 12 2 2 4-4"/>
                </svg>
              </div>
              <div>
                <div class="sentinel-header-title-row">
                  <h2 class="sentinel-header-title">SentinelAI Threat Intelligence</h2>
                  <span class="sentinel-overlay-tag">Overlay</span>
                </div>
                <p class="sentinel-header-subtitle">Email Security Guard</p>
              </div>
            </div>
          </div>

          <div class="sentinel-header-right">
            ${isBackendLive ? `
              <span class="sentinel-badge-mode backend" title="Connected to FastAPI backend at http://127.0.0.1:8000">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                Backend Demo
              </span>
            ` : `
              <span class="sentinel-badge-mode fallback" title="Backend unreachable — using local fallback">
                Local Fallback
              </span>
            `}
            <button type="button" id="sentinel-toggle-theme" class="sentinel-icon-btn" aria-label="${isLightTheme ? 'Switch to dark mode' : 'Switch to light mode'}" title="${isLightTheme ? 'Switch to dark mode' : 'Switch to light mode'}" tabIndex="0">
              ${isLightTheme ? `
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/></svg>
              ` : `
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
              `}
            </button>
            <button type="button" id="sentinel-toggle-collapse" class="sentinel-icon-btn" aria-label="${isCollapsed ? 'Expand panel' : 'Collapse panel'}" tabIndex="0">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${isCollapsed ? '<path d="m6 9 6 6 6-6"/>' : '<path d="m18 15-6-6-6 6"/>'}
              </svg>
            </button>
          </div>
        </div>

        ${!isCollapsed ? `
          <!-- Email Context Bar -->
          <div class="sentinel-context-box">
            ${emailContext.isReliable ? `
              <div class="sentinel-context-row">
                <span class="sentinel-context-label">Sender:</span>
                <span class="sentinel-context-val" title="${escapeHtml(emailContext.sender)}">${escapeHtml(emailContext.sender)}</span>
              </div>
              <div class="sentinel-context-row">
                <span class="sentinel-context-label">Subject:</span>
                <span class="sentinel-context-val" title="${escapeHtml(emailContext.subject)}">${escapeHtml(emailContext.subject)}</span>
              </div>
              <div class="sentinel-context-meta">
                <span>Attachments: <strong>${emailContext.attachmentCount}</strong></span>
                <span>Scanned: <strong>${emailContext.timestamp}</strong></span>
              </div>
            ` : `
              <div class="sentinel-context-unavailable">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span>Email details unavailable</span>
              </div>
            `}
          </div>

          <!-- Body Content: Scanning State vs Complete State -->
          <div class="sentinel-panel-body">
            ${isScanning ? `
              <!-- Scanning State -->
              <div class="sentinel-scan-loading" role="status" aria-live="polite">
                <div class="sentinel-spinner-wrap">
                  <div class="sentinel-spinner"></div>
                </div>
                <p class="sentinel-loading-title">Scanning email & attachments...</p>
                <p class="sentinel-loading-step">${escapeHtml(scanStep)}</p>
                <div class="sentinel-progress-track">
                  <div class="sentinel-progress-fill" style="width: ${scanProgress}%"></div>
                </div>
                <span class="sentinel-progress-text">${scanProgress}% completed</span>
              </div>
            ` : `
              <!-- Analysis Completed State -->
              <div class="sentinel-analysis-results">
                ${!isBackendLive && backendErrorMessage ? `
                  <div class="sentinel-fallback-notice">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>${escapeHtml(backendErrorMessage)}</span>
                  </div>
                ` : ''}

                <!-- Status Banner -->
                <div class="sentinel-status-banner">
                  <div class="sentinel-status-banner-left">
                    <svg class="sentinel-check-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <span>${isBackendLive ? 'Analysis Complete' : 'Demo Fallback Complete'}</span>
                  </div>
                  <span class="sentinel-review-tag ${reviewStatus}">${reviewStatus === 'reviewed' ? 'Reviewed ✓' : 'Action Required'}</span>
                </div>

                <!-- Overall Threat Score Card -->
                <div class="sentinel-score-card ${riskLevelText.toLowerCase()}">
                  <div class="sentinel-score-header">
                    <div>
                      <span class="sentinel-score-title">Overall Threat Score</span>
                      <div class="sentinel-score-val-row">
                        <span class="sentinel-score-num">${riskScore}</span>
                        <span class="sentinel-score-denom">/ 10</span>
                      </div>
                    </div>
                    <div class="sentinel-score-badge-wrap">
                      <span class="sentinel-risk-badge ${riskLevelText.toLowerCase()}" tabIndex="0" aria-label="Risk Level: ${riskLevelText}">${riskLevelText}</span>
                      <span class="sentinel-confidence">Phishing Confidence: 94%</span>
                    </div>
                  </div>

                  <!-- Risk Bar with range boundaries -->
                  <div class="sentinel-risk-bar-wrap">
                    <div class="sentinel-scale-boundaries">
                      <span class="sentinel-scale-mark pos-0">0<small>LOW</small></span>
                      <span class="sentinel-scale-mark pos-25">2.5<small>MED</small></span>
                      <span class="sentinel-scale-mark pos-50">5.0<small>HIGH</small></span>
                      <span class="sentinel-scale-mark pos-75">7.5<small>CRIT</small></span>
                      <span class="sentinel-scale-mark pos-100">10</span>
                    </div>
                    <div class="sentinel-bar-track">
                      <div class="sentinel-bar-fill" style="width: ${Math.min(100, Math.max(0, parseFloat(riskScore) * 10))}%;"></div>
                      <div class="sentinel-score-pin" style="left: ${Math.min(100, Math.max(0, parseFloat(riskScore) * 10))}%;" title="Score: ${riskScore} (${riskLevelText})"></div>
                    </div>
                  </div>

                  <p class="sentinel-score-explanation">
                    ${escapeHtml(currentResults.summary || 'Demo analysis detected suspicious indicators requiring review.')}
                  </p>
                </div>

                ${currentResults.attachments && currentResults.attachments.length > 0 ? `
                  <!-- Attachment Metadata Scan Results -->
                  <div class="sentinel-attachments-section">
                    <div class="sentinel-attachments-header">
                      <span class="sentinel-attachments-title">Attachment Metadata (${currentResults.attachments.length})</span>
                    </div>
                    <div class="sentinel-attachments-list">
                      ${currentResults.attachments.map(att => `
                        <div class="sentinel-attachment-card ${att.threat_score >= 5.0 ? 'high-risk' : (att.threat_score >= 2.5 ? 'med-risk' : 'low-risk')}">
                          <div class="sentinel-att-info">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
                            <span class="sentinel-att-name" title="${escapeHtml(att.filename || att.name || 'attachment')}">${escapeHtml(att.filename || att.name || 'attachment')}</span>
                          </div>
                          <div class="sentinel-att-meta">
                            <span class="sentinel-badge-sev ${(att.risk_level || 'LOW').toLowerCase()}">${att.threat_score !== undefined ? att.threat_score.toFixed(1) : '0.0'} ${att.risk_level || 'LOW'}</span>
                          </div>
                        </div>
                      `).join('')}
                    </div>
                  </div>
                ` : ''}

                <!-- Findings List -->
                <div class="sentinel-findings-section">
                  <div class="sentinel-findings-header">
                    <span class="sentinel-findings-title">Security Findings (${findingsList.length})</span>
                    <span class="sentinel-findings-hint">Click row to toggle details</span>
                  </div>

                  <div class="sentinel-findings-list">
                    ${findingsList.map((finding, idx) => {
                      const findingId = `f-${idx + 1}`;
                      const isExpanded = expandedFindingId === findingId;
                      const sevClass = (finding.severity || 'high').toLowerCase();
                      return `
                        <div class="sentinel-finding-item ${isExpanded ? 'expanded' : ''}" data-finding-id="${findingId}" tabIndex="0" role="button" aria-expanded="${isExpanded}" aria-label="Finding: ${escapeHtml(finding.title)}, Severity: ${escapeHtml(finding.severity)}">
                          <div class="sentinel-finding-header">
                            <div class="sentinel-finding-left">
                              <span class="sentinel-finding-icon ${sevClass}">
                                ${getFindingIconSvg(finding.type || finding.icon)}
                              </span>
                              <div>
                                <div class="sentinel-finding-title-row">
                                  <span class="sentinel-finding-title">${escapeHtml(finding.title)}</span>
                                  <span class="sentinel-badge-sev ${sevClass}">${escapeHtml(finding.severity)}</span>
                                </div>
                                <p class="sentinel-finding-desc">${escapeHtml(finding.description || finding.explanation)}</p>
                              </div>
                            </div>
                            <span class="sentinel-arrow-icon" aria-hidden="true">
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                ${isExpanded ? '<path d="m18 15-6-6-6 6"/>' : '<path d="m6 9 6 6 6-6"/>'}
                              </svg>
                            </span>
                          </div>
                          ${isExpanded ? `
                            <div class="sentinel-finding-details">
                              <p><strong>Recommendation:</strong> ${escapeHtml(riskRecommendation)}</p>
                              <span class="sentinel-signal-id">Signal Type: ${escapeHtml(finding.type)}</span>
                            </div>
                          ` : ''}
                        </div>
                      `;
                    }).join('')}
                  </div>
                </div>

                <!-- Security Recommendation Box -->
                <div class="sentinel-rec-box">
                  <div class="sentinel-rec-header">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span>Security Guidance</span>
                  </div>
                  <p class="sentinel-rec-text">${escapeHtml(riskRecommendation)}</p>
                </div>

                <!-- Action Buttons -->
                <div class="sentinel-actions-row">
                  <button type="button" id="sentinel-btn-review" class="sentinel-btn ${reviewStatus === 'reviewed' ? 'sentinel-btn-success' : 'sentinel-btn-secondary'}" aria-label="Mark email review status">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 6L9 17l-5-5"/></svg>
                    <span>${reviewStatus === 'reviewed' ? 'Reviewed ✓' : 'Mark as Reviewed'}</span>
                  </button>
                  <button type="button" id="sentinel-btn-rescan" class="sentinel-btn sentinel-btn-secondary" aria-label="Rescan email and attachments">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                    <span>Rescan Email</span>
                  </button>
                </div>
              </div>
            `}
          </div>

          <!-- Footer Disclaimer -->
          <div class="sentinel-panel-footer">
            <p class="sentinel-footer-note">Demo mode: analysis processed locally. Email credentials or full attachments are never uploaded or stored.</p>
          </div>
        ` : ''}
      </div>
    `;

    if (isNew) {
      injectPanelIntoDOM(panelEl);
      applyTheme(panelEl, currentTheme);
      applyPanelPosition(panelEl, getSavedPosition());
      initDrag(panelEl);
    } else {
      applyTheme(panelEl, currentTheme);
    }

    // Attach Event Listeners
    attachPanelEvents(panelEl, emailView);
  }

  // Attach Event Handlers to Interactive Elements
  function attachPanelEvents(panelEl, emailView) {
    // Theme toggle
    const themeBtn = panelEl.querySelector('#sentinel-toggle-theme');
    if (themeBtn) {
      themeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const activeTheme = getSavedTheme();
        const nextTheme = activeTheme === 'light' ? 'dark' : 'light';
        saveTheme(nextTheme);
        currentTheme = nextTheme;
        applyTheme(panelEl, nextTheme);
        updateThemeToggleButton(panelEl, nextTheme);
      });

      themeBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          themeBtn.click();
        }
      });
    }

    // Collapse toggle
    const collapseBtn = panelEl.querySelector('#sentinel-toggle-collapse');
    if (collapseBtn) {
      collapseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        isCollapsed = !isCollapsed;
        try {
          sessionStorage.setItem('sentinel_panel_collapsed', isCollapsed.toString());
        } catch (err) {}
        renderOrUpdatePanel(emailView);
      });

      collapseBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          collapseBtn.click();
        }
      });
    }

    // Rescan button
    const rescanBtn = panelEl.querySelector('#sentinel-btn-rescan');
    if (rescanBtn) {
      rescanBtn.addEventListener('click', () => {
        debugLog('Rescan requested by user');
        startScanSequence(emailView);
      });
      rescanBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          rescanBtn.click();
        }
      });
    }

    // Review button
    const reviewBtn = panelEl.querySelector('#sentinel-btn-review');
    if (reviewBtn) {
      reviewBtn.addEventListener('click', () => {
        reviewStatus = reviewStatus === 'reviewed' ? 'pending' : 'reviewed';
        debugLog('Review status toggled:', reviewStatus);
        renderOrUpdatePanel(emailView);
      });
      reviewBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          reviewBtn.click();
        }
      });
    }

    // Findings row expand/collapse
    const findingItems = panelEl.querySelectorAll('.sentinel-finding-item');
    findingItems.forEach((item) => {
      const id = item.getAttribute('data-finding-id');
      const toggleFn = () => {
        expandedFindingId = expandedFindingId === id ? null : id;
        renderOrUpdatePanel(emailView);
      };

      item.addEventListener('click', toggleFn);
      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleFn();
        }
      });
    });
  }

  // Icon Helper for Finding Types
  function getFindingIconSvg(findingType) {
    switch (findingType) {
      case 'sender_impersonation':
      case 'UserX':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="22" y2="13"/><line x1="22" y1="8" x2="17" y2="13"/></svg>';
      case 'suspicious_link':
      case 'Link2Off':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 4 8"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/></svg>';
      case 'credential_request':
      case 'KeyRound':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>';
      case 'urgency':
      case 'Clock':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
      default:
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    }
  }

  // HTML Escaper for XSS Prevention
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Run initial setup
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
