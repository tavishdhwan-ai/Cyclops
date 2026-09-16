/**
 * SentinelAI Gmail Security Guard - Content Script
 * Phase 2 Polish Add-ons Implementation
 */

(function () {
  // Prevent duplicate content script injection
  if (window.__SENTINEL_AI_CONTENT_SCRIPT_LOADED__) {
    return;
  }
  window.__SENTINEL_AI_CONTENT_SCRIPT_LOADED__ = true;

  // Debugging toggle (default false as required)
  const DEBUG = false;

  function debugLog(...args) {
    if (DEBUG) {
      console.log('[SentinelAI]', ...args);
    }
  }

  // Constants & State
  const PANEL_ID = 'sentinel-ai-panel';
  let isProtectionEnabled = true;
  let isCollapsed = false;
  let isScanning = false;
  let scanProgress = 0;
  let scanStep = 'Checking sender domain & signatures...';
  let scanTimer = null;
  let reviewStatus = 'pending'; // 'pending' | 'reviewed'
  let expandedFindingId = null;
  let currentEmailKey = null;
  let observer = null;
  let debounceTimeout = null;

  // Findings catalog for simulated analysis
  const simulatedFindings = [
    {
      id: 'f-1',
      title: 'Sender impersonation',
      severity: 'High',
      explanation: 'The sender domain does not match claimed Microsoft authentication headers.',
      icon: 'UserX'
    },
    {
      id: 'f-2',
      title: 'Suspicious link',
      severity: 'High',
      explanation: 'Verification link points to an unverified external domain.',
      icon: 'Link2Off'
    },
    {
      id: 'f-3',
      title: 'Credential request',
      severity: 'Critical',
      explanation: 'Message requests sensitive account verification via email link.',
      icon: 'KeyRound'
    },
    {
      id: 'f-4',
      title: 'Urgency language',
      severity: 'Medium',
      explanation: 'Pressures recipient with immediate account suspension threats.',
      icon: 'Clock'
    }
  ];

  // Initialize Extension State
  function init() {
    debugLog('Extension content script initialized.');
    
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
    // Selectors for open email container in Gmail
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

  // Safely extract email details without risking crashes or throwing errors
  function extractEmailContext(emailContainer) {
    try {
      let sender = '';
      let subject = '';
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

      // Detect attachments count safely
      const attachmentEls = document.querySelectorAll('.aQy, div[aria-label*="Attachment"], .aZo, [aria-label*="attachment"]');
      attachmentCount = attachmentEls ? attachmentEls.length : 0;

      // Fallback check if sender or subject missing
      const isReliable = Boolean(sender || subject);

      return {
        isReliable,
        sender: sender || 'Sender email unavailable',
        subject: subject || 'Subject unavailable',
        attachmentCount,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
    } catch (err) {
      debugLog('Error parsing Gmail details:', err);
      return {
        isReliable: false,
        sender: 'Email details unavailable',
        subject: 'Email details unavailable',
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
      // User is in inbox or navigation list, clean up panel
      if (currentEmailKey !== null) {
        debugLog('Left email view - removing panel');
        currentEmailKey = null;
        removePanel();
      }
      return;
    }

    // Determine unique email key to trigger fresh scan on new email view
    const newEmailKey = getEmailUniqueKey(emailView);
    const existingPanel = document.getElementById(PANEL_ID);

    if (existingPanel && currentEmailKey === newEmailKey) {
      // Panel already injected for this opened email view
      return;
    }

    currentEmailKey = newEmailKey;
    debugLog('Gmail email view detected:', currentEmailKey);

    // Start simulation scan for this email
    startScanSimulation(emailView);
  }

  function getEmailUniqueKey(emailView) {
    const subjectEl = document.querySelector('.hP');
    if (subjectEl && subjectEl.textContent) {
      return subjectEl.textContent.trim();
    }
    return emailView.id || emailView.className || 'default-email';
  }

  // Trigger scan animation step sequence
  function startScanSimulation(emailView) {
    if (scanTimer) clearInterval(scanTimer);
    isScanning = true;
    scanProgress = 10;
    scanStep = 'Checking sender domain & authentication signatures...';
    reviewStatus = 'pending';

    renderOrUpdatePanel(emailView);

    const steps = [
      { progress: 40, step: 'Scanning email body text & urgency signals...' },
      { progress: 75, step: 'Checking links and attachment safety...' },
      { progress: 100, step: 'Analysis complete. Phishing indicators mapped.' }
    ];

    let stepIndex = 0;
    scanTimer = setInterval(() => {
      if (stepIndex < steps.length) {
        scanProgress = steps[stepIndex].progress;
        scanStep = steps[stepIndex].step;
        stepIndex++;
        renderOrUpdatePanel(emailView);
      } else {
        clearInterval(scanTimer);
        scanTimer = null;
        isScanning = false;
        debugLog('Scan completed');
        renderOrUpdatePanel(emailView);
      }
    }, 450);
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
  function injectPanelIntoDOM(panelEl, emailView) {
    // Attempt preferred placement near opened email, avoiding compose / left nav
    let targetContainer = null;
    
    // Look for Gmail toolbar or message header container
    const headerContainer = emailView.querySelector('.ha') || emailView.querySelector('.gE') || emailView;
    if (headerContainer && headerContainer.parentNode) {
      targetContainer = headerContainer;
    }

    if (targetContainer) {
      panelEl.className = 'sentinel-panel sentinel-inline-panel';
      if (targetContainer.nextSibling) {
        targetContainer.parentNode.insertBefore(panelEl, targetContainer.nextSibling);
      } else {
        targetContainer.parentNode.appendChild(panelEl);
      }
      debugLog('Panel injected inline near opened email container');
    } else {
      // Fallback to fixed overlay position avoiding left nav and compose button
      panelEl.className = 'sentinel-panel sentinel-overlay-panel';
      document.body.appendChild(panelEl);
      debugLog('Panel injected using fixed overlay fallback position');
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

    if (isNew) {
      panelEl = document.createElement('div');
      panelEl.id = PANEL_ID;
      panelEl.setAttribute('role', 'region');
      panelEl.setAttribute('aria-label', 'SentinelAI Security Analysis Overlay');
    }

    // Risk level calculations (Simulated High Risk Demo)
    const riskScore = '8.7';
    const riskLevelText = 'High Risk';
    const riskConfidence = 'Phishing Confidence: 94%';
    const riskRecommendation = 'Recommended: Do not click links or open attachments until verified.';

    // HTML Structure
    panelEl.innerHTML = `
      <div class="sentinel-panel-inner ${isCollapsed ? 'sentinel-collapsed' : ''}">
        <!-- Header Strip -->
        <div class="sentinel-panel-header">
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

          <div class="sentinel-header-right">
            <span class="sentinel-badge-demo" title="Demo analysis simulated locally">Demo analysis</span>
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
                <!-- Status Banner -->
                <div class="sentinel-status-banner">
                  <div class="sentinel-status-banner-left">
                    <svg class="sentinel-check-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <span>Analysis Complete</span>
                  </div>
                  <span class="sentinel-review-tag ${reviewStatus}">${reviewStatus === 'reviewed' ? 'Reviewed ✓' : 'Action Required'}</span>
                </div>

                <!-- Overall Threat Score Card -->
                <div class="sentinel-score-card">
                  <div class="sentinel-score-header">
                    <div>
                      <span class="sentinel-score-title">Overall Threat Score</span>
                      <div class="sentinel-score-val-row">
                        <span class="sentinel-score-num">${riskScore}</span>
                        <span class="sentinel-score-denom">/ 10</span>
                      </div>
                    </div>
                    <div class="sentinel-score-badge-wrap">
                      <span class="sentinel-risk-badge critical" tabIndex="0" aria-label="Risk Level: ${riskLevelText}">${riskLevelText}</span>
                      <span class="sentinel-confidence">${riskConfidence}</span>
                    </div>
                  </div>

                  <!-- Risk Bar -->
                  <div class="sentinel-risk-bar-wrap">
                    <div class="sentinel-risk-labels">
                      <span>0 Low</span>
                      <span>5 Med</span>
                      <span class="sentinel-high-mark">${riskScore} High</span>
                      <span>10 Crit</span>
                    </div>
                    <div class="sentinel-bar-track">
                      <div class="sentinel-bar-fill" style="width: 87%;"></div>
                    </div>
                  </div>

                  <p class="sentinel-score-explanation">
                    This email exhibits multiple high-confidence phishing signals, including sender domain mismatch and credential theft indicators.
                  </p>
                </div>

                <!-- Findings List -->
                <div class="sentinel-findings-section">
                  <div class="sentinel-findings-header">
                    <span class="sentinel-findings-title">Security Findings (${simulatedFindings.length})</span>
                    <span class="sentinel-findings-hint">Click row to toggle details</span>
                  </div>

                  <div class="sentinel-findings-list">
                    ${simulatedFindings.map((finding) => {
                      const isExpanded = expandedFindingId === finding.id;
                      return `
                        <div class="sentinel-finding-item ${isExpanded ? 'expanded' : ''}" data-finding-id="${finding.id}" tabIndex="0" role="button" aria-expanded="${isExpanded}" aria-label="Finding: ${finding.title}, Severity: ${finding.severity}">
                          <div class="sentinel-finding-header">
                            <div class="sentinel-finding-left">
                              <span class="sentinel-finding-icon ${finding.severity.toLowerCase()}">
                                ${getFindingIconSvg(finding.icon)}
                              </span>
                              <div>
                                <div class="sentinel-finding-title-row">
                                  <span class="sentinel-finding-title">${escapeHtml(finding.title)}</span>
                                  <span class="sentinel-badge-sev ${finding.severity.toLowerCase()}">${finding.severity}</span>
                                </div>
                                <p class="sentinel-finding-desc">${escapeHtml(finding.explanation)}</p>
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
                              <p><strong>Recommendation:</strong> Do not click external links. Verify domain authenticity with security administrators.</p>
                              <span class="sentinel-signal-id">Signal ID: ${finding.id} • Contribution +1.8</span>
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
            <p class="sentinel-footer-note">Demo mode: analysis is simulated locally. Email content is not uploaded or stored.</p>
          </div>
        ` : ''}
      </div>
    `;

    if (isNew) {
      injectPanelIntoDOM(panelEl, emailView);
    }

    // Attach Event Listeners
    attachPanelEvents(panelEl, emailView);
  }

  // Attach Event Handlers to Interactive Elements
  function attachPanelEvents(panelEl, emailView) {
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
        startScanSimulation(emailView);
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

  // Icon Helper
  function getFindingIconSvg(iconName) {
    switch (iconName) {
      case 'UserX':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="22" y2="13"/><line x1="22" y1="8" x2="17" y2="13"/></svg>';
      case 'Link2Off':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 4 8"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/></svg>';
      case 'KeyRound':
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>';
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
