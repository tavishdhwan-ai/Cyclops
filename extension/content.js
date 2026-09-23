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
  let isAttachmentsExpanded = false;
  let currentEmailKey = null;
  let observer = null;
  let debounceTimeout = null;

  // Particle & Transition Animation state
  let isTransitionAnimating = false;
  let activeParticleTimer = null;
  let activeParticleOverlay = null;

  // Theme & Drag state
  let currentTheme = 'dark';
  let isThemeWipeInProgress = false;  // Guard: prevents overlapping wipe animations
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

  /**
   * performThemeWipe - Directional horizontal clip-path wipe between themes.
   *
   * Dark  → Light : new theme reveals Left → Right (➡️)
   * Light → Dark  : new theme reveals Right → Left (⬅️)
   *
   * When reduced-motion is preferred the wipe is skipped and the theme
   * is applied instantly (identical to the old applyTheme path).
   */
  function performThemeWipe(panelEl, fromTheme, toTheme) {
    if (!panelEl) return;

    // Respect prefers-reduced-motion — instant switch, no wipe.
    const prefersReducedMotion =
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {
      applyTheme(panelEl, toTheme);
      return;
    }

    // Guard: if a wipe is already running, finish it immediately and start fresh.
    if (isThemeWipeInProgress) {
      // Remove any stale overlay
      const stale = panelEl.querySelector('.sentinel-wipe-overlay');
      if (stale) stale.remove();
      // Commit the current theme-in-progress state so panel is in a known state
      applyTheme(panelEl, toTheme);
      isThemeWipeInProgress = false;
      return;
    }

    isThemeWipeInProgress = true;

    // Determine wipe direction:
    //   dark  → light  : ltr (new light theme sweeps from left)
    //   light → dark   : rtl (new dark theme sweeps from right)
    const wipeClass = (toTheme === 'light') ? 'sentinel-wipe-ltr' : 'sentinel-wipe-rtl';

    // Find the inner card element to attach overlay to.
    const innerEl = panelEl.querySelector('.sentinel-panel-inner');
    if (!innerEl) {
      // Fallback: no inner found, just switch instantly.
      applyTheme(panelEl, toTheme);
      isThemeWipeInProgress = false;
      return;
    }

    // Build the wipe overlay: a full-size div carrying the target theme.
    // It is positioned absolute inside .sentinel-panel-inner (which has
    // position:relative + overflow:hidden + border-radius), so it clips cleanly.
    const overlay = document.createElement('div');
    overlay.className =
      `sentinel-wipe-overlay sentinel-theme-${toTheme} ${wipeClass}`;

    // Clone only the direct children of innerEl into the overlay, so the target
    // theme CSS variables (on the overlay element) cascade into each child.
    // Exclude any stale .sentinel-wipe-overlay to prevent recursive nesting.
    Array.from(innerEl.childNodes).forEach((child) => {
      if (child.classList && child.classList.contains('sentinel-wipe-overlay')) return;
      overlay.appendChild(child.cloneNode(true));
    });

    innerEl.appendChild(overlay);

    // On animation end: commit theme, remove overlay, clear guard.
    const onWipeDone = () => {
      overlay.removeEventListener('animationend', onWipeDone);
      // Safety: overlay may have already been removed by a rapid click guard.
      if (overlay.parentNode) overlay.remove();
      applyTheme(panelEl, toTheme);
      isThemeWipeInProgress = false;
    };

    overlay.addEventListener('animationend', onWipeDone);

    // Failsafe timeout in case animationend never fires (e.g. display:none).
    setTimeout(() => {
      if (isThemeWipeInProgress) {
        onWipeDone();
      }
    }, 700);
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
      if (e.target.closest('button, a, input, select, textarea, .sentinel-icon-btn, .sentinel-strip-item, [role="button"]')) {
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

  // Helper: Parse sender display name, email, domain, and compute security trust status
  function parseSenderDetails(senderString, findingsList = []) {
    if (!senderString || senderString === 'Sender email unavailable' || senderString === 'Email details unavailable') {
      return {
        displayName: '',
        emailAddress: 'Sender details unavailable',
        domain: '',
        badgeText: 'Unable to verify',
        badgeClass: 'neutral',
        badgeIcon: '—'
      };
    }

    let displayName = '';
    let emailAddress = senderString.trim();
    const match = senderString.match(/^(.*?)\s*<([^>]+)>$/);
    if (match) {
      displayName = match[1].replace(/^["']|["']$/g, '').trim();
      emailAddress = match[2].trim();
    }

    const domainParts = emailAddress.split('@');
    const domain = domainParts.length > 1 ? domainParts[1].toLowerCase() : '';

    // Check findings for sender-specific security indicators
    const senderFinding = findingsList.find(f => {
      const t = (f.type || '').toLowerCase();
      const c = (f.category || '').toLowerCase();
      return c === 'sender' || t.includes('sender') || t.includes('impersonation') || t.includes('lookalike') || t.includes('reply_to') || t.includes('domain');
    });

    let badgeText = 'Domain verified';
    let badgeClass = 'verified';
    let badgeIcon = '✓';

    if (senderFinding) {
      const t = (senderFinding.type || '').toLowerCase();
      const sev = (senderFinding.severity || 'high').toLowerCase();
      if (t.includes('impersonation')) {
        badgeText = 'Possible impersonation';
      } else if (t.includes('lookalike')) {
        badgeText = 'Lookalike domain';
      } else if (t.includes('reply_to')) {
        badgeText = 'Reply-To mismatch';
      } else {
        badgeText = 'Domain mismatch';
      }
      badgeClass = (sev === 'critical' || sev === 'high') ? 'crit' : 'warn';
      badgeIcon = '⚠';
    } else if (!domain || !emailAddress.includes('@')) {
      badgeText = 'Unable to verify';
      badgeClass = 'neutral';
      badgeIcon = '—';
    }

    return {
      displayName,
      emailAddress,
      domain,
      badgeText,
      badgeClass,
      badgeIcon
    };
  }

  // Helper: Compute risk summary statuses for SENDER, CONTENT, LINKS, ATTACHMENTS
  function computeCategoryStatuses(findingsList = [], attachmentsList = [], emailContext = {}) {
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, safe: 0, none: -1 };

    function getStatusFromSev(maxSev, isNone = false) {
      if (isNone) return { label: '—', class: 'none', sev: 'none' };
      if (maxSev === 4) return { label: 'CRIT', class: 'crit', sev: 'critical' };
      if (maxSev === 3) return { label: 'HIGH', class: 'high', sev: 'high' };
      if (maxSev === 2) return { label: 'MED', class: 'warn', sev: 'medium' };
      if (maxSev === 1) return { label: 'LOW', class: 'safe', sev: 'low' };
      return { label: 'SAFE', class: 'safe', sev: 'safe' };
    }

    // 1. SENDER
    let maxSender = 0;
    findingsList.forEach(f => {
      const t = (f.type || '').toLowerCase();
      const c = (f.category || '').toLowerCase();
      if (c === 'sender' || t.includes('sender') || t.includes('impersonation') || t.includes('lookalike') || t.includes('reply_to') || t.includes('domain')) {
        const rank = sevRank[(f.severity || 'high').toLowerCase()] || 2;
        if (rank > maxSender) maxSender = rank;
      }
    });

    // 2. CONTENT
    let maxContent = 0;
    findingsList.forEach(f => {
      const t = (f.type || '').toLowerCase();
      const c = (f.category || '').toLowerCase();
      if (c === 'content' || t.includes('credential') || t.includes('urgency') || t.includes('financial') || t.includes('keyword') || t.includes('phishing')) {
        const rank = sevRank[(f.severity || 'high').toLowerCase()] || 2;
        if (rank > maxContent) maxContent = rank;
      }
    });

    // 3. LINKS
    let maxLinks = 0;
    let linksHasFinding = false;
    findingsList.forEach(f => {
      const t = (f.type || '').toLowerCase();
      const c = (f.category || '').toLowerCase();
      if (c === 'links' || c === 'urls' || t.includes('link') || t.includes('url') || t.includes('ip_in_url') || t.includes('tld') || t.includes('shortener')) {
        linksHasFinding = true;
        const rank = sevRank[(f.severity || 'high').toLowerCase()] || 2;
        if (rank > maxLinks) maxLinks = rank;
      }
    });
    const hasLinks = (emailContext.links && emailContext.links.length > 0);

    // 4. ATTACHMENTS
    const hasAtts = (emailContext.attachmentCount > 0 || attachmentsList.length > 0);
    let maxAtts = 0;
    if (hasAtts) {
      attachmentsList.forEach(att => {
        const rank = sevRank[(att.risk_level || 'LOW').toLowerCase()] || 1;
        if (rank > maxAtts) maxAtts = rank;
      });
      findingsList.forEach(f => {
        const t = (f.type || '').toLowerCase();
        const c = (f.category || '').toLowerCase();
        if (c === 'attachments' || t.includes('attachment') || t.includes('extension') || t.includes('macro')) {
          const rank = sevRank[(f.severity || 'high').toLowerCase()] || 2;
          if (rank > maxAtts) maxAtts = rank;
        }
      });
    }

    return {
      sender: getStatusFromSev(maxSender),
      content: getStatusFromSev(maxContent),
      links: !hasLinks && !linksHasFinding ? getStatusFromSev(0) : getStatusFromSev(maxLinks),
      attachments: !hasAtts ? getStatusFromSev(-1, true) : getStatusFromSev(maxAtts)
    };
  }

  // Helper: Safely extract suspicious text phrase from finding evidence or description
  function getSuspiciousTextHighlight(finding) {
    if (!finding) return null;

    const desc = finding.description || finding.explanation || '';
    const evidence = finding.evidence || {};

    if (evidence.matched_text) {
      return { phrase: String(evidence.matched_text), type: 'exact' };
    }
    if (evidence.phrase) {
      return { phrase: String(evidence.phrase), type: 'exact' };
    }

    const quoteMatch = desc.match(/"([^"]+)"|'([^']+)'/);
    if (quoteMatch) {
      const quoted = quoteMatch[1] || quoteMatch[2];
      if (quoted && quoted.length >= 3) {
        return { phrase: quoted, type: 'quote' };
      }
    }

    const type = (finding.type || '').toLowerCase();
    if (type.includes('credential')) {
      return { phrase: 'verify your password', type: 'pattern' };
    }
    if (type.includes('urgency')) {
      return { phrase: 'within 10 minutes', type: 'pattern' };
    }

    return { phrase: null, type: 'generic' };
  }

  // Helper: Generate tailored "WHAT SHOULD I DO?" recommendation text
  function generateGuidanceText(riskLevel = 'LOW', findingsList = [], attachmentsList = [], backendRecommendation = '') {
    const rLevel = riskLevel.toUpperCase();

    if (rLevel === 'LOW') {
      return 'No significant security indicators detected. No action required.';
    }

    const types = findingsList.map(f => (f.type || '').toLowerCase());
    const hasCredential = types.some(t => t.includes('credential'));
    const hasUrl = types.some(t => t.includes('link') || t.includes('url') || t.includes('ip_in_url') || t.includes('shortener'));
    const hasAttachment = attachmentsList.some(a => (a.threat_score || 0) >= 2.5) || types.some(t => t.includes('attachment'));

    if (rLevel === 'CRITICAL') {
      if (hasCredential && (hasUrl || hasAttachment)) {
        return 'Do not click links, open attachments, or enter credentials. Verify sender through a trusted out-of-band channel.';
      }
      if (hasCredential) {
        return 'Do not enter passwords, security codes, or credentials. Verify sender before taking any action.';
      }
      if (hasUrl) {
        return 'Do not click links or enter information. Destination URL contains critical security indicators.';
      }
      return 'Do not click links, open attachments, or provide credentials. Verify the sender through a trusted channel.';
    }

    if (rLevel === 'HIGH') {
      if (hasUrl && hasAttachment) {
        return 'Avoid interacting with links or attachments until the sender is verified.';
      }
      if (hasUrl) {
        return 'Avoid clicking links until the destination URL is verified with the sender.';
      }
      if (hasAttachment) {
        return 'Avoid opening attachments until verified with the sender.';
      }
      return 'Avoid interacting with links or attachments until the sender is verified.';
    }

    if (rLevel === 'MEDIUM') {
      if (hasUrl) {
        return 'Verify the destination URL before clicking links in this email.';
      }
      return 'Verify the sender before clicking links or opening attachments.';
    }

    return backendRecommendation || 'Verify the sender before interacting with this email.';
  }

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
      debugLog('Extension disabled - disintegrating panel');
      disintegrateAndRemovePanel();
    } else {
      checkGmailAndInject();
    }
  }

  // Accessibility check for reduced motion
  function isReducedMotionPreferred() {
    return typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  // Active animation tracking handles
  let activeCanvasRaf = null;
  let activeCanvasEl = null;

  function cancelActiveAnimations() {
    if (activeParticleTimer) {
      clearTimeout(activeParticleTimer);
      activeParticleTimer = null;
    }
    if (activeCanvasRaf) {
      cancelAnimationFrame(activeCanvasRaf);
      activeCanvasRaf = null;
    }
    if (activeCanvasEl) {
      if (activeCanvasEl.parentNode) {
        activeCanvasEl.remove();
      }
      activeCanvasEl = null;
    }
    if (activeParticleOverlay && activeParticleOverlay.parentNode) {
      activeParticleOverlay.remove();
    }
    activeParticleOverlay = null;
    isTransitionAnimating = false;

    const panelEl = document.getElementById(PANEL_ID);
    if (panelEl) {
      panelEl.classList.remove('sentinel-panel-hidden', 'sentinel-materializing', 'sentinel-disintegrating');
      panelEl.style.opacity = '';
    }
  }

  // Surface sampling engine: maps panel layout & DOM elements into particle fragments
  function samplePanelSurface(panelEl) {
    const panelRect = panelEl.getBoundingClientRect();
    const width = Math.round(panelRect.width || 420);
    const height = Math.round(panelRect.height || 300);

    const isLight = panelEl.classList.contains('sentinel-theme-light');
    const defaultBg = isLight ? '#ffffff' : 'rgba(24, 24, 27, 0.96)';

    // Map visible sub-elements inside panel to sample exact layout coordinates and colors
    const elements = Array.from(panelEl.querySelectorAll('*')).map(el => {
      const r = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);
      const bg = style.backgroundColor;
      const fg = style.color;
      const border = style.borderColor;
      const hasText = el.childNodes.length > 0 && Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim().length > 0);

      return {
        rect: {
          left: r.left - panelRect.left,
          top: r.top - panelRect.top,
          right: r.right - panelRect.left,
          bottom: r.bottom - panelRect.top,
          width: r.width,
          height: r.height
        },
        bg: (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') ? bg : null,
        fg: (fg && fg !== 'rgba(0, 0, 0, 0)' && fg !== 'transparent') ? fg : null,
        border: (border && border !== 'rgba(0, 0, 0, 0)' && border !== 'transparent' && style.borderWidth !== '0px') ? border : null,
        hasText
      };
    }).filter(item => item.rect.width > 0 && item.rect.height > 0);

    const particles = [];
    const step = 8; // Sampling resolution step in px

    for (let y = 2; y < height; y += step) {
      for (let x = 2; x < width; x += step) {
        let color = defaultBg;
        let isForeground = false;

        // Traverse elements from topmost child to background
        for (let i = elements.length - 1; i >= 0; i--) {
          const item = elements[i];
          if (x >= item.rect.left && x <= item.rect.right && y >= item.rect.top && y <= item.rect.bottom) {
            if (item.hasText && item.fg) {
              color = item.fg;
              isForeground = true;
              break;
            } else if (item.bg) {
              color = item.bg;
              if (item.bg !== defaultBg) isForeground = true;
              break;
            } else if (item.border) {
              color = item.border;
              isForeground = true;
              break;
            }
          }
        }

        // Staggered peeling delay across panel regions (wave top-left to bottom-right + subtle noise)
        const positionalDelay = (y / height) * 140 + (x / width) * 80;
        const randomNoise = (Math.sin(x * 12.7 + y * 31.1) * 0.5 + 0.5) * 120;
        const delay = positionalDelay + randomNoise;

        particles.push({
          x,
          y,
          color,
          size: isForeground ? (2.2 + Math.random() * 1.5) : (step * 0.7 + Math.random() * 1.5),
          delay,
          vx: (Math.sin(y * 0.08 + x * 0.04) * 0.7) + 0.5 + Math.random() * 0.6, // Wind horizontal drift
          vy: -(1.4 + Math.random() * 1.8) // Upward air carry
        });
      }
    }

    return { width, height, particles };
  }

  // Unified Canvas Particle Animation Engine (Surface Disintegration & Dust Materialization)
  function runCanvasSurfaceAnimation(panelEl, type, duration, onComplete) {
    cancelActiveAnimations();

    if (!panelEl || isReducedMotionPreferred()) {
      if (typeof onComplete === 'function') onComplete();
      return;
    }

    const { width, height, particles } = samplePanelSurface(panelEl);

    if (particles.length === 0) {
      if (typeof onComplete === 'function') onComplete();
      return;
    }

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const canvas = document.createElement('canvas');
    canvas.className = 'sentinel-surface-canvas';
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      if (typeof onComplete === 'function') onComplete();
      return;
    }
    ctx.scale(dpr, dpr);

    if (getComputedStyle(panelEl).position === 'static') {
      panelEl.style.position = 'relative';
    }
    panelEl.appendChild(canvas);
    activeCanvasEl = canvas;

    // Instantly hide actual panel DOM content while canvas takes over visually
    panelEl.classList.add('sentinel-panel-hidden');
    isTransitionAnimating = true;

    const startTime = performance.now();

    const animateFrame = (now) => {
      const elapsed = now - startTime;
      ctx.clearRect(0, 0, width, height);

      let activeCount = 0;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        if (type === 'disintegrate') {
          // DISINTEGRATION: Panel surface breaks apart, particles peel away and drift with wind
          if (elapsed < p.delay) {
            // Unpeeled fragment: remains solid on panel surface
            ctx.fillStyle = p.color;
            ctx.globalAlpha = 1.0;
            ctx.fillRect(p.x, p.y, p.size, p.size);
            activeCount++;
          } else {
            const particleElapsed = elapsed - p.delay;
            const animProgress = particleElapsed / (duration - 100);

            if (animProgress < 1.0) {
              const driftX = p.x + p.vx * particleElapsed * 0.12;
              const driftY = p.y + p.vy * particleElapsed * 0.12;
              const alpha = Math.max(0, 1.0 - Math.pow(animProgress, 1.5));

              ctx.fillStyle = p.color;
              ctx.globalAlpha = alpha;
              ctx.fillRect(driftX, driftY, p.size * (1 - animProgress * 0.4), p.size * (1 - animProgress * 0.4));
              activeCount++;
            }
          }
        } else {
          // MATERIALIZATION: Dust fragments arrive from upwind positions, converging to form panel
          const startDelay = p.delay * 0.6;
          const particleElapsed = elapsed - startDelay;
          const particleDuration = duration - 120;

          if (particleElapsed <= 0) {
            // Not arrived yet
            activeCount++;
          } else {
            const rawProgress = Math.min(1.0, particleElapsed / particleDuration);
            // Ease-out cubic deceleration curve
            const progress = 1.0 - Math.pow(1.0 - rawProgress, 3);

            // Upwind starting offset
            const startX = p.x + (p.vx * 70) + 40;
            const startY = p.y + (p.vy * 60) - 30;

            const currentX = startX + (p.x - startX) * progress;
            const currentY = startY + (p.y - startY) * progress;
            const alpha = Math.min(1.0, progress * 1.3);

            ctx.fillStyle = p.color;
            ctx.globalAlpha = alpha;
            ctx.fillRect(currentX, currentY, p.size, p.size);

            if (rawProgress < 1.0) {
              activeCount++;
            }
          }
        }
      }

      if (elapsed < duration + 150 && activeCount > 0) {
        activeCanvasRaf = requestAnimationFrame(animateFrame);
      } else {
        cancelActiveAnimations();
        if (typeof onComplete === 'function') {
          onComplete();
        }
      }
    };

    activeCanvasRaf = requestAnimationFrame(animateFrame);
  }

  // Disintegrate and remove panel cleanly
  function disintegrateAndRemovePanel() {
    if (scanTimer) {
      clearInterval(scanTimer);
      scanTimer = null;
    }
    isScanning = false;

    const panelEl = document.getElementById(PANEL_ID);
    if (!panelEl) return;

    if (isReducedMotionPreferred()) {
      removePanel();
      return;
    }

    runCanvasSurfaceAnimation(panelEl, 'disintegrate', 700, () => {
      removePanel();
    });
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
        debugLog('Left email view - disintegrating panel');
        currentEmailKey = null;
        disintegrateAndRemovePanel();
      }
      return;
    }

    const newEmailKey = getEmailUniqueKey(emailView);
    const existingPanel = document.getElementById(PANEL_ID);

    if (existingPanel && currentEmailKey === newEmailKey && !existingPanel.classList.contains('sentinel-disintegrating')) {
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
    if (scanTimer) {
      clearInterval(scanTimer);
      scanTimer = null;
    }

    cancelActiveAnimations();

    let existingPanel = document.getElementById(PANEL_ID);
    const isNewPanel = !existingPanel || existingPanel.classList.contains('sentinel-panel-hidden');

    if (isNewPanel && existingPanel) {
      existingPanel.remove();
      existingPanel = null;
    }

    isScanning = true;
    scanProgress = 15;
    scanStep = 'Checking sender & connecting to FastAPI backend...';
    reviewStatus = 'pending';
    scanResults = null; // Clear stale results from previous email

    renderOrUpdatePanel(emailView);
    const panelEl = document.getElementById(PANEL_ID);

    const executeScanningSequence = async () => {
      if (!isScanning) return;

      // Progress bar animation while requesting backend
      scanTimer = setInterval(() => {
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

      if (scanTimer) clearInterval(scanTimer);
      scanTimer = null;
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
    };

    if (isNewPanel && panelEl && !isReducedMotionPreferred()) {
      runCanvasSurfaceAnimation(panelEl, 'assemble', 600, () => {
        if (panelEl) panelEl.classList.remove('sentinel-panel-hidden');
        executeScanningSequence();
      });
    } else {
      executeScanningSequence();
    }
  }

  // Remove existing panel safely
  function removePanel() {
    cancelActiveAnimations();
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
    const riskLevelText = (currentResults.risk_level || 'HIGH').toUpperCase();
    const riskLevelClass = riskLevelText.toLowerCase();
    const findingsList = currentResults.findings || [];
    const attachmentsList = currentResults.attachments || [];

    const senderDetails = parseSenderDetails(emailContext.sender, findingsList);
    const catStatuses = computeCategoryStatuses(findingsList, attachmentsList, emailContext);
    const guidanceText = generateGuidanceText(riskLevelText, findingsList, attachmentsList, currentResults.recommendation);

    const isLightTheme = currentTheme === 'light';

    // HTML Structure
    panelEl.innerHTML = `
      <div class="sentinel-panel-inner ${isCollapsed ? 'sentinel-collapsed' : ''}">
        <!-- Compact Header Strip -->
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
              <div class="sentinel-header-logo ${riskLevelClass}" aria-hidden="true">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <path d="m9 12 2 2 4-4"/>
                </svg>
              </div>
              <div>
                <div class="sentinel-header-title-row">
                  <h2 class="sentinel-header-title">SentinelAI Threat Intelligence</h2>
                </div>
                <p class="sentinel-header-subtitle">Email Security Guard</p>
              </div>
            </div>
          </div>

          <div class="sentinel-header-right">
            ${isBackendLive ? `
              <span class="sentinel-badge-mode backend" title="Connected to FastAPI backend">
                <span class="sentinel-dot live"></span>
                Backend Demo
              </span>
            ` : `
              <span class="sentinel-badge-mode fallback" title="Backend unreachable — showing local fallback">
                <span class="sentinel-dot fallback"></span>
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
          <!-- Sender Context Box (Enhanced Verification Treatment) -->
          <div class="sentinel-context-box">
            ${emailContext.isReliable ? `
              <div class="sentinel-sender-card">
                <div class="sentinel-sender-top">
                  <div class="sentinel-sender-identity">
                    ${senderDetails.displayName ? `<span class="sentinel-sender-name">${escapeHtml(senderDetails.displayName)}</span>` : ''}
                    <span class="sentinel-sender-email" title="${escapeHtml(senderDetails.emailAddress)}">${escapeHtml(senderDetails.emailAddress)}</span>
                  </div>
                  <span class="sentinel-sender-trust-badge ${senderDetails.badgeClass}" title="${escapeHtml(senderDetails.badgeText)}">
                    <span class="sentinel-trust-icon">${senderDetails.badgeIcon}</span>
                    <span>${escapeHtml(senderDetails.badgeText)}</span>
                  </span>
                </div>
                <div class="sentinel-sender-subrow">
                  <span class="sentinel-context-label">Subject</span>
                  <span class="sentinel-context-val" title="${escapeHtml(emailContext.subject)}">${escapeHtml(emailContext.subject)}</span>
                </div>
                ${emailContext.attachmentCount > 0 ? `
                  <div class="sentinel-context-meta">
                    <span>Attachments: <strong>${emailContext.attachmentCount}</strong></span>
                  </div>
                ` : ''}
              </div>
            ` : `
              <div class="sentinel-context-unavailable">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span>Email details unavailable</span>
              </div>
            `}
          </div>

          <!-- Body Content: Scanning State vs Complete State -->
          <div class="sentinel-panel-body">
            ${isScanning ? `
              <!-- Scanning Progress State -->
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
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>${escapeHtml(backendErrorMessage)}</span>
                  </div>
                ` : ''}

                <!-- Primary Threat Verdict Section -->
                <div class="sentinel-verdict-card ${riskLevelClass}">
                  <div class="sentinel-verdict-header">
                    <div class="sentinel-verdict-badge-wrap">
                      <span class="sentinel-risk-badge ${riskLevelClass}" tabIndex="0" aria-label="Risk Level: ${riskLevelText}">
                        ${riskLevelText}
                      </span>
                    </div>
                    <div class="sentinel-verdict-score">
                      <span class="sentinel-score-num">${riskScore}</span>
                      <span class="sentinel-score-denom">/ 10</span>
                    </div>
                  </div>

                  <p class="sentinel-verdict-summary">
                    ${escapeHtml(currentResults.summary || 'Analysis detected security indicators requiring review.')}
                  </p>

                  <!-- Compact Risk Bar Scale -->
                  <div class="sentinel-risk-bar-wrap">
                    <div class="sentinel-bar-track">
                      <div class="sentinel-bar-fill" style="width: ${Math.min(100, Math.max(0, parseFloat(riskScore) * 10))}%;"></div>
                      <div class="sentinel-score-pin" style="left: ${Math.min(100, Math.max(0, parseFloat(riskScore) * 10))}%;" title="Score: ${riskScore} (${riskLevelText})"></div>
                    </div>
                    <div class="sentinel-scale-boundaries">
                      <span class="sentinel-scale-mark pos-0">0<small>LOW</small></span>
                      <span class="sentinel-scale-mark pos-25">2.5<small>MED</small></span>
                      <span class="sentinel-scale-mark pos-50">5.0<small>HIGH</small></span>
                      <span class="sentinel-scale-mark pos-75">7.5<small>CRIT</small></span>
                      <span class="sentinel-scale-mark pos-100">10</span>
                    </div>
                  </div>
                </div>

                <!-- Risk Summary Strip -->
                <div class="sentinel-risk-strip" role="group" aria-label="Risk category summary">
                  <button type="button" class="sentinel-strip-item ${catStatuses.sender.class}" data-category="sender" title="Filter / Jump to Sender findings">
                    <span class="sentinel-strip-dot ${catStatuses.sender.class}"></span>
                    <span class="sentinel-strip-label">SENDER</span>
                    <span class="sentinel-strip-val">${catStatuses.sender.label}</span>
                  </button>
                  <button type="button" class="sentinel-strip-item ${catStatuses.content.class}" data-category="content" title="Filter / Jump to Content findings">
                    <span class="sentinel-strip-dot ${catStatuses.content.class}"></span>
                    <span class="sentinel-strip-label">CONTENT</span>
                    <span class="sentinel-strip-val">${catStatuses.content.label}</span>
                  </button>
                  <button type="button" class="sentinel-strip-item ${catStatuses.links.class}" data-category="links" title="Filter / Jump to Link findings">
                    <span class="sentinel-strip-dot ${catStatuses.links.class}"></span>
                    <span class="sentinel-strip-label">LINKS</span>
                    <span class="sentinel-strip-val">${catStatuses.links.label}</span>
                  </button>
                  <button type="button" class="sentinel-strip-item ${catStatuses.attachments.class}" data-category="attachments" title="Filter / Jump to Attachment findings">
                    <span class="sentinel-strip-dot ${catStatuses.attachments.class}"></span>
                    <span class="sentinel-strip-label">ATTACHMENTS</span>
                    <span class="sentinel-strip-val">${catStatuses.attachments.label}</span>
                  </button>
                </div>

                <!-- WHY THIS WAS FLAGGED (Security Signals) -->
                <div class="sentinel-findings-section">
                  <div class="sentinel-findings-header">
                    <div>
                      <h3 class="sentinel-findings-title">WHY THIS WAS FLAGGED</h3>
                      <span class="sentinel-findings-subtitle">${findingsList.length} security ${findingsList.length === 1 ? 'indicator' : 'indicators'} detected</span>
                    </div>
                    <span class="sentinel-findings-hint">Click finding to toggle details</span>
                  </div>

                  <div class="sentinel-findings-list">
                    ${findingsList.map((finding, idx) => {
                      const findingId = `f-${idx + 1}`;
                      const isExpanded = expandedFindingId === findingId;
                      const sevClass = (finding.severity || 'high').toLowerCase();
                      const textHighlight = getSuspiciousTextHighlight(finding);

                      return `
                        <div class="sentinel-finding-item ${isExpanded ? 'expanded' : ''}" data-finding-id="${findingId}" tabIndex="0" role="button" aria-expanded="${isExpanded}" aria-label="Finding: ${escapeHtml(finding.title)}, Severity: ${escapeHtml(finding.severity)}">
                          <div class="sentinel-finding-header">
                            <div class="sentinel-finding-left">
                              <span class="sentinel-finding-icon ${sevClass}">
                                ${getFindingIconSvg(finding.type || finding.icon)}
                              </span>
                              <span class="sentinel-finding-title">${escapeHtml(finding.title)}</span>
                            </div>
                            <div class="sentinel-finding-right">
                              <span class="sentinel-badge-sev ${sevClass}">${escapeHtml(finding.severity)}</span>
                              <span class="sentinel-arrow-icon ${isExpanded ? 'rotated' : ''}" aria-hidden="true">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                  <path d="m6 9 6 6 6-6"/>
                                </svg>
                              </span>
                            </div>
                          </div>
                          ${isExpanded ? `
                            <div class="sentinel-finding-details">
                              <p class="sentinel-finding-why"><strong>Why it matters:</strong> ${escapeHtml(finding.description || finding.explanation)}</p>
                              ${textHighlight && textHighlight.phrase ? `
                                <div class="sentinel-finding-quote-box">
                                  <span class="sentinel-quote-label">DETECTED PATTERN</span>
                                  <mark class="sentinel-quote-text">"${escapeHtml(textHighlight.phrase)}"</mark>
                                </div>
                              ` : `
                                <div class="sentinel-finding-quote-box">
                                  <span class="sentinel-quote-label">DETECTED PATTERN</span>
                                  <span class="sentinel-quote-generic">Suspicious language pattern detected</span>
                                </div>
                              `}
                              <div class="sentinel-finding-meta-row">
                                <span class="sentinel-signal-id">Signal: ${escapeHtml(finding.type)}</span>
                              </div>
                            </div>
                          ` : ''}
                        </div>
                      `;
                    }).join('')}
                  </div>
                </div>

                ${attachmentsList.length > 0 ? `
                  <!-- Attachment Summary Section (Progressive Disclosure) -->
                  <div class="sentinel-attachments-section">
                    <div class="sentinel-attachments-header" id="sentinel-toggle-attachments" tabIndex="0" role="button" aria-expanded="${isAttachmentsExpanded}">
                      <div class="sentinel-attachments-left">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
                        <span class="sentinel-attachments-title">Attachments (${attachmentsList.length})</span>
                      </div>
                      <div class="sentinel-attachments-right">
                        <span class="sentinel-attachments-status">${attachmentsList.length} analyzed</span>
                        <span class="sentinel-arrow-icon ${isAttachmentsExpanded ? 'rotated' : ''}" aria-hidden="true">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <path d="m6 9 6 6 6-6"/>
                          </svg>
                        </span>
                      </div>
                    </div>
                    ${isAttachmentsExpanded ? `
                      <div class="sentinel-attachments-list">
                        ${attachmentsList.map(att => `
                          <div class="sentinel-attachment-card ${att.threat_score >= 5.0 ? 'high-risk' : (att.threat_score >= 2.5 ? 'med-risk' : 'low-risk')}">
                            <div class="sentinel-att-info">
                              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
                              <span class="sentinel-att-name" title="${escapeHtml(att.filename || att.name || 'attachment')}">${escapeHtml(att.filename || att.name || 'attachment')}</span>
                            </div>
                            <div class="sentinel-att-meta">
                              <span class="sentinel-badge-sev ${(att.risk_level || 'LOW').toLowerCase()}">${att.threat_score !== undefined ? att.threat_score.toFixed(1) : '0.0'} ${att.risk_level || 'LOW'}</span>
                            </div>
                          </div>
                        `).join('')}
                      </div>
                    ` : ''}
                  </div>
                ` : ''}

                <!-- WHAT SHOULD I DO? Action Guidance Box -->
                <div class="sentinel-guidance-box ${riskLevelClass}">
                  <div class="sentinel-guidance-header">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span>WHAT SHOULD I DO?</span>
                  </div>
                  <p class="sentinel-guidance-text">${escapeHtml(guidanceText)}</p>
                </div>

                <!-- Secondary Action Buttons -->
                <div class="sentinel-actions-row">
                  <button type="button" id="sentinel-btn-review" class="sentinel-btn ${reviewStatus === 'reviewed' ? 'sentinel-btn-success' : 'sentinel-btn-secondary'}" aria-label="Mark email review status">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 6L9 17l-5-5"/></svg>
                    <span>${reviewStatus === 'reviewed' ? 'Reviewed ✓' : 'Mark as Reviewed'}</span>
                  </button>
                  <button type="button" id="sentinel-btn-rescan" class="sentinel-btn sentinel-btn-secondary" aria-label="Rescan email and attachments">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
                    <span>Rescan Email</span>
                  </button>
                </div>
              </div>
            `}
          </div>

          <!-- Muted Footer Disclaimer -->
          <div class="sentinel-panel-footer">
            <p class="sentinel-footer-note">Demo mode: analysis processed locally. Email credentials or full attachments are never stored.</p>
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

        // Persist and update button immediately — responsive feel.
        saveTheme(nextTheme);
        currentTheme = nextTheme;
        updateThemeToggleButton(panelEl, nextTheme);

        // Run the directional wipe. The real theme class is applied at wipe end.
        performThemeWipe(panelEl, activeTheme, nextTheme);
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

    // Risk summary strip button interactions
    const stripButtons = panelEl.querySelectorAll('.sentinel-strip-item');
    stripButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const cat = btn.getAttribute('data-category');
        if (cat === 'attachments') {
          isAttachmentsExpanded = true;
          renderOrUpdatePanel(emailView);
          const attSection = panelEl.querySelector('.sentinel-attachments-section');
          if (attSection) {
            attSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        } else {
          const currentRes = scanResults || localFallbackResults;
          const fList = currentRes.findings || [];
          const matchIdx = fList.findIndex(f => {
            const t = (f.type || '').toLowerCase();
            const c = (f.category || '').toLowerCase();
            if (cat === 'sender') return c === 'sender' || t.includes('sender') || t.includes('impersonation') || t.includes('lookalike') || t.includes('reply_to') || t.includes('domain');
            if (cat === 'content') return c === 'content' || t.includes('credential') || t.includes('urgency') || t.includes('financial') || t.includes('keyword') || t.includes('phishing');
            if (cat === 'links') return c === 'links' || c === 'urls' || t.includes('link') || t.includes('url') || t.includes('ip_in_url') || t.includes('tld') || t.includes('shortener');
            return false;
          });

          if (matchIdx !== -1) {
            expandedFindingId = `f-${matchIdx + 1}`;
            renderOrUpdatePanel(emailView);
            const targetEl = panelEl.querySelector(`[data-finding-id="f-${matchIdx + 1}"]`);
            if (targetEl) {
              targetEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              targetEl.classList.add('sentinel-pulse-highlight');
            }
          } else {
            if (cat === 'sender') {
              const senderBox = panelEl.querySelector('.sentinel-context-box');
              if (senderBox) senderBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } else {
              const findingsBox = panelEl.querySelector('.sentinel-findings-section');
              if (findingsBox) findingsBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
          }
        }
      });
    });

    // Attachment section expand/collapse toggle
    const attToggleBtn = panelEl.querySelector('#sentinel-toggle-attachments');
    if (attToggleBtn) {
      const toggleAttFn = (e) => {
        e.stopPropagation();
        isAttachmentsExpanded = !isAttachmentsExpanded;
        renderOrUpdatePanel(emailView);
      };
      attToggleBtn.addEventListener('click', toggleAttFn);
      attToggleBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleAttFn(e);
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
