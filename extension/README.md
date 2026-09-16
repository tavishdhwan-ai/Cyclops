# SentinelAI - Gmail Threat Intelligence Chrome Extension (Phase 2)

**SentinelAI Email Security Guard** is a Manifest V3 Chrome Extension providing a Grammarly-like overlay inside Gmail for simulated B2B email security and phishing threat detection.

---

## 🚀 Features Supported in Phase 2

- **Demo Protection Toggle**: Enable/disable extension protection anytime via the popup switch. Settings persist across browser sessions using `chrome.storage.local`.
- **Real-Time Statuses**: Live indicators for `Protection Active`, `Protection Paused`, and `Demo Mode`.
- **Safe Email Context Extraction**: Safely extracts opened email sender address, subject line, attachment count, and timestamp without crashing if elements are missing ("Email details unavailable" fallback).
- **Flexible Panel Positioning**: Places threat analysis inline next to opened email headers, or falls back to a fixed non-blocking overlay on the right (`sentinel-overlay-panel`) that never obscures Gmail email body, compose buttons, or navigation.
- **Session Collapse Memory**: Supports collapsing and expanding the panel, remembering user preference for the active Gmail session.
- **Loading & Error Handling**: Animated multi-step progress bar (0% -> 100%), scanning status updates, and graceful error handling without raw JavaScript exceptions.
- **"Test Demo Email" Action**: Quick launcher in popup to open the local SentinelAI security app at `http://localhost:3000/emails`.
- **Security Guidance & Recommendations**: Risk-appropriate action guidance (High, Medium, Low Risk recommendations) based on simulated findings.
- **Accessibility & Keyboard Control**: ARIA regions (`role="region"`, `aria-label`), keyboard navigation (`Enter` and `Space`), high-contrast focus rings (`:focus-visible`), and text labels for all risk levels.
- **SPA Navigation Observer**: Debounced `MutationObserver` handling Gmail SPA navigation between inbox, email details, and search views without duplicate injections or uncontrolled loops.
- **Debug Logging Toggle**: Built-in `const DEBUG = false;` flag for clean development logging.

---

## 🔒 Local Simulation & Privacy Notice

> **Demo mode:** All threat scores, findings, urgency signals, and scan steps are **simulated locally**.
> - **No email content, credentials, or passwords** are read, collected, or uploaded to external servers.
> - **No attachment files** are read or stored.
> - The extension requests host permissions strictly for `https://mail.google.com/*` to inject the local overlay UI.

---

## 🔧 Installation & Reload Instructions

### 1. Load Unpacked Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory inside this repository (`c:\Users\Tavish\Desktop\cyclops\extension`).

### 2. Reloading Code Changes
Whenever you update `content.js`, `popup.js`, or `styles.css`:
1. Go to `chrome://extensions/`.
2. Click the **Reload (↻)** icon on the SentinelAI extension card.
3. Refresh your active `https://mail.google.com/` tab to apply content script changes.

---

## ⚙️ How to Toggle Protection

1. Click the **SentinelAI** extension icon in your Chrome toolbar.
2. Toggle the **Demo Protection** switch:
   - **Enabled (Green)**: SentinelAI automatically injects the threat analysis panel when an email is opened in Gmail.
   - **Disabled (Amber)**: Protection is paused; panels are hidden and no new panels are injected into Gmail.

---

## 🛠️ Troubleshooting Guide

### 1. Panel Not Appearing in Gmail
- **Check Toggle**: Open extension popup and ensure **Demo Protection** is toggled **ON** ("Protection Active").
- **Open an Email**: Make sure you have opened an email thread in Gmail (panels do not display on empty inbox list view).
- **Reload Tab**: Refresh the Gmail tab (`Ctrl+R` / `F5`).
- **Check Debug Logs**: In `extension/content.js`, change `const DEBUG = false;` to `const DEBUG = true;`, reload the extension, and inspect Chrome Developer Tools (`F12 -> Console`) for `[SentinelAI]` logs.

### 2. Duplicate Panel Appearing
- The content script includes a guard (`window.__SENTINEL_AI_CONTENT_SCRIPT_LOADED__`) and checks for existing element ID `#sentinel-ai-panel`.
- If duplicate panels appear after rapid re-loads, close and re-open the Gmail tab.

### 3. Manifest Error on Extension Load
- Ensure `extension/icons/icon16.png`, `icon48.png`, and `icon128.png` exist.
- Run `node extension/generate-icons.js` if icon assets are missing.

### 4. Gmail Layout Not Recognized / Email Details Unavailable
- Gmail uses obfuscated and dynamically changing DOM class names.
- If Gmail DOM elements cannot be parsed, SentinelAI gracefully switches to **"Email details unavailable"** and renders the fixed overlay fallback position without breaking Gmail layout or throwing JS errors.

---

## 📁 Extension File Structure

```
extension/
├── manifest.json       # Manifest V3 extension configuration
├── popup.html          # Extension toolbar popup layout
├── popup.js            # Popup logic, chrome.storage sync, test demo button
├── content.js          # Gmail DOM injection, SPA observer, threat panel UI
├── styles.css          # Design system CSS for popup & injected panel
├── generate-icons.js   # Script to build icon PNG assets
├── icons/              # Extension icons (16x16, 48x48, 128x128)
└── README.md           # Extension documentation & user guide
```
