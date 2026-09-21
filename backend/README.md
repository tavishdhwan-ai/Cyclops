# SentinelAI FastAPI Backend (Phase 4A.3)

FastAPI backend service for SentinelAI email security analysis. Phase 4A.3 extends the scanner with Advanced Attachment Intelligence (passive, metadata-only attachment risk analysis).

> **CLASSIFICATION**: **Rule-based threat analysis**
> *This backend performs passive, rule-based heuristic threat analysis on email metadata and text supplied by the extension. It does NOT perform live malware analysis, dynamic sandbox execution, or real-time domain reputation queries.*

---

## Technical Overview

- **Framework**: Python / FastAPI / Uvicorn / Pydantic v2
- **Host**: `127.0.0.1` (Localhost binding only for security)
- **Port**: `8000`
- **Analysis Mode**: Controlled Demo Mode (`mode: "demo"`)

---

## Scanner Architecture (Phase 4A.2 Design)

The scanner engine is structured into modular analyzers under `app/scanner/`:

```
backend/
  app/
    main.py           # FastAPI web application routes and exception handlers
    models.py         # Data models re-exported from app.schemas
    schemas.py        # Pydantic v2 request/response schemas and Finding definitions
    scanner/
      __init__.py     # Package exports for scanner engine
      engine.py       # Core scan orchestrator
      sender.py       # Advanced sender, domain, display-name & Reply-To intelligence
      content.py      # Urgency, credential request & account pressure rules
      urls.py         # Advanced passive URL intelligence & structural heuristics (Phase 4A.2)
      attachments.py  # Advanced passive attachment metadata analysis (Phase 4A.3)
      scoring.py      # Centralized continuous decimal threat score & risk level mapping
      brands.py       # Deterministic brand configuration and lookalike helper utilities
```

---

## Rule-based Attachment threat analysis (Phase 4A.3)

### Passive Safety Guarantee

Attachment analysis in SentinelAI is **completely passive and metadata-only**:
- Only inspects the filename, declared MIME/content-type, and file size already supplied by the extension.
- **Never** reads, opens, executes, renders, or decompresses attachment contents.
- **Never** extracts archives or inspects archive member files.
- **Never** executes macros or documents.
- **Never** uploads attachments to any external service.
- **Never** uses antivirus engines or external reputation APIs.

### Implemented Attachment Heuristics

1. **Double / Multiple Extension**: Detects `invoice.pdf.exe`, `salary.xlsx.js`, `image.jpg.lnk` — benign decoy extension before dangerous final extension. HIGH severity.
2. **Executable Attachment**: Flags `.exe`, `.scr`, `.com`, `.bat`, `.cmd`, `.pif`, `.cpl`, `.dll`. HIGH severity.
3. **Script Attachment**: Flags `.ps1`, `.vbs`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.vbe`, `.py`, `.rb`, `.sh`. HIGH severity.
4. **Shortcut Attachment**: Flags `.lnk`, `.url`, `.webloc`. HIGH severity.
5. **Installer Package**: Flags `.msi`, `.msp`, `.mst`, `.cab`, `.appx`. HIGH severity.
6. **Macro-Enabled Office Document**: Flags `.docm`, `.xlsm`, `.xltm`, `.pptm`, `.dotm`. HIGH severity.
7. **Suspicious HTML Attachment**: HTML/HTM/MHTML files combined with sensitive email context (credential, login, account language). HIGH severity.
8. **Archive / Container**: `.zip`, `.rar`, `.7z`, `.tar`, `.iso`, `.img`. LOW severity (elevated to MEDIUM when suspicious filename keywords present).
9. **MIME / Extension Mismatch**: Detects when declared MIME type contradicts filename extension (e.g. `invoice.pdf` with `application/x-msdownload`). MEDIUM severity.
10. **Social-Engineering Filename Keywords**: `invoice`, `payment`, `salary`, `password`, `verification`, `payroll`, etc. LOW severity. Only emitted when no stronger finding is already present.
11. **Suspicious Filename Spacing**: Detects unusual whitespace around extensions (e.g. `payment.pdf .exe`). MEDIUM severity.
12. **Unusually Long Filename**: Filenames >100 characters that could push the real extension off-screen. LOW severity.
13. **Excessive Punctuation**: Filenames with ≥4 special characters in the base name. LOW severity.
14. **Suspiciously Small Document**: Files declaring a document extension but containing <512 bytes. LOW severity.

### Anti-Double-Counting Rules

- **Double extension subsumes executable/script/shortcut findings**: a file with `double_extension` does not also emit `executable_attachment` or `script_attachment`.
- **Strong findings suppress keyword signals**: `attachment_keyword` is not emitted when `double_extension`, `executable_attachment`, `macro_enabled_document`, etc. are already present.
- **Per-category cap**: the `attachments` category contribution is capped at **4.0** in the overall email score calculation.

### Limitations

- MIME types are not validated by inspecting file bytes — only the declared `content_type` field is used.
- Archive contents are never inspected; a `.zip` containing a `.exe` will not be detected at the inner level.

---

## Rule-based URL threat analysis (Phase 4A.2)

### Passive Safety Guarantee

URL analysis in SentinelAI is **completely passive**:
- Parses URLs locally using standard URL parsers.
- **Never** visits or connects to any URL.
- **Never** sends HTTP/HTTPS requests to destinations.
- **Never** resolves hostnames through external reputation services or DNS queries.
- **Never** crawls pages or follows HTTP redirects.
- **Never** downloads content or executes scripts.

### Implemented URL Heuristics

1. **Unencrypted HTTP Protocol**: Detects `http://` URLs. Generates a medium-severity finding explaining that connection lacks transport encryption. HTTPS links do not trigger this.
2. **Raw IP Address URLs**: Detects IPv4 and IPv6 hosts (e.g. `http://192.0.2.10/login` or `http://[2001:db8::1]/login`). Generates high-severity findings for bypassing domain registration.
3. **Non-Standard Ports**: Identifies explicit ports other than 80/443 (e.g. `:8443`, `:8080`).
4. **Userinfo / `@` URL Tricks**: Detects URLs with userinfo before hostname (`https://trusted.example@evil.example/login`). Correctly extracts destination host (`evil.example`).
5. **Excessive Subdomains**: Identifies hostname structures with more than 3–4 subdomain levels.
6. **Very Long URLs**: Identifies URLs exceeding length thresholds (>150 chars total or >64 char hostnames).
7. **Heavy URL Encoding**: Flags excessive percent-encoding (%2F, %3A, %40, %2E) obscuring paths or parameters.
8. **Suspicious Query Parameters**: Inspects parameter *names* only (e.g., `redirect`, `return`, `next`, `url`, `destination`). **Never** logs or exposes parameter values.
9. **Credential / Login Path Signals**: Flags sensitive security/auth terms in path (`/login`, `/verify`, `/password`, `/account`).
10. **URL Shorteners**: Matches hostnames against known shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`, `is.gd`, `cutt.ly`, etc.).
11. **Hostname / Domain Heuristics**: Detects structural anomalies like excessive hyphens (>=3).
12. **Punycode / Internationalized Domains**: Flags `xn--` domain prefixes and non-ASCII character sets.
13. **Visible Link Text vs Destination Mismatch**: Detects discrepancies when visible display text (e.g. `https://microsoft.com`) points to a different target domain (`https://example.xyz/login`).
14. **Lookalike Domain Integration**: Integrates with centralized brand database to detect character substitution (`paypa1.com`, `micr0soft.com`).

### Limitations of Structural URL Analysis

- Structural heuristics flag structural patterns associated with phishing, but do not provide definitive malware detection or real-time domain reputation.
- Legitimate tracking links or complex web app URLs may trigger long-URL or parameter findings; severity levels remain low/medium to prevent false positives.

### Scoring & Deduplication

- URL findings contribute severity weights: `critical` (+3.0), `high` (+2.5), `medium` (+1.5), `low` (+0.5).
- The `urls` category contribution is capped at **4.0** maximum to prevent multiple findings on a single link from endlessly inflating the overall email score.
- Identical findings across URLs are deduplicated to keep results clean and readable.

---

## Scoring Model & Risk Boundaries

Final threat scores are continuous decimal numbers from **0.0 to 10.0**, rounded to one decimal place.

The risk level mapping strictly follows these exact boundaries:
- **`0.0` – `2.49`**: **`LOW`** (Minimal or no security indicators)
- **`2.5` – `4.99`**: **`MEDIUM`** (Moderate security warnings)
- **`5.0` – `7.49`**: **`HIGH`** (High-risk phishing indicators requiring review)
- **`7.5` – `10.0`**: **`CRITICAL`** (Severe security threats)

---

## Setup & Running Instructions (Windows PowerShell)

1. Navigate to the backend folder:
   ```powershell
   cd C:\Users\Tavish\Desktop\cyclops\backend
   ```
2. Run tests:
   ```powershell
   python -m pytest tests/
   ```
3. Verify byte-compilation:
   ```powershell
   python -m compileall app
   ```
4. Start backend server:
   ```powershell
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
