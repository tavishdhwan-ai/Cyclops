# SentinelAI FastAPI Backend (Phase 4A.1)

FastAPI backend service for SentinelAI email security analysis. Phase 4A.1 refactors the scanner engine into a modular architecture and introduces advanced sender intelligence rules.

> **CLASSIFICATION**: **Rule-based threat analysis**
> *This backend performs passive, rule-based heuristic threat analysis on email metadata and text supplied by the extension. It does NOT perform live malware analysis, dynamic sandbox execution, or real-time domain reputation queries.*

---

## Technical Overview

- **Framework**: Python / FastAPI / Uvicorn / Pydantic v2
- **Host**: `127.0.0.1` (Localhost binding only for security)
- **Port**: `8000`
- **Analysis Mode**: Controlled Demo Mode (`mode: "demo"`)

---

## Scanner Architecture (Phase 4A.1 Modular Design)

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
      urls.py         # Passive URL structural and protocol analysis
      attachments.py # Passive attachment filename/type metadata analysis
      scoring.py      # Centralized continuous decimal threat score & risk level mapping
      brands.py       # Deterministic brand configuration and lookalike helper utilities
```

### Module Responsibilities

1. **`engine.py`**: Accepts `EmailScanRequest`, invokes individual analyzers, aggregates findings, calculates threat score/risk level, and constructs `EmailScanResponse`.
2. **`sender.py`**: Executes deterministic sender analysis rules on display names, email domains, lookalike patterns, punycode, free-mail provider context, and Reply-To headers.
3. **`content.py`**: Preserves Phase 3B text analysis rules for urgency language, credential/password requests, and artificial account/payment pressure.
4. **`urls.py`**: Performs passive structural checks on links (IP hostnames, URL shorteners, excessive subdomains, punycode URLs, HTTP vs HTTPS).
5. **`attachments.py`**: Inspects attachment metadata (double extensions, script/executable extensions, HTML attachments combined with sensitive text context, suspicious filename terms).
6. **`scoring.py`**: Calculates continuous decimal threat scores (0.0 to 10.0) with category capping to prevent duplicate score inflation, and maps scores to exact risk boundaries.
7. **`brands.py`**: Maintains deterministic configuration for common brands (Microsoft, Google, Apple, Amazon, PayPal, Meta, LinkedIn, Dropbox, Adobe, Netflix, DocuSign) and legitimate domain mappings.

---

## Advanced Sender Intelligence Rules

- **Missing / Malformed Sender**: Flags missing or structurally invalid email addresses.
- **Brand Impersonation**: Detects when display names reference a recognized brand while sending from an unrelated domain (e.g. `Microsoft Support <security@example.xyz>`).
- **Lookalike Domain Heuristics**: Detects character substitution (0 -> o, 1 -> l/i, 5 -> s, 3 -> e) or hyphenated brand extensions mimicking known brands (e.g., `paypa1.com`, `micr0soft.example`, `amaz0n.example`).
- **Punycode / Unicode Domains**: Flags `xn--` internationalized domains or unusual character sets.
- **Free Email Domain Context**: Generates a warning when a business identity or corporate brand uses a generic free email provider (e.g., `Microsoft Billing Department <billingteam@gmail.com>`).
- **Reply-To Analysis**: Compares `From` domain vs `Reply-To` domain and flags significant discrepancies.

---

## Scoring Model & Risk Boundaries

Final threat scores are continuous decimal numbers from **0.0 to 10.0**, rounded to one decimal place.

The risk level mapping strictly follows these exact boundaries:
- **`0.0` – `2.49`**: **`LOW`** (Minimal or no security indicators)
- **`2.5` – `4.99`**: **`MEDIUM`** (Moderate security warnings)
- **`5.0` – `7.49`**: **`HIGH`** (High-risk phishing indicators requiring review)
- **`7.5` – `10.0`**: **`CRITICAL`** (Severe security threats, e.g., credential theft or executable attachments)

### Explainability

Every score increase corresponds directly to an item in the returned `findings` array. Each finding provides an `id`, `category`, `title`, `severity`, `explanation`, `evidence`, and `score_contribution`.

---

## Brand Heuristic Limitations

- The brand domain mapping is **not** a comprehensive global domain reputation database.
- It relies on a small, extensible, deterministic list of high-visibility brands to spot obvious display-name and domain mismatches.

---

## Scope & Passive Analysis Safety Controls

Phase 4A.1 operates strictly under passive metadata and text analysis.

**Phase 4A.1 does NOT:**
- Visit or send HTTP requests to URLs found in emails.
- Download, extract, open, or execute email attachments.
- Connect to external threat intelligence APIs or third-party networks.
- Use LLMs or non-deterministic AI generation.
- Collect passwords, session cookies, auth tokens, or OAuth credentials.
- Inspect unrelated Gmail page content or bypass browser security controls.

---

## Setup & Running Instructions (Windows PowerShell)

1. Navigate to the backend folder:
   ```powershell
   cd C:\Users\Tavish\Desktop\cyclops\backend
   ```
2. Activate virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
3. Run tests:
   ```powershell
   python -m pytest
   ```
4. Verify byte-compilation:
   ```powershell
   python -m compileall app
   ```
5. Start backend server:
   ```powershell
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
