# Cyclops — Advanced Security Telemetry & URL Scanner

Cyclops is an enterprise application security intelligence platform featuring an email threat scanner and a production-quality website URL security scanner.

---

## Architecture Overview

Cyclops runs as a paired Next.js frontend and a high-performance Python FastAPI backend:

- **Frontend**: Next.js 16 (App Router + Turbopack), React 19, TailwindCSS v4, Lucide icons.
- **Backend**: FastAPI, Uvicorn, Pydantic v2, HTTPX, with an asynchronous, non-executing security scanner pipeline.

---

## Running the Application

### 1. Start the FastAPI Backend

Open a terminal and navigate to the `backend/` directory:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **API Base**: `http://127.0.0.1:8000`
- **Swagger Documentation**: `http://127.0.0.1:8000/docs`

### 2. Start the Next.js Frontend

Open another terminal in the root directory:

```powershell
npm run dev
# Or on Windows PowerShell if execution policies restrict npm.ps1:
npm.cmd run dev
```

- **Web Dashboard**: `http://localhost:3000`
- **URL Security Scanner Route**: `http://localhost:3000/url-scanner`

---

## URL Security Scanner Capabilities

The Cyclops URL security scanner analyzes target links **without navigating the user's browser to the target website, executing its JavaScript, downloading binaries, or submitting forms**.

### 1. URL Normalization & Validation
- **Protocol Enforcing**: Supports HTTP and HTTPS exclusively. Rejects `ftp:`, `file:`, `javascript:`, and unsupported schemes.
- **Domain & Scheme Defaults**: Automatically normalizes domain-only inputs (e.g. `example.com` &rarr; `https://example.com/`).
- **Credential & Parameter Sanitization**: Embedded credentials in URL netlocs (`admin:pass@host`) and sensitive query parameters (`token=`, `session=`, `key=`, `pwd=`) are automatically scrubbed and displayed as `[REDACTED]` in audit logs and reports.
- **IDN & Punycode Detection**: Detects internationalized domain names (IDN) and decodes/encodes Punycode.
- **Homograph Attack Detection**: Identifies confusable Unicode characters (such as Cyrillic homoglyphs `а`, `с`, `е`, `о`, `р`) mimicking Latin letters.
- **Raw IP Identification**: Detects direct IPv4 and IPv6 URLs and differentiates public addresses from internal/reserved address spaces.

### 2. Server-Side Request Forgery (SSRF) Protection
Treats every user-supplied URL and every redirect destination as untrusted:
- **Pre-Flight DNS Resolution**: Resolves target hostnames before socket connection and validates every returned IP address.
- **Strict Blocked IP Ranges**:
  - Loopback (`127.0.0.0/8`, `::1`)
  - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
  - Cloud metadata & link-local (`169.254.0.0/16`, `fe80::/10`)
  - Carrier-grade NAT (`100.64.0.0/10`)
  - Multicast (`224.0.0.0/4`, `ff00::/8`) and reserved addresses
- **Hop-by-Hop Re-resolution**: Re-evaluates destination IP at every HTTP redirect hop to prevent DNS rebinding and redirect-based SSRF.

### 3. Redirect-Hop Timeline
- Inspects HTTP status codes (`301`, `302`, `303`, `307`, `308`).
- Tracks cross-domain hops.
- Flags **HTTPS-to-HTTP downgrades** as a high-severity security risk.
- Enforces strict hop limits (default: 6 hops) and connection timeouts.

### 4. Domain Age & RDAP Intelligence
- Directly queries authoritative ICANN RDAP (Registration Data Access Protocol) endpoints.
- Calculates domain age in days and flags newly registered domains (< 14 days, < 60 days).
- Reports registrar name, registration date, expiration date, and nameservers.
- Handles privacy-protected whois/RDAP responses and unsupported TLDs gracefully.

### 5. IP & Hosting Reputation
- Resolves DNS records (`A`, `AAAA`).
- Identifies autonomous system numbers (ASN), hosting organizations, and cloud/CDN edge routing (Cloudflare, AWS, Fastly, Google, Akamai).
- Provides contextual explanations: cloud and CDN hosting explains why IP geolocation may differ from website owner physical registration without assuming malice.

### 6. Safe Read-Only Static HTML Inspection
- Safe HTML parsing using standard Python `html.parser` without executing scripts.
- Inspects page title and meta description.
- Detects forms, password inputs, and credit card fields.
- **External Form Action Alerts**: Emits high-risk findings when a password input submits credentials to an external third-party domain.
- Flags sensitive credential harvesting phrasing (e.g. "enter your password", "unlock your account", "verify identity").

### 7. Modular Reputation Providers
- **Google Safe Browsing API v4**
- **VirusTotal v3**
- **AbuseIPDB v2**
- **Explicit Provider States**: If an API key is not configured, the report explicitly states **"Not configured"** rather than fabricating false scores or clean bills of health.

---

## Environment Variables Configuration

Backend environment configuration is stored in `backend/.env` (see `backend/.env.example`):

```bash
# Backend Network Binding
HOST=127.0.0.1
PORT=8000
ENVIRONMENT=development
MODE=demo

# External Reputation Providers (Optional)
# If unconfigured, Cyclops marks them as "Not configured" without failing the scan
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=

# Inspection Limits
URL_SCAN_TIMEOUT_SECONDS=5.0
URL_SCAN_MAX_REDIRECTS=6
```

Frontend environment configuration (optional):
```bash
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
```

---

## Running the Automated Tests

### 1. Backend Python Unit & Integration Tests (106 tests)

Run all scanner, SSRF, redirect, and email tests:

```powershell
cd backend
python -m pytest tests/
```

To run specifically the URL scanner and SSRF defense suite:

```powershell
python -m pytest tests/test_url_scanner.py -v
```

### 2. Frontend Production Build & TypeScript Verification

```powershell
npm.cmd run build
```
