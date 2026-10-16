# Cyclops & SentinelAI Security Intelligence Backend

FastAPI backend service for SentinelAI Email Security Analysis and Cyclops Advanced Website URL Security Intelligence.

---

## 1. Cyclops Advanced URL Security Intelligence Features

Cyclops provides six explainable, production-grade URL security intelligence modules integrated into a unified asynchronous pipeline:

### Feature 1: SSL/TLS Certificate Intelligence (`app/scanner/ssl_inspector.py`)
- **Capability**: Safely retrieves and inspects TLS certificates over a secure connection bound to SSRF-validated IP addresses.
- **Checks**: Certificate validity window, remaining days until expiration, hostname matching (SAN and Common Name), certificate chain verification, and trusted public Certificate Authority identification.
- **Key Interpretation Principle**: *HTTPS encrypts your connection, but it does not guarantee that a website is legitimate.* Free domain-validation (DV) certificates from automated authorities (e.g., Let's Encrypt) are standard industry practice and are never classified as fraudulent solely because they are free. DV certificates verify domain control, not legal business identity.
- **Honest Statuses**: Valid & Trusted, Expired, Hostname Mismatch, Self-Signed, Untrusted Root, Unencrypted HTTP, Unable to Verify.

### Feature 2: Real-Time Threat Intelligence & Blocklists (`app/scanner/reputation.py`)
- **Capability**: Cross-checks URLs, domains, and resolved IP addresses against reputable threat feeds.
- **Integrations**:
  - **abuse.ch URLhaus** (Open Threat API — Zero Configuration, No API Key Required)
  - **Google Safe Browsing API v4** (Configurable via `GOOGLE_SAFE_BROWSING_API_KEY`)
  - **VirusTotal v3 URL API** (Configurable via `VIRUSTOTAL_API_KEY`)
  - **AbuseIPDB IP Reputation API** (Configurable via `ABUSEIPDB_API_KEY`)
- **Strict Distinction**: Explicitly differentiates *Confirmed Threat Detection*, *Clean (No Detection)*, *Not Configured*, *Check Unavailable*, and *Rate Limited*. A missing or failed check is never reported as clean.
- **Key Principle**: *An absence of threat intelligence detections does not guarantee that a website is safe.*

### Feature 3: Password and Sensitive Input Auditing (`app/scanner/html_inspector.py`)
- **Capability**: Static, non-executing HTML parser using Python's standard library. Audits forms without executing JavaScript or interacting with buttons.
- **Checks**: Password inputs, login/email fields, payment/financial inputs (credit card, CVV, bank details), form submission action destinations (`action` URL), method (`POST`/`GET`), and HTTP vs HTTPS transport.
- **Cross-Origin Detection**: Detects when form action points to an external, third-party domain.
- **Contextual Risk Interpretation**: Password fields on established banking or web platforms are standard. Concern is raised when credential fields coincide with newly registered domains, external form submission targets, or unencrypted HTTP transport. Cyclops never collects, stores, or transmits actual user credentials.

### Feature 4: Dangerous Download and Hidden File Extension Detection (`app/scanner/download_detector.py`)
- **Capability**: Evaluates HTTP response headers (`Content-Disposition`, `Content-Type`), final URL paths, and a strictly size-limited initial response body prefix (1 KB) for magic byte file signatures.
- **Checks**:
  - File download vs standard HTML webpage
  - Server-reported filename extraction (RFC 6266 / RFC 5987)
  - Effective file extensions (case-insensitive, URL-decoded)
  - Double extension attacks (e.g., `invoice.pdf.exe`, `statement.docx.vbs`)
  - Executable/script formats (`.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.dll`, `.msi`)
  - Magic byte file signature assessment: Windows PE (`MZ`), Linux (`ELF`), Mach-O, PDF (`%PDF-`), ZIP/Office (`PK\x03\x04`), 7-Zip (`7z`), RAR (`Rar!`), OLE2 documents.
  - Disguise/mismatch warnings: flags when a file claims to be a benign document (e.g. PDF) but server headers or magic bytes reveal an executable binary.
- **Safety Boundaries**: Files are never executed, decompressed, or downloaded to user devices.

### Feature 5: Hosting Provider and Infrastructure Footprint (`app/scanner/dns_intelligence.py`)
- **Capability**: Gathers passive network and hosting telemetry for target domains and IPs.
- **Checks**: Forward DNS resolution (A, AAAA records), Reverse DNS (PTR record via `socket.gethostbyaddr`), Hosting / Network Organization, ASN, ISP, approximate IP geolocation (city, region, country), and CDN/reverse-proxy indicators (Cloudflare, AWS, Fastly, Akamai).
- **Domain Registration**: Authoritative domain age, created date, and accredited registrar via ICANN RDAP.
- **Contextual Note**: Hosting on AWS, Google Cloud, Microsoft Azure, or a CDN does not establish trustworthiness or malicious intent. Geolocation reflects network routing points rather than the website owner's legal address.

### Feature 6: Trustworthy Agency and Security Authority Audit (`app/scanner/reputation.py`)
- **Capability**: Transparent security authority checklist displaying the evaluation results across recognized authorities:
  - abuse.ch URLhaus (URL Malware Feed)
  - Google Safe Browsing (Social Engineering & Malware Feed)
  - VirusTotal Intelligence (Multi-Engine Aggregator Feed)
  - AbuseIPDB (IP Reputation & Abuse)
  - TLS Root Store Authority (Cryptographic Trust)
  - ICANN / Regional Internet Registries (Domain Registration & Age)
- **Distinct Statuses**: Threat Reported, No Threat Reported, Not Configured, Check Unavailable, Not Applicable.
- **Ethical Reporting**: Clearly distinguishes verified threats from missing evidence. Never fabricates certifications, endorsements, or law enforcement investigations.

---

## 2. SSRF and Network Security Guardrails

The URL scanner implements multi-layered protections against Server-Side Request Forgery (SSRF) in `app/scanner/ssrf.py`:
- Blocks loopback (`127.0.0.0/8`, `::1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.0.0/16`), multicast, CGNAT (`100.64.0.0/10`), documentation IPs, and IPv4-mapped IPv6.
- Enforces DNS pre-flight validation and re-validates destination IPs at **every single redirect hop**.
- Enforces strict hop limits (max 6 redirects) and timeouts (4s connect, 5s read).
- Strict response prefix limits (max 512 KB) to prevent memory exhaustion and decompression bombs.

---

## 3. Configuration & API Keys

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### Zero-Configuration Feeds (Works Without Any API Keys)
The following checks function out of the box with zero credentials:
1. **SSL/TLS Certificate Intelligence** (Direct TLS socket query)
2. **abuse.ch URLhaus Threat Intelligence** (Open Public Threat API)
3. **Password & Sensitive Input Auditing** (Non-executing static HTML parser)
4. **Dangerous Download & Disguised Extension Detection** (Prefix & header inspection)
5. **Hosting, ASN, Reverse DNS & Geolocation Footprint** (IP-API open telemetry)
6. **ICANN RDAP Domain Registration & Age** (Public RDAP servers)

### Optional Provider API Keys
If you have API keys, add them to `backend/.env`:
- `VIRUSTOTAL_API_KEY`: VirusTotal v3 API (Free tier: 4 req/min, 500 req/day).
- `ABUSEIPDB_API_KEY`: AbuseIPDB v2 API (Free tier: 1,000 checks/day).
- `GOOGLE_SAFE_BROWSING_API_KEY`: Google Safe Browsing v4 (Free tier: 10,000 req/day).

If left blank, Cyclops marks these providers as **Not configured** in the UI and checklist without crashing or fabricating results.

---

## 4. Running Backend Tests

Run all unit and integration tests using pytest:

```powershell
backend\.venv\Scripts\python.exe -m pytest
```

Run URL security scanner tests specifically:

```powershell
backend\.venv\Scripts\python.exe -m pytest backend/tests/test_advanced_features.py backend/tests/test_url_scanner.py
```

---

## 5. Running the Application

### Start Backend:
```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Start Frontend:
```powershell
npm run dev
```
Visit `http://localhost:3000/url-scanner` in your browser.
