import pytest
from app.scanner.urls import analyze_urls
from app.schemas import EmailScanRequest
from app.scanner import analyze_demo_email


def test_1_normal_https_url():
    """1. Normal HTTPS URL -> no suspicious URL finding."""
    findings = analyze_urls(["https://example.com"])
    assert len(findings) == 0


def test_2_http_url():
    """2. HTTP URL -> unencrypted HTTP signal."""
    findings = analyze_urls(["http://example.com"])
    types = [f.type for f in findings]
    assert "http_unencrypted" in types
    finding = next(f for f in findings if f.type == "http_unencrypted")
    assert finding.severity == "medium"
    assert "HTTP instead of HTTPS" in finding.explanation


def test_3_ipv4_url():
    """3. IPv4 URL -> IP-address finding."""
    findings = analyze_urls(["http://192.0.2.10/login"])
    types = [f.type for f in findings]
    assert "ip_address_url" in types
    finding = next(f for f in findings if f.type == "ip_address_url")
    assert finding.severity == "high"
    assert finding.evidence["hostname"] == "192.0.2.10"


def test_4_ipv6_url():
    """4. IPv6 URL -> correct parsing & IP-address finding."""
    findings = analyze_urls(["http://[2001:db8::1]/login"])
    types = [f.type for f in findings]
    assert "ip_address_url" in types
    finding = next(f for f in findings if f.type == "ip_address_url")
    assert finding.severity == "high"


def test_5_non_standard_port():
    """5. Non-standard port -> non-standard port signal."""
    findings = analyze_urls(["https://example.com:8443/login"])
    types = [f.type for f in findings]
    assert "non_standard_port" in types
    finding = next(f for f in findings if f.type == "non_standard_port")
    assert finding.evidence["port"] == 8443


def test_6_standard_https_port():
    """6. Standard HTTPS port (443) -> no non-standard-port finding."""
    findings = analyze_urls(["https://example.com:443/login"])
    types = [f.type for f in findings]
    assert "non_standard_port" not in types


def test_7_userinfo_at_trick():
    """7. @ trick -> userinfo/@ finding, actual hostname = evil.example."""
    findings = analyze_urls(["https://trusted.example@evil.example/login"])
    types = [f.type for f in findings]
    assert "userinfo_url_trick" in types
    finding = next(f for f in findings if f.type == "userinfo_url_trick")
    assert finding.severity == "high"
    assert finding.evidence["hostname"] == "evil.example"
    assert finding.evidence["userinfo"] == "trusted.example"


def test_8_deep_subdomain():
    """8. Deep subdomain -> deep subdomain signal."""
    findings = analyze_urls(["https://a.b.c.d.example.com/login"])
    types = [f.type for f in findings]
    assert "deep_subdomain_structure" in types
    finding = next(f for f in findings if f.type == "deep_subdomain_structure")
    assert finding.evidence["subdomain_count"] >= 4


def test_9_normal_subdomain():
    """9. Normal subdomain -> no deep subdomain finding."""
    findings = analyze_urls(["https://mail.example.com"])
    types = [f.type for f in findings]
    assert "deep_subdomain_structure" not in types


def test_10_very_long_url():
    """10. Very long URL -> long-URL signal when threshold exceeded."""
    long_path = "a" * 160
    findings = analyze_urls([f"https://example.com/{long_path}"])
    types = [f.type for f in findings]
    assert "excessive_url_length" in types


def test_11_normal_encoded_url():
    """11. Normal encoded URL -> no heavy encoding finding."""
    findings = analyze_urls(["https://example.com/search?q=hello%20world"])
    types = [f.type for f in findings]
    assert "heavy_url_encoding" not in types


def test_12_heavily_encoded_url():
    """12. Heavily encoded URL -> encoding finding."""
    findings = analyze_urls(["https://example.com/%2F%3A%40%2E%255C%2F%3A"])
    types = [f.type for f in findings]
    assert "heavy_url_encoding" in types


def test_13_redirect_parameter():
    """13. Redirect parameter -> redirect parameter finding."""
    findings = analyze_urls(["https://example.com/login?redirect=https://other.example"])
    types = [f.type for f in findings]
    assert "suspicious_redirect_parameter" in types
    finding = next(f for f in findings if f.type == "suspicious_redirect_parameter")
    assert "redirect" in finding.evidence["parameter_names"]
    # Ensure parameter value 'https://other.example' is NOT exposed in evidence parameter_names
    assert "https://other.example" not in finding.evidence["parameter_names"]


def test_14_credential_path():
    """14. Credential path -> credential path signal."""
    findings = analyze_urls(["https://example.com/account/login"])
    types = [f.type for f in findings]
    assert "credential_path_signal" in types


def test_15_url_shortener():
    """15. URL shortener -> shortener finding."""
    findings = analyze_urls(["https://bit.ly/example"])
    types = [f.type for f in findings]
    assert "url_shortener" in types
    finding = next(f for f in findings if f.type == "url_shortener")
    assert finding.evidence["hostname"] == "bit.ly"


def test_16_punycode():
    """16. Punycode -> internationalized domain finding."""
    findings = analyze_urls(["https://xn--example-domain.test"])
    types = [f.type for f in findings]
    assert "internationalized_domain" in types


def test_17_visible_text_mismatch():
    """17. Visible link text mismatch -> visible text differs from href -> mismatch finding."""
    link_details = [{"text": "https://microsoft.com", "href": "https://example.xyz/login"}]
    findings = analyze_urls(links=[], link_details=link_details)
    types = [f.type for f in findings]
    assert "visible_link_mismatch" in types
    finding = next(f for f in findings if f.type == "visible_link_mismatch")
    assert finding.severity == "high"
    assert finding.evidence["visible_domain"] == "microsoft.com"
    assert finding.evidence["destination_domain"] == "example.xyz"


def test_18_lookalike_brand_domain():
    """18. Lookalike brand domain (paypa1.com) -> lookalike domain finding."""
    findings = analyze_urls(["https://paypa1.com/login"])
    types = [f.type for f in findings]
    assert "lookalike_domain" in types
    finding = next(f for f in findings if f.type == "lookalike_domain")
    assert finding.severity == "high"


def test_19_legitimate_brand_domain():
    """19. Legitimate brand domain (paypal.com) -> no lookalike domain finding."""
    findings = analyze_urls(["https://paypal.com/login"])
    types = [f.type for f in findings]
    assert "lookalike_domain" not in types


def test_20_combined_suspicious_url():
    """20. Combined suspicious URL -> multiple findings, deduplicated, score <= 10.0."""
    combined_url = "http://paypa1.com:8080/account/login?redirect=https://evil.test"
    req = EmailScanRequest(
        sender="Alert <alert@paypa1.com>",
        subject="Urgent Security Alert",
        body="Please click the link to verify your account.",
        links=[combined_url]
    )
    res = analyze_demo_email(req)
    assert res.status == "completed"
    assert 0.0 <= res.threat_score <= 10.0
    assert res.risk_level in ["HIGH", "CRITICAL"]

    url_findings = [f for f in res.findings if f.category == "urls"]
    assert len(url_findings) >= 2


def test_21_malformed_url():
    """21. Malformed URL -> scanner handles safely without crashing."""
    findings = analyze_urls(["ht://invalid_url_###", "not-a-valid-url"])
    assert isinstance(findings, list)
