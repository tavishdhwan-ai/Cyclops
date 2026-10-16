"""
Explainable multi-signal risk scoring and evidence aggregator for Cyclops Website URL Scanner.

Combines:
1. URL syntax & hostname heuristics (homographs, raw IP, sensitive path terms, shorteners)
2. Domain age & registration evidence (RDAP)
3. Infrastructure & Network footprint (SSRF, cloud hosting, DNS, Reverse DNS)
4. Redirect behavior (downgrades, cross-domain redirects, loops)
5. Static HTML observations (password fields, credential harvesting text, external form actions)
6. Feature 1: SSL/TLS Certificate Intelligence
7. Feature 2: Real-time Threat Intelligence Adapters (URLhaus, GSB, VT, AbuseIPDB)
8. Feature 3: Password and Sensitive Input Auditing
9. Feature 4: Dangerous Download and Disguised Extension Detection
10. Feature 5: Hosting Provider and Infrastructure Footprint
11. Feature 6: Security Authority Checklist

Separates observed facts from risk interpretations.
Never classifies a site as verified safe merely because external checks were unknown.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.scanner.url_validator import NormalizedUrl
from app.scanner.ssrf import SafeFetchResult
from app.scanner.dns_intelligence import DnsIntelligence, HostingIntelligence
from app.scanner.rdap import DomainRegistrationInfo
from app.scanner.html_inspector import StaticContentAnalysis, SensitiveInputAudit
from app.scanner.reputation import ProviderResult, SecurityAuthorityChecklist
from app.scanner.ssl_inspector import SslCertificateIntelligence
from app.scanner.download_detector import DownloadSafetyResult


class SecuritySignal(BaseModel):
    id: str
    category: str  # "url_heuristics", "redirects", "domain_age", "network", "page_content", "threat_intel", "ssl_certificate", "download_safety"
    severity: str  # "low", "medium", "high", "critical", "info"
    title: str
    description: str
    is_positive: bool = False  # True if evidence provides reassurance/lowers uncertainty
    weight: float = 0.0


class AggregatedUrlReport(BaseModel):
    id: str
    submitted_url: str
    normalized_url: str
    sanitized_display_url: str
    verdict: str  # "clean", "suspicious", "phishing", "malicious", "unknown"
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
    threat_score: float  # 0.0 to 10.0 continuous decimal index
    summary: str
    plain_english_explanation: str
    recommended_action: str
    reassuring_factors: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    missing_data_notes: List[str] = Field(default_factory=list)
    signals: List[SecuritySignal] = Field(default_factory=list)

    # Modular Evidence Sub-sections
    normalization: NormalizedUrl
    redirect_analysis: SafeFetchResult
    dns_intelligence: DnsIntelligence
    hosting_intelligence: HostingIntelligence
    domain_registration: DomainRegistrationInfo
    page_content: StaticContentAnalysis
    reputation_providers: List[ProviderResult] = Field(default_factory=list)

    # Six Advanced URL Security Features
    ssl_certificate: Optional[SslCertificateIntelligence] = None
    sensitive_input_audit: Optional[SensitiveInputAudit] = None
    download_safety: Optional[DownloadSafetyResult] = None
    hosting_footprint: Optional[HostingIntelligence] = None
    security_authority_checklist: Optional[SecurityAuthorityChecklist] = None

    timestamp: str


def compute_url_risk_report(
    scan_id: str,
    norm: NormalizedUrl,
    fetch_result: SafeFetchResult,
    dns_info: DnsIntelligence,
    hosting_info: HostingIntelligence,
    rdap_info: DomainRegistrationInfo,
    html_info: StaticContentAnalysis,
    providers: List[ProviderResult],
    timestamp: str,
    ssl_info: Optional[SslCertificateIntelligence] = None,
    download_info: Optional[DownloadSafetyResult] = None,
    authority_checklist: Optional[SecurityAuthorityChecklist] = None
) -> AggregatedUrlReport:
    """
    Computes explainable risk assessment based on genuine collected evidence.
    """
    signals: List[SecuritySignal] = []
    reassuring: List[str] = []
    risks: List[str] = []
    missing: List[str] = []

    base_score = 0.5  # Baseline

    # 1. Evaluate URL and Hostname Heuristics
    if norm.has_homograph_chars:
        signals.append(SecuritySignal(
            id="homograph_detected",
            category="url_heuristics",
            severity="high",
            title="Potential Homograph / Confusable Domain Attack",
            description=f"Hostname contains Unicode confusable characters: {'; '.join(norm.homograph_details[:2])}",
            weight=2.5
        ))
        risks.append("Contains lookalike Unicode characters resembling legitimate Latin domain characters.")

    if norm.is_ip:
        signals.append(SecuritySignal(
            id="raw_ip_host",
            category="url_heuristics",
            severity="medium",
            title="Direct IP Address Host",
            description=f"URL directs to a numerical IP address ({norm.ascii_hostname}) rather than a registered domain name.",
            weight=1.5
        ))
        risks.append(f"Uses a raw IP address ({norm.ascii_hostname}) instead of a verifiable domain.")

    if norm.credentials_detected:
        signals.append(SecuritySignal(
            id="embedded_credentials",
            category="url_heuristics",
            severity="medium",
            title="Embedded Authentication Credentials",
            description="URL contained user authentication credentials in the network authority segment.",
            weight=1.5
        ))
        risks.append("Contains embedded user authentication tokens or credentials in the URL structure.")

    if norm.is_shortener:
        signals.append(SecuritySignal(
            id="url_shortener",
            category="url_heuristics",
            severity="medium",
            title="URL Shortening Service",
            description=f"The domain {norm.ascii_hostname} is an intermediary URL shortener that masks the true destination.",
            weight=1.5
        ))
        risks.append("URL shortener used to conceal final destination.")

    # 2. Redirect Analysis
    has_downgrade = any(h.scheme_downgraded for h in fetch_result.redirect_chain)
    if has_downgrade:
        signals.append(SecuritySignal(
            id="scheme_downgrade",
            category="redirects",
            severity="high",
            title="HTTPS to Insecure HTTP Downgrade",
            description="The redirect chain downgraded from an encrypted HTTPS connection to unencrypted HTTP.",
            weight=2.5
        ))
        risks.append("Security downgrade: Redirects from HTTPS to unencrypted plain HTTP.")

    cross_domain_hops = [h for h in fetch_result.redirect_chain if h.hostname_changed]
    if cross_domain_hops:
        signals.append(SecuritySignal(
            id="cross_domain_redirect",
            category="redirects",
            severity="medium",
            title="Cross-Domain Redirection",
            description=f"The URL redirects across different hostnames ({len(cross_domain_hops)} time(s)).",
            weight=1.0
        ))
        risks.append(f"Redirects across distinct domains to {fetch_result.final_url}.")

    if fetch_result.error and "Too many redirects" in fetch_result.error:
        signals.append(SecuritySignal(
            id="redirect_limit_exceeded",
            category="redirects",
            severity="medium",
            title="Redirect Limit Exceeded",
            description="Analysis stopped because the URL exceeded the maximum hop threshold (possible loop or cloaking).",
            weight=1.5
        ))
        risks.append("Excessive redirects detected (possible redirect loop or bot evasion).")

    # 3. Domain Registration (RDAP)
    if rdap_info.status == "live":
        if rdap_info.domain_age_days is not None:
            if rdap_info.domain_age_days < 14:
                signals.append(SecuritySignal(
                    id="very_new_domain",
                    category="domain_age",
                    severity="high",
                    title="Recently Registered Domain (< 14 days)",
                    description=f"Domain was registered only {rdap_info.domain_age_days} day(s) ago ({rdap_info.created_date}).",
                    weight=2.5
                ))
                risks.append(f"Domain registered extremely recently ({rdap_info.domain_age_days} days ago).")
            elif rdap_info.domain_age_days < 60:
                signals.append(SecuritySignal(
                    id="young_domain",
                    category="domain_age",
                    severity="medium",
                    title="Young Domain (< 60 days)",
                    description=f"Domain was registered {rdap_info.domain_age_days} days ago ({rdap_info.created_date}).",
                    weight=1.0
                ))
                risks.append(f"Domain is relatively new ({rdap_info.domain_age_days} days old).")
            elif rdap_info.domain_age_days > 730:
                signals.append(SecuritySignal(
                    id="established_domain",
                    category="domain_age",
                    severity="info",
                    title="Established Domain Registration",
                    description=f"Domain has been registered for {rdap_info.domain_age_days // 365} year(s) ({rdap_info.created_date}).",
                    is_positive=True,
                    weight=-0.5
                ))
                reassuring.append(f"Domain is well-established ({rdap_info.domain_age_days // 365}+ years old).")
    elif rdap_info.status in ("unavailable", "skipped", "not_found"):
        missing.append(f"Domain registration details (RDAP): {rdap_info.error or 'Data unavailable'}")

    # 4. Feature 1: SSL/TLS Certificate Intelligence
    if ssl_info:
        if ssl_info.status == "expired":
            signals.append(SecuritySignal(
                id="ssl_expired",
                category="ssl_certificate",
                severity="high",
                title="Expired SSL/TLS Certificate",
                description="The server presents an expired certificate. Encrypted communication cannot be verified.",
                weight=2.5
            ))
            risks.append("Expired TLS certificate presented by server.")
        elif ssl_info.status == "hostname_mismatch":
            signals.append(SecuritySignal(
                id="ssl_hostname_mismatch",
                category="ssl_certificate",
                severity="high",
                title="Certificate Hostname Mismatch",
                description=f"Certificate names do not match target hostname '{ssl_info.hostname}'.",
                weight=2.5
            ))
            risks.append(f"Certificate hostname mismatch ({ssl_info.hostname}).")
        elif ssl_info.status == "self_signed":
            signals.append(SecuritySignal(
                id="ssl_self_signed",
                category="ssl_certificate",
                severity="medium",
                title="Self-Signed Certificate",
                description="Server certificate was self-signed and not issued by a publicly trusted root CA.",
                weight=1.5
            ))
            risks.append("Self-signed TLS certificate in use.")
        elif ssl_info.status == "unencrypted_http":
            signals.append(SecuritySignal(
                id="unencrypted_http_connection",
                category="ssl_certificate",
                severity="medium",
                title="Unencrypted HTTP Protocol",
                description="Target website operates over unencrypted HTTP without TLS transport security.",
                weight=1.5
            ))
            risks.append("Unencrypted HTTP in use (no TLS certificate).")
        elif ssl_info.status == "valid":
            reassuring.append(f"Valid TLS certificate issued by {ssl_info.issuer} matching hostname.")
    else:
        missing.append("TLS certificate verification was not evaluated.")

    # 5. Feature 3: Static Page Content & Sensitive Input Auditing
    sensitive_audit = html_info.sensitive_input_audit
    if sensitive_audit:
        if sensitive_audit.cross_origin_submission_detected:
            signals.append(SecuritySignal(
                id="cross_origin_form_submission",
                category="page_content",
                severity="critical",
                title="Cross-Origin Form Submission",
                description="Input form transmits credentials or data to an external third-party domain.",
                weight=3.5
            ))
            risks.append("Form inputs submit data across origins to a third-party host.")
        if sensitive_audit.submits_over_insecure_http:
            signals.append(SecuritySignal(
                id="insecure_http_form_action",
                category="page_content",
                severity="high",
                title="Form Submitting Over Insecure HTTP",
                description="Form action endpoint submits sensitive inputs over plaintext HTTP.",
                weight=2.5
            ))
            risks.append("Form action submits credentials over unencrypted HTTP.")
        if sensitive_audit.password_fields_detected > 0:
            if not sensitive_audit.is_https_page:
                risks.append("Password input detected on an unencrypted page.")
            elif rdap_info.is_recently_registered:
                signals.append(SecuritySignal(
                    id="password_on_new_domain",
                    category="page_content",
                    severity="high",
                    title="Password Field on New Domain",
                    description="Password input field detected on a newly registered or unverified domain.",
                    weight=2.0
                ))
                risks.append("Password entry requested on a recently registered domain.")
            else:
                reassuring.append("Login password form detected over HTTPS with consistent domain actions.")

    # Check for credential harvesting text
    if html_info.has_credential_harvesting_terms and (rdap_info.is_recently_registered or norm.is_ip):
        signals.append(SecuritySignal(
            id="phishing_landing_signature",
            category="page_content",
            severity="high",
            title="Credential Phishing Characteristics",
            description=f"New domain/IP displaying sensitive authentication terms: {', '.join(html_info.matched_phrases[:3])}",
            weight=2.5
        ))
        risks.append("Sensitive account login prompts detected on a newly established or raw-IP host.")

    # 6. Feature 4: Dangerous Download and Disguised Extension Detection
    if download_info and download_info.is_download:
        if download_info.mismatch_detected:
            signals.append(SecuritySignal(
                id="disguised_file_payload",
                category="download_safety",
                severity="critical",
                title="Deceptive Download / Disguised File Extension",
                description=download_info.warning or "File extension claims benign document format, but server or magic bytes indicate executable payload.",
                weight=4.0
            ))
            risks.append(download_info.warning or "Deceptive file download: executable disguised as document.")
        elif download_info.has_double_extension:
            signals.append(SecuritySignal(
                id="double_extension_download",
                category="download_safety",
                severity="critical",
                title="Double Extension Detected",
                description=f"Deceptive double extension on downloadable file: '{download_info.server_reported_filename}'.",
                weight=3.5
            ))
            risks.append(f"Downloadable file has a disguised double extension ({download_info.server_reported_filename}).")
        elif download_info.is_executable_or_script:
            signals.append(SecuritySignal(
                id="executable_download",
                category="download_safety",
                severity="high",
                title="Executable Binary / Script Download",
                description=f"URL delivers an executable file or script ({download_info.server_reported_filename or download_info.effective_extension}).",
                weight=2.5
            ))
            risks.append(f"Delivers an executable binary/script ({download_info.server_reported_filename or download_info.effective_extension}).")
        else:
            reassuring.append(f"Downloadable file detected ({download_info.server_reported_filename or 'file'}), no disguised extension.")
    elif download_info and not download_info.is_download:
        reassuring.append("Target returns standard HTML webpage content. No file download was initiated.")

    # 7. Feature 2: Reputation Providers
    for prov in providers:
        if prov.status == "malicious_found":
            signals.append(SecuritySignal(
                id=f"intel_{prov.provider_name.lower().replace(' ', '_').replace('.', '_')}",
                category="threat_intel",
                severity="critical",
                title=f"Flagged by {prov.provider_name}",
                description=prov.threat_details or "Confirmed malicious threat indicator by security intelligence provider.",
                weight=3.5
            ))
            risks.append(f"Flagged as malicious by {prov.provider_name}.")
        elif prov.status == "clean":
            reassuring.append(f"No threat indicators reported by {prov.provider_name}.")
        elif prov.status in ("not_configured", "unavailable", "rate_limited"):
            missing.append(f"{prov.provider_name}: {prov.error_message or 'Provider unavailable'}")

    # 8. Aggregate Threat Score with Category Caps
    cat_weights: Dict[str, float] = {}
    for sig in signals:
        cat_weights[sig.category] = cat_weights.get(sig.category, 0.0) + sig.weight

    caps = {
        "url_heuristics": 3.0,
        "redirects": 3.0,
        "domain_age": 3.0,
        "network": 2.5,
        "page_content": 4.0,
        "ssl_certificate": 3.0,
        "download_safety": 4.5,
        "threat_intel": 5.0,
    }

    total_added = 0.0
    for cat, val in cat_weights.items():
        cap = caps.get(cat, 3.5)
        total_added += min(val, cap)

    raw_threat_score = base_score + total_added
    final_score = round(min(10.0, max(0.0, raw_threat_score)), 1)

    # Determine Risk Level & Verdict
    has_critical = any(s.severity == "critical" for s in signals)
    has_high = any(s.severity == "high" for s in signals)

    risk_signals = [s for s in signals if not s.is_positive and s.severity in ("low", "medium", "high", "critical")]

    if has_critical or final_score >= 7.5:
        risk_level = "CRITICAL"
        verdict = "malicious"
        summary = "Severe security threat detected. Active phishing, malicious download, or threat intelligence detections present."
        recommendation = "DO NOT visit this destination, enter credentials, or open downloads. Block network access immediately."
    elif has_high or final_score >= 5.0:
        risk_level = "HIGH"
        verdict = "phishing" if (html_info.has_password_input or norm.has_homograph_chars) else "suspicious"
        summary = "High-risk indicators identified. URL exhibits structural, download, or credential harvesting anomalies."
        recommendation = "Exercise extreme caution. Do not input authentication credentials until verified through independent out-of-band channels."
    elif final_score >= 2.5 or len(risk_signals) > 0:
        risk_level = "MEDIUM"
        verdict = "suspicious"
        summary = f"Identified {len(risk_signals)} moderate risk indicator(s). Review evidence before proceeding."
        recommendation = "Proceed with caution. Verify that the destination domain matches the intended organization."
    else:
        risk_level = "LOW"
        verdict = "clean"
        summary = "No anomalous phishing, redirect, certificate, or download threats identified during passive analysis."
        recommendation = "URL appears consistent with standard web properties. Maintain standard web browsing hygiene."

    # Plain English explanation synthesis
    parts = []
    if risks:
        parts.append(f"Risk indicators identified: {'; '.join(risks[:3])}.")
    if reassuring:
        parts.append(f"Reassuring evidence: {'; '.join(reassuring[:2])}.")
    if missing:
        parts.append(f"Note: Certain checks were incomplete or unconfigured ({len(missing)} item(s)), so results reflect available passive data only.")

    plain_english = " ".join(parts) if parts else "No elevated security concerns detected."

    return AggregatedUrlReport(
        id=scan_id,
        submitted_url=norm.raw_input,
        normalized_url=norm.normalized_url,
        sanitized_display_url=norm.sanitized_display_url,
        verdict=verdict,
        risk_level=risk_level,
        threat_score=final_score,
        summary=summary,
        plain_english_explanation=plain_english,
        recommended_action=recommendation,
        reassuring_factors=reassuring,
        risk_factors=risks,
        missing_data_notes=missing,
        signals=signals,
        normalization=norm,
        redirect_analysis=fetch_result,
        dns_intelligence=dns_info,
        hosting_intelligence=hosting_info,
        domain_registration=rdap_info,
        page_content=html_info,
        reputation_providers=providers,
        ssl_certificate=ssl_info,
        sensitive_input_audit=sensitive_audit,
        download_safety=download_info,
        hosting_footprint=hosting_info,
        security_authority_checklist=authority_checklist,
        timestamp=timestamp
    )
