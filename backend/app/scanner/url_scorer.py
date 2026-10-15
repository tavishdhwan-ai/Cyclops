"""
Explainable multi-signal risk scoring and evidence aggregator for Cyclops Website URL Scanner.

Combines:
1. URL syntax & hostname heuristics (homographs, raw IP, sensitive path terms, shorteners)
2. Domain age & registration evidence (RDAP)
3. Infrastructure & Network observations (SSRF, cloud hosting, DNS)
4. Redirect behavior (downgrades, cross-domain redirects, loops)
5. Static HTML observations (password fields, credential harvesting text, external form actions)
6. Reputation providers (VirusTotal, Google Safe Browsing, AbuseIPDB)

Separates observed facts from risk interpretations.
Never classifies a site as verified safe merely because external checks were unknown.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.scanner.url_validator import NormalizedUrl
from app.scanner.ssrf import SafeFetchResult
from app.scanner.dns_intelligence import DnsIntelligence, HostingIntelligence
from app.scanner.rdap import DomainRegistrationInfo
from app.scanner.html_inspector import StaticContentAnalysis
from app.scanner.reputation import ProviderResult


class SecuritySignal(BaseModel):
    id: str
    category: str  # "url_heuristics", "redirects", "domain_age", "network", "page_content", "threat_intel"
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
    timestamp: str
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
                # Established domain (> 2 years)
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

    # 4. Static Page Content Inspection
    if html_info.has_password_input and html_info.has_external_form_action:
        signals.append(SecuritySignal(
            id="credential_theft_external_post",
            category="page_content",
            severity="critical",
            title="Credential Form Submitting to External Domain",
            description="The page renders a password input form whose action destination submits data to an external host.",
            weight=3.5
        ))
        risks.append("CRITICAL: Password form transmits credentials to an external destination.")
    elif html_info.has_password_input and norm.scheme == "http":
        signals.append(SecuritySignal(
            id="insecure_password_form",
            category="page_content",
            severity="high",
            title="Insecure Password Input on Plain HTTP",
            description="The page solicits passwords over unencrypted HTTP, exposing credentials in cleartext.",
            weight=2.5
        ))
        risks.append("Password input detected over an unencrypted connection.")

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

    # 5. Reputation Providers
    for prov in providers:
        if prov.status == "malicious_found":
            signals.append(SecuritySignal(
                id=f"intel_{prov.provider_name.lower().replace(' ', '_')}",
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

    # 6. Aggregate Threat Score with Category Caps
    cat_weights: Dict[str, float] = {}
    for sig in signals:
        cat_weights[sig.category] = cat_weights.get(sig.category, 0.0) + sig.weight

    # Category caps
    caps = {
        "url_heuristics": 3.0,
        "redirects": 3.0,
        "domain_age": 3.0,
        "network": 2.5,
        "page_content": 4.0,
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

    if has_critical or final_score >= 7.5:
        risk_level = "CRITICAL"
        verdict = "malicious"
        summary = "Severe security threat detected. Active phishing or malicious infrastructure indicators present."
        recommendation = "DO NOT visit this destination, enter credentials, or download attachments. Block network traffic immediately."
    elif has_high or final_score >= 5.0:
        risk_level = "HIGH"
        verdict = "phishing" if (html_info.has_password_input or norm.has_homograph_chars) else "suspicious"
        summary = "High-risk indicators identified. URL exhibits structural or credential harvesting anomalies."
        recommendation = "Exercise extreme caution. Do not input authentication credentials until verified through independent out-of-band channels."
    elif final_score >= 2.5 or len(signals) > 0:
        risk_level = "MEDIUM"
        verdict = "suspicious"
        summary = f"Identified {len(signals)} moderate risk indicator(s). Review findings before proceeding."
        recommendation = "Proceed with caution. Verify that the destination domain matches the intended organization."
    else:
        risk_level = "LOW"
        verdict = "clean"
        summary = "No anomalous phishing, redirect, or domain threats identified during passive analysis."
        recommendation = "URL appears consistent with normal web properties. Maintain standard web browsing hygiene."

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
        timestamp=timestamp
    )
