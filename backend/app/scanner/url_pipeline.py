"""
High-level Orchestrator for Cyclops Website URL Scanner Pipeline.
Executes full asynchronous URL inspection workflow:
1. Normalization & Input Validation
2. SSRF Check & DNS Resolution
3. Concurrent Bounded Execution:
   - Passive RDAP Domain Registration Analysis
   - Safe Multi-hop Redirect Inspection & Static HTML Fetching
   - SSL/TLS Certificate Intelligence Inspection (Feature 1)
   - IP Geolocation, Reverse DNS, and Network/Hosting Footprint (Feature 5)
   - Real-time Threat Intelligence Adapters: URLhaus, GSB, VT, AbuseIPDB (Feature 2)
4. Dangerous Download & Hidden File Extension Assessment (Feature 4)
5. Static Read-Only HTML & Sensitive Input Auditing (Feature 3)
6. Security Authority Audit Checklist Synthesis (Feature 6)
7. Multi-Signal Scoring and Report Synthesis
"""
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional, List

from app.scanner.url_validator import normalize_and_validate_url
from app.scanner.ssrf import safe_fetch_url, SafeFetchResult
from app.scanner.dns_intelligence import resolve_domain_dns, lookup_ip_hosting_intelligence, HostingIntelligence
from app.scanner.rdap import lookup_domain_rdap, DomainRegistrationInfo
from app.scanner.html_inspector import analyze_static_html
from app.scanner.reputation import (
    check_urlhaus,
    check_google_safe_browsing,
    check_virustotal,
    check_abuseipdb,
    synthesize_authority_checklist,
    ProviderResult
)
from app.scanner.ssl_inspector import inspect_tls_certificate, SslCertificateIntelligence
from app.scanner.download_detector import evaluate_download_safety, DownloadSafetyResult
from app.scanner.url_scorer import compute_url_risk_report, AggregatedUrlReport


async def orchestrate_url_scan(raw_url: str) -> AggregatedUrlReport:
    """
    Executes the comprehensive, passive, SSRF-protected URL scan pipeline.
    Runs independent network checks concurrently with bounded timeouts.
    Never fails the whole scan if a single provider or network check is unavailable.
    """
    scan_id = f"url-scan-{uuid.uuid4().hex[:8]}"
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Normalize and Validate URL syntax
    norm = normalize_and_validate_url(raw_url)

    # 2. DNS Intelligence (Forward resolution)
    dns_info = resolve_domain_dns(norm.ascii_hostname)

    # Determine primary resolved IP safely
    primary_ip = dns_info.resolved_ips[0] if dns_info.resolved_ips else None

    # Determine if destination is a private/internal network address
    is_internal_dest = norm.is_private_ip or norm.is_loopback or norm.is_link_local or norm.is_reserved

    # 3. Prepare Concurrent Tasks for independent network operations
    # Task A: RDAP Domain Registration
    async def _fetch_rdap() -> DomainRegistrationInfo:
        if norm.is_ip:
            return DomainRegistrationInfo(
                domain=norm.ascii_hostname,
                status="skipped",
                error="Target is an IP address; domain registration lookups do not apply."
            )
        parts = norm.ascii_hostname.split(".")
        domain_query = ".".join(parts[-2:]) if len(parts) >= 2 else norm.ascii_hostname
        try:
            return await lookup_domain_rdap(domain_query)
        except Exception as e:
            return DomainRegistrationInfo(
                domain=norm.ascii_hostname,
                status="unavailable",
                error=f"RDAP lookup failed: {str(e)}"
            )

    # Task B: Safe Fetch & Redirect Inspection (Strict SSRF & Non-execution)
    async def _fetch_http() -> SafeFetchResult:
        if is_internal_dest:
            return SafeFetchResult(
                final_url=norm.normalized_url,
                initial_url=norm.normalized_url,
                stopped_reason="Connection skipped: Destination is an internal/non-routable private network address.",
                error="Connection blocked by SSRF security policy."
            )
        try:
            return await safe_fetch_url(norm.normalized_url)
        except Exception as e:
            return SafeFetchResult(
                final_url=norm.normalized_url,
                initial_url=norm.normalized_url,
                stopped_reason=f"Safe fetch encountered error: {str(e)}",
                error=str(e)
            )

    # Task C: Feature 1 - SSL/TLS Certificate Intelligence
    async def _fetch_ssl() -> SslCertificateIntelligence:
        if is_internal_dest:
            return SslCertificateIntelligence(
                hostname=norm.ascii_hostname,
                status="unable_to_verify",
                connection_status="Connection Blocked",
                plain_language_explanation="TLS inspection skipped for private or reserved destination.",
                warnings=["Destination is a private or non-routable address."]
            )
        try:
            return await inspect_tls_certificate(
                hostname=norm.ascii_hostname,
                port=norm.port or 443,
                is_https=(norm.scheme == "https"),
                ip_override=primary_ip,
                timeout=4.0
            )
        except Exception as e:
            return SslCertificateIntelligence(
                hostname=norm.ascii_hostname,
                status="unable_to_verify",
                connection_status="Unable to verify certificate",
                plain_language_explanation="Unable to verify certificate due to an internal inspection error.",
                warnings=[str(e)]
            )

    # Task D: Feature 5 - Hosting & Network Footprint
    async def _fetch_hosting() -> HostingIntelligence:
        if is_internal_dest:
            return HostingIntelligence(
                ip_address=primary_ip or norm.ascii_hostname,
                status="skipped",
                organization="Private / Reserved Address Space",
                contextual_note="Internal network address. External hosting intelligence does not apply."
            )
        if primary_ip:
            try:
                return await lookup_ip_hosting_intelligence(primary_ip)
            except Exception:
                pass
        return HostingIntelligence(
            ip_address=primary_ip or "Unknown",
            status="unavailable",
            contextual_note="No valid public IP could be determined for hosting intelligence."
        )

    # Task E: Feature 2 - Threat Intelligence Providers
    async def _fetch_urlhaus() -> ProviderResult:
        try:
            return await check_urlhaus(norm.normalized_url)
        except Exception as e:
            return ProviderResult(provider_name="abuse.ch URLhaus", status="unavailable", error_message=str(e))

    async def _fetch_gsb() -> ProviderResult:
        try:
            return await check_google_safe_browsing(norm.normalized_url)
        except Exception as e:
            return ProviderResult(provider_name="Google Safe Browsing", status="unavailable", error_message=str(e))

    async def _fetch_vt() -> ProviderResult:
        try:
            return await check_virustotal(norm.normalized_url)
        except Exception as e:
            return ProviderResult(provider_name="VirusTotal", status="unavailable", error_message=str(e))

    async def _fetch_abuseipdb() -> Optional[ProviderResult]:
        if primary_ip and not is_internal_dest:
            try:
                return await check_abuseipdb(primary_ip)
            except Exception as e:
                return ProviderResult(provider_name="AbuseIPDB", category="ip_reputation", status="unavailable", error_message=str(e))
        return None

    # Execute concurrent tasks with safety
    results = await asyncio.gather(
        _fetch_rdap(),
        _fetch_http(),
        _fetch_ssl(),
        _fetch_hosting(),
        _fetch_urlhaus(),
        _fetch_gsb(),
        _fetch_vt(),
        _fetch_abuseipdb(),
        return_exceptions=True
    )

    # Unpack safely
    rdap_res = results[0] if not isinstance(results[0], Exception) else DomainRegistrationInfo(domain=norm.ascii_hostname, status="unavailable", error=str(results[0]))
    fetch_res = results[1] if not isinstance(results[1], Exception) else SafeFetchResult(final_url=norm.normalized_url, initial_url=norm.normalized_url, error=str(results[1]))
    ssl_res = results[2] if not isinstance(results[2], Exception) else SslCertificateIntelligence(hostname=norm.ascii_hostname, status="unable_to_verify", connection_status="Unable to verify certificate")
    hosting_res = results[3] if not isinstance(results[3], Exception) else HostingIntelligence(ip_address="Unknown", status="unavailable")

    providers: List[ProviderResult] = []
    # URLhaus
    if not isinstance(results[4], Exception) and results[4]:
        providers.append(results[4])
    # GSB
    if not isinstance(results[5], Exception) and results[5]:
        providers.append(results[5])
    # VT
    if not isinstance(results[6], Exception) and results[6]:
        providers.append(results[6])
    # AbuseIPDB
    if len(results) > 7 and not isinstance(results[7], Exception) and results[7]:
        providers.append(results[7])

    threat_intel_flagged = any(p.status == "malicious_found" for p in providers)

    # 4. Feature 4: Dangerous Download and Hidden File Extension Assessment
    download_res = evaluate_download_safety(
        final_url=fetch_res.final_url,
        headers=fetch_res.headers,
        prefix_bytes=fetch_res.raw_prefix_bytes or b"",
        content_length=fetch_res.content_length
    )

    # 5. Feature 3: Static HTML & Sensitive Input Auditing
    html_res = analyze_static_html(
        fetch_res.html_content,
        page_host=norm.ascii_hostname,
        is_https=(norm.scheme == "https"),
        domain_age_days=rdap_res.domain_age_days,
        threat_intel_flagged=threat_intel_flagged
    )

    # 6. Feature 6: Security Authority Checklist Synthesis
    authority_checklist = synthesize_authority_checklist(
        providers=providers,
        ssl_status=ssl_res.status,
        ssl_issuer=ssl_res.issuer,
        rdap_status=rdap_res.status,
        domain_age_days=rdap_res.domain_age_days,
        target_ip=primary_ip
    )

    # 7. Multi-Signal Scoring and Report Synthesis
    report = compute_url_risk_report(
        scan_id=scan_id,
        norm=norm,
        fetch_result=fetch_res,
        dns_info=dns_info,
        hosting_info=hosting_res,
        rdap_info=rdap_res,
        html_info=html_res,
        providers=providers,
        timestamp=now_ts,
        ssl_info=ssl_res,
        download_info=download_res,
        authority_checklist=authority_checklist
    )

    return report
