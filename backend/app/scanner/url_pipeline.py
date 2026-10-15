"""
High-level Orchestrator for Cyclops Website URL Scanner Pipeline.
Executes full asynchronous URL inspection workflow:
1. Normalization & Input Validation
2. SSRF Check & DNS Resolution
3. Passive RDAP Domain Registration Analysis
4. Safe Multi-hop Redirect Inspection & Static HTML Fetching
5. Static Read-Only HTML Inspection
6. IP Geolocation and Network/Hosting Intelligence
7. Third-party Threat Intelligence Adapters
8. Multi-Signal Scoring and Report Synthesis
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.scanner.url_validator import normalize_and_validate_url
from app.scanner.ssrf import safe_fetch_url, SafeFetchResult
from app.scanner.dns_intelligence import resolve_domain_dns, lookup_ip_hosting_intelligence
from app.scanner.rdap import lookup_domain_rdap
from app.scanner.html_inspector import analyze_static_html
from app.scanner.reputation import check_google_safe_browsing, check_virustotal, check_abuseipdb
from app.scanner.url_scorer import compute_url_risk_report, AggregatedUrlReport


async def orchestrate_url_scan(raw_url: str) -> AggregatedUrlReport:
    """
    Executes the comprehensive, passive, SSRF-protected URL scan pipeline.
    """
    scan_id = f"url-scan-{uuid.uuid4().hex[:8]}"
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Normalize and Validate
    norm = normalize_and_validate_url(raw_url)

    # 2. DNS Intelligence
    dns_info = resolve_domain_dns(norm.ascii_hostname)

    # 3. Domain Registration (RDAP)
    # Only for domains, skip for raw IP addresses
    if not norm.is_ip:
        # Extract registrable domain (e.g. login.example.com -> example.com)
        parts = norm.ascii_hostname.split(".")
        if len(parts) >= 2:
            domain_query = ".".join(parts[-2:])
        else:
            domain_query = norm.ascii_hostname
        rdap_info = await lookup_domain_rdap(domain_query)
    else:
        from app.scanner.rdap import DomainRegistrationInfo
        rdap_info = DomainRegistrationInfo(
            domain=norm.ascii_hostname,
            status="skipped",
            error="Target is an IP address; domain registration lookups do not apply."
        )

    # 4. Safe Fetch & Redirect Inspection (Strict SSRF & Non-execution)
    # If the URL is loopback / private IP, we do NOT attempt to connect
    if norm.is_private_ip or norm.is_loopback or norm.is_link_local or norm.is_reserved:
        fetch_result = SafeFetchResult(
            final_url=norm.normalized_url,
            initial_url=norm.normalized_url,
            stopped_reason="Connection skipped: Destination is an internal/non-routable private network address.",
            error="Connection blocked by SSRF security policy."
        )
    else:
        fetch_result = await safe_fetch_url(norm.normalized_url)

    # 5. Static HTML Inspection (Safe, non-executing)
    html_info = analyze_static_html(
        fetch_result.html_content,
        norm.ascii_hostname
    )

    # 6. Hosting & Network Intelligence
    target_ip = fetch_result.final_resolved_ip or (dns_info.resolved_ips[0] if dns_info.resolved_ips else None)
    if target_ip:
        hosting_info = await lookup_ip_hosting_intelligence(target_ip)
    else:
        from app.scanner.dns_intelligence import HostingIntelligence
        hosting_info = HostingIntelligence(
            ip_address="Unknown",
            status="unavailable",
            contextual_note="No valid public IP could be determined for hosting intelligence."
        )

    # 7. External Threat Intelligence Adapters
    providers = []
    # Check Google Safe Browsing
    gsb_res = await check_google_safe_browsing(norm.normalized_url)
    providers.append(gsb_res)

    # Check VirusTotal
    vt_res = await check_virustotal(norm.normalized_url)
    providers.append(vt_res)

    # Check AbuseIPDB if public IP available
    if target_ip and hosting_info.status != "skipped":
        abuse_res = await check_abuseipdb(target_ip)
        providers.append(abuse_res)

    # 8. Compute Multi-Signal Score and Synthesize Plain-English Report
    report = compute_url_risk_report(
        scan_id=scan_id,
        norm=norm,
        fetch_result=fetch_result,
        dns_info=dns_info,
        hosting_info=hosting_info,
        rdap_info=rdap_info,
        html_info=html_info,
        providers=providers,
        timestamp=now_ts
    )

    return report
