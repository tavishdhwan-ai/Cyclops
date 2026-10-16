"""
Reputation Provider Adapters and Security Authority Audit for Cyclops URL Scanner.

Integrates with:
- abuse.ch URLhaus (Open API - malware/phishing distribution URL database, no key required)
- Google Safe Browsing API v4 (Key required)
- VirusTotal v3 URL API (Key required)
- AbuseIPDB IP reputation API (Key required)

Strict Requirements:
- If API key is not configured or missing from environment, returns explicit 'not_configured' state.
- If provider request fails, times out, or errors, returns explicit 'unavailable' state with error reason.
- Never fabricates scores or threat matches.
- Respects rate limits, timeouts, and private data disclosure.
- Distinguishes verified threats from unconfigured/unavailable feeds.
"""
import os
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
import httpx


class ProviderResult(BaseModel):
    provider_name: str
    category: str = "url_reputation"  # "url_reputation", "domain_reputation", "ip_reputation", "malware_feed"
    status: str  # "clean", "malicious_found", "not_configured", "unavailable", "rate_limited", "not_applicable"
    is_malicious: Optional[bool] = None
    detection_category: Optional[str] = None  # e.g., "Malware", "Phishing", "Abusive Host", "Social Engineering"
    threat_details: Optional[str] = None
    reputation_score: Optional[int] = None
    timestamp: Optional[str] = None
    error_message: Optional[str] = None
    reference_url: Optional[str] = None
    raw_summary: Optional[Dict[str, Any]] = None


class AuthorityChecklistItem(BaseModel):
    authority_name: str
    target_checked: str  # "URL", "Domain", "IP Address", "TLS Certificate", "Domain Registration"
    check_type: str      # "Reputation / Malware Feed", "Spam & Abuse Database", "Cryptographic Trust", "Registry Age"
    status: str          # "threat_reported", "no_threat_reported", "not_configured", "check_unavailable", "not_applicable"
    verdict_label: str   # "Threat Reported", "No Threat Reported", "Not Configured", "Check Unavailable", "Not Applicable"
    evidence_summary: str
    last_checked: str
    queried_successfully: bool = False


class SecurityAuthorityChecklist(BaseModel):
    items: List[AuthorityChecklistItem] = Field(default_factory=list)
    threats_reported_count: int = 0
    clean_verdicts_count: int = 0
    unconfigured_count: int = 0
    unavailable_count: int = 0
    summary: str = "No security authorities reported an active threat."
    disclaimer: str = (
        "An absence of reported detections does not guarantee that a website is safe. "
        "Threat intelligence databases only track previously identified malicious infrastructure."
    )


def _get_utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


async def check_urlhaus(url: str) -> ProviderResult:
    """
    Check URL against abuse.ch URLhaus database.
    Open public threat intelligence feed - requires no API key.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    now_ts = _get_utc_now_str()

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(endpoint, data={"url": url})
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "")

                if query_status == "ok":
                    threat = data.get("threat") or "Malware distribution"
                    url_status = data.get("url_status", "unknown")
                    tags = data.get("tags") or []
                    date_added = data.get("date_added")
                    ref = data.get("urlhaus_reference")

                    tag_str = f" [tags: {', '.join(tags)}]" if tags else ""
                    return ProviderResult(
                        provider_name="abuse.ch URLhaus",
                        category="url_reputation",
                        status="malicious_found",
                        is_malicious=True,
                        detection_category="Malware Distribution",
                        threat_details=f"Listed in URLhaus database as {threat} (status: {url_status}){tag_str}.",
                        timestamp=date_added or now_ts,
                        reference_url=ref or "https://urlhaus.abuse.ch/",
                        raw_summary={"urlhaus_status": url_status, "threat": threat, "tags": tags}
                    )
                elif query_status == "no_results":
                    return ProviderResult(
                        provider_name="abuse.ch URLhaus",
                        category="url_reputation",
                        status="clean",
                        is_malicious=False,
                        detection_category=None,
                        threat_details="URL not listed in abuse.ch URLhaus malware database.",
                        timestamp=now_ts,
                        reference_url="https://urlhaus.abuse.ch/"
                    )
                else:
                    return ProviderResult(
                        provider_name="abuse.ch URLhaus",
                        category="url_reputation",
                        status="unavailable",
                        error_message=f"URLhaus query returned status: '{query_status}'.",
                        timestamp=now_ts
                    )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="abuse.ch URLhaus",
                    category="url_reputation",
                    status="rate_limited",
                    error_message="URLhaus public API rate limit reached.",
                    timestamp=now_ts
                )
            else:
                return ProviderResult(
                    provider_name="abuse.ch URLhaus",
                    category="url_reputation",
                    status="unavailable",
                    error_message=f"URLhaus returned HTTP {resp.status_code}.",
                    timestamp=now_ts
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="abuse.ch URLhaus",
            category="url_reputation",
            status="unavailable",
            error_message="URLhaus request timed out after 4.0s.",
            timestamp=now_ts
        )
    except Exception as e:
        return ProviderResult(
            provider_name="abuse.ch URLhaus",
            category="url_reputation",
            status="unavailable",
            error_message=f"Error contacting URLhaus: {str(e)}",
            timestamp=now_ts
        )


async def check_google_safe_browsing(url: str) -> ProviderResult:
    """
    Check URL against Google Safe Browsing API v4.
    """
    now_ts = _get_utc_now_str()
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            category="url_reputation",
            status="not_configured",
            timestamp=now_ts,
            error_message="API key not configured in backend environment (GOOGLE_SAFE_BROWSING_API_KEY)."
        )

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "cyclops-url-scanner",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list(set(m.get("threatType", "") for m in matches))
                    return ProviderResult(
                        provider_name="Google Safe Browsing",
                        category="url_reputation",
                        status="malicious_found",
                        is_malicious=True,
                        detection_category=" / ".join(threat_types),
                        threat_details=f"Identified as {', '.join(threat_types)} by Google Safe Browsing.",
                        timestamp=now_ts,
                        reference_url="https://safebrowsing.google.com/"
                    )
                else:
                    return ProviderResult(
                        provider_name="Google Safe Browsing",
                        category="url_reputation",
                        status="clean",
                        is_malicious=False,
                        threat_details="No threat matches reported by Google Safe Browsing database.",
                        timestamp=now_ts,
                        reference_url="https://safebrowsing.google.com/"
                    )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="Google Safe Browsing",
                    category="url_reputation",
                    status="rate_limited",
                    error_message="Google Safe Browsing API quota exceeded.",
                    timestamp=now_ts
                )
            else:
                return ProviderResult(
                    provider_name="Google Safe Browsing",
                    category="url_reputation",
                    status="unavailable",
                    error_message=f"Google Safe Browsing returned HTTP {resp.status_code}.",
                    timestamp=now_ts
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            category="url_reputation",
            status="unavailable",
            error_message="Request to Google Safe Browsing timed out.",
            timestamp=now_ts
        )
    except Exception as e:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            category="url_reputation",
            status="unavailable",
            error_message=f"Error contacting Google Safe Browsing: {str(e)}",
            timestamp=now_ts
        )


async def check_virustotal(url: str) -> ProviderResult:
    """
    Check URL against VirusTotal v3 API.
    """
    now_ts = _get_utc_now_str()
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="VirusTotal",
            category="url_reputation",
            status="not_configured",
            timestamp=now_ts,
            error_message="API key not configured in backend environment (VIRUSTOTAL_API_KEY)."
        )

    # URL identifier in VT v3 is base64url encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        async with httpx.AsyncClient(timeout=4.5) as client:
            resp = await client.get(endpoint, headers={"x-apikey": api_key})
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                is_flagged = malicious > 0 or suspicious > 1
                return ProviderResult(
                    provider_name="VirusTotal",
                    category="url_reputation",
                    status="malicious_found" if is_flagged else "clean",
                    is_malicious=is_flagged,
                    detection_category="Malicious / Suspicious" if is_flagged else None,
                    threat_details=f"{malicious} security vendors flagged this URL as malicious ({malicious}/{total} engines).",
                    timestamp=now_ts,
                    reference_url=f"https://www.virustotal.com/gui/url/{url_id}",
                    raw_summary=stats
                )
            elif resp.status_code == 404:
                return ProviderResult(
                    provider_name="VirusTotal",
                    category="url_reputation",
                    status="clean",
                    is_malicious=False,
                    threat_details="URL not previously indexed in VirusTotal corpus.",
                    timestamp=now_ts
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="VirusTotal",
                    category="url_reputation",
                    status="rate_limited",
                    error_message="VirusTotal API rate limit reached.",
                    timestamp=now_ts
                )
            else:
                return ProviderResult(
                    provider_name="VirusTotal",
                    category="url_reputation",
                    status="unavailable",
                    error_message=f"VirusTotal API returned HTTP {resp.status_code}.",
                    timestamp=now_ts
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="VirusTotal",
            category="url_reputation",
            status="unavailable",
            error_message="VirusTotal request timed out.",
            timestamp=now_ts
        )
    except Exception as e:
        return ProviderResult(
            provider_name="VirusTotal",
            category="url_reputation",
            status="unavailable",
            error_message=f"Error contacting VirusTotal: {str(e)}",
            timestamp=now_ts
        )


async def check_abuseipdb(ip_address: str) -> ProviderResult:
    """
    Check IP address against AbuseIPDB v2 API.
    """
    now_ts = _get_utc_now_str()
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="AbuseIPDB",
            category="ip_reputation",
            status="not_configured",
            timestamp=now_ts,
            error_message="API key not configured in backend environment (ABUSEIPDB_API_KEY)."
        )

    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": False
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(endpoint, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                is_abusive = score > 25

                return ProviderResult(
                    provider_name="AbuseIPDB",
                    category="ip_reputation",
                    status="malicious_found" if is_abusive else "clean",
                    is_malicious=is_abusive,
                    reputation_score=score,
                    detection_category=f"Abuse Score {score}%" if is_abusive else None,
                    threat_details=f"Abuse confidence score: {score}% based on {reports} user report(s).",
                    timestamp=now_ts,
                    reference_url=f"https://www.abuseipdb.com/check/{ip_address}"
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="AbuseIPDB",
                    category="ip_reputation",
                    status="rate_limited",
                    error_message="AbuseIPDB daily query quota exceeded.",
                    timestamp=now_ts
                )
            else:
                return ProviderResult(
                    provider_name="AbuseIPDB",
                    category="ip_reputation",
                    status="unavailable",
                    error_message=f"AbuseIPDB returned HTTP {resp.status_code}.",
                    timestamp=now_ts
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="AbuseIPDB",
            category="ip_reputation",
            status="unavailable",
            error_message="AbuseIPDB request timed out.",
            timestamp=now_ts
        )
    except Exception as e:
        return ProviderResult(
            provider_name="AbuseIPDB",
            category="ip_reputation",
            status="unavailable",
            error_message=f"Error contacting AbuseIPDB: {str(e)}",
            timestamp=now_ts
        )


def synthesize_authority_checklist(
    providers: List[ProviderResult],
    ssl_status: str,
    ssl_issuer: str,
    rdap_status: str,
    domain_age_days: Optional[int],
    target_ip: Optional[str]
) -> SecurityAuthorityChecklist:
    """
    Synthesizes Feature 6: Security Authority Checklist.
    Strictly reports real provider findings without fabricating government or agency investigations.
    """
    now_ts = _get_utc_now_str()
    items: List[AuthorityChecklistItem] = []

    threats_count = 0
    clean_count = 0
    unconfigured_count = 0
    unavailable_count = 0

    # 1. Threat Intel Providers (URLhaus, GSB, VT, AbuseIPDB)
    for p in providers:
        if p.status == "malicious_found":
            threats_count += 1
            status_code = "threat_reported"
            verdict_label = "Threat Reported"
            ev = p.threat_details or f"Flagged by {p.provider_name}"
            queried = True
        elif p.status == "clean":
            clean_count += 1
            status_code = "no_threat_reported"
            verdict_label = "No Detection"
            ev = p.threat_details or f"No malicious activity indexed in {p.provider_name}."
            queried = True
        elif p.status == "not_configured":
            unconfigured_count += 1
            status_code = "not_configured"
            verdict_label = "Not Configured"
            ev = p.error_message or "API key not set in environment."
            queried = False
        else:
            unavailable_count += 1
            status_code = "check_unavailable"
            verdict_label = "Check Unavailable"
            ev = p.error_message or "Provider service unreachable or timed out."
            queried = False

        target_type = "IP Address" if p.category == "ip_reputation" else "URL"
        check_desc = "IP Abuse & Threat Reputation" if p.category == "ip_reputation" else "Malware & Phishing Threat Intelligence"

        items.append(AuthorityChecklistItem(
            authority_name=p.provider_name,
            target_checked=target_type,
            check_type=check_desc,
            status=status_code,
            verdict_label=verdict_label,
            evidence_summary=ev,
            last_checked=p.timestamp or now_ts,
            queried_successfully=queried
        ))

    # 2. TLS Certificate Authority (Root Store Trust)
    if ssl_status == "valid":
        clean_count += 1
        items.append(AuthorityChecklistItem(
            authority_name="TLS Certificate Authority Trust Store",
            target_checked="TLS Certificate",
            check_type="Cryptographic Trust Chain & Hostname Validation",
            status="no_threat_reported",
            verdict_label="Valid & Trusted",
            evidence_summary=f"Issued by recognized CA ({ssl_issuer}); matches requested hostname.",
            last_checked=now_ts,
            queried_successfully=True
        ))
    elif ssl_status in ("expired", "hostname_mismatch", "self_signed", "untrusted"):
        threats_count += 1
        items.append(AuthorityChecklistItem(
            authority_name="TLS Certificate Authority Trust Store",
            target_checked="TLS Certificate",
            check_type="Cryptographic Trust Chain & Hostname Validation",
            status="threat_reported",
            verdict_label="Certificate Issue",
            evidence_summary=f"TLS certificate failure: {ssl_status.replace('_', ' ').title()}.",
            last_checked=now_ts,
            queried_successfully=True
        ))
    elif ssl_status == "unencrypted_http":
        items.append(AuthorityChecklistItem(
            authority_name="TLS Certificate Authority Trust Store",
            target_checked="TLS Certificate",
            check_type="Cryptographic Trust Chain & Hostname Validation",
            status="not_applicable",
            verdict_label="Not Applicable (HTTP)",
            evidence_summary="Target uses unencrypted HTTP. No TLS certificate present.",
            last_checked=now_ts,
            queried_successfully=True
        ))
    else:
        unavailable_count += 1
        items.append(AuthorityChecklistItem(
            authority_name="TLS Certificate Authority Trust Store",
            target_checked="TLS Certificate",
            check_type="Cryptographic Trust Chain & Hostname Validation",
            status="check_unavailable",
            verdict_label="Check Unavailable",
            evidence_summary="Unable to connect to port 443 to retrieve certificate chain.",
            last_checked=now_ts,
            queried_successfully=False
        ))

    # 3. Domain Registration Authority (RDAP / ICANN)
    if rdap_status in ("live", "cached"):
        queried = True
        if domain_age_days is not None and domain_age_days >= 0:
            clean_count += 1
            if domain_age_days < 30:
                verdict_label = "Warning: Recently Registered"
                ev_str = f"Domain was registered {domain_age_days} day{'s' if domain_age_days != 1 else ''} ago (ICANN RDAP)."
            else:
                verdict_label = "Verified Domain Age"
                ev_str = f"Registered {domain_age_days} days ago via accredited registrar (ICANN RDAP)."
            status_code = "no_threat_reported"
        else:
            status_code = "no_threat_reported"
            verdict_label = "Verified Registration"
            ev_str = "Verified registration record available via ICANN RDAP."
    elif rdap_status == "skipped":
        status_code = "not_applicable"
        verdict_label = "Not Applicable (IP Host)"
        ev_str = "Target is a raw IP address; domain registration lookups do not apply."
        queried = True
    else:
        unavailable_count += 1
        status_code = "check_unavailable"
        verdict_label = "Check Unavailable"
        ev_str = "RDAP registry server timed out or returned no authoritative record."
        queried = False

    items.append(AuthorityChecklistItem(
        authority_name="ICANN / Regional Internet Registries (RDAP)",
        target_checked="Domain Registration",
        check_type="Authoritative Domain Registration & Age Verification",
        status=status_code,
        verdict_label=verdict_label,
        evidence_summary=ev_str,
        last_checked=now_ts,
        queried_successfully=queried
    ))

    # Compute overall summary
    if threats_count > 0:
        summary_text = f"Threat indicators or certificate issues identified across {threats_count} verified source(s)."
    elif clean_count > 0:
        summary_text = f"No threat detections reported across {clean_count} successfully queried authority source(s)."
    else:
        summary_text = "External authority checks could not be completed (sources unconfigured or unavailable)."

    return SecurityAuthorityChecklist(
        items=items,
        threats_reported_count=threats_count,
        clean_verdicts_count=clean_count,
        unconfigured_count=unconfigured_count,
        unavailable_count=unavailable_count,
        summary=summary_text
    )
