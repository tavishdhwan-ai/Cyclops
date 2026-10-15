"""
Reputation Provider Adapters for Cyclops URL Scanner.
Integrates with:
- Google Safe Browsing API v4
- VirusTotal v3 URL API
- AbuseIPDB IP reputation API

Strict Requirements:
- If API key is not configured or missing from environment, returns explicit 'Not configured' state.
- If provider request fails, times out, or errors, returns explicit 'Unavailable' state with error reason.
- Never fabricates scores or threat matches.
- Respects rate limits, timeouts, and private data disclosure.
"""
import os
import base64
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import httpx


class ProviderResult(BaseModel):
    provider_name: str
    status: str  # "configured", "not_configured", "unavailable", "malicious_found", "clean", "rate_limited"
    is_malicious: Optional[bool] = None
    threat_details: Optional[str] = None
    reputation_score: Optional[int] = None
    timestamp: Optional[str] = None
    error_message: Optional[str] = None
    raw_summary: Optional[Dict[str, Any]] = None


async def check_google_safe_browsing(url: str) -> ProviderResult:
    """
    Check URL against Google Safe Browsing API v4.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            status="not_configured",
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
                        status="malicious_found",
                        is_malicious=True,
                        threat_details=f"Identified as {', '.join(threat_types)} by Google Safe Browsing."
                    )
                else:
                    return ProviderResult(
                        provider_name="Google Safe Browsing",
                        status="clean",
                        is_malicious=False,
                        threat_details="No threat matches reported by Google Safe Browsing database."
                    )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="Google Safe Browsing",
                    status="rate_limited",
                    error_message="Google Safe Browsing API quota exceeded."
                )
            else:
                return ProviderResult(
                    provider_name="Google Safe Browsing",
                    status="unavailable",
                    error_message=f"Google Safe Browsing returned HTTP {resp.status_code}."
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            status="unavailable",
            error_message="Request to Google Safe Browsing timed out."
        )
    except Exception as e:
        return ProviderResult(
            provider_name="Google Safe Browsing",
            status="unavailable",
            error_message=f"Error contacting Google Safe Browsing: {str(e)}"
        )


async def check_virustotal(url: str) -> ProviderResult:
    """
    Check URL against VirusTotal v3 API.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="VirusTotal",
            status="not_configured",
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
                    status="malicious_found" if is_flagged else "clean",
                    is_malicious=is_flagged,
                    threat_details=f"{malicious} security vendors flagged this URL as malicious ({malicious}/{total}).",
                    raw_summary=stats
                )
            elif resp.status_code == 404:
                return ProviderResult(
                    provider_name="VirusTotal",
                    status="clean",
                    is_malicious=False,
                    threat_details="URL not previously indexed in VirusTotal corpus."
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="VirusTotal",
                    status="rate_limited",
                    error_message="VirusTotal API rate limit reached."
                )
            else:
                return ProviderResult(
                    provider_name="VirusTotal",
                    status="unavailable",
                    error_message=f"VirusTotal API returned HTTP {resp.status_code}."
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="VirusTotal",
            status="unavailable",
            error_message="VirusTotal request timed out."
        )
    except Exception as e:
        return ProviderResult(
            provider_name="VirusTotal",
            status="unavailable",
            error_message=f"Error contacting VirusTotal: {str(e)}"
        )


async def check_abuseipdb(ip_address: str) -> ProviderResult:
    """
    Check IP address against AbuseIPDB v2 API.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return ProviderResult(
            provider_name="AbuseIPDB",
            status="not_configured",
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
                    status="malicious_found" if is_abusive else "clean",
                    is_malicious=is_abusive,
                    reputation_score=score,
                    threat_details=f"Abuse confidence score: {score}% based on {reports} user report(s)."
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name="AbuseIPDB",
                    status="rate_limited",
                    error_message="AbuseIPDB daily query quota exceeded."
                )
            else:
                return ProviderResult(
                    provider_name="AbuseIPDB",
                    status="unavailable",
                    error_message=f"AbuseIPDB returned HTTP {resp.status_code}."
                )
    except httpx.TimeoutException:
        return ProviderResult(
            provider_name="AbuseIPDB",
            status="unavailable",
            error_message="AbuseIPDB request timed out."
        )
    except Exception as e:
        return ProviderResult(
            provider_name="AbuseIPDB",
            status="unavailable",
            error_message=f"Error contacting AbuseIPDB: {str(e)}"
        )
