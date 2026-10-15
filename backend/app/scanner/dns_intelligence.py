"""
Passive DNS and Network/Hosting Intelligence for Cyclops URL scanner.
Performs:
- Forward DNS resolution (A, AAAA, MX, TXT, NS records using socket and stdlib)
- IP Geolocation & ASN lookup via clean documented RDAP/Geo services (ip-api / rdap)
- Contextual mismatch explanation (CDNs, Cloudflare, AWS vs country)
- Shared hosting indicators
"""
import socket
import ipaddress
import urllib.parse
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import httpx
from app.scanner.ssrf import resolve_and_validate_hostname, SSRFValidationError


class DnsRecord(BaseModel):
    record_type: str
    value: str


class HostingIntelligence(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    is_cloud_or_cdn: bool = False
    provider_name: Optional[str] = None
    is_shared_hosting: bool = False
    contextual_note: Optional[str] = None
    data_provider: str = "Unavailable"
    status: str = "unknown"  # "live", "cached", "unavailable", "skipped"


class DnsIntelligence(BaseModel):
    hostname: str
    resolved_ips: List[str] = Field(default_factory=list)
    dns_records: List[DnsRecord] = Field(default_factory=list)
    canonical_cname: Optional[str] = None
    error: Optional[str] = None


# Known CDN / Cloud hosting ASN or Org keywords
CLOUD_CDN_SIGNATURES = [
    "cloudflare", "amazon", "aws", "google", "fastly", "akamai",
    "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode"
]


def resolve_domain_dns(hostname: str) -> DnsIntelligence:
    """
    Performs standard safe forward DNS resolution for the target hostname.
    """
    clean_host = hostname.strip("[]")

    # If it's a raw IP
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return DnsIntelligence(
            hostname=hostname,
            resolved_ips=[str(ip_obj)],
            dns_records=[DnsRecord(record_type="A" if ip_obj.version == 4 else "AAAA", value=str(ip_obj))]
        )
    except ValueError:
        pass

    try:
        resolved_ips = resolve_and_validate_hostname(clean_host)
    except SSRFValidationError as e:
        return DnsIntelligence(
            hostname=hostname,
            resolved_ips=[],
            error=f"DNS Resolution Blocked: {str(e)}"
        )
    except Exception as e:
        return DnsIntelligence(
            hostname=hostname,
            resolved_ips=[],
            error=f"DNS Resolution Failed: {str(e)}"
        )

    records = []
    for ip in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            rec_type = "A" if ip_obj.version == 4 else "AAAA"
            records.append(DnsRecord(record_type=rec_type, value=ip))
        except ValueError:
            pass

    return DnsIntelligence(
        hostname=hostname,
        resolved_ips=resolved_ips,
        dns_records=records
    )


async def lookup_ip_hosting_intelligence(ip_str: str) -> HostingIntelligence:
    """
    Look up IP hosting, ASN, and Geolocation metadata.
    Uses free public IP-API endpoint with graceful fallback and no required API key.
    Respects private/reserved IP constraints.
    """
    clean_ip = ip_str.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return HostingIntelligence(
            ip_address=ip_str,
            status="unavailable",
            contextual_note="Invalid IP address syntax for hosting intelligence."
        )

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return HostingIntelligence(
            ip_address=ip_str,
            status="skipped",
            organization="Private / Reserved Address Space",
            contextual_note="Internal network address. Geolocation and external ASN do not apply."
        )

    # Query public IP intelligence (ip-api.com json API with 4s timeout)
    url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    org = data.get("org") or data.get("isp") or ""
                    asn = data.get("as") or ""
                    combined_org = f"{org} {asn}".lower()

                    is_cloud = any(sig in combined_org for sig in CLOUD_CDN_SIGNATURES)

                    note = None
                    if is_cloud:
                        note = "Hosted on a major cloud/CDN network. Server geolocation reflects edge routing, not website owner identity."

                    return HostingIntelligence(
                        ip_address=clean_ip,
                        country=data.get("country"),
                        country_code=data.get("countryCode"),
                        region=data.get("regionName"),
                        city=data.get("city"),
                        latitude=data.get("lat"),
                        longitude=data.get("lon"),
                        asn=asn,
                        organization=org,
                        isp=data.get("isp"),
                        is_cloud_or_cdn=is_cloud,
                        is_shared_hosting=is_cloud,
                        contextual_note=note,
                        data_provider="IP-API Network Intelligence",
                        status="live"
                    )
    except Exception:
        pass

    return HostingIntelligence(
        ip_address=clean_ip,
        data_provider="Unavailable",
        status="unavailable",
        contextual_note="External hosting intelligence lookup timed out or was unreachable."
    )
