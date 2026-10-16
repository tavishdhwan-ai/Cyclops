"""
Passive DNS and Network/Hosting Infrastructure Footprint for Cyclops URL scanner.

Performs:
- Forward DNS resolution (A, AAAA records using socket and stdlib)
- Reverse DNS (PTR record lookup via socket.gethostbyaddr)
- IP Geolocation & ASN lookup via clean documented RDAP/Geo services (ip-api / rdap)
- CDN and cloud reverse-proxy identification (Cloudflare, AWS, Fastly, Akamai)
- Contextual interpretation without arbitrary trust penalties for cloud hosting
"""
import socket
import ipaddress
from datetime import datetime, timezone
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
    reverse_dns: Optional[str] = None
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
    cdn_provider: Optional[str] = None
    is_shared_hosting: bool = False
    contextual_note: Optional[str] = None
    footprint_summary: Optional[str] = None
    data_provider: str = "Unavailable"
    lookup_timestamp: Optional[str] = None
    status: str = "unknown"  # "live", "cached", "unavailable", "skipped"


class DnsIntelligence(BaseModel):
    hostname: str
    resolved_ips: List[str] = Field(default_factory=list)
    dns_records: List[DnsRecord] = Field(default_factory=list)
    canonical_cname: Optional[str] = None
    error: Optional[str] = None


# Known CDN / Cloud hosting ASN or Org keywords and human-readable names
CLOUD_CDN_PROVIDERS = {
    "cloudflare": "Cloudflare Edge",
    "amazon": "Amazon Web Services (AWS)",
    "aws": "Amazon Web Services (AWS)",
    "cloudfront": "Amazon CloudFront CDN",
    "google": "Google Cloud Platform",
    "fastly": "Fastly CDN",
    "akamai": "Akamai Edge",
    "microsoft": "Microsoft Azure",
    "azure": "Microsoft Azure",
    "digitalocean": "DigitalOcean",
    "ovh": "OVHcloud",
    "hetzner": "Hetzner Online",
    "linode": "Akamai / Linode"
}


def _get_utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


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


def lookup_reverse_dns(ip_str: str) -> Optional[str]:
    """Resolves reverse DNS (PTR record) for an IP address with safe fallback."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return None


async def lookup_ip_hosting_intelligence(ip_str: str) -> HostingIntelligence:
    """
    Look up IP hosting, ASN, Reverse DNS, and Geolocation metadata.
    Uses free public IP-API endpoint with graceful fallback and no required API key.
    Respects private/reserved IP constraints.
    """
    now_ts = _get_utc_now_str()
    clean_ip = ip_str.strip("[]")

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return HostingIntelligence(
            ip_address=ip_str,
            status="unavailable",
            lookup_timestamp=now_ts,
            contextual_note="Invalid IP address syntax for hosting intelligence."
        )

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return HostingIntelligence(
            ip_address=ip_str,
            status="skipped",
            lookup_timestamp=now_ts,
            organization="Private / Reserved Address Space",
            contextual_note="Internal network address. Geolocation and external ASN lookups do not apply."
        )

    # Reverse DNS lookup (safe stdlib)
    rev_dns = lookup_reverse_dns(clean_ip)

    # Query public IP intelligence (ip-api.com json API with 4s timeout)
    url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    org = data.get("org") or data.get("isp") or "Unknown Organization"
                    asn = data.get("as") or ""
                    combined_org = f"{org} {asn}".lower()

                    is_cloud = False
                    detected_cdn = None
                    for sig, label in CLOUD_CDN_PROVIDERS.items():
                        if sig in combined_org:
                            is_cloud = True
                            detected_cdn = label
                            break

                    note = (
                        "Hosted on a major cloud or CDN edge network. Edge server geolocation reflects network routing points rather than the website operator's legal address."
                        if is_cloud
                        else "Infrastructure hosted on independent network or regional datacenter provider."
                    )

                    loc_parts = [p for p in [data.get("city"), data.get("regionName"), data.get("country")] if p]
                    loc_str = ", ".join(loc_parts) or "Unknown Location"

                    footprint_summary = f"{org} ({asn}) in {loc_str}"

                    return HostingIntelligence(
                        ip_address=clean_ip,
                        hostname=data.get("city"),
                        reverse_dns=rev_dns,
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
                        provider_name=detected_cdn or org,
                        cdn_provider=detected_cdn,
                        is_shared_hosting=is_cloud,
                        contextual_note=note,
                        footprint_summary=footprint_summary,
                        data_provider="IP-API Network Intelligence",
                        lookup_timestamp=now_ts,
                        status="live"
                    )
    except Exception:
        pass

    return HostingIntelligence(
        ip_address=clean_ip,
        reverse_dns=rev_dns,
        data_provider="Unavailable",
        lookup_timestamp=now_ts,
        status="unavailable",
        contextual_note="External hosting intelligence lookup timed out or was unreachable."
    )
