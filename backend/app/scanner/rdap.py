"""
Domain registration intelligence using official RDAP (Registration Data Access Protocol).
Queries authoritative ICANN RDAP bootstrap endpoints without screen-scraping whois.
Features:
- Registration / creation date
- Domain age in days
- Expiration date
- Registrar name
- Domain status codes (e.g. clientTransferProhibited, redemptionPeriod)
- Nameservers
- Privacy protection detection
- Graceful handling of unsupported TLDs, timeouts, and rate limits.
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import httpx


class DomainRegistrationInfo(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    expires_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_recently_registered: bool = False
    status_codes: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    privacy_protected: bool = False
    source: str = "RDAP (Registration Data Access Protocol)"
    status: str = "unknown"  # "live", "unavailable", "skipped", "not_found"
    error: Optional[str] = None


def parse_rdap_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse various ISO-8601 RDAP timestamp formats."""
    if not ts_str:
        return None
    # Truncate Z or +00:00
    cleaned = ts_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned)
    except Exception:
        # Fallback to date slice
        try:
            return datetime.strptime(ts_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None


async def lookup_domain_rdap(domain: str) -> DomainRegistrationInfo:
    """
    Look up domain registration data using public ICANN RDAP servers.
    """
    if not domain or "." not in domain:
        return DomainRegistrationInfo(
            domain=domain,
            status="skipped",
            error="Raw IP or single-label domain has no RDAP domain registry."
        )

    # Use rdap.org as transparent IANA-compliant RDAP router
    rdap_url = f"https://rdap.org/domain/{domain.lower().strip()}"

    try:
        async with httpx.AsyncClient(timeout=4.5, follow_redirects=True) as client:
            resp = await client.get(
                rdap_url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "SentinelAI-RDAP-Client/1.0"
                }
            )

            if resp.status_code == 404:
                return DomainRegistrationInfo(
                    domain=domain,
                    status="not_found",
                    error="Domain not found in authoritative RDAP registry."
                )

            if resp.status_code == 429:
                return DomainRegistrationInfo(
                    domain=domain,
                    status="unavailable",
                    error="RDAP registry rate limit reached."
                )

            if resp.status_code != 200:
                return DomainRegistrationInfo(
                    domain=domain,
                    status="unavailable",
                    error=f"RDAP query returned HTTP {resp.status_code}."
                )

            data = resp.json()

            # 1. Extract Events (registration, expiration)
            created_dt: Optional[datetime] = None
            expires_dt: Optional[datetime] = None
            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                date_str = event.get("eventDate")
                if action == "registration":
                    created_dt = parse_rdap_timestamp(date_str)
                elif action == "expiration":
                    expires_dt = parse_rdap_timestamp(date_str)

            # 2. Extract Registrar
            registrar_name = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for field in vcard[1]:
                            if len(field) > 3 and field[0] == "fn":
                                registrar_name = field[3]
                                break

            # 3. Extract Nameservers
            nameservers = []
            for ns in data.get("nameservers", []):
                ldh = ns.get("ldhName")
                if ldh:
                    nameservers.append(ldh.lower())

            # 4. Extract Status Codes
            status_codes = data.get("status", [])

            # 5. Check Privacy Protection
            privacy = False
            raw_text = str(data).lower()
            if "privacy" in raw_text or "proxy" in raw_text or "whoisguard" in raw_text or "redacted" in raw_text:
                privacy = True

            # 6. Compute Age in days
            age_days = None
            is_recent = False
            if created_dt:
                now = datetime.now(timezone.utc)
                age_days = (now - created_dt).days
                if age_days < 30:
                    is_recent = True

            return DomainRegistrationInfo(
                domain=domain,
                registrar=registrar_name or "Private / Undisclosed",
                created_date=created_dt.strftime("%Y-%m-%d") if created_dt else None,
                expires_date=expires_dt.strftime("%Y-%m-%d") if expires_dt else None,
                domain_age_days=age_days,
                is_recently_registered=is_recent,
                status_codes=status_codes,
                nameservers=nameservers[:4],
                privacy_protected=privacy,
                status="live"
            )

    except httpx.TimeoutException:
        return DomainRegistrationInfo(
            domain=domain,
            status="unavailable",
            error="RDAP query timed out."
        )
    except Exception as exc:
        return DomainRegistrationInfo(
            domain=domain,
            status="unavailable",
            error=f"RDAP query error: {str(exc)}"
        )
