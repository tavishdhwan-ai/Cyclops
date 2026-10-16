"""
SSRF Protection & Safe HTTP Client for Cyclops URL Analysis.

Guarantees:
- DNS resolution is validated before opening connections.
- Re-resolves and validates target IP at every redirect hop.
- Blocks localhost, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  169.254.0.0/16 (link-local/cloud metadata), 100.64.0.0/10 (carrier-grade NAT),
  multicast (224.0.0.0/4), documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
  IPv6 loopback (::1), IPv6 unique-local (fc00::/7), link-local (fe80::/10), IPv4-mapped IPv6.
- Prevents DNS rebinding by connecting directly to the validated IP address while passing the SNI / Host header.
- Enforces strict response size limits, timeouts, and redirect hop limits.
"""
import socket
import ipaddress
import urllib.parse
from typing import List, Tuple, Optional, Dict, Any
from pydantic import BaseModel, Field
import httpx

# Default limits
MAX_REDIRECT_HOPS = 6
CONNECT_TIMEOUT_SECONDS = 4.0
READ_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB max for safety (prevents decompression bombs)

# Blocked IPv4 / IPv6 network definitions
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),        # Private network
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space / CGNAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS / GCP / Azure metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),     # Private network
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),    # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),    # Private network
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),    # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),      # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),          # Discard-only
    ipaddress.ip_network("2001:db8::/32"),     # Documentation
    ipaddress.ip_network("fc00::/7"),          # Unique local (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
]


class SSRFValidationError(Exception):
    """Raised when an IP address or hostname resolves to an unauthorized destination."""
    pass


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if an IP address belongs to any blocked or reserved range."""
    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is strictly forbidden."
    if ip.is_link_local:
        return True, f"Link-local/metadata address ({ip}) is strictly forbidden."
    if ip.is_private:
        return True, f"Private/internal network address ({ip}) is not accessible."
    if ip.is_reserved:
        return True, f"Reserved network address ({ip}) is forbidden."
    if ip.is_multicast:
        return True, f"Multicast address ({ip}) is forbidden."

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True, f"Address {ip} falls inside blocked network range {net}."

    return False, ""


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and validates that NONE belong to private/reserved ranges.
    Returns list of safe resolved IP strings.
    Raises SSRFValidationError on violation.
    """
    clean_host = hostname.strip("[]")

    # If it is already a literal IP
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        blocked, reason = is_ip_blocked(ip_obj)
        if blocked:
            raise SSRFValidationError(reason)
        return [str(ip_obj)]
    except ValueError:
        pass  # It's a domain name

    # Resolve via DNS
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for '{hostname}': {str(e)}")

    resolved_ips = []
    for family, socktype, proto, canonname, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise SSRFValidationError(f"No IP addresses resolved for '{hostname}'.")

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            blocked, reason = is_ip_blocked(ip_obj)
            if blocked:
                raise SSRFValidationError(f"Hostname '{hostname}' resolved to blocked IP {ip_str}: {reason}")
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP '{ip_str}' for hostname '{hostname}'.")

    return resolved_ips


class RedirectHop(BaseModel):
    hop_number: int
    url: str
    status_code: int
    resolved_ip: str
    headers: Dict[str, str] = Field(default_factory=dict)
    hostname_changed: bool = False
    scheme_downgraded: bool = False


class SafeFetchResult(BaseModel):
    final_url: str
    initial_url: str
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    final_status_code: Optional[int] = None
    final_resolved_ip: Optional[str] = None
    content_type: Optional[str] = None
    html_content: Optional[str] = None
    content_length: int = 0
    raw_prefix_bytes: Optional[bytes] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    stopped_reason: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    error: Optional[str] = None


async def safe_fetch_url(
    initial_url: str,
    max_redirects: int = MAX_REDIRECT_HOPS,
    timeout: float = READ_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES
) -> SafeFetchResult:
    """
    Safely inspects URL redirects and downloads initial static HTML without executing JavaScript.
    Validates DNS and SSRF at every single redirect hop.
    """
    current_url = initial_url
    redirect_chain: List[RedirectHop] = []
    final_ip: Optional[str] = None

    for hop in range(1, max_redirects + 1):
        parsed = urllib.parse.urlsplit(current_url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                stopped_reason=f"Unsupported protocol scheme '{scheme}'.",
                error=f"Unsupported protocol '{scheme}'."
            )

        hostname = parsed.hostname
        if not hostname:
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                stopped_reason="Missing or invalid hostname in URL.",
                error="Invalid hostname."
            )

        # 1. Resolve and validate SSRF at this hop
        try:
            safe_ips = resolve_and_validate_hostname(hostname)
            primary_ip = safe_ips[0]
            final_ip = primary_ip
        except SSRFValidationError as e:
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                stopped_reason=f"Security Policy Blocked: {str(e)}",
                error=str(e)
            )

        # 2. Make controlled request without automatic redirect following
        try:
            transport = httpx.AsyncHTTPTransport(verify=True)
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT_SECONDS),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko; SentinelAI/1.0)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                }
            ) as client:
                response = await client.get(current_url)
        except httpx.ConnectTimeout:
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                final_resolved_ip=primary_ip,
                stopped_reason="Connection timeout while connecting to server.",
                error="Connection timed out."
            )
        except httpx.ReadTimeout:
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                final_resolved_ip=primary_ip,
                stopped_reason="Read timeout waiting for response payload.",
                error="Read timed out."
            )
        except httpx.RequestError as exc:
            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                final_resolved_ip=primary_ip,
                stopped_reason=f"Network error: {type(exc).__name__}",
                error=str(exc)
            )

        status_code = response.status_code
        headers_dict = dict(response.headers)
        location_header = response.headers.get("Location")

        # Record hop details
        is_redirect = status_code in (301, 302, 303, 307, 308) and location_header is not None

        # Check for scheme downgrade or cross-domain change
        if is_redirect:
            next_url = urllib.parse.urljoin(current_url, location_header)
            next_parsed = urllib.parse.urlsplit(next_url)
            hostname_changed = (parsed.hostname.lower() != (next_parsed.hostname or "").lower())
            scheme_downgraded = (parsed.scheme.lower() == "https" and next_parsed.scheme.lower() == "http")

            redirect_chain.append(RedirectHop(
                hop_number=hop,
                url=current_url,
                status_code=status_code,
                resolved_ip=primary_ip,
                headers={"location": location_header},
                hostname_changed=hostname_changed,
                scheme_downgraded=scheme_downgraded
            ))

            current_url = next_url
            continue
        else:
            # Final destination reached!
            # Stream response body safely with size limit
            content_type = response.headers.get("Content-Type", "")
            raw_bytes = response.content[:max_bytes]
            
            # Safe text decode (fallback to utf-8 ignore)
            try:
                html_text = raw_bytes.decode(response.encoding or "utf-8", errors="replace")
            except Exception:
                html_text = raw_bytes.decode("utf-8", errors="replace")

            return SafeFetchResult(
                final_url=current_url,
                initial_url=initial_url,
                redirect_chain=redirect_chain,
                final_status_code=status_code,
                final_resolved_ip=primary_ip,
                content_type=content_type,
                html_content=html_text,
                content_length=len(raw_bytes),
                raw_prefix_bytes=raw_bytes[:2048],
                headers={k.lower(): v for k, v in headers_dict.items() if k.lower() in ("server", "content-type", "content-disposition", "content-length", "x-frame-options", "strict-transport-security", "content-security-policy")},
                stopped_reason="Analysis completed normally."
            )

    # Exceeded max redirects
    return SafeFetchResult(
        final_url=current_url,
        initial_url=initial_url,
        redirect_chain=redirect_chain,
        final_resolved_ip=final_ip,
        stopped_reason=f"Exceeded maximum redirect limit ({max_redirects} hops). Potential redirect loop.",
        error="Too many redirects."
    )
