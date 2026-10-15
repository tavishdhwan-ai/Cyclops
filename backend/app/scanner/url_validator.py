"""
Robust URL normalization, validation, and deterministic heuristic signals.
Safely handles:
- Scheme prefixing (HTTP/HTTPS only)
- Punycode / IDN conversions and homograph character detection
- Credential & query string sensitive parameter redaction
- Raw IPv4 / IPv6 host identification (including bracket-wrapped, loopback, private)
- Port checks, excessive subdomains, shorteners, and deceptive path patterns.
"""
import re
import urllib.parse
import ipaddress
import idna
from typing import Optional, Dict, Any, List, Tuple
from pydantic import BaseModel, Field

# High-risk URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "v.ht"
}

# Suspicious path signals indicative of phishing/credential harvesting
SUSPICIOUS_PATH_TERMS = [
    "login", "signin", "verify", "verification", "password", "passwd",
    "reset", "account", "security", "auth", "credential", "billing",
    "update-payment", "unlock", "confirm", "wallet", "banking"
]

# Sensitive query parameter names whose values must be sanitized/redacted
SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "auth", "auth_token", "key", "api_key",
    "secret", "password", "pass", "pwd", "credential", "session", "sessionid",
    "sid", "jwt", "code", "refresh_token", "private"
}

# Multi-part second-level domain suffixes for accurate subdomain counting
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "me.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "ne.jp", "or.jp",
    "co.nz", "net.nz", "org.nz",
    "com.br", "net.br",
    "co.in", "net.in", "org.in", "gen.in"
}

# Cyrillic / Greek characters frequently abused for IDN homograph attacks
CONFUSABLE_CYRILLIC_MAP = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y',
    '\u0456': 'i', '\u0458': 'j'
}


class NormalizedUrl(BaseModel):
    raw_input: str
    normalized_url: str
    sanitized_display_url: str
    scheme: str
    hostname: str
    raw_hostname: str
    ascii_hostname: str
    unicode_hostname: str
    port: Optional[int] = None
    path: str = "/"
    query: Optional[str] = None
    fragment: Optional[str] = None
    is_ip: bool = False
    ip_version: Optional[int] = None
    is_private_ip: bool = False
    is_loopback: bool = False
    is_link_local: bool = False
    is_multicast: bool = False
    is_reserved: bool = False
    is_punycode: bool = False
    has_homograph_chars: bool = False
    homograph_details: List[str] = Field(default_factory=list)
    subdomain_count: int = 0
    is_shortener: bool = False
    credentials_detected: bool = False
    heuristic_notes: List[str] = Field(default_factory=list)


def normalize_and_validate_url(raw_input: str) -> NormalizedUrl:
    """
    Validates and normalizes user input into a canonical URL model.
    Raises ValueError on invalid formats, unsupported schemes, or malformed hosts.
    """
    if not raw_input or not isinstance(raw_input, str):
        raise ValueError("URL input cannot be empty.")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("URL input cannot be blank.")

    # Prevent whitespace or control characters
    if any(c in cleaned for c in ('\r', '\n', '\t')):
        raise ValueError("URL contains illegal whitespace or control characters.")

    # 1. Scheme normalization
    # Detect scheme if present
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):(?://)?', cleaned)
    if scheme_match:
        found_scheme = scheme_match.group(1).lower()
        if found_scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{found_scheme}'. Only HTTP and HTTPS are supported.")
        # Ensure double slash format
        scheme = found_scheme
        remainder = cleaned[scheme_match.end():]
        url_to_parse = f"{scheme}://{remainder}"
    else:
        # Default safe scheme to https
        scheme = "https"
        url_to_parse = f"https://{cleaned}"

    parsed = urllib.parse.urlsplit(url_to_parse)

    # 2. Hostname extraction & credentials check
    netloc = parsed.netloc
    if not netloc:
        raise ValueError("Could not extract a valid host from the provided input.")

    credentials_detected = False
    if "@" in netloc:
        credentials_detected = True
        # Split off user credentials for security
        userinfo, host_port = netloc.rsplit("@", 1)
    else:
        host_port = netloc

    # Extract port if specified
    port = None
    if host_port.startswith("["):
        # IPv6 bracket notation
        closing_bracket = host_port.find("]")
        if closing_bracket == -1:
            raise ValueError("Malformed IPv6 literal with missing closing bracket.")
        raw_host = host_port[1:closing_bracket]
        port_str = host_port[closing_bracket + 1:]
        if port_str.startswith(":"):
            try:
                port = int(port_str[1:])
            except ValueError:
                raise ValueError("Invalid port specified.")
    else:
        if ":" in host_port:
            parts = host_port.split(":")
            if len(parts) == 2:
                raw_host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    raise ValueError(f"Invalid port: {parts[1]}")
            else:
                # Could be raw unbracketed IPv6
                raw_host = host_port
        else:
            raw_host = host_port

    if not raw_host:
        raise ValueError("Hostname is missing or invalid.")

    # Validate port range
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is out of valid range (1-65535).")

    # 3. IP Address validation
    is_ip = False
    ip_version = None
    is_private_ip = False
    is_loopback = False
    is_link_local = False
    is_multicast = False
    is_reserved = False

    try:
        ip_obj = ipaddress.ip_address(raw_host)
        is_ip = True
        ip_version = ip_obj.version
        is_private_ip = ip_obj.is_private
        is_loopback = ip_obj.is_loopback
        is_link_local = ip_obj.is_link_local
        is_multicast = ip_obj.is_multicast
        is_reserved = ip_obj.is_reserved
        ascii_hostname = str(ip_obj)
        unicode_hostname = str(ip_obj)
        is_punycode = False
        has_homograph = False
        homograph_details = []
        subdomain_count = 0
    except ValueError:
        # It is a domain name
        # 4. Punycode & IDN normalization
        is_punycode = raw_host.lower().startswith("xn--") or ".xn--" in raw_host.lower()

        try:
            # Decode to unicode
            unicode_hostname = idna.decode(raw_host.encode('ascii', errors='ignore')) if is_punycode else raw_host
        except Exception:
            unicode_hostname = raw_host

        try:
            # Encode to ASCII Punycode
            ascii_hostname = idna.encode(unicode_hostname).decode('ascii').lower()
        except Exception as e:
            # If standard idna fails, basic lowercase validation
            ascii_hostname = raw_host.lower()

        # Check for invalid characters in ascii hostname
        if not re.match(r'^[a-z0-9\.\-]+$', ascii_hostname):
            raise ValueError(f"Invalid hostname characters in '{raw_host}'.")

        # Homograph attack detection (mixed-script / confusable cyrillic)
        has_homograph = False
        homograph_details = []
        for char in unicode_hostname:
            if char in CONFUSABLE_CYRILLIC_MAP:
                has_homograph = True
                homograph_details.append(
                    f"Character '{char}' (U+{ord(char):04X}) resembles Latin '{CONFUSABLE_CYRILLIC_MAP[char]}'"
                )

        # Subdomain count
        parts = ascii_hostname.split(".")
        if len(parts) <= 2:
            subdomain_count = 0
        else:
            tld_cand = ".".join(parts[-2:])
            if tld_cand in MULTI_PART_TLDS:
                subdomain_count = max(0, len(parts) - 3)
            else:
                subdomain_count = max(0, len(parts) - 2)

    # 5. Path and Query normalization
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    query = parsed.query if parsed.query else None

    # Construct clean canonical normalized URL
    host_for_url = f"[{ascii_hostname}]" if is_ip and ip_version == 6 else ascii_hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        norm_netloc = f"{host_for_url}:{port}"
    else:
        norm_netloc = host_for_url

    norm_url = urllib.parse.urlunsplit((scheme, norm_netloc, path, query or "", ""))

    # Construct sanitized display URL (redacting sensitive parameters and credentials)
    sanitized_query = None
    if query:
        sanitized_pairs = []
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k.lower() in SENSITIVE_PARAM_NAMES:
                    sanitized_pairs.append(f"{k}=[REDACTED]")
                else:
                    sanitized_pairs.append(f"{k}={v}")
            else:
                sanitized_pairs.append(pair)
        sanitized_query = "&".join(sanitized_pairs)

    sanitized_display_url = urllib.parse.urlunsplit(
        (scheme, norm_netloc, path, sanitized_query or "", "")
    )

    # 6. Heuristic observations
    heuristic_notes = []
    is_shortener = ascii_hostname.lower() in URL_SHORTENERS
    if is_shortener:
        heuristic_notes.append(f"Domain '{ascii_hostname}' is a known URL shortening service.")

    if is_ip:
        if is_loopback or is_private_ip or is_link_local or is_reserved:
            heuristic_notes.append(f"Host '{ascii_hostname}' is an internal/non-routable IP address.")
        else:
            heuristic_notes.append(f"URL uses a raw IP address ({ascii_hostname}) instead of a registered domain.")

    if has_homograph:
        heuristic_notes.append(
            f"Unicode homograph characters detected in hostname: {', '.join(homograph_details[:3])}"
        )

    if credentials_detected:
        heuristic_notes.append("URL contained user authentication credentials in netloc (redacted for safety).")

    if port and port not in (80, 443, 8080, 8443):
        heuristic_notes.append(f"URL connects to a non-standard web port ({port}).")

    if subdomain_count >= 3:
        heuristic_notes.append(f"Unusually deep subdomain hierarchy ({subdomain_count} levels).")

    # Path signals
    lower_path = path.lower()
    found_path_signals = [t for t in SUSPICIOUS_PATH_TERMS if t in lower_path]
    if found_path_signals:
        heuristic_notes.append(f"URL path includes sensitive terms: {', '.join(found_path_signals[:3])}")

    return NormalizedUrl(
        raw_input=raw_input,
        normalized_url=norm_url,
        sanitized_display_url=sanitized_display_url,
        scheme=scheme,
        hostname=ascii_hostname,
        raw_hostname=raw_host,
        ascii_hostname=ascii_hostname,
        unicode_hostname=unicode_hostname,
        port=port,
        path=path,
        query=query,
        fragment=parsed.fragment or None,
        is_ip=is_ip,
        ip_version=ip_version,
        is_private_ip=is_private_ip,
        is_loopback=is_loopback,
        is_link_local=is_link_local,
        is_multicast=is_multicast,
        is_reserved=is_reserved,
        is_punycode=is_punycode,
        has_homograph_chars=has_homograph,
        homograph_details=homograph_details,
        subdomain_count=subdomain_count,
        is_shortener=is_shortener,
        credentials_detected=credentials_detected,
        heuristic_notes=heuristic_notes,
    )
