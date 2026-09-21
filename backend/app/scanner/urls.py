"""
URL structural & passive intelligence analyzer for SentinelAI scanner.
Completely passive: parses URL strings locally without making network requests,
resolving DNS, downloading content, or following redirects.
"""
import re
import urllib.parse
import ipaddress
from typing import List, Dict, Any, Optional, Set, Tuple
from app.schemas import Finding
from app.scanner.brands import (
    RECOGNIZED_BRANDS,
    is_domain_legitimate_for_brand,
    normalize_lookalike_string,
)

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "v.ht"
}

SUSPICIOUS_PATH_KEYWORDS: List[str] = [
    "login", "signin", "verify", "verification", "password",
    "reset", "account", "secure", "auth", "credential",
    "update-payment", "billing", "unlock", "confirm"
]

SUSPICIOUS_QUERY_PARAMS: Set[str] = {
    "redirect", "redirect_url", "return", "return_url", "next",
    "continue", "url", "destination", "dest", "target", "goto", "r", "to", "out"
}

MULTI_PART_TLDS: Set[str] = {
    "co.uk", "org.uk", "gov.uk", "me.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "ne.jp", "or.jp",
    "co.nz", "net.nz", "org.nz",
    "com.br", "net.br",
    "co.in", "net.in", "org.in", "gen.in"
}


def is_ip_address(host: str) -> bool:
    """Check if host string is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def get_subdomain_count(hostname: str) -> int:
    """
    Calculate the number of subdomain labels prior to the registrable domain.
    E.g. for 'login.account.verify.example.com':
    TLD: 'com', Registrable: 'example.com', Subdomain parts: ['login', 'account', 'verify'] -> count = 3.
    """
    if not hostname or is_ip_address(hostname):
        return 0

    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return 0

    # Check for multi-part TLD (e.g. co.uk)
    tld_candidate = ".".join(parts[-2:])
    if tld_candidate in MULTI_PART_TLDS:
        if len(parts) <= 3:
            return 0
        subdomains = parts[:-3]
    else:
        subdomains = parts[:-2]

    return len(subdomains)


def extract_query_param_names(query_string: str) -> List[str]:
    """
    Safely extract query parameter names without revealing or logging sensitive values.
    """
    if not query_string:
        return []
    try:
        parsed_qs = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        return list(parsed_qs.keys())
    except Exception:
        keys = re.findall(r'(?:^|&)([^=&]+)=', query_string)
        return list(set(keys))


def check_heavy_encoding(raw_url: str, path: str, query: str) -> bool:
    """
    Detect suspicious levels of URL encoding (e.g. %2F, %3A, %40, %2E, %25).
    Small standard encoding (like space %20) is ignored.
    """
    suspicious_encodings = ["%2f", "%3a", "%40", "%2e", "%25", "%5c"]
    url_lower = raw_url.lower()

    structural_encoded_count = sum(url_lower.count(enc) for enc in suspicious_encodings)
    total_percent_count = url_lower.count("%")

    return structural_encoded_count >= 2 or total_percent_count > 5


def format_brand_name(b_key: str) -> str:
    if b_key == "paypal":
        return "PayPal"
    elif b_key == "docusign":
        return "DocuSign"
    elif b_key == "linkedin":
        return "LinkedIn"
    return b_key.capitalize()


def analyze_urls(
    links: List[str],
    body: Optional[str] = None,
    link_details: Optional[List[Dict[str, str]]] = None,
) -> List[Finding]:
    """
    Passively analyze links provided in email metadata/body for structural security risks.
    Completely local and passive.
    """
    findings: List[Finding] = []
    if not links and not link_details:
        return findings

    urls_to_analyze: List[Tuple[str, Optional[str]]] = []

    if link_details:
        for detail in link_details:
            href = detail.get("href")
            text = detail.get("text")
            if href:
                urls_to_analyze.append((href, text))

    for link in links:
        if isinstance(link, str) and link.strip():
            if "|" in link:
                parts = link.split("|", 1)
                urls_to_analyze.append((parts[1].strip(), parts[0].strip()))
            else:
                if not any(u == link for u, _ in urls_to_analyze):
                    urls_to_analyze.append((link.strip(), None))

    processed_urls: Set[str] = set()

    for raw_url, visible_text in urls_to_analyze:
        if not raw_url or raw_url in processed_urls:
            continue

        try:
            # 0. Check visible text mismatch if visible_text looks like a URL/domain
            if visible_text:
                vis_clean = visible_text.strip()
                if re.match(r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', vis_clean):
                    vis_parsed = urllib.parse.urlparse(vis_clean if vis_clean.startswith(('http://', 'https://')) else f"http://{vis_clean}")
                    dest_parsed = urllib.parse.urlparse(raw_url)

                    vis_host = (vis_parsed.hostname or "").lower()
                    dest_host = (dest_parsed.hostname or "").lower()

                    if vis_host and dest_host and vis_host != dest_host:
                        findings.append(Finding(
                            id="visible_link_mismatch",
                            category="urls",
                            type="visible_link_mismatch",
                            severity="high",
                            title="Visible link does not match destination",
                            description=f"The link display text '{vis_clean}' refers to domain '{vis_host}', but the actual link destination points to '{dest_host}'.",
                            explanation="The text shown to the recipient differs from the actual link destination.",
                            evidence={
                                "visible_text": vis_clean,
                                "visible_domain": vis_host,
                                "destination_domain": dest_host,
                                "destination_url": raw_url,
                            },
                            score_contribution=2.5,
                        ))

            if body and not visible_text:
                body_url_matches = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
                for vis_url in body_url_matches:
                    vis_parsed = urllib.parse.urlparse(vis_url)
                    dest_parsed = urllib.parse.urlparse(raw_url)
                    vis_host = (vis_parsed.hostname or "").lower()
                    dest_host = (dest_parsed.hostname or "").lower()

                    if vis_host and dest_host and vis_host != dest_host:
                        if any(b in vis_host for b in RECOGNIZED_BRANDS):
                            if not any(f.type == "visible_link_mismatch" for f in findings):
                                findings.append(Finding(
                                    id="visible_link_mismatch",
                                    category="urls",
                                    type="visible_link_mismatch",
                                    severity="high",
                                    title="Visible link does not match destination",
                                    description=f"Email body references '{vis_host}', but the actual link points to '{dest_host}'.",
                                    explanation="The text shown to the recipient differs from the actual link destination.",
                                    evidence={
                                        "visible_domain": vis_host,
                                        "destination_domain": dest_host,
                                        "destination_url": raw_url,
                                    },
                                    score_contribution=2.5,
                                ))

            parsed = urllib.parse.urlparse(raw_url)

            netloc = parsed.netloc or ""
            userinfo = None
            if "@" in netloc:
                userinfo_part, host_part = netloc.rsplit("@", 1)
                userinfo = userinfo_part
                hostname = host_part.split(":")[0].lower()
            else:
                hostname = (parsed.hostname or "").lower()

            scheme = (parsed.scheme or "").lower()
            port = parsed.port
            path = parsed.path or ""
            query = parsed.query or ""

            if not hostname and not netloc:
                findings.append(Finding(
                    id="malformed_url",
                    category="urls",
                    type="malformed_url",
                    severity="medium",
                    title="Malformed URL detected",
                    description=f"The URL '{raw_url}' has an invalid structure or missing hostname.",
                    explanation="The link has an invalid or malformed URL structure.",
                    evidence={"raw_url": raw_url},
                    score_contribution=1.5,
                ))
                continue

            url_signals: Set[str] = set()

            # 1. Userinfo / @ URL trick check
            if userinfo:
                url_signals.add("userinfo_url_trick")
                findings.append(Finding(
                    id="userinfo_url_trick",
                    category="urls",
                    type="userinfo_url_trick",
                    severity="high",
                    title="URL contains a userinfo component",
                    description=f"The URL contains an '@' symbol before the actual hostname ('{hostname}'), which can mislead users about the true destination.",
                    explanation="The URL contains an @ symbol before the actual hostname, which can make the destination harder to identify.",
                    evidence={
                        "raw_url": raw_url,
                        "hostname": hostname,
                        "userinfo": userinfo,
                    },
                    score_contribution=2.5,
                ))

            # 2. Raw IP address URL check
            if is_ip_address(hostname):
                url_signals.add("ip_address_url")
                findings.append(Finding(
                    id="ip_address_url",
                    category="urls",
                    type="ip_address_url",
                    severity="high",
                    title="URL uses an IP address",
                    description=f"The link points directly to an IP address ({hostname}) instead of a conventional domain name.",
                    explanation="The link points directly to an IP address instead of using a conventional domain name.",
                    evidence={
                        "raw_url": raw_url,
                        "hostname": hostname,
                    },
                    score_contribution=2.5,
                ))

            # 3. Unencrypted HTTP URL check
            if scheme == "http" and not is_ip_address(hostname):
                url_signals.add("http_unencrypted")
                findings.append(Finding(
                    id="unencrypted_http",
                    category="urls",
                    type="http_unencrypted",
                    severity="medium",
                    title="Unencrypted HTTP URL",
                    description=f"The link '{raw_url}' uses HTTP instead of HTTPS, so the connection is not protected by transport encryption.",
                    explanation="The link uses HTTP instead of HTTPS, so the connection is not protected by transport encryption.",
                    evidence={
                        "raw_url": raw_url,
                        "scheme": scheme,
                        "hostname": hostname,
                    },
                    score_contribution=1.5,
                ))

            # 4. Non-standard port check
            if port is not None:
                is_standard = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                if not is_standard:
                    url_signals.add("non_standard_port")
                    findings.append(Finding(
                        id="non_standard_port",
                        category="urls",
                        type="non_standard_port",
                        severity="medium",
                        title="Non-standard URL port",
                        description=f"The URL specifies non-standard port {port} on hostname '{hostname}'.",
                        explanation=f"The URL explicitly specifies a non-standard port ({port}) instead of default web ports.",
                        evidence={
                            "hostname": hostname,
                            "port": port,
                            "scheme": scheme,
                        },
                        score_contribution=1.5,
                    ))

            # 5. Excessive subdomains check
            subdomain_count = get_subdomain_count(hostname)
            if subdomain_count > 3:
                url_signals.add("deep_subdomain_structure")
                findings.append(Finding(
                    id="deep_subdomain_structure",
                    category="urls",
                    type="deep_subdomain_structure",
                    severity="medium",
                    title="Unusually deep subdomain structure",
                    description=f"The hostname '{hostname}' has an unusually deep subdomain structure ({subdomain_count} subdomain levels).",
                    explanation="The link has an unusually deep subdomain hierarchy, which can sometimes be used to obfuscate the real destination.",
                    evidence={
                        "hostname": hostname,
                        "subdomain_count": subdomain_count,
                    },
                    score_contribution=1.5,
                ))

            # 6. Very long URL check
            if len(raw_url) > 150 or len(hostname) > 64 or len(query) > 100:
                url_signals.add("excessive_url_length")
                findings.append(Finding(
                    id="excessive_url_length",
                    category="urls",
                    type="excessive_url_length",
                    severity="low",
                    title="Unusually long URL",
                    description=f"The URL length ({len(raw_url)} characters) is unusually long.",
                    explanation="The URL is unusually long. While long URLs are common in tracking links, excessive length can obscure the true destination.",
                    evidence={
                        "url_length": len(raw_url),
                        "hostname_length": len(hostname),
                    },
                    score_contribution=0.5,
                ))

            # 7. Heavy URL encoding check
            if check_heavy_encoding(raw_url, path, query):
                url_signals.add("heavy_url_encoding")
                findings.append(Finding(
                    id="heavy_url_encoding",
                    category="urls",
                    type="heavy_url_encoding",
                    severity="medium",
                    title="Heavy URL encoding",
                    description=f"The URL contains heavy or suspicious percent-encoding.",
                    explanation="The link contains extensive character encoding, which can obscure the actual destination or parameters.",
                    evidence={"hostname": hostname},
                    score_contribution=1.5,
                ))

            # 8. Suspicious query parameter check
            param_names = extract_query_param_names(query)
            suspicious_found_params = [p for p in param_names if p.lower() in SUSPICIOUS_QUERY_PARAMS]
            if suspicious_found_params:
                url_signals.add("suspicious_redirect_parameter")
                findings.append(Finding(
                    id="suspicious_redirect_parameter",
                    category="urls",
                    type="suspicious_redirect_parameter",
                    severity="medium",
                    title="Possible redirect parameter",
                    description=f"The URL contains redirect-style query parameter(s): {', '.join(suspicious_found_params)}.",
                    explanation="The URL contains query parameters often used for open redirects, which may forward visitors to an external site.",
                    evidence={
                        "hostname": hostname,
                        "parameter_names": suspicious_found_params,
                    },
                    score_contribution=1.5,
                ))

            # 9. Credential / Login path check
            path_lower = path.lower()
            found_path_kws = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_lower]
            if found_path_kws:
                url_signals.add("credential_path_signal")
                findings.append(Finding(
                    id="credential_path_signal",
                    category="urls",
                    type="credential_path_signal",
                    severity="medium",
                    title="Credential-related URL path",
                    description=f"The URL path contains security/login keyword(s): {', '.join(found_path_kws)}.",
                    explanation="The URL path includes security or login keywords, indicating a potentially sensitive action or credential portal.",
                    evidence={
                        "hostname": hostname,
                        "path": path,
                        "keywords": found_path_kws,
                    },
                    score_contribution=1.5,
                ))

            # 10. URL Shortener check
            if hostname in URL_SHORTENERS:
                url_signals.add("url_shortener")
                findings.append(Finding(
                    id="url_shortener",
                    category="urls",
                    type="url_shortener",
                    severity="medium",
                    title="URL shortener detected",
                    description=f"The link uses URL shortening service ({hostname}) which hides the real destination.",
                    explanation="Shortened URLs hide the final destination and make manual verification harder.",
                    evidence={"hostname": hostname},
                    score_contribution=1.5,
                ))

            # 11. Punycode / Internationalized domain check
            if "xn--" in hostname or any(ord(c) > 127 for c in hostname):
                url_signals.add("internationalized_domain")
                findings.append(Finding(
                    id="internationalized_domain",
                    category="urls",
                    type="internationalized_domain",
                    severity="medium",
                    title="Internationalized domain detected",
                    description=f"The domain '{hostname}' uses Punycode / internationalized character encoding.",
                    explanation="The domain uses Punycode (internationalized character encoding) which can be used for visual domain spoofing.",
                    evidence={"hostname": hostname},
                    score_contribution=1.5,
                ))

            # 12. Lookalike domain check & Hostname heuristics
            norm_host = normalize_lookalike_string(hostname)
            lookalike_flagged = False

            for brand in RECOGNIZED_BRANDS.keys():
                if brand in norm_host:
                    if not is_domain_legitimate_for_brand(hostname, brand):
                        brand_cap = format_brand_name(brand)
                        url_signals.add("lookalike_domain")
                        findings.append(Finding(
                            id="lookalike_domain",
                            category="urls",
                            type="lookalike_domain",
                            severity="high",
                            title="Possible lookalike domain",
                            description=f"The URL domain '{hostname}' resembles a known brand ({brand_cap}) but does not match official brand domains.",
                            explanation="The URL domain resembles a known brand but does not match its official domain.",
                            evidence={
                                "hostname": hostname,
                                "resembled_brand": brand_cap,
                            },
                            score_contribution=2.5,
                        ))
                        lookalike_flagged = True
                        break

            # 13. Hostname Heuristics (excessive hyphens, non-brand keyword in domain) if not lookalike or shortener
            if not lookalike_flagged and hostname not in URL_SHORTENERS and not is_ip_address(hostname):
                hyphen_count = hostname.count("-")
                if hyphen_count >= 3:
                    url_signals.add("suspicious_hostname_structure")
                    findings.append(Finding(
                        id="suspicious_hostname_structure",
                        category="urls",
                        type="suspicious_hostname_structure",
                        severity="medium",
                        title="Suspicious hostname structure",
                        description=f"The domain '{hostname}' contains an excessive number of hyphens ({hyphen_count}).",
                        explanation="The domain name contains structural patterns such as excessive hyphens or unverified brand keywords.",
                        evidence={
                            "hostname": hostname,
                            "hyphen_count": hyphen_count,
                        },
                        score_contribution=1.5,
                    ))

            processed_urls.add(raw_url)

        except Exception:
            continue

    # Deduplicate findings if multiple URLs produce identical findings
    deduped_findings: List[Finding] = []
    seen_keys: Set[str] = set()

    for f in findings:
        host = f.evidence.get("hostname", "") if f.evidence else ""
        key = f"{f.type}:{host}:{f.title}"
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_findings.append(f)

    return deduped_findings
