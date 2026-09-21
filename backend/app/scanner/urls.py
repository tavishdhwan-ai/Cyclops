"""
URL structural analysis for SentinelAI scanner.
Passively checks links provided in email metadata without visiting URLs.
"""
import re
import urllib.parse
from typing import List
from app.schemas import Finding
from app.scanner.brands import RECOGNIZED_BRANDS

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "account", "password",
    "billing", "payment", "unlock", "confirm"
]


def analyze_urls(links: List[str]) -> List[Finding]:
    """Analyze links present in the email body for structural security risks."""
    findings: List[Finding] = []
    if not links:
        return findings

    flagged_urls = set()

    for link in links:
        if not link or link in flagged_urls:
            continue

        try:
            parsed = urllib.parse.urlparse(link)
            hostname = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "").lower()

            if not hostname:
                continue

            reasons = []

            # 1. IP address host check
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, hostname):
                reasons.append(f"uses a raw IP address ({hostname}) instead of a domain name")

            # 2. URL Shorteners check
            if hostname in URL_SHORTENERS:
                reasons.append(f"uses a URL shortening service ({hostname}) which hides the real destination")

            # 3. Excessive subdomains check
            subdomain_parts = hostname.split('.')
            if len(subdomain_parts) > 4:
                reasons.append(f"contains an unusually high number of subdomains ({hostname})")

            # 4. Punycode encoding check
            if "xn--" in hostname:
                reasons.append("uses punycode encoding which can be used for internationalized domain spoofing")

            # 5. Suspicious keywords in non-recognized domain check
            for kw in SUSPICIOUS_URL_KEYWORDS:
                if kw in hostname and not any(hostname.endswith(vd) for brand_list in RECOGNIZED_BRANDS.values() for vd in brand_list):
                    reasons.append(f"domain includes security keyword '{kw}' ({hostname})")
                    break

            # 6. HTTP instead of HTTPS on sensitive link check
            if scheme == "http" and any(kw in link.lower() for kw in ["login", "verify", "secure", "account", "password", "bank"]):
                reasons.append("uses unencrypted HTTP protocol for a sensitive request")

            if reasons:
                flagged_urls.add(link)
                reasons_str = "; ".join(reasons)
                findings.append(Finding(
                    id="suspicious_link",
                    category="urls",
                    type="suspicious_link",
                    severity="high",
                    title="Suspicious link detected",
                    description=f"Link '{link}' exhibits security concerns: {reasons_str}.",
                    explanation=f"Link '{link}' exhibits security concerns: {reasons_str}.",
                    evidence={
                        "link": link,
                        "hostname": hostname,
                        "reasons": reasons,
                    },
                    score_contribution=2.5,
                ))

        except Exception:
            continue

    return findings
