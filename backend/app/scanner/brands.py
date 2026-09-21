"""
Brand configuration & domain heuristic lookup tables for SentinelAI scanner.
"""
from typing import Dict, List, Set

# Deterministic list of common recognized brands and their known legitimate domains
RECOGNIZED_BRANDS: Dict[str, List[str]] = {
    "microsoft": [
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
        "hotmail.com", "office.com", "office365.com", "msn.com"
    ],
    "google": [
        "google.com", "googleusercontent.com", "gmail.com", "youtube.com"
    ],
    "apple": [
        "apple.com", "icloud.com"
    ],
    "amazon": [
        "amazon.com", "amazonaws.com", "amazon.co.uk"
    ],
    "paypal": [
        "paypal.com", "paypal-communication.com", "paypal.co.uk"
    ],
    "meta": [
        "meta.com", "facebook.com", "instagram.com"
    ],
    "linkedin": [
        "linkedin.com"
    ],
    "dropbox": [
        "dropbox.com"
    ],
    "adobe": [
        "adobe.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "docusign": [
        "docusign.com", "docusign.net"
    ]
}

GENERIC_BRAND_KEYWORDS: List[str] = [
    "bank", "it support", "security team", "billing department",
    "customer care", "helpdesk", "finance team", "official notice",
    "account service", "service desk", "support team"
]

# Common generic free-mail providers
FREE_MAIL_DOMAINS: Set[str] = {
    "gmail.com", "outlook.com", "yahoo.com", "proton.me", "protonmail.com",
    "hotmail.com", "icloud.com", "aol.com", "zoho.com", "mail.com", "yandex.com"
}


def is_domain_legitimate_for_brand(domain: str, brand: str) -> bool:
    """
    Check if domain matches or is a subdomain of any legitimate domain registered for the brand.
    """
    valid_domains = RECOGNIZED_BRANDS.get(brand, [])
    domain_lower = domain.lower()
    return any(domain_lower == vd or domain_lower.endswith("." + vd) for vd in valid_domains)


def normalize_lookalike_string(text: str) -> str:
    """
    Normalize character substitutions (0 -> o, 1 -> l, 5 -> s, 3 -> e) for lookalike domain heuristics.
    """
    res = text.lower()
    res = res.replace('0', 'o')
    res = res.replace('1', 'l')
    res = res.replace('5', 's')
    res = res.replace('3', 'e')
    return res
