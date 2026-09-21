"""
Sender, Display-Name, Domain, and Reply-To intelligence analyzer for SentinelAI.
"""
import re
from typing import List, Tuple, Optional
from app.schemas import Finding
from app.scanner.brands import (
    RECOGNIZED_BRANDS,
    GENERIC_BRAND_KEYWORDS,
    FREE_MAIL_DOMAINS,
    is_domain_legitimate_for_brand,
    normalize_lookalike_string,
)


def parse_sender_info(sender_raw: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extracts (display_name, email_address, domain) from sender string.
    Supports formats like 'Display Name <user@domain.com>' or 'user@domain.com'.
    """
    if not sender_raw or not sender_raw.strip():
        return None, None, None

    sender_clean = sender_raw.strip()
    match = re.search(r'^(.*?)\s*<([^>]+)>$', sender_clean)
    if match:
        display_name = match.group(1).strip('"\' ')
        email_addr = match.group(2).strip()
    else:
        display_name = ""
        email_addr = sender_clean

    domain = None
    if "@" in email_addr:
        domain = email_addr.split("@")[-1].lower().strip()

    return display_name if display_name else None, email_addr, domain


def analyze_sender(
    sender_raw: Optional[str],
    reply_to_raw: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
) -> List[Finding]:
    """
    Deterministic sender analysis rules:
    - Missing or malformed sender check
    - Lookalike domain heuristics
    - Display-name / Brand domain impersonation check
    - Punycode / Internationalized domain check
    - Free email provider with business context check
    - Reply-To mismatch check
    """
    findings: List[Finding] = []

    # TODO Phase 4A.2: Support extracting Reply-To header directly from Gmail DOM in extension if available.

    if not sender_raw or not sender_raw.strip():
        return findings

    display_name, email_addr, domain = parse_sender_info(sender_raw)

    # 1. Malformed sender check (if sender string present but email/domain invalid)
    if not email_addr or not domain or "@" not in email_addr or len(domain.split('.')) < 2:
        findings.append(Finding(
            id="missing_or_malformed_sender",
            category="sender",
            type="sender_impersonation",
            severity="high",
            title="Missing or malformed sender email",
            description=f"The email sender address ('{sender_raw}') is malformed or invalid.",
            explanation="The email sender address is malformed or invalid.",
            evidence={"sender_raw": sender_raw},
            score_contribution=2.5,
        ))
        return findings

    display_name_lower = (display_name or "").lower()

    def format_brand_name(b_key: str) -> str:
        if b_key == "paypal":
            return "PayPal"
        elif b_key == "docusign":
            return "DocuSign"
        elif b_key == "linkedin":
            return "LinkedIn"
        return b_key.capitalize()

    sender_flagged = False

    # 2. Lookalike Domain Heuristics (e.g. paypa1.com, micr0soft.example, amaz0n.example)
    norm_domain = normalize_lookalike_string(domain)
    for brand in RECOGNIZED_BRANDS.keys():
        if brand in norm_domain:
            if not is_domain_legitimate_for_brand(domain, brand):
                has_char_sub = any(c in domain for c in ['0', '1', '5', '3'])
                has_hyphenated_brand = ("-" in domain and brand in norm_domain)
                if has_char_sub or has_hyphenated_brand or norm_domain != domain:
                    brand_cap = format_brand_name(brand)
                    findings.append(Finding(
                        id="lookalike_domain",
                        category="sender",
                        type="lookalike_domain",
                        severity="high",
                        title="Possible lookalike domain",
                        description=f"The sender domain '{domain}' resembles a known brand ({brand_cap}) but does not match the expected domain.",
                        explanation="The sender domain resembles a known brand but does not match the expected domain.",
                        evidence={
                            "sender_domain": domain,
                            "resembled_brand": brand_cap,
                        },
                        score_contribution=2.5,
                    ))
                    sender_flagged = True
                    break

    # 3. Display-name / Brand Impersonation Check (if not already flagged as lookalike)
    if not sender_flagged and display_name:
        for brand in RECOGNIZED_BRANDS.keys():
            if brand in display_name_lower:
                if not is_domain_legitimate_for_brand(domain, brand):
                    brand_cap = format_brand_name(brand)
                    findings.append(Finding(
                        id="brand_impersonation",
                        category="sender",
                        type="sender_impersonation",
                        severity="high",
                        title="Possible brand impersonation",
                        description=f"The display name references {brand_cap}, but the sender domain ({domain}) does not match a known {brand_cap} domain.",
                        explanation=f"Sender appears to reference {brand_cap}, but the sending domain ({domain}) is unrelated to expected {brand_cap} domains.",
                        evidence={
                            "display_name": display_name,
                            "sender_domain": domain,
                            "referenced_brand": brand_cap,
                        },
                        score_contribution=2.5,
                    ))
                    sender_flagged = True
                    break

    # 4. Punycode / Internationalized Domain Heuristics
    if "xn--" in domain or any(ord(c) > 127 for c in domain):
        findings.append(Finding(
            id="unusual_domain",
            category="sender",
            type="unusual_domain",
            severity="high" if "xn--" in domain else "medium",
            title="Unusual internationalized domain",
            description=f"The sender domain '{domain}' uses internationalized/encoded characters that can make domain names harder to visually verify.",
            explanation="The sender domain uses internationalized/encoded characters that can make domain names harder to visually verify.",
            evidence={"sender_domain": domain},
            score_contribution=2.5 if "xn--" in domain else 1.5,
        ))

    # 5. Free Email Domain Context (e.g. Microsoft Billing Department <billingteam@gmail.com>)
    if domain in FREE_MAIL_DOMAINS:
        context_text = f"{display_name or ''} {subject or ''} {body or ''}".lower()
        business_keywords = [
            "billing", "support", "customer care", "helpdesk", "security team",
            "account", "department", "bank", "finance", "service desk",
            "official", "inc", "ltd", "corp", "admin", "payment"
        ]
        has_business_kw = any(kw in context_text for kw in business_keywords)
        has_brand = any(brand in display_name_lower for brand in RECOGNIZED_BRANDS.keys())

        if has_business_kw or has_brand:
            findings.append(Finding(
                id="free_mail_business_context",
                category="sender",
                type="free_mail_business_context",
                severity="medium",
                title="Business identity uses a free-mail domain",
                description=f"The sender presents a business identity ('{display_name or 'Business Sender'}'), but the message originates from a generic free-mail provider ({domain}).",
                explanation="Business identity uses a generic free email domain instead of an enterprise domain.",
                evidence={
                    "sender_domain": domain,
                    "display_name": display_name or "",
                },
                score_contribution=1.5,
            ))

    # 6. Generic Brand Keyword Impersonation Check (if not already flagged)
    if not sender_flagged and display_name:
        for generic_kw in GENERIC_BRAND_KEYWORDS:
            if generic_kw in display_name_lower:
                known_good = any(is_domain_legitimate_for_brand(domain, b) for b in RECOGNIZED_BRANDS)
                if not known_good and ("test" in domain or "example" in domain or "random" in domain or len(domain.split('.')) < 2):
                    findings.append(Finding(
                        id="generic_sender_impersonation",
                        category="sender",
                        type="sender_impersonation",
                        severity="high",
                        title="Possible sender impersonation",
                        description=f"The display name references '{generic_kw}', but the sender address uses an unverified domain ({domain}).",
                        explanation=f"The display name references '{generic_kw}', but the sender address uses an unverified domain ({domain}).",
                        evidence={
                            "display_name": display_name,
                            "sender_domain": domain,
                        },
                        score_contribution=2.5,
                    ))
                    break

    # 7. Reply-To Analysis
    if reply_to_raw:
        _, _, reply_to_domain = parse_sender_info(reply_to_raw)
        if reply_to_domain and domain:
            if reply_to_domain != domain and not reply_to_domain.endswith("." + domain) and not domain.endswith("." + reply_to_domain):
                findings.append(Finding(
                    id="reply_to_mismatch",
                    category="sender",
                    type="reply_to_mismatch",
                    severity="medium",
                    title="Reply-To domain differs from sender",
                    description=f"The Reply-To address domain ({reply_to_domain}) differs from the sender domain ({domain}).",
                    explanation="The Reply-To domain differs from the sender domain.",
                    evidence={
                        "from_domain": domain,
                        "reply_to_domain": reply_to_domain,
                    },
                    score_contribution=1.5,
                ))

    return findings
