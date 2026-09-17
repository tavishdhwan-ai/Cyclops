import re
import uuid
import urllib.parse
from typing import List, Tuple, Dict, Any, Optional
from app.schemas import (
    EmailScanRequest,
    EmailScanResponse,
    Finding,
    AttachmentResult,
)


RECOGNIZED_BRANDS: Dict[str, List[str]] = {
    "microsoft": [
        "microsoft.com", "live.com", "outlook.com", "hotmail.com", 
        "office.com", "office365.com", "microsoftonline.com", "msn.com"
    ],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com", "paypal-communication.com", "paypal.co.uk"],
    "amazon": ["amazon.com", "amazonaws.com", "amazon.co.uk"],
    "docusign": ["docusign.com", "docusign.net"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
}

GENERIC_BRAND_KEYWORDS = ["bank", "it support", "security team"]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", 
    "is.gd", "buff.ly", "cutt.ly", "rb.gy"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "account", "password", 
    "billing", "payment", "unlock", "confirm"
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1"
}

ATTACHMENT_SUSPICIOUS_KEYWORDS = [
    "urgent", "payment", "invoice", "password", "verification", 
    "account", "secure", "unlock"
]


def calculate_risk_level(threat_score: float) -> str:
    """
    Exact risk level thresholds:
    0.0 <= score <= 2.49 -> LOW
    2.5 <= score <= 4.99 -> MEDIUM
    5.0 <= score <= 7.49 -> HIGH
    7.5 <= score <= 10.0 -> CRITICAL
    """
    if threat_score < 2.5:
        return "LOW"
    elif threat_score < 5.0:
        return "MEDIUM"
    elif threat_score < 7.5:
        return "HIGH"
    else:
        return "CRITICAL"


def parse_sender_info(sender_raw: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extracts (display_name, email_address, domain) from sender string.
    Supports formats like 'Display Name <user@domain.com>' or 'user@domain.com'.
    """
    if not sender_raw:
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


def analyze_sender(sender_raw: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    if not sender_raw:
        return findings

    display_name, email_addr, domain = parse_sender_info(sender_raw)
    if not display_name or not domain:
        return findings

    display_name_lower = display_name.lower()

    # Check recognized specific brands
    for brand, valid_domains in RECOGNIZED_BRANDS.items():
        if brand in display_name_lower:
            is_valid = any(domain == vd or domain.endswith("." + vd) for vd in valid_domains)
            if not is_valid:
                brand_cap = brand.capitalize() if brand != "paypal" and brand != "docusign" else brand
                if brand == "paypal":
                    brand_cap = "PayPal"
                elif brand == "docusign":
                    brand_cap = "DocuSign"

                findings.append(Finding(
                    type="sender_impersonation",
                    severity="high",
                    title="Possible sender impersonation",
                    description=f"The display name references {brand_cap}, but the sender domain ({domain}) does not appear related to {brand_cap}."
                ))
                return findings

    # Check generic brand keywords
    for generic_kw in GENERIC_BRAND_KEYWORDS:
        if generic_kw in display_name_lower:
            # If domain is clearly suspicious or mismatched
            known_good = False
            for brand, valid_domains in RECOGNIZED_BRANDS.items():
                if any(domain == vd or domain.endswith("." + vd) for vd in valid_domains):
                    known_good = True
                    break
            if not known_good and ("test" in domain or "example" in domain or "random" in domain or len(domain.split('.')) < 2):
                findings.append(Finding(
                    type="sender_impersonation",
                    severity="high",
                    title="Possible sender impersonation",
                    description=f"The display name references '{generic_kw}', but the sender address uses an unverified domain ({domain})."
                ))
                return findings

    return findings


def analyze_urgency(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    urgency_phrases = [
        "within 10 minutes",
        "immediate action required",
        "account will be suspended",
        "final warning",
        "expires today",
        "respond now",
        "act now",
        "immediately",
        "urgent"
    ]

    for phrase in urgency_phrases:
        if phrase in text:
            findings.append(Finding(
                type="urgency",
                severity="medium",
                title="Urgency-based language",
                description=f"Email uses high-urgency language (\"{phrase}\") to create pressure to act quickly without verification."
            ))
            break  # Add one finding per requirement

    return findings


def analyze_credential_request(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    credential_phrases = [
        "verify your password",
        "confirm your password",
        "enter your password",
        "login verification",
        "verify your account",
        "confirm your login",
        "security verification",
        "reset your password",
        "enter your credentials",
        "confirm your identity"
    ]

    for phrase in credential_phrases:
        if phrase in text:
            findings.append(Finding(
                type="credential_request",
                severity="critical",
                title="Credential request",
                description=f"The message requests account, password, login, or identity information (\"{phrase}\")."
            ))
            break

    return findings


def analyze_account_pressure(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    pressure_phrases = [
        "account suspended",
        "account will be suspended",
        "account disabled",
        "unusual activity",
        "payment failed",
        "verify billing",
        "invoice overdue",
        "confirm identity",
        "payment required",
        "billing issue"
    ]

    for phrase in pressure_phrases:
        if phrase in text:
            findings.append(Finding(
                type="account_action",
                severity="high",
                title="Suspicious account or payment action",
                description=f"The email warns of account or payment issues (\"{phrase}\"), creating pressure to take immediate action."
            ))
            break

    return findings


def analyze_urls(links: List[str]) -> List[Finding]:
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

            # 1. IP address host
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, hostname):
                reasons.append(f"uses a raw IP address ({hostname}) instead of a domain name")

            # 2. URL Shorteners
            if hostname in URL_SHORTENERS:
                reasons.append(f"uses a URL shortening service ({hostname}) which hides the real destination")

            # 3. Excessive subdomains
            subdomain_parts = hostname.split('.')
            if len(subdomain_parts) > 4:
                reasons.append(f"contains an unusually high number of subdomains ({hostname})")

            # 4. Punycode encoding
            if "xn--" in hostname:
                reasons.append("uses punycode encoding which can be used for internationalized domain spoofing")

            # 5. Suspicious keywords in domain
            for kw in SUSPICIOUS_URL_KEYWORDS:
                if kw in hostname and not any(hostname.endswith(vd) for brand_list in RECOGNIZED_BRANDS.values() for vd in brand_list):
                    reasons.append(f"domain includes security keyword '{kw}' ({hostname})")
                    break

            # 6. HTTP instead of HTTPS on suspicious link
            if scheme == "http" and any(kw in link.lower() for kw in ["login", "verify", "secure", "account", "password", "bank"]):
                reasons.append("uses unencrypted HTTP protocol for a sensitive request")

            if reasons:
                flagged_urls.add(link)
                findings.append(Finding(
                    type="suspicious_link",
                    severity="high",
                    title="Suspicious link detected",
                    description=f"Link '{link}' exhibits security concerns: {'; '.join(reasons)}."
                ))

        except Exception:
            continue

    return findings


def analyze_attachments(attachments_input: List[Any], email_subject: Optional[str], email_body: Optional[str]) -> Tuple[List[AttachmentResult], List[Finding]]:
    attachment_results: List[AttachmentResult] = []
    aggregated_findings: List[Finding] = []

    context_text = f"{email_subject or ''} {email_body or ''}".lower()
    has_sensitive_context = any(kw in context_text for kw in ["login", "password", "verify", "account", "billing"])

    for att in attachments_input:
        filename = getattr(att, 'name', None) or (att.get('name') if isinstance(att, dict) else '') or 'unnamed_attachment'
        att_findings: List[Finding] = []

        filename_lower = filename.lower()
        parts = filename_lower.split('.')

        # 1. Double extension check
        if len(parts) >= 3:
            penultimate_ext = "." + parts[-2]
            final_ext = "." + parts[-1]
            if final_ext in EXECUTABLE_EXTENSIONS or penultimate_ext in [".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt"]:
                finding = Finding(
                    type="double_extension",
                    severity="high",
                    title="Double file extension detected",
                    description=f"Attachment '{filename}' uses a double extension pattern, a common technique to disguise malicious files."
                )
                att_findings.append(finding)

        # 2. Executable or script extension
        final_ext = "." + parts[-1] if len(parts) > 1 else ""
        if final_ext in EXECUTABLE_EXTENSIONS:
            finding = Finding(
                type="executable_attachment",
                severity="high",
                title="Executable file attachment",
                description=f"Attachment '{filename}' has an executable or script extension ({final_ext}) which presents risk."
            )
            att_findings.append(finding)

        # 3. HTML attachment combined with sensitive context
        if final_ext in [".html", ".htm"]:
            if has_sensitive_context or any(kw in filename_lower for kw in ATTACHMENT_SUSPICIOUS_KEYWORDS):
                finding = Finding(
                    type="html_attachment",
                    severity="high",
                    title="Suspicious HTML attachment",
                    description=f"HTML attachment '{filename}' combined with credential/account request language is a common phishing vector."
                )
                att_findings.append(finding)

        # 4. Suspicious filename terms
        for kw in ATTACHMENT_SUSPICIOUS_KEYWORDS:
            if kw in filename_lower and not any(f.type == "double_extension" for f in att_findings):
                finding = Finding(
                    type="attachment_keyword",
                    severity="medium",
                    title="Suspicious attachment filename",
                    description=f"Attachment filename '{filename}' includes sensitive keywords ('{kw}')."
                )
                att_findings.append(finding)
                break

        # Calculate attachment-specific threat score
        att_score = 0.0
        if att_findings:
            att_score = 1.0
            for f in att_findings:
                if f.severity == "critical":
                    att_score += 3.0
                elif f.severity == "high":
                    att_score += 2.5
                elif f.severity == "medium":
                    att_score += 1.5
                elif f.severity == "low":
                    att_score += 0.5
        
        att_score = round(min(10.0, max(0.0, att_score)), 1)
        att_risk = calculate_risk_level(att_score)

        summary = f"Attachment '{filename}' passed initial metadata inspection with no threats."
        if att_findings:
            summary = f"Attachment '{filename}' flagged {len(att_findings)} security warning(s)."

        attachment_results.append(AttachmentResult(
            filename=filename,
            threat_score=att_score,
            risk_level=att_risk,
            findings=att_findings,
            summary=summary,
            name=filename,
            status="scanned",
            threat_found=len(att_findings) > 0
        ))

        aggregated_findings.extend(att_findings)

    return attachment_results, aggregated_findings


def analyze_demo_email(request: EmailScanRequest) -> EmailScanResponse:
    """
    Deterministic rule-based email threat scanner for SentinelAI Phase 3B.
    Analyzes sender, subject, body, URLs, and attachment metadata.
    """
    findings: List[Finding] = []

    # 1. Sender Analysis
    sender_findings = analyze_sender(request.sender)
    findings.extend(sender_findings)

    # 2. Urgency Detection
    urgency_findings = analyze_urgency(request.subject, request.body)
    findings.extend(urgency_findings)

    # 3. Credential Request Detection
    cred_findings = analyze_credential_request(request.subject, request.body)
    findings.extend(cred_findings)

    # 4. Account Pressure Detection
    account_findings = analyze_account_pressure(request.subject, request.body)
    findings.extend(account_findings)

    # 5. URL Structural Analysis
    url_findings = analyze_urls(request.links)
    findings.extend(url_findings)

    # 6. Attachment Metadata Analysis
    attachment_results, att_findings = analyze_attachments(request.attachments, request.subject, request.body)
    findings.extend(att_findings)

    # Calculate overall threat score deterministically
    if not findings:
        threat_score = 0.5
    else:
        threat_score = 1.0  # Baseline when suspicious signals are present
        for f in findings:
            if f.severity == "critical":
                threat_score += 3.0
            elif f.severity == "high":
                threat_score += 2.5
            elif f.severity == "medium":
                threat_score += 1.5
            elif f.severity == "low":
                threat_score += 0.5

    threat_score = round(min(10.0, max(0.0, threat_score)), 1)
    risk_level = calculate_risk_level(threat_score)

    # Human-readable summary & recommendation based on score and findings
    if risk_level == "LOW":
        summary = "No significant security threats or phishing indicators detected."
        recommendation = "Message appears safe based on rule checks. Exercise standard caution with unknown senders."
    elif risk_level == "MEDIUM":
        summary = f"Analysis identified {len(findings)} low-to-moderate security indicator(s)."
        recommendation = "Exercise caution. Verify sender identity before clicking links or taking requested actions."
    elif risk_level == "HIGH":
        summary = f"Analysis detected {len(findings)} high-risk phishing indicator(s) requiring review."
        recommendation = "Do not click links or open attachments until sender and request are verified through an out-of-band channel."
    else:
        summary = f"CRITICAL THREAT: Identified {len(findings)} severe security risk(s) including potential credential theft or malicious files."
        recommendation = "DO NOT comply with credential requests, do not click links or open attachments. Report this email to security immediately."

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    return EmailScanResponse(
        scan_id=scan_id,
        mode="demo",
        status="completed",
        threat_score=threat_score,
        risk_level=risk_level,
        summary=summary,
        findings=findings,
        attachments=attachment_results,
        recommendation=recommendation
    )
