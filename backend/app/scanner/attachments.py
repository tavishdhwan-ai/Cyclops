"""
Attachment metadata analysis for SentinelAI scanner.
Analyzes attachment metadata (filename, file_type) without downloading or executing files.
"""
from typing import List, Tuple, Any, Optional
from app.schemas import Finding, AttachmentResult
from app.scanner.scoring import calculate_risk_level

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1"
}

ATTACHMENT_SUSPICIOUS_KEYWORDS = [
    "urgent", "payment", "invoice", "password", "verification",
    "account", "secure", "unlock"
]


def analyze_attachments(
    attachments_input: List[Any],
    email_subject: Optional[str],
    email_body: Optional[str],
) -> Tuple[List[AttachmentResult], List[Finding]]:
    """
    Analyze attachment metadata against static risk rules.
    Returns individual AttachmentResult objects and aggregated findings.
    """
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
                    id="double_extension",
                    category="attachments",
                    type="double_extension",
                    severity="high",
                    title="Double file extension detected",
                    description=f"Attachment '{filename}' uses a double extension pattern, a common technique to disguise malicious files.",
                    explanation=f"Attachment '{filename}' uses a double extension pattern, a common technique to disguise malicious files.",
                    evidence={"filename": filename},
                    score_contribution=2.5,
                )
                att_findings.append(finding)

        # 2. Executable or script extension check
        final_ext = "." + parts[-1] if len(parts) > 1 else ""
        if final_ext in EXECUTABLE_EXTENSIONS:
            finding = Finding(
                id="executable_attachment",
                category="attachments",
                type="executable_attachment",
                severity="high",
                title="Executable file attachment",
                description=f"Attachment '{filename}' has an executable or script extension ({final_ext}) which presents risk.",
                explanation=f"Attachment '{filename}' has an executable or script extension ({final_ext}) which presents risk.",
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            )
            att_findings.append(finding)

        # 3. HTML attachment combined with sensitive context check
        if final_ext in [".html", ".htm"]:
            if has_sensitive_context or any(kw in filename_lower for kw in ATTACHMENT_SUSPICIOUS_KEYWORDS):
                finding = Finding(
                    id="html_attachment",
                    category="attachments",
                    type="html_attachment",
                    severity="high",
                    title="Suspicious HTML attachment",
                    description=f"HTML attachment '{filename}' combined with credential/account request language is a common phishing vector.",
                    explanation=f"HTML attachment '{filename}' combined with credential/account request language is a common phishing vector.",
                    evidence={"filename": filename},
                    score_contribution=2.5,
                )
                att_findings.append(finding)

        # 4. Suspicious filename terms check
        for kw in ATTACHMENT_SUSPICIOUS_KEYWORDS:
            if kw in filename_lower and not any(f.type == "double_extension" for f in att_findings):
                finding = Finding(
                    id="attachment_keyword",
                    category="attachments",
                    type="attachment_keyword",
                    severity="medium",
                    title="Suspicious attachment filename",
                    description=f"Attachment filename '{filename}' includes sensitive keywords ('{kw}').",
                    explanation=f"Attachment filename '{filename}' includes sensitive keywords ('{kw}').",
                    evidence={"filename": filename, "matched_keyword": kw},
                    score_contribution=1.5,
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
            threat_found=len(att_findings) > 0,
        ))

        aggregated_findings.extend(att_findings)

    return attachment_results, aggregated_findings
