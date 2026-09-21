"""
Core scanner engine for SentinelAI.
Orchestrates individual security analyzers and aggregates scan results.
"""
import uuid
from typing import List
from app.schemas import EmailScanRequest, EmailScanResponse, Finding
from app.scanner.sender import analyze_sender
from app.scanner.content import analyze_urgency, analyze_credential_request, analyze_account_pressure
from app.scanner.urls import analyze_urls
from app.scanner.attachments import analyze_attachments
from app.scanner.scoring import calculate_overall_score, calculate_risk_level


def scan_email_engine(request: EmailScanRequest) -> EmailScanResponse:
    """
    Orchestrate full email scan across sender intelligence, content rules,
    URL structural checks, and attachment metadata rules.
    Returns structured EmailScanResponse.
    """
    findings: List[Finding] = []

    # 1. Sender Intelligence Analysis
    sender_findings = analyze_sender(
        sender_raw=request.sender,
        reply_to_raw=getattr(request, 'reply_to', None),
        subject=request.subject,
        body=request.body,
    )
    findings.extend(sender_findings)

    # 2. Urgency Language Detection
    urgency_findings = analyze_urgency(request.subject, request.body)
    findings.extend(urgency_findings)

    # 3. Credential Request Detection
    cred_findings = analyze_credential_request(request.subject, request.body)
    findings.extend(cred_findings)

    # 4. Account/Payment Pressure Detection
    account_findings = analyze_account_pressure(request.subject, request.body)
    findings.extend(account_findings)

    # 5. URL Structural Analysis
    url_findings = analyze_urls(
        links=request.links,
        body=request.body,
        link_details=getattr(request, 'link_details', None),
    )
    findings.extend(url_findings)

    # 6. Attachment Metadata Analysis
    attachment_results, att_findings = analyze_attachments(request.attachments, request.subject, request.body)
    findings.extend(att_findings)

    # 7. Threat Score & Risk Level Calculation
    threat_score = calculate_overall_score(findings)
    risk_level = calculate_risk_level(threat_score)

    # 8. Human-readable summary & recommendation
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
        recommendation=recommendation,
    )
