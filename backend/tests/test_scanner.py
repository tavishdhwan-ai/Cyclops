import pytest
from app.schemas import EmailScanRequest, AttachmentInput
from app.scanner import analyze_demo_email, calculate_risk_level


def test_1_normal_personal_email():
    """1. Normal personal email -> expected LOW score / minimal findings."""
    req = EmailScanRequest(
        sender="Alex <alex@company.com>",
        subject="Team lunch tomorrow",
        body="Hi, are we still meeting at noon?"
    )
    res = analyze_demo_email(req)
    assert len(res.findings) == 0
    assert res.threat_score <= 2.49
    assert res.risk_level == "LOW"


def test_2_microsoft_display_name_unrelated_domain():
    """2. Microsoft display name from unrelated domain -> brand impersonation finding."""
    req = EmailScanRequest(
        sender="Microsoft Support <security@example.xyz>",
        subject="Account update",
        body="Please check your settings."
    )
    res = analyze_demo_email(req)
    finding_ids = [f.id for f in res.findings]
    assert "brand_impersonation" in finding_ids or "sender_impersonation" in [f.type for f in res.findings]
    brand_finding = next(f for f in res.findings if f.id == "brand_impersonation" or f.type == "sender_impersonation")
    assert brand_finding.severity == "high"
    assert "Microsoft" in brand_finding.description or "Microsoft" in brand_finding.explanation


def test_3_legitimate_microsoft_domain():
    """3. Legitimate Microsoft domain -> no brand-impersonation finding."""
    req = EmailScanRequest(
        sender="Microsoft Support <support@microsoft.com>",
        subject="Security Notification",
        body="Your security baseline has been updated."
    )
    res = analyze_demo_email(req)
    finding_ids = [f.id for f in res.findings]
    assert "brand_impersonation" not in finding_ids


def test_4_obvious_lookalike_domain():
    """4. Obvious lookalike domain (paypa1.com) -> lookalike-domain finding."""
    req = EmailScanRequest(
        sender="PayPal Service <billing@paypa1.com>",
        subject="Payment receipt",
        body="Thank you for your transaction."
    )
    res = analyze_demo_email(req)
    finding_types = [f.type for f in res.findings]
    assert "lookalike_domain" in finding_types
    lookalike_finding = next(f for f in res.findings if f.type == "lookalike_domain")
    assert lookalike_finding.severity == "high"


def test_5_punycode_domain():
    """5. Punycode domain (xn--...) -> unusual-domain finding."""
    req = EmailScanRequest(
        sender="Security Team <support@xn--microsft-1za.com>",
        subject="Account Notification",
        body="Please review your account."
    )
    res = analyze_demo_email(req)
    finding_types = [f.type for f in res.findings]
    assert "unusual_domain" in finding_types


def test_6_business_looking_sender_from_gmail():
    """6. Business-looking sender from gmail.com -> contextual free-mail finding."""
    req = EmailScanRequest(
        sender="Microsoft Billing Department <billingteam@gmail.com>",
        subject="Invoice Overdue",
        body="Your account invoice is overdue."
    )
    res = analyze_demo_email(req)
    finding_ids = [f.id for f in res.findings]
    assert "free_mail_business_context" in finding_ids
    free_mail_finding = next(f for f in res.findings if f.id == "free_mail_business_context")
    assert free_mail_finding.severity == "medium"


def test_7_from_and_reply_to_mismatch():
    """7. From and Reply-To mismatch -> reply-to mismatch finding."""
    req = EmailScanRequest(
        sender="Support Team <support@legitimatebusiness.com>",
        reply_to="hacker@evil-external-domain.com",
        subject="Request update",
        body="Please reply to this email."
    )
    res = analyze_demo_email(req)
    finding_ids = [f.id for f in res.findings]
    assert "reply_to_mismatch" in finding_ids
    reply_finding = next(f for f in res.findings if f.id == "reply_to_mismatch")
    assert reply_finding.severity == "medium"


def test_8_existing_phase_3b_phishing_email():
    """8. Existing Phase 3B suspicious phishing email -> previous findings still appear."""
    req = EmailScanRequest(
        sender="Microsoft Security <alerts@random-example.com>",
        subject="Urgent: Verify your password immediately",
        body="Your account will be suspended. Confirm your password within 10 minutes."
    )
    res = analyze_demo_email(req)
    
    assert res.mode == "demo"
    assert res.status == "completed"
    assert 0.0 <= res.threat_score <= 10.0
    assert res.risk_level in ["HIGH", "CRITICAL"]
    assert res.risk_level == calculate_risk_level(res.threat_score)
    
    finding_types = [f.type for f in res.findings]
    assert "sender_impersonation" in finding_types
    assert "credential_request" in finding_types
    assert "urgency" in finding_types
    assert "account_action" in finding_types


def test_9_existing_normal_email():
    """9. Existing normal email -> previous behavior still works."""
    req = EmailScanRequest(
        sender="Alex <alex@company.com>",
        subject="Team lunch tomorrow",
        body="Hi, are we still meeting at noon?"
    )
    res = analyze_demo_email(req)
    assert res.threat_score <= 2.49
    assert res.risk_level == "LOW"


def test_10_score_boundaries():
    """10. Score boundaries: 2.49 LOW, 2.5 MEDIUM, 4.99 MEDIUM, 5.0 HIGH, 7.49 HIGH, 7.5 CRITICAL."""
    assert calculate_risk_level(0.0) == "LOW"
    assert calculate_risk_level(1.5) == "LOW"
    assert calculate_risk_level(2.49) == "LOW"
    assert calculate_risk_level(2.5) == "MEDIUM"
    assert calculate_risk_level(3.5) == "MEDIUM"
    assert calculate_risk_level(4.99) == "MEDIUM"
    assert calculate_risk_level(5.0) == "HIGH"
    assert calculate_risk_level(6.0) == "HIGH"
    assert calculate_risk_level(7.49) == "HIGH"
    assert calculate_risk_level(7.5) == "CRITICAL"
    assert calculate_risk_level(8.5) == "CRITICAL"
    assert calculate_risk_level(10.0) == "CRITICAL"


def test_suspicious_attachment_double_extension():
    """Verify double extension attachment detection."""
    req = EmailScanRequest(
        attachments=[AttachmentInput(name="invoice.pdf.exe", file_type="exe")]
    )
    res = analyze_demo_email(req)
    assert len(res.attachments) == 1
    att = res.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.threat_score > 2.0
    assert att.threat_found is True
    assert len(att.findings) > 0


def test_empty_payload():
    """Verify default empty payload scan behavior."""
    req = EmailScanRequest()
    res = analyze_demo_email(req)
    assert res.status == "completed"
    assert res.threat_score == 0.5
    assert res.risk_level == "LOW"
    assert isinstance(res.findings, list)
