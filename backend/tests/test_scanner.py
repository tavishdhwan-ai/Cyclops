import pytest
from app.schemas import EmailScanRequest, AttachmentInput
from app.scanner import analyze_demo_email, calculate_risk_level


def test_scenario_1_suspicious_email():
    """Test 1 — Suspicious email with impersonation, credential request, urgency, account pressure."""
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


def test_scenario_2_normal_email():
    """Test 2 — Normal harmless email."""
    req = EmailScanRequest(
        sender="Alex <alex@company.com>",
        subject="Team lunch tomorrow",
        body="Hi, are we still meeting at noon?"
    )
    res = analyze_demo_email(req)
    
    assert len(res.findings) == 0
    assert res.threat_score <= 2.49
    assert res.risk_level == "LOW"


def test_scenario_3_suspicious_url():
    """Test 3 — Suspicious IP address URL."""
    req = EmailScanRequest(
        sender="service@normal.com",
        subject="Verify your account",
        body="Please verify your account.",
        links=["http://198.51.100.10/login"]
    )
    res = analyze_demo_email(req)
    
    finding_types = [f.type for f in res.findings]
    assert "suspicious_link" in finding_types
    assert res.threat_score > 2.0
    assert res.risk_level == calculate_risk_level(res.threat_score)


def test_scenario_4_suspicious_attachment():
    """Test 4 — Double extension executable attachment."""
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


def test_scenario_5_normal_attachment():
    """Test 5 — Benign image attachment."""
    req = EmailScanRequest(
        attachments=[AttachmentInput(name="receipt.jpg", file_type="jpg")]
    )
    res = analyze_demo_email(req)
    
    assert len(res.attachments) == 1
    att = res.attachments[0]
    assert att.filename == "receipt.jpg"
    assert att.threat_score <= 2.49
    assert att.risk_level == "LOW"


def test_scenario_6_multiple_attachments():
    """Test 6 — Multiple distinct attachments per result."""
    att_list = [
        AttachmentInput(name="invoice.pdf"),
        AttachmentInput(name="payment-details.docx"),
        AttachmentInput(name="receipt.jpg"),
        AttachmentInput(name="meeting-invite.ics"),
        AttachmentInput(name="event-pass.pkpass"),
    ]
    req = EmailScanRequest(attachments=att_list)
    res = analyze_demo_email(req)
    
    assert len(res.attachments) == 5
    filenames = [a.filename for a in res.attachments]
    assert filenames == ["invoice.pdf", "payment-details.docx", "receipt.jpg", "meeting-invite.ics", "event-pass.pkpass"]


def test_scenario_7_missing_fields():
    """Test 7 — Empty payload / missing fields."""
    req = EmailScanRequest()
    res = analyze_demo_email(req)
    
    assert res.status == "completed"
    assert res.threat_score == 0.5
    assert res.risk_level == "LOW"
    assert isinstance(res.findings, list)


def test_scenario_8_score_boundaries():
    """Test 8 — Exact score boundary mappings."""
    assert calculate_risk_level(0.0) == "LOW"
    assert calculate_risk_level(1.2) == "LOW"
    assert calculate_risk_level(2.49) == "LOW"
    assert calculate_risk_level(2.5) == "MEDIUM"
    assert calculate_risk_level(3.8) == "MEDIUM"
    assert calculate_risk_level(4.99) == "MEDIUM"
    assert calculate_risk_level(5.0) == "HIGH"
    assert calculate_risk_level(6.4) == "HIGH"
    assert calculate_risk_level(7.49) == "HIGH"
    assert calculate_risk_level(7.5) == "CRITICAL"
    assert calculate_risk_level(8.7) == "CRITICAL"
    assert calculate_risk_level(9.6) == "CRITICAL"
    assert calculate_risk_level(10.0) == "CRITICAL"
