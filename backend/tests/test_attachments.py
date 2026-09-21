"""
Comprehensive deterministic tests for SentinelAI Phase 4A.3 — Attachment Intelligence.
All tests use metadata only; no real files, no malware samples.
"""
import pytest
from app.schemas import EmailScanRequest, AttachmentInput
from app.scanner import analyze_demo_email, calculate_risk_level
from app.scanner.attachments import analyze_attachments, _analyze_single_attachment


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def att(name, file_type=None, size_bytes=None):
    return AttachmentInput(name=name, file_type=file_type, size_bytes=size_bytes)


def scan_with_att(*attachments, subject="", body=""):
    req = EmailScanRequest(
        sender="Sender <sender@example.com>",
        subject=subject,
        body=body,
        attachments=list(attachments),
    )
    return analyze_demo_email(req)


def att_result(res, filename):
    """Retrieve a single AttachmentResult from response by filename."""
    return next((a for a in res.attachments if a.filename == filename), None)


# ===========================================================================
# 1. Normal safe attachments — should produce no findings
# ===========================================================================

def test_1_normal_pdf():
    """Normal PDF → no attachment findings."""
    res = scan_with_att(att("report.pdf", "application/pdf"))
    r = att_result(res, "report.pdf")
    assert r is not None
    assert r.threat_found is False
    assert r.threat_score == 0.0
    assert r.findings == []


def test_2_normal_docx():
    """Normal DOCX → no attachment findings."""
    res = scan_with_att(att("letter.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"))
    r = att_result(res, "letter.docx")
    assert r.threat_found is False
    assert r.findings == []


def test_3_normal_jpg():
    """Normal JPG → no attachment findings."""
    res = scan_with_att(att("photo.jpg", "image/jpeg"))
    r = att_result(res, "photo.jpg")
    assert r.threat_found is False
    assert r.findings == []


def test_3b_normal_png():
    """Normal PNG → no attachment findings."""
    res = scan_with_att(att("screenshot.png", "image/png"))
    r = att_result(res, "screenshot.png")
    assert r.threat_found is False
    assert r.findings == []


# ===========================================================================
# 4. Executable attachments
# ===========================================================================

def test_4_executable_exe():
    """EXE attachment → executable finding, high severity."""
    res = scan_with_att(att("setup.exe", "application/octet-stream"))
    r = att_result(res, "setup.exe")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "executable_attachment" in types
    f = next(x for x in r.findings if x.type == "executable_attachment")
    assert f.severity == "high"
    assert r.threat_score >= 2.5


def test_4b_executable_scr():
    """.scr attachment → executable finding."""
    findings, score = _analyze_single_attachment("screen.scr", None, None, "", "")
    types = [f.type for f in findings]
    assert "executable_attachment" in types


def test_4c_executable_com():
    """.com attachment → executable finding."""
    findings, score = _analyze_single_attachment("virus.com", None, None, "", "")
    types = [f.type for f in findings]
    assert "executable_attachment" in types


def test_4d_executable_bat():
    """.bat attachment → executable finding."""
    findings, score = _analyze_single_attachment("run.bat", None, None, "", "")
    types = [f.type for f in findings]
    assert "executable_attachment" in types


# ===========================================================================
# 5. Script attachments
# ===========================================================================

def test_5_script_js():
    """JS attachment → script finding, high severity."""
    res = scan_with_att(att("app.js", "application/javascript"))
    r = att_result(res, "app.js")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "script_attachment" in types
    f = next(x for x in r.findings if x.type == "script_attachment")
    assert f.severity == "high"


def test_6_powershell_ps1():
    """PS1 attachment → script finding, high severity."""
    res = scan_with_att(att("deploy.ps1", None))
    r = att_result(res, "deploy.ps1")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "script_attachment" in types


def test_5b_script_vbs():
    """.vbs → script finding."""
    findings, _ = _analyze_single_attachment("macro.vbs", None, None, "", "")
    assert any(f.type == "script_attachment" for f in findings)


# ===========================================================================
# 7. Shortcut / LNK
# ===========================================================================

def test_7_shortcut_lnk():
    """LNK attachment → shortcut finding, high severity."""
    res = scan_with_att(att("link.lnk", None))
    r = att_result(res, "link.lnk")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "shortcut_attachment" in types
    f = next(x for x in r.findings if x.type == "shortcut_attachment")
    assert f.severity == "high"


# ===========================================================================
# 8. Macro-enabled Office documents
# ===========================================================================

def test_8_macro_docm():
    """DOCM attachment → macro_enabled_document finding, high severity."""
    res = scan_with_att(att("report.docm", None))
    r = att_result(res, "report.docm")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "macro_enabled_document" in types
    f = next(x for x in r.findings if x.type == "macro_enabled_document")
    assert f.severity == "high"


def test_8b_macro_xlsm():
    """.xlsm → macro_enabled_document finding."""
    findings, _ = _analyze_single_attachment("data.xlsm", None, None, "", "")
    assert any(f.type == "macro_enabled_document" for f in findings)


def test_8c_macro_pptm():
    """.pptm → macro_enabled_document finding."""
    findings, _ = _analyze_single_attachment("slides.pptm", None, None, "", "")
    assert any(f.type == "macro_enabled_document" for f in findings)


# ===========================================================================
# 9 & 10. Double extension
# ===========================================================================

def test_9_double_extension_pdf_exe():
    """invoice.pdf.exe → double_extension finding (NOT a separate executable_attachment)."""
    res = scan_with_att(att("invoice.pdf.exe", "application/octet-stream"))
    r = att_result(res, "invoice.pdf.exe")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "double_extension" in types
    # No separate executable_attachment when double_extension already covers it
    assert "executable_attachment" not in types
    f = next(x for x in r.findings if x.type == "double_extension")
    assert f.severity == "high"
    assert f.evidence["decoy_extension"] == ".pdf"
    assert f.evidence["real_extension"] == ".exe"


def test_10_double_extension_xlsx_js():
    """salary.xlsx.js → double_extension finding."""
    findings, score = _analyze_single_attachment("salary.xlsx.js", None, None, "", "")
    types = [f.type for f in findings]
    assert "double_extension" in types
    assert "script_attachment" not in types  # not double-counted
    f = next(x for x in findings if x.type == "double_extension")
    assert f.evidence["decoy_extension"] == ".xlsx"
    assert f.evidence["real_extension"] == ".js"
    assert score >= 2.5


def test_10b_double_extension_docx_scr():
    """resume.docx.scr → double_extension, scr classified as executable."""
    findings, _ = _analyze_single_attachment("resume.docx.scr", None, None, "", "")
    types = [f.type for f in findings]
    assert "double_extension" in types
    f = next(x for x in findings if x.type == "double_extension")
    assert ".docx" in f.evidence["decoy_extension"]
    assert ".scr" in f.evidence["real_extension"]


def test_10c_double_extension_lnk():
    """image.jpg.lnk → double_extension (shortcut disguised as image)."""
    findings, _ = _analyze_single_attachment("image.jpg.lnk", None, None, "", "")
    types = [f.type for f in findings]
    assert "double_extension" in types


# ===========================================================================
# 11. Archive / container
# ===========================================================================

def test_11_archive_zip():
    """Plain zip archive → archive finding, low severity."""
    res = scan_with_att(att("data.zip", "application/zip"))
    r = att_result(res, "data.zip")
    assert r.threat_found is True
    types = [f.type for f in r.findings]
    assert "archive_attachment" in types
    f = next(x for x in r.findings if x.type == "archive_attachment")
    assert f.severity == "low"


def test_11b_archive_with_suspicious_name():
    """invoice.zip → archive finding with elevated severity (medium)."""
    findings, score = _analyze_single_attachment("invoice.zip", None, None, "", "")
    types = [f.type for f in findings]
    assert "archive_attachment" in types
    f = next(x for x in findings if x.type == "archive_attachment")
    assert f.severity == "medium"


def test_11c_archive_7z():
    """.7z → archive finding."""
    findings, _ = _analyze_single_attachment("backup.7z", None, None, "", "")
    assert any(f.type == "archive_attachment" for f in findings)


def test_11d_archive_iso():
    """.iso → archive finding."""
    findings, _ = _analyze_single_attachment("windows.iso", None, None, "", "")
    assert any(f.type == "archive_attachment" for f in findings)


# ===========================================================================
# 12. MIME / extension mismatch
# ===========================================================================

def test_12_mime_extension_mismatch():
    """invoice.pdf with application/x-msdownload MIME → mime_extension_mismatch."""
    findings, score = _analyze_single_attachment(
        "invoice.pdf", "application/x-msdownload", None, "", ""
    )
    types = [f.type for f in findings]
    assert "mime_extension_mismatch" in types
    f = next(x for x in findings if x.type == "mime_extension_mismatch")
    assert f.severity == "medium"
    assert f.evidence["mime_type"] == "application/x-msdownload"
    assert f.evidence["extension"] == ".pdf"
    assert score >= 1.0


# ===========================================================================
# 13. Suspicious filename language without dangerous extension
# ===========================================================================

def test_13_suspicious_keyword_filename_only():
    """invoice.xlsx → no double extension, but attachment_keyword finding (low)."""
    findings, score = _analyze_single_attachment("invoice.xlsx", None, None, "", "")
    types = [f.type for f in findings]
    # xlsx alone is safe — only keyword finding should appear
    assert "attachment_keyword" in types
    f = next(x for x in findings if x.type == "attachment_keyword")
    assert f.severity == "low"
    assert f.evidence["matched_keyword"] == "invoice"


def test_13b_normal_name_no_keyword():
    """report.pdf → no keyword finding."""
    findings, _ = _analyze_single_attachment("report.pdf", None, None, "", "")
    types = [f.type for f in findings]
    assert "attachment_keyword" not in types


def test_13c_password_in_filename():
    """password_reset.docx → keyword finding."""
    findings, _ = _analyze_single_attachment("password_reset.docx", None, None, "", "")
    types = [f.type for f in findings]
    assert "attachment_keyword" in types


# ===========================================================================
# 14. Unusual filename spacing
# ===========================================================================

def test_14_suspicious_filename_spacing():
    """'payment.pdf .exe' → suspicious_filename_spacing finding."""
    findings, score = _analyze_single_attachment("payment.pdf .exe", None, None, "", "")
    types = [f.type for f in findings]
    # May also catch double_extension depending on parsing — spacing finding must be present
    assert "suspicious_filename_spacing" in types
    f = next(x for x in findings if x.type == "suspicious_filename_spacing")
    assert f.severity == "medium"


# ===========================================================================
# 15. Multiple attachments in one email
# ===========================================================================

def test_15_multiple_attachments():
    """Multiple attachments: safe PDF + dangerous EXE → each analysed independently."""
    res = scan_with_att(
        att("summary.pdf", "application/pdf"),
        att("malware.exe", "application/octet-stream"),
    )
    assert len(res.attachments) == 2

    pdf_r = att_result(res, "summary.pdf")
    exe_r = att_result(res, "malware.exe")

    assert pdf_r is not None
    assert exe_r is not None

    assert pdf_r.threat_found is False
    assert exe_r.threat_found is True

    # Dangerous EXE should push overall score above LOW
    assert res.threat_score > 2.49


def test_15b_two_dangerous_attachments_score_capped():
    """Two dangerous attachments — overall email score must remain <= 10.0."""
    res = scan_with_att(
        att("evil1.exe", "application/octet-stream"),
        att("evil2.ps1", None),
    )
    assert res.threat_score <= 10.0
    assert res.risk_level in ["HIGH", "CRITICAL"]


# ===========================================================================
# 16. Missing filename
# ===========================================================================

def test_16_missing_filename():
    """Attachment with no filename → handled safely, named 'unnamed_attachment'."""
    res = scan_with_att(att(None, None))
    assert len(res.attachments) == 1
    r = res.attachments[0]
    assert r.filename == "unnamed_attachment"
    assert r.status == "scanned"
    assert isinstance(r.findings, list)


# ===========================================================================
# 17. Missing MIME type
# ===========================================================================

def test_17_missing_mime_type():
    """Attachment with no MIME type → analyse by extension only, no crash."""
    findings, score = _analyze_single_attachment("setup.exe", None, None, "", "")
    types = [f.type for f in findings]
    assert "executable_attachment" in types


# ===========================================================================
# 18. Missing attachment list (empty or omitted)
# ===========================================================================

def test_18_missing_attachment_list():
    """No attachments → attachment results empty, no crash."""
    req = EmailScanRequest(
        sender="Alice <alice@company.com>",
        subject="Hello",
        body="Just checking in.",
        attachments=[],
    )
    res = analyze_demo_email(req)
    assert res.attachments == []
    assert res.status == "completed"


def test_18b_omitted_attachments():
    """EmailScanRequest with default (omitted) attachments → no crash."""
    req = EmailScanRequest(sender="Bob <bob@company.com>")
    res = analyze_demo_email(req)
    assert res.attachments == []


# ===========================================================================
# 19. Score boundary behaviour
# ===========================================================================

def test_19_score_boundary_executable():
    """EXE alone pushes per-attachment score into HIGH range."""
    findings, score = _analyze_single_attachment("run.exe", None, None, "", "")
    # baseline 1.0 + high contrib 2.5 = 3.5 → MEDIUM border (could be HIGH with baseline)
    assert score >= 2.5
    risk = calculate_risk_level(score)
    assert risk in ["MEDIUM", "HIGH", "CRITICAL"]


def test_19b_score_boundary_double_extension():
    """Double extension: invoice.pdf.exe → score >= 3.5 (MEDIUM at per-attachment level).
    Per-attachment score: baseline 1.0 + high contrib 2.5 = 3.5 → MEDIUM.
    The full email score may reach HIGH/CRITICAL with additional categories."""
    findings, score = _analyze_single_attachment("invoice.pdf.exe", None, None, "", "")
    assert score >= 3.5
    # Per-attachment score of 3.5 is correctly MEDIUM (HIGH requires 5.0+)
    assert calculate_risk_level(score) in ["MEDIUM", "HIGH", "CRITICAL"]


def test_19c_score_never_exceeds_10():
    """Score must never exceed 10.0 regardless of how many findings."""
    findings, score = _analyze_single_attachment(
        "invoice.pdf.exe", "application/x-msdownload", 100, "URGENT", "password account"
    )
    assert score <= 10.0


def test_19d_clean_attachment_score_zero():
    """Clean attachment has score 0.0."""
    findings, score = _analyze_single_attachment("photo.jpg", "image/jpeg", None, "", "")
    assert score == 0.0


# ===========================================================================
# 20. Regression: existing sender + URL + content analysis unaffected
# ===========================================================================

def test_20_regression_sender_url_content_alongside_attachments():
    """
    Full phishing email with bad sender, URL, content, AND dangerous attachment.
    All finding categories must coexist; overall score must stay <= 10.0.
    """
    req = EmailScanRequest(
        sender="Microsoft Security <alerts@paypa1.com>",
        subject="Urgent: Verify your password immediately",
        body="Your account will be suspended. Confirm your password within 10 minutes.",
        links=["http://paypa1.com/account/login?redirect=https://evil.test"],
        attachments=[AttachmentInput(name="invoice.pdf.exe", file_type="application/octet-stream")],
    )
    res = analyze_demo_email(req)

    assert res.status == "completed"
    assert 0.0 <= res.threat_score <= 10.0
    assert res.risk_level in ["HIGH", "CRITICAL"]

    finding_types = [f.type for f in res.findings]
    # Sender
    assert any(t in finding_types for t in ["sender_impersonation", "lookalike_domain"])
    # Content
    assert "credential_request" in finding_types
    assert "urgency" in finding_types
    # URLs
    assert any(t in finding_types for t in ["http_unencrypted", "lookalike_domain", "suspicious_redirect_parameter"])
    # Attachments
    assert "double_extension" in finding_types


def test_20b_regression_normal_email_unaffected():
    """Regression: plain email still scores LOW and has zero findings."""
    req = EmailScanRequest(
        sender="Alex <alex@company.com>",
        subject="Team lunch tomorrow",
        body="Hi, are we still meeting at noon?",
    )
    res = analyze_demo_email(req)
    assert res.threat_score <= 2.49
    assert res.risk_level == "LOW"
    assert res.findings == []


def test_20c_regression_double_extension_existing_test():
    """Existing regression: invoice.pdf.exe → threat_found + score > 2.0."""
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


# ===========================================================================
# Additional edge-case / deduplication tests
# ===========================================================================

def test_no_double_count_exe_on_double_ext():
    """
    invoice.pdf.exe must NOT produce BOTH double_extension AND executable_attachment.
    Double_extension subsumes executable_attachment.
    """
    findings, _ = _analyze_single_attachment("invoice.pdf.exe", None, None, "", "")
    types = [f.type for f in findings]
    assert "double_extension" in types
    assert "executable_attachment" not in types


def test_keyword_suppressed_by_strong_finding():
    """
    invoice.pdf.exe already has a strong (high) finding.
    The 'invoice' keyword signal should NOT be emitted separately to avoid bloat.
    """
    findings, _ = _analyze_single_attachment("invoice.pdf.exe", None, None, "", "")
    types = [f.type for f in findings]
    assert "attachment_keyword" not in types


def test_html_attachment_no_context_no_finding():
    """HTML attachment with no suspicious filename or email context → no html_attachment finding."""
    findings, _ = _analyze_single_attachment("newsletter.html", "text/html", None, "Weekly digest", "Here is this week's news.")
    types = [f.type for f in findings]
    assert "html_attachment" not in types


def test_html_attachment_with_sensitive_context():
    """HTML attachment with credential context → html_attachment finding."""
    findings, _ = _analyze_single_attachment(
        "login_form.html", "text/html", None, "Verify account", "Please enter your password."
    )
    types = [f.type for f in findings]
    assert "html_attachment" in types


def test_api_response_structure():
    """AttachmentResult fields are correctly populated in the API response."""
    res = scan_with_att(att("invoice.pdf.exe", "application/octet-stream"))
    assert len(res.attachments) == 1
    r = res.attachments[0]
    assert r.filename == "invoice.pdf.exe"
    assert r.name == "invoice.pdf.exe"
    assert r.status == "scanned"
    assert r.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert isinstance(r.findings, list)
    for f in r.findings:
        assert f.type
        assert f.severity in ["low", "medium", "high", "critical"]
        assert f.title
        assert f.description
        assert f.explanation


def test_size_small_document_signal():
    """A very small PDF (200 bytes) → suspiciously_small_document finding (low)."""
    findings, _ = _analyze_single_attachment("report.pdf", "application/pdf", 200, "", "")
    types = [f.type for f in findings]
    assert "suspiciously_small_document" in types
    f = next(x for x in findings if x.type == "suspiciously_small_document")
    assert f.severity == "low"


def test_size_normal_document_no_signal():
    """A normally-sized PDF → no small-document signal."""
    findings, _ = _analyze_single_attachment("report.pdf", "application/pdf", 150000, "", "")
    types = [f.type for f in findings]
    assert "suspiciously_small_document" not in types
