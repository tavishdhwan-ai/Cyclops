"""
Cyclops Advanced Document Security Scanner Pipeline
Orchestrates all 9 document security capabilities into a unified, evidence-based assessment.
"""
import hashlib
import time
from typing import Dict, Any, List
from app.schemas import DocumentScanResponse
from app.scanner.macro_inspector import inspect_macros_and_code
from app.scanner.html_doc_inspector import inspect_html_attachment
from app.scanner.doc_links import extract_document_links
from app.scanner.pdf_inspector import inspect_structure_and_forms
from app.scanner.safe_view import generate_safe_view_preview
from app.scanner.script_translator import translate_macro_script
from app.scanner.hidden_content import audit_hidden_content

MAX_DOCUMENT_SIZE = 35 * 1024 * 1024  # 35 MB

def orchestrate_document_scan(file_bytes: bytes, filename: str) -> DocumentScanResponse:
    """
    Executes all 9 document security analysis modules safely in bounded time.
    """
    if len(file_bytes) > MAX_DOCUMENT_SIZE:
        raise ValueError(f"File size exceeds maximum supported limit of {MAX_DOCUMENT_SIZE // (1024*1024)}MB.")

    # 1. Basic Metadata
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size_bytes = len(file_bytes)
    if file_size_bytes < 1024:
        file_size_formatted = f"{file_size_bytes} B"
    elif file_size_bytes < 1024 * 1024:
        file_size_formatted = f"{file_size_bytes / 1024:.1f} KB"
    else:
        file_size_formatted = f"{file_size_bytes / (1024 * 1024):.1f} MB"

    ext = filename.lower().split(".")[-1] if "." in filename else "bin"
    file_type_map = {
        "pdf": "PDF Document (.pdf)",
        "docx": "Word Document (.docx)",
        "docm": "Macro-Enabled Word Document (.docm)",
        "xlsx": "Excel Spreadsheet (.xlsx)",
        "xlsm": "Macro-Enabled Excel Spreadsheet (.xlsm)",
        "pptx": "PowerPoint Presentation (.pptx)",
        "pptm": "Macro-Enabled PowerPoint (.pptm)",
        "html": "HTML Attachment (.html)",
        "htm": "HTML Attachment (.htm)",
    }
    file_type = file_type_map.get(ext, f"Binary File (.{ext})")

    # 2. Execute Feature 1: Macro & Embedded Code
    macro_res = inspect_macros_and_code(file_bytes, filename)

    # 3. Execute Feature 2: HTML Phishing Safety
    html_res = inspect_html_attachment(file_bytes, filename)

    # 4. Execute Feature 3 & 7: Hyperlinks and Brand Domain Consistency
    links_res, brand_res = extract_document_links(file_bytes, filename)

    # 5. Execute Feature 4 & 5: Exploit Indicators and Form Submission
    exploit_res, form_res = inspect_structure_and_forms(file_bytes, filename)

    # 6. Execute Feature 8: Script Translator
    script_res = translate_macro_script(macro_res)

    # 7. Execute Feature 9: Hidden Content Audit
    hidden_res = audit_hidden_content(file_bytes, filename)

    # 8. Execute Feature 6: Safe View Flattened Preview
    safe_view_res = generate_safe_view_preview(file_bytes, filename)

    # 9. Synthesize Unified Risk Score, Verdict, and Signals
    signals: List[str] = []
    risk_score = 0.0

    # Macro risks
    if macro_res.macro_detected:
        if macro_res.suspicious_indicators:
            signals.append(f"High-Risk Automation: {len(macro_res.suspicious_indicators)} suspicious API call(s) in macro code")
            risk_score += 45.0
        else:
            signals.append("Embedded Macro Present (standard automation structure)")
            risk_score += 15.0

    if macro_res.embedded_objects_detected:
        signals.append(f"Embedded Objects: {len(macro_res.embedded_objects_detected)} binary package embedding(s)")
        risk_score += 20.0

    # HTML risks
    if html_res.is_html:
        if html_res.password_fields_found and html_res.external_form_destinations:
            signals.append("Credential Harvesting: HTML form solicits password and submits to external destination")
            risk_score += 50.0
        elif html_res.password_fields_found:
            signals.append("Interactive Login: HTML attachment contains credential login fields")
            risk_score += 25.0
        if html_res.obfuscated_scripts:
            signals.append("Script Obfuscation: Obfuscated JavaScript delivery detected")
            risk_score += 20.0

    # Hyperlink mismatches
    if links_res.mismatched_links_count > 0:
        signals.append(f"Misleading Links: {links_res.mismatched_links_count} hyperlink(s) conceal actual destination")
        risk_score += 25.0

    # Exploit / Launch action
    if exploit_res.suspicious_actions:
        for sa in exploit_res.suspicious_actions:
            signals.append(f"Structural Exploit Indicator: {sa}")
            risk_score += 40.0

    if exploit_res.structural_anomalies:
        signals.append(f"Structural Anomaly: {exploit_res.structural_anomalies[0]}")
        risk_score += 20.0

    # External form submission
    if form_res.external_destinations:
        signals.append("Data Exfiltration Hook: Form contains external submission actions")
        risk_score += 35.0

    # Brand mismatch
    if brand_res.mismatches:
        signals.append(f"Identity Inconsistency: Links route to unverified domain ({brand_res.mismatches[0]})")
        risk_score += 20.0

    # Hidden text
    if hidden_res.hidden_elements_count > 0:
        signals.append(f"Concealed Text: {hidden_res.hidden_elements_count} hidden/microscopic text element(s)")
        risk_score += 15.0

    # Normalize risk score to 0.0 - 100.0
    risk_score = min(100.0, max(0.0, risk_score))

    # Determine Verdict
    if risk_score >= 60.0:
        verdict = "malicious"
        risk_level = "critical"
        executive_summary = (
            f"High-confidence threat signals identified. The document contains active threats "
            f"such as {signals[0].lower() if signals else 'suspicious automation'}. "
            f"Opening this document outside a restricted sandbox risks system compromise."
        )
        recommended_action = "Quarantine document immediately. Do not enable macros, submit credentials, or open links."
    elif risk_score >= 25.0:
        verdict = "suspicious"
        risk_level = "warning"
        executive_summary = (
            f"Suspicious properties detected. Static analysis observed anomalies including "
            f"{signals[0].lower() if signals else 'structural inconsistencies'}. "
            f"Proceed with heightened caution and verify sender authenticity."
        )
        recommended_action = "Inspect in Safe View only. Avoid enabling macros or following embedded links."
    else:
        verdict = "clean"
        risk_level = "safe"
        executive_summary = (
            "Static structural audit completed. No malicious macro execution hooks, credential harvesting forms, "
            "dangerous launch actions, or anomalous concealment techniques were detected."
        )
        recommended_action = "Document appears standard. Normal security hygiene applies."

    return DocumentScanResponse(
        id=f"doc-{hashlib.md5(f'{filename}{time.time()}'.encode()).hexdigest()[:12]}",
        file_name=filename,
        file_size_bytes=file_size_bytes,
        file_size_formatted=file_size_formatted,
        file_type=file_type,
        sha256_hash=sha256_hash,
        timestamp="Just now",
        verdict=verdict,
        risk_level=risk_level,
        risk_score=risk_score,
        detected_signals=signals,
        executive_summary=executive_summary,
        recommended_action=recommended_action,
        macro_inspection=macro_res,
        html_safety=html_res,
        embedded_links=links_res,
        exploit_indicators=exploit_res,
        forms_and_submission=form_res,
        safe_view=safe_view_res,
        brand_domain_consistency=brand_res,
        script_translator=script_res,
        hidden_content=hidden_res,
    )
