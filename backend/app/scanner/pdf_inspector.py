"""
Feature 4: Document Exploit and Structural Anomaly Detection
Feature 5: Invisible Form Traps — Form and Data-Submission Analysis
Inspects PDF and Office structures for anomalies, /Launch, /JavaScript, AcroForms, and submit actions.
"""
import io
import re
import zipfile
from typing import Tuple, List, Dict, Any
from app.schemas import ExploitIndicatorResult, FormSubmissionResult

SENSITIVE_FORM_KEYWORDS = [
    "password", "pwd", "ssn", "social security", "pin", "credit card",
    "cvv", "bank account", "routing", "routing number", "card number"
]

def inspect_structure_and_forms(file_bytes: bytes, filename: str) -> Tuple[ExploitIndicatorResult, FormSubmissionResult]:
    """
    Performs structural inspection for exploit indicators and audits interactive forms / submission hooks.
    """
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    exploit_res = ExploitIndicatorResult()
    form_res = FormSubmissionResult()

    # 1. Archive compression ratio audit (Office / ZIP-based formats)
    if file_bytes.startswith(b"PK\x03\x04"):
        _audit_zip_structure(file_bytes, exploit_res)

    # 2. PDF Deep Structural and Form Audit
    if ext == "pdf" or file_bytes.startswith(b"%PDF"):
        _audit_pdf_structure_and_forms(file_bytes, exploit_res, form_res)
    elif ext in {"html", "htm"}:
        _audit_html_forms(file_bytes, form_res)

    return exploit_res, form_res


def _audit_zip_structure(file_bytes: bytes, res: ExploitIndicatorResult):
    """
    Checks for decompression bomb patterns, nested archives, and unusual compression ratios.
    """
    try:
        compressed_size = max(1, len(file_bytes))
        total_uncompressed = 0
        file_count = 0

        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            infolist = zf.infolist()
            file_count = len(infolist)
            for info in infolist:
                total_uncompressed += info.file_size
                # Check for suspicious nested executables in archive
                name_lower = info.filename.lower()
                if any(name_lower.endswith(sfx) for sfx in [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs"]):
                    res.embedded_payloads.append(f"Executable file inside archive package: {info.filename}")

        ratio = round(total_uncompressed / compressed_size, 2)
        res.compression_ratio = ratio

        if ratio > 100.0 or total_uncompressed > 50 * 1024 * 1024:
            res.structural_anomalies.append(
                f"Abnormal archive compression ratio ({ratio}:1, {total_uncompressed // (1024*1024)}MB uncompressed). Potential decompression bomb."
            )
            res.explanation = "Warning: Abnormal archive compression ratio detected."

        if file_count > 1000:
            res.structural_anomalies.append(f"Unusually large internal package file count: {file_count} entries.")

    except zipfile.BadZipFile:
        res.parser_warnings.append("Malformed ZIP header or truncated central directory.")
    except Exception as e:
        res.parser_warnings.append(f"Archive audit exception: {str(e)}")


def _audit_pdf_structure_and_forms(file_bytes: bytes, exp_res: ExploitIndicatorResult, form_res: FormSubmissionResult):
    """
    Statically audits PDF dictionaries for /Launch, /JavaScript, /AcroForm, /SubmitForm, /AA, and /OpenAction.
    """
    raw_str = file_bytes.decode("latin1", errors="ignore")

    # 1. Exploit Indicators via raw byte pattern matching (resilient against parser evasion)
    # /Launch actions: Executes external binaries
    launch_matches = list(re.finditer(r"/Launch\s*(?:<<[^>]*>>|\[[^\]]*\]|/[A-Za-z0-9_-]+|\([^)]+\))", raw_str))
    if launch_matches:
        for m in launch_matches[:3]:
            exp_res.suspicious_actions.append(f"Dangerous /Launch action detected: '{m.group(0)[:60]}'")
        exp_res.explanation = (
            "The file contains a suspicious launch action. "
            "This is a structural warning, not proof that the document successfully exploits a vulnerability."
        )

    # /JavaScript /JS actions
    js_matches = list(re.finditer(r"/(?:JavaScript|JS)\s*(?:<<|\(|\[|<)", raw_str))
    if js_matches:
        exp_res.suspicious_actions.append(f"Embedded PDF JavaScript stream or dictionary ({len(js_matches)} instance(s))")

    # /EmbeddedFiles /Filespec (droppers)
    emb_matches = list(re.finditer(r"/(?:EmbeddedFiles|FileSpec)\b", raw_str))
    if emb_matches:
        exp_res.embedded_payloads.append(f"Embedded file container (/EmbeddedFiles) detected ({len(emb_matches)} ref(s))")

    # Event-triggered actions /OpenAction, /AA
    open_action_matches = list(re.finditer(r"/(?:OpenAction|AA)\s*<<", raw_str))
    if open_action_matches:
        form_res.event_triggered_behavior.append(f"Automatic event-triggered action (/OpenAction or /AA) on document load")

    # Header check
    if not file_bytes.startswith(b"%PDF"):
        exp_res.structural_anomalies.append("PDF header does not start at offset 0 (prepended header anomaly).")

    # Trailer & EOF check
    if b"%%EOF" not in file_bytes[-2048:]:
        exp_res.structural_anomalies.append("PDF missing standard %%EOF marker near file termination.")

    # 2. PyPDF Catalog and AcroForm extraction
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        trailer = reader.trailer if hasattr(reader, "trailer") else None
        root = reader.root_object if hasattr(reader, "root_object") else {}

        # Inspect AcroForm
        acro_form = root.get("/AcroForm")
        if acro_form:
            form_res.interactive_forms_detected = True
            form_res.form_type = "PDF AcroForm"
            acro_dict = acro_form.get_object() if hasattr(acro_form, "get_object") else acro_form

            # Check for XFA
            if "/XFA" in acro_dict:
                form_res.form_type = "PDF XFA XML Form"
                form_res.evidence.append("Document utilizes dynamic XML Forms Architecture (XFA)")

            # Check fields
            fields = acro_dict.get("/Fields", [])
            for f_ref in fields:
                try:
                    f_obj = f_ref.get_object() if hasattr(f_ref, "get_object") else f_ref
                    field_name = str(f_obj.get("/T", "")).lower()
                    alt_name = str(f_obj.get("/TU", "")).lower()

                    for kw in SENSITIVE_FORM_KEYWORDS:
                        if kw in field_name or kw in alt_name:
                            form_res.sensitive_fields_detected.append(f"Sensitive field: '{field_name or alt_name}'")

                    # Check for submit actions in field actions (/A)
                    action = f_obj.get("/A")
                    if action:
                        act_obj = action.get_object() if hasattr(action, "get_object") else action
                        if act_obj.get("/S") == "/SubmitForm":
                            dest = str(act_obj.get("/F", ""))
                            form_res.submission_actions.append(f"SubmitForm action pointing to destination: {dest}")
                            if dest.startswith("http://") or dest.startswith("https://"):
                                form_res.external_destinations.append(dest)
                except Exception:
                    pass

    except Exception as e:
        exp_res.parser_warnings.append(f"PDF structure parser notification: {str(e)[:100]}")

    # Check for raw /SubmitForm references if pypdf missed any
    submit_raw = list(re.finditer(r"/SubmitForm\b[^>]*", raw_str))
    if submit_raw and not form_res.submission_actions:
        form_res.interactive_forms_detected = True
        form_res.submission_actions.append("PDF contains /SubmitForm action dictionary")

    # Form explanations
    if form_res.external_destinations:
        form_res.explanation = (
            f"This PDF contains an interactive form with an external submission action ({', '.join(form_res.external_destinations)}). "
            f"Do not enter sensitive information until you verify the document's source and destination."
        )
    elif form_res.interactive_forms_detected:
        if form_res.sensitive_fields_detected:
            form_res.explanation = (
                f"Interactive form detected with sensitive field prompts ({', '.join(form_res.sensitive_fields_detected[:3])}). "
                f"No external automated submission targets were identified."
            )
        else:
            form_res.explanation = "Document contains standard benign interactive fillable form fields."
    else:
        form_res.explanation = "No interactive form or submission actions found."

    # Exploit explanation
    if exp_res.suspicious_actions or exp_res.structural_anomalies:
        findings_count = len(exp_res.suspicious_actions) + len(exp_res.structural_anomalies)
        exp_res.explanation = (
            f"Structural audit identified {findings_count} anomalous or active indicators. "
            f"This is a structural warning, not proof that the document successfully exploits a vulnerability."
        )


def _audit_html_forms(file_bytes: bytes, form_res: FormSubmissionResult):
    """
    Populates form audit for HTML documents.
    """
    text = file_bytes.decode("utf-8", errors="ignore").lower()
    if "<form" in text:
        form_res.interactive_forms_detected = True
        form_res.form_type = "HTML Form"
        for kw in SENSITIVE_FORM_KEYWORDS:
            if kw in text:
                form_res.sensitive_fields_detected.append(f"HTML field keyword '{kw}'")
        for m in re.finditer(r'action=["\'](https?://[^"\']+)["\']', text):
            form_res.external_destinations.append(m.group(1))
            form_res.submission_actions.append(f"HTTP POST action to {m.group(1)}")
