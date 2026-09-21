"""
Attachment metadata analysis for SentinelAI scanner — Phase 4A.3.

IMPORTANT: All analysis is completely passive and metadata-only.
- No attachment contents are accessed, read, or uploaded.
- No files are executed, opened, rendered, or decompressed.
- No archives are extracted.
- No external reputation APIs are used.
- Only filename, MIME type/file_type, and size (when available) are inspected.
"""
import os
import re
from typing import List, Tuple, Any, Optional, Set
from app.schemas import Finding, AttachmentResult
from app.scanner.scoring import calculate_risk_level

# ---------------------------------------------------------------------------
# Extension classification tables
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".cpl", ".dll",
}

SCRIPT_EXTENSIONS: Set[str] = {
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".vbe", ".py", ".rb", ".sh", ".bash",
}

SHORTCUT_EXTENSIONS: Set[str] = {
    ".lnk", ".url", ".webloc",
}

INSTALLER_EXTENSIONS: Set[str] = {
    ".msi", ".msp", ".mst", ".cab", ".appx", ".msix",
}

MACRO_OFFICE_EXTENSIONS: Set[str] = {
    ".docm", ".xlsm", ".xltm", ".pptm", ".dotm", ".xlam", ".xla",
}

ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".iso", ".img", ".dmg",
}

HTML_EXTENSIONS: Set[str] = {".html", ".htm", ".mhtml", ".mht"}

# Safe / common types that should not produce findings on their own
SAFE_DOCUMENT_EXTENSIONS: Set[str] = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods",
    ".odp", ".txt", ".csv", ".rtf", ".pages", ".numbers", ".key",
}

SAFE_IMAGE_EXTENSIONS: Set[str] = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff", ".ico",
}

SAFE_MEDIA_EXTENSIONS: Set[str] = {
    ".mp3", ".mp4", ".m4a", ".avi", ".mov", ".mkv", ".wav", ".flac",
}

# All dangerous executable/script/shortcut/installer families combined
ALL_DANGEROUS_EXTENSIONS: Set[str] = (
    EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | SHORTCUT_EXTENSIONS | INSTALLER_EXTENSIONS
)

# Benign-looking extensions commonly used as a disguise prefix in double-ext attacks
BENIGN_DECOY_EXTENSIONS: Set[str] = {
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4",
}

# Social-engineering filename keywords
SUSPICIOUS_FILENAME_KEYWORDS: List[str] = [
    "invoice", "payment", "refund", "urgent", "salary", "payroll",
    "password", "verification", "account", "secure", "document",
    "receipt", "order", "tax", "w-2", "w2", "statement",
]

# MIME type → expected extension families (broad groupings only)
MIME_EXTENSION_FAMILIES = {
    "application/pdf": {".pdf"},
    "application/msword": {".doc", ".dot"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls", ".csv"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.ms-powerpoint": {".ppt"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    "application/x-msdownload": {".exe", ".dll"},
    "application/x-executable": {".exe"},
    "application/x-dosexec": {".exe", ".com"},
    "application/x-msdos-program": {".exe", ".com", ".bat", ".cmd"},
    "application/x-sh": {".sh"},
    "application/x-shellscript": {".sh"},
    "application/javascript": {".js"},
    "text/javascript": {".js"},
    "application/zip": {".zip"},
    "application/x-7z-compressed": {".7z"},
    "application/vnd.rar": {".rar"},
    "application/x-rar-compressed": {".rar"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "image/webp": {".webp"},
    "image/svg+xml": {".svg"},
    "text/html": {".html", ".htm"},
    "text/plain": {".txt", ".csv", ".log"},
    "application/octet-stream": None,   # generic binary — mismatch checked separately
}

# MIME types that strongly suggest an executable regardless of declared extension
DANGEROUS_MIME_TYPES: Set[str] = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/x-sh",
    "application/x-shellscript",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_file_extension(filename: str) -> str:
    """Return the final lowercase extension of a filename (e.g. '.exe')."""
    _, ext = os.path.splitext(filename.lower())
    return ext


def _get_all_extensions(filename: str) -> List[str]:
    """Return all extensions of a filename (e.g. ['pdf', 'exe'] for 'foo.pdf.exe')."""
    name = filename.lower()
    parts = name.split(".")
    if len(parts) <= 1:
        return []
    return ["." + p for p in parts[1:]]


def _classify_extension(ext: str) -> str:
    """Return a human-readable category label for an extension."""
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in SCRIPT_EXTENSIONS:
        return "script"
    if ext in SHORTCUT_EXTENSIONS:
        return "shortcut"
    if ext in INSTALLER_EXTENSIONS:
        return "installer"
    if ext in MACRO_OFFICE_EXTENSIONS:
        return "macro-enabled document"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive/container"
    if ext in HTML_EXTENSIONS:
        return "html"
    if ext in SAFE_DOCUMENT_EXTENSIONS:
        return "document"
    if ext in SAFE_IMAGE_EXTENSIONS:
        return "image"
    if ext in SAFE_MEDIA_EXTENSIONS:
        return "media"
    return "unknown"


def _normalize_mime(mime: Optional[str]) -> Optional[str]:
    """Lowercase and strip parameters from MIME type (e.g. 'text/html; charset=utf-8' → 'text/html')."""
    if not mime:
        return None
    return mime.lower().split(";")[0].strip()


# ---------------------------------------------------------------------------
# Per-attachment analysis
# ---------------------------------------------------------------------------

def _analyze_single_attachment(
    filename: str,
    file_type: Optional[str],
    size_bytes: Optional[int],
    email_subject: Optional[str],
    email_body: Optional[str],
) -> Tuple[List[Finding], float]:
    """
    Analyse one attachment's metadata and return (findings, per-attachment_threat_score).
    All analysis is passive: no bytes are read, no files are opened.
    """
    findings: List[Finding] = []
    filename_lower = filename.lower()
    final_ext = _get_file_extension(filename)
    all_exts = _get_all_extensions(filename)
    mime = _normalize_mime(file_type)
    context_text = f"{email_subject or ''} {email_body or ''}".lower()

    # Track which signal types have already been emitted to prevent double-counting
    emitted: Set[str] = set()

    # -----------------------------------------------------------------------
    # A. DOUBLE / MULTIPLE EXTENSION CHECK
    # -----------------------------------------------------------------------
    if len(all_exts) >= 2:
        penultimate_ext = all_exts[-2]
        if final_ext in ALL_DANGEROUS_EXTENSIONS and penultimate_ext in BENIGN_DECOY_EXTENSIONS:
            category_label = _classify_extension(final_ext)
            findings.append(Finding(
                id="double_extension",
                category="attachments",
                type="double_extension",
                severity="high",
                title="Double file extension",
                description=(
                    f"The attachment '{filename}' uses a benign-looking document extension "
                    f"('{penultimate_ext}') before a {category_label} extension ('{final_ext}'). "
                    "This is a common technique used to disguise the true file type."
                ),
                explanation=(
                    "The filename uses a benign-looking document extension before an executable "
                    "or script extension. This pattern is a classic method to disguise malicious "
                    "attachments as ordinary documents."
                ),
                evidence={"filename": filename, "decoy_extension": penultimate_ext, "real_extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("double_extension")

    # -----------------------------------------------------------------------
    # B. EXECUTABLE / SCRIPT / SHORTCUT EXTENSION CHECK
    #    Only add if not already covered by double_extension (to avoid double-counting)
    # -----------------------------------------------------------------------
    if "double_extension" not in emitted:
        if final_ext in EXECUTABLE_EXTENSIONS:
            findings.append(Finding(
                id="executable_attachment",
                category="attachments",
                type="executable_attachment",
                severity="high",
                title="Executable attachment",
                description=(
                    f"This attachment ends in '{final_ext}', an executable file type that can "
                    "run code when opened."
                ),
                explanation=(
                    f"The attachment has an executable extension ('{final_ext}'). "
                    "Executable attachments can run arbitrary code when opened and are "
                    "a common malware delivery vector."
                ),
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("executable_attachment")

        elif final_ext in SCRIPT_EXTENSIONS:
            findings.append(Finding(
                id="script_attachment",
                category="attachments",
                type="script_attachment",
                severity="high",
                title="Script file attachment",
                description=(
                    f"This attachment ends in '{final_ext}', a script file type that can "
                    "execute commands when opened."
                ),
                explanation=(
                    f"The attachment has a script extension ('{final_ext}'). "
                    "Script attachments can run arbitrary commands and are frequently "
                    "used in phishing attacks."
                ),
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("script_attachment")

        elif final_ext in SHORTCUT_EXTENSIONS:
            findings.append(Finding(
                id="shortcut_attachment",
                category="attachments",
                type="shortcut_attachment",
                severity="high",
                title="Shortcut file attachment",
                description=(
                    f"This attachment ends in '{final_ext}', a Windows shortcut file that can "
                    "point to arbitrary executables or remote resources."
                ),
                explanation=(
                    f"Shortcut files ('{final_ext}') can reference executables or network "
                    "paths and are used to bypass safe attachment handling."
                ),
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("shortcut_attachment")

        elif final_ext in INSTALLER_EXTENSIONS:
            findings.append(Finding(
                id="installer_attachment",
                category="attachments",
                type="installer_attachment",
                severity="high",
                title="Installer package attachment",
                description=(
                    f"This attachment ends in '{final_ext}', an installer package that can "
                    "modify the system when executed."
                ),
                explanation=(
                    f"Installer attachments ('{final_ext}') are capable of making system-level "
                    "changes and represent a significant risk if the source is untrusted."
                ),
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("installer_attachment")

    # -----------------------------------------------------------------------
    # C. MACRO-ENABLED OFFICE DOCUMENT
    # -----------------------------------------------------------------------
    if final_ext in MACRO_OFFICE_EXTENSIONS and "double_extension" not in emitted:
        findings.append(Finding(
            id="macro_enabled_document",
            category="attachments",
            type="macro_enabled_document",
            severity="high",
            title="Macro-enabled Office document",
            description=(
                f"The attachment '{filename}' is a macro-enabled Office document "
                f"('{final_ext}'). Macros can execute code automatically when the file is opened."
            ),
            explanation=(
                "Macro-enabled Office documents can contain embedded code that executes "
                "when the file is opened. This is a common technique for delivering malware."
            ),
            evidence={"filename": filename, "extension": final_ext},
            score_contribution=2.5,
        ))
        emitted.add("macro_enabled_document")

    # -----------------------------------------------------------------------
    # D. SUSPICIOUS HTML ATTACHMENT
    # -----------------------------------------------------------------------
    if final_ext in HTML_EXTENSIONS:
        has_sensitive_context = any(
            kw in context_text for kw in ["login", "password", "verify", "account", "billing", "credential"]
        )
        has_keyword_in_name = any(kw in filename_lower for kw in SUSPICIOUS_FILENAME_KEYWORDS)
        if has_sensitive_context or has_keyword_in_name:
            findings.append(Finding(
                id="html_attachment",
                category="attachments",
                type="html_attachment",
                severity="high",
                title="Suspicious HTML attachment",
                description=(
                    f"The HTML attachment '{filename}' combined with credential or account "
                    "language is a common phishing vector used to capture sensitive information."
                ),
                explanation=(
                    "HTML attachments can render fake login pages locally without requiring "
                    "an internet connection. Combined with urgency or credential language, "
                    "this is a recognised phishing technique."
                ),
                evidence={"filename": filename, "extension": final_ext},
                score_contribution=2.5,
            ))
            emitted.add("html_attachment")

    # -----------------------------------------------------------------------
    # E. ARCHIVE / CONTAINER
    # -----------------------------------------------------------------------
    if final_ext in ARCHIVE_EXTENSIONS:
        # Archives are contextual — elevated when combined with suspicious filename keywords
        has_suspicious_name = any(kw in filename_lower for kw in SUSPICIOUS_FILENAME_KEYWORDS)
        severity = "medium" if has_suspicious_name else "low"
        contrib = 1.5 if has_suspicious_name else 0.5
        findings.append(Finding(
            id="archive_attachment",
            category="attachments",
            type="archive_attachment",
            severity=severity,
            title="Archive or container attachment",
            description=(
                f"The attachment '{filename}' is an archive or container file ('{final_ext}'). "
                "Archives can conceal the actual file types of their contents."
            ),
            explanation=(
                "Archive files can contain files of any type, including executables, "
                "and the contents are not inspected by metadata-only analysis. "
                "Exercise caution, especially when the sender or email context is suspicious."
            ),
            evidence={"filename": filename, "extension": final_ext},
            score_contribution=contrib,
        ))
        emitted.add("archive_attachment")

    # -----------------------------------------------------------------------
    # F. MIME / EXTENSION MISMATCH
    # -----------------------------------------------------------------------
    if mime and final_ext and mime != "application/octet-stream":
        expected_exts = MIME_EXTENSION_FAMILIES.get(mime)
        if expected_exts is not None and final_ext not in expected_exts:
            # Only flag if the mismatch is actually suspicious (not just an unknown type)
            if mime in DANGEROUS_MIME_TYPES or (
                mime.startswith("application/") and final_ext in SAFE_DOCUMENT_EXTENSIONS | SAFE_IMAGE_EXTENSIONS
            ):
                findings.append(Finding(
                    id="mime_extension_mismatch",
                    category="attachments",
                    type="mime_extension_mismatch",
                    severity="medium",
                    title="Attachment metadata mismatch",
                    description=(
                        f"The declared MIME type ('{mime}') does not match the filename "
                        f"extension ('{final_ext}') of '{filename}'."
                    ),
                    explanation=(
                        "The declared content type does not match the filename extension. "
                        "This inconsistency can indicate a disguised file type."
                    ),
                    evidence={"filename": filename, "mime_type": mime, "extension": final_ext},
                    score_contribution=1.5,
                ))
                emitted.add("mime_extension_mismatch")

    # -----------------------------------------------------------------------
    # G. SUSPICIOUS FILENAME LANGUAGE
    #    Only emit if not already captured by a stronger finding
    # -----------------------------------------------------------------------
    strong_findings = {"double_extension", "executable_attachment", "script_attachment",
                       "shortcut_attachment", "installer_attachment", "macro_enabled_document",
                       "html_attachment"}
    if not emitted.intersection(strong_findings):
        for kw in SUSPICIOUS_FILENAME_KEYWORDS:
            if kw in filename_lower:
                findings.append(Finding(
                    id="attachment_keyword",
                    category="attachments",
                    type="attachment_keyword",
                    severity="low",
                    title="Social-engineering filename",
                    description=(
                        f"The attachment filename '{filename}' contains the term '{kw}', "
                        "which is commonly used in social engineering to create urgency or "
                        "legitimacy."
                    ),
                    explanation=(
                        "The filename contains language often used in phishing or social "
                        "engineering. This alone is not conclusive, but should be considered "
                        "in combination with other signals."
                    ),
                    evidence={"filename": filename, "matched_keyword": kw},
                    score_contribution=0.5,
                ))
                break  # one keyword finding per attachment is enough

    # -----------------------------------------------------------------------
    # H. UNUSUAL FILENAME PATTERNS
    # -----------------------------------------------------------------------

    # H1. Suspicious trailing/leading whitespace near extension
    if re.search(r'\s+\.\w+$', filename) or re.search(r'\.\w+\s+\.\w+$', filename):
        findings.append(Finding(
            id="suspicious_filename_spacing",
            category="attachments",
            type="suspicious_filename_spacing",
            severity="medium",
            title="Suspicious filename spacing",
            description=(
                f"The filename '{filename}' contains unusual whitespace near the file extension, "
                "which can be used to obscure the true file type."
            ),
            explanation=(
                "Unusual whitespace before or around extensions is a known technique "
                "to disguise the real file type from users."
            ),
            evidence={"filename": filename},
            score_contribution=1.5,
        ))
        emitted.add("suspicious_filename_spacing")

    # H2. Suspiciously long filename (threshold: >100 chars)
    if len(filename) > 100 and "suspicious_filename_spacing" not in emitted:
        findings.append(Finding(
            id="long_filename",
            category="attachments",
            type="long_filename",
            severity="low",
            title="Unusually long filename",
            description=(
                f"The attachment filename is unusually long ({len(filename)} characters), "
                "which can be a technique to push the true extension beyond visible display limits."
            ),
            explanation=(
                "Excessively long filenames can obscure the true file extension by pushing "
                "it off-screen or beyond the visible portion of a filename."
            ),
            evidence={"filename": filename, "length": len(filename)},
            score_contribution=0.5,
        ))

    # H3. Excessive punctuation (excluding the extension dots)
    base_name = os.path.splitext(filename)[0]
    punctuation_count = sum(1 for c in base_name if c in "!@#$%^&*()+=[]{}|\\:;<>?,/~`")
    if punctuation_count >= 4:
        findings.append(Finding(
            id="excessive_punctuation_filename",
            category="attachments",
            type="excessive_punctuation_filename",
            severity="low",
            title="Excessive punctuation in filename",
            description=(
                f"The attachment filename '{filename}' contains an unusual amount of punctuation "
                f"({punctuation_count} special characters), which may indicate an obfuscated name."
            ),
            explanation=(
                "Filenames with excessive special characters are uncommon and may indicate "
                "an attempt to obfuscate the attachment's true purpose."
            ),
            evidence={"filename": filename, "punctuation_count": punctuation_count},
            score_contribution=0.5,
        ))

    # -----------------------------------------------------------------------
    # I. SIZE-BASED CONTEXTUAL SIGNAL (if size available)
    # -----------------------------------------------------------------------
    # Very small files claiming to be documents can be suspicious (e.g. empty decoys)
    # Only flag if declaring a document extension but is suspiciously tiny (<512 bytes)
    if (
        size_bytes is not None
        and size_bytes < 512
        and final_ext in SAFE_DOCUMENT_EXTENSIONS
        and not emitted.intersection(strong_findings)
    ):
        findings.append(Finding(
            id="suspiciously_small_document",
            category="attachments",
            type="suspiciously_small_document",
            severity="low",
            title="Suspiciously small document",
            description=(
                f"The attachment '{filename}' declares itself as a document but is only "
                f"{size_bytes} bytes, which is unusually small."
            ),
            explanation=(
                "A file claiming to be a document but containing very little data may be "
                "a decoy or an incomplete/test file. This is a low-severity contextual signal."
            ),
            evidence={"filename": filename, "size_bytes": size_bytes},
            score_contribution=0.5,
        ))

    # -----------------------------------------------------------------------
    # Per-attachment threat score
    # -----------------------------------------------------------------------
    att_score = _calculate_attachment_score(findings)
    return findings, att_score


def _calculate_attachment_score(findings: List[Finding]) -> float:
    """
    Calculate a continuous 0.0–10.0 threat score for a single attachment.
    Uses a baseline of 1.0 when any finding exists, then adds contribution per finding.
    Clamped to 10.0.
    """
    if not findings:
        return 0.0

    baseline = 1.0
    total = baseline
    for f in findings:
        contrib = f.score_contribution
        if contrib is None:
            contrib = {"critical": 3.0, "high": 2.5, "medium": 1.5, "low": 0.5}.get(f.severity, 0.5)
        total += contrib

    return round(min(10.0, max(0.0, total)), 1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_attachments(
    attachments_input: List[Any],
    email_subject: Optional[str],
    email_body: Optional[str],
) -> Tuple[List[AttachmentResult], List[Finding]]:
    """
    Passively analyze attachment metadata against static risk rules.

    Returns:
        - List[AttachmentResult]: per-attachment structured results
        - List[Finding]: flat list of all findings for email-level scoring integration
    """
    attachment_results: List[AttachmentResult] = []
    aggregated_findings: List[Finding] = []

    for att in attachments_input:
        # Safely extract fields from either a Pydantic model or a plain dict
        if isinstance(att, dict):
            filename = att.get("name") or att.get("filename") or "unnamed_attachment"
            file_type = att.get("file_type") or att.get("content_type") or att.get("mime_type")
            size_bytes = att.get("size_bytes")
        else:
            filename = getattr(att, "name", None) or getattr(att, "filename", None) or "unnamed_attachment"
            file_type = getattr(att, "file_type", None)
            size_bytes = getattr(att, "size_bytes", None)

        att_findings, att_score = _analyze_single_attachment(
            filename=filename,
            file_type=file_type,
            size_bytes=size_bytes,
            email_subject=email_subject,
            email_body=email_body,
        )

        att_risk = calculate_risk_level(att_score)

        if att_findings:
            summary = f"Attachment '{filename}' flagged {len(att_findings)} security indicator(s)."
        else:
            summary = f"Attachment '{filename}' passed metadata inspection with no suspicious indicators."

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
