"""
Dangerous Download and Hidden File Extension Detector for Cyclops URL Scanner.

Safely evaluates HTTP response headers, URLs, and size-limited body prefixes to identify:
- File downloads versus HTML web pages
- Server-reported Content-Disposition filenames (RFC 6266 / RFC 5987)
- Double extensions (e.g., 'invoice.pdf.exe', 'statement.docx.vbs')
- Discrepancies between filename, Content-Type, and magic byte file signatures
- Executable binaries disguised as benign documents or images

Security Guarantees:
- Never downloads complete files to client device.
- Never executes, renders, or opens scanned payloads.
- Strict inspection prefix limit (first 1024 - 2048 bytes only).
- Explains limitations explicitly without claiming deep dynamic sandboxing.
"""
import re
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

# Dangerous executable and script extension definitions
EXECUTABLE_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".cpl", ".dll", ".msi", ".msp"}
SCRIPT_EXTS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".rb", ".sh", ".bash"}
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".cab"}
DECOY_EXTS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4"}

EXECUTABLE_MIME_TYPES = {
    "application/x-msdownload", "application/x-executable", "application/x-dosexec",
    "application/x-msdos-program", "application/octet-stream", "application/x-sharedlib"
}

SCRIPT_MIME_TYPES = {
    "application/x-sh", "application/x-shellscript", "application/javascript",
    "text/javascript", "application/x-powershell", "text/x-python"
}


class DownloadSafetyResult(BaseModel):
    is_download: bool = False
    server_reported_filename: Optional[str] = None
    effective_extension: Optional[str] = None
    mime_type: Optional[str] = None
    magic_byte_signature: Optional[str] = None
    detected_format: Optional[str] = None
    has_double_extension: bool = False
    is_executable_or_script: bool = False
    mismatch_detected: bool = False
    warning: Optional[str] = None
    explanation: str = "Target returns a standard HTML webpage. No file download was initiated."
    inspection_limitations: List[str] = Field(default_factory=list)


def parse_content_disposition_filename(header_val: Optional[str]) -> Optional[str]:
    """
    Extracts filename from Content-Disposition header.
    Handles filename*=UTF-8''encoded_name and filename="standard_name".
    """
    if not header_val:
        return None

    # 1. Check for RFC 5987 / RFC 6266 filename*=
    ext_match = re.search(r"filename\*\s*=\s*(?:UTF-8|iso-8859-1)?''([^;]+)", header_val, re.IGNORECASE)
    if ext_match:
        try:
            return urllib.parse.unquote(ext_match.group(1).strip().strip('"'))
        except Exception:
            pass

    # 2. Check for standard filename="..." or filename=...
    std_match = re.search(r'filename\s*=\s*"([^"]+)"', header_val, re.IGNORECASE)
    if std_match:
        return std_match.group(1).strip()

    fallback_match = re.search(r'filename\s*=\s*([^; ]+)', header_val, re.IGNORECASE)
    if fallback_match:
        return fallback_match.group(1).strip().strip('"')

    return None


def extract_url_filename(url: str) -> Optional[str]:
    """Extracts basename filename from URL path if it has an extension."""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path.rstrip("/")
    if not path:
        return None
    basename = path.split("/")[-1]
    if "." in basename:
        return urllib.parse.unquote(basename)
    return None


def inspect_magic_bytes(prefix_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Inspects leading file bytes for standard magic number signatures.
    Returns (signature_name, broad_category).
    """
    if not prefix_bytes:
        return None, None

    # MZ Header (Windows PE executable / DLL)
    if prefix_bytes.startswith(b"MZ"):
        return "Windows PE Executable / DLL (MZ Header)", "executable"

    # ELF Header (Linux / Unix binary)
    if prefix_bytes.startswith(b"\x7fELF"):
        return "Linux / Unix Executable (ELF Header)", "executable"

    # Mach-O (macOS binary)
    if prefix_bytes.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
        return "macOS Mach-O Executable", "executable"

    # PDF Document
    if prefix_bytes.startswith(b"%PDF-"):
        return "PDF Document Header", "document"

    # ZIP / Office OpenXML
    if prefix_bytes.startswith(b"PK\x03\x04"):
        return "PK ZIP / Office OpenXML Archive", "archive"

    # 7-Zip
    if prefix_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip Compressed Archive", "archive"

    # RAR Archive
    if prefix_bytes.startswith(b"Rar!\x1a\x07"):
        return "RAR Compressed Archive", "archive"

    # GZIP
    if prefix_bytes.startswith(b"\x1f\x8b"):
        return "GZIP Compressed File", "archive"

    # OLE2 Compound File (Legacy MS Office .doc / .xls / .ppt, possible macro container)
    if prefix_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "Microsoft Compound OLE2 Document", "document"

    # Script shebang
    if prefix_bytes.startswith(b"#!"):
        return "Shell Script (Shebang header)", "script"

    # HTML / Text
    lower_prefix = prefix_bytes[:200].lower()
    if b"<!doctype html" in lower_prefix or b"<html" in lower_prefix or b"<head" in lower_prefix:
        return "HTML Webpage Content", "webpage"

    return "Unknown or Generic Binary/Text Stream", "unknown"


def evaluate_download_safety(
    final_url: str,
    headers: Dict[str, str],
    prefix_bytes: bytes,
    content_length: int = 0
) -> DownloadSafetyResult:
    """
    Evaluates response headers and leading body bytes for download risk indicators.
    """
    limitations = [
        "Analysis performed on HTTP response headers and initial 1 KB buffer only.",
        "Full dynamic execution and deep malware sandbox analysis were NOT performed.",
        "Payloads were NOT downloaded to disk or executed."
    ]

    cd_header = headers.get("content-disposition") or headers.get("Content-Disposition")
    ct_header = headers.get("content-type") or headers.get("Content-Type") or ""
    mime_type = ct_header.split(";")[0].strip().lower() if ct_header else "unknown"

    reported_filename = parse_content_disposition_filename(cd_header)
    url_filename = extract_url_filename(final_url)

    effective_filename = reported_filename or url_filename
    is_attachment = bool(cd_header and "attachment" in cd_header.lower())

    # Detect if response is a download
    is_download = is_attachment or (
        mime_type in EXECUTABLE_MIME_TYPES or
        mime_type.startswith("application/x-") or
        mime_type in {"application/zip", "application/pdf", "application/octet-stream"} or
        (effective_filename is not None and not mime_type.startswith("text/html"))
    )

    magic_sig, magic_category = inspect_magic_bytes(prefix_bytes)

    # If it's pure HTML and no download header, return clean webpage result
    if not is_download and (mime_type.startswith("text/html") or magic_category == "webpage"):
        return DownloadSafetyResult(
            is_download=False,
            mime_type=mime_type,
            magic_byte_signature=magic_sig,
            detected_format="HTML Webpage",
            explanation="Target returns standard static HTML webpage content. No file download was initiated.",
            inspection_limitations=limitations
        )

    # Analyze file extension
    effective_extension = None
    has_double_ext = False
    is_exec_or_script = False
    mismatch = False
    warning = None

    if effective_filename:
        clean_name = effective_filename.lower()
        parts = clean_name.split(".")
        if len(parts) >= 2:
            effective_extension = f".{parts[-1]}"

            # Double extension check (e.g. invoice.pdf.exe)
            if len(parts) >= 3:
                second_ext = f".{parts[-2]}"
                if second_ext in DECOY_EXTS and effective_extension in (EXECUTABLE_EXTS | SCRIPT_EXTS | ARCHIVE_EXTS):
                    has_double_ext = True

            if effective_extension in EXECUTABLE_EXTS or effective_extension in SCRIPT_EXTS:
                is_exec_or_script = True

    # Check for mismatch between filename claim and magic bytes / MIME type
    if effective_filename:
        clean_name = effective_filename.lower()
        claimed_doc = any(clean_name.endswith(ext) for ext in DECOY_EXTS)

        # Disguise check 1: claims document extension but magic bytes indicate Windows executable
        if claimed_doc and magic_category == "executable":
            mismatch = True
            warning = "The server reports an executable file, although its filename resembles a document. Do not open it unless you can verify its origin."

        # Disguise check 2: double extension
        elif has_double_ext:
            mismatch = True
            warning = f"Disguised double file extension detected: '{effective_filename}'. The file ends in an executable/script extension disguised behind a document extension."

        # Disguise check 3: claims PDF/doc but MIME is application/x-msdownload
        elif claimed_doc and mime_type in EXECUTABLE_MIME_TYPES:
            mismatch = True
            warning = f"Content-Type mismatch: Server declares '{mime_type}' for a file named '{effective_filename}'."

    # Construct plain English explanation
    if mismatch and warning:
        explanation = warning
    elif is_exec_or_script:
        explanation = f"Target returns an executable binary or script payload ('{effective_filename or effective_extension}'). Executable downloads from untrusted sources present high security risks."
        if not warning:
            warning = f"Executable file download detected ({effective_filename or effective_extension}). Confirm source authenticity before downloading."
    elif has_double_ext:
        explanation = f"Target disguised with deceptive double extension '{effective_filename}'."
    elif is_download:
        explanation = f"Target initiates a file download ({effective_filename or 'unnamed file'}, MIME: {mime_type})."
    else:
        explanation = "No suspicious file download indicators detected."

    return DownloadSafetyResult(
        is_download=True,
        server_reported_filename=effective_filename,
        effective_extension=effective_extension,
        mime_type=mime_type,
        magic_byte_signature=magic_sig,
        detected_format=magic_sig or mime_type,
        has_double_extension=has_double_ext,
        is_executable_or_script=is_exec_or_script,
        mismatch_detected=mismatch,
        warning=warning,
        explanation=explanation,
        inspection_limitations=limitations
    )
