"""
Feature 1: Hidden Trapdoor — Macro and Embedded Code Detection
Safely inspects Office Open XML (DOCX, XLSX, XLSM, DOCM) and OLE packages without executing code.
"""
import io
import re
import zipfile
from typing import Dict, Any, List, Tuple
from app.schemas import MacroInspectionResult


SUSPICIOUS_EXEC_PATTERNS = [
    (r"(?i)\b(?:wscript\.shell|shell\.application|createobject\s*\(\s*[\"']wscript\.shell[\"']\s*\))", "Process creation via WScript.Shell", "high"),
    (r"(?i)\b(?:cmd\.exe|powershell(?:\.exe)?|mshta(?:\.exe)?|cscript(?:\.exe)?|wscript(?:\.exe)?|rundll32(?:\.exe)?)", "Direct command-line or script interpreter execution", "critical"),
    (r"(?i)\b(?:urldownloadtofile(?:a|w)?|msxml2\.xmlhttp|winhttp\.winhttprequest|msxml2\.serverxmlhttp)", "Remote network file retrieval or HTTP request", "critical"),
    (r"(?i)\b(?:autoopen|auto_open|document_open|workbook_open|autoexec|autoexit|document_close)\b", "Automatic execution hook on document open/close", "medium"),
    (r"(?i)\b(?:environ\s*\(\s*[\"'](?:temp|appdata|userprofile)[\"']\s*\))", "Staging payload in user or temporary directories", "medium"),
    (r"(?i)\b(?:scripting\.filesystemobject)\b", "Direct file system manipulation", "low"),
    (r"(?i)(?:chr(?:w)?\s*\(\s*\d+\s*\)\s*&\s*){3,}", "Dynamic string obfuscation using chained Chr() functions", "high"),
    (r"(?i)\bstrreverse\s*\(", "String reversal obfuscation technique", "medium"),
    (r"(?i)\b(?:callbyname|alias\s+[\"'](?:kernel32|ntdll|advapi32)[\"'])", "Low-level Windows API invocation or DLL loading", "high"),
]

def inspect_macros_and_code(file_bytes: bytes, filename: str) -> MacroInspectionResult:
    """
    Statically analyzes Office documents for embedded macros, OLE objects,
    external relationships, and suspicious automation patterns.
    """
    res = MacroInspectionResult()
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_macro_extension = ext in {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam"}

    # Check for ZIP structure (OOXML: docx, xlsx, xlsm, docm, etc.)
    if not file_bytes.startswith(b"PK\x03\x04"):
        # Check if legacy OLE compound file
        if file_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            res.affected_components.append("Legacy OLE Compound Binary File")
            # Search for VBA keywords in raw binary
            vba_indicators = [b"VBA_Project", b"dir\x00", b"_VBA_PROJECT", b"Attribut"]
            found_vba = any(ind in file_bytes for ind in vba_indicators)
            if found_vba:
                res.macro_detected = True
                res.status = "detected"
                res.extracted_code_status = "Extracted OLE macro binary streams"
                _analyze_raw_macro_stream(file_bytes, res)
            else:
                res.status = "not_detected"
                res.explanation = "Legacy OLE format inspected; no VBA project signatures detected."
            return res

        # Not an Office Open XML or OLE file
        if ext in {"doc", "docx", "xls", "xlsx", "xlsm", "docm", "ppt", "pptm"}:
            res.status = "unable_to_inspect"
            res.explanation = "Document header does not match valid ZIP or OLE package specifications."
        else:
            res.status = "not_detected"
            res.explanation = f"File format (.{ext}) does not contain Office VBA automation structures."
        return res

    # Inspect ZIP structure safely
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            file_list = zf.namelist()
            vba_parts = [f for f in file_list if "vbaProject" in f or "vbaData" in f]
            ole_parts = [f for f in file_list if "oleObject" in f or "embeddings/" in f]
            rels_parts = [f for f in file_list if f.endswith(".rels")]

            if vba_parts:
                res.macro_detected = True
                res.status = "detected"
                res.affected_components.extend(vba_parts)
                res.extracted_code_status = f"Found {len(vba_parts)} VBA package part(s)"

                # Extract and analyze VBA stream content statically
                extracted_bytes = bytearray()
                for vp in vba_parts:
                    try:
                        extracted_bytes.extend(zf.read(vp))
                    except Exception:
                        pass
                if extracted_bytes:
                    _analyze_raw_macro_stream(bytes(extracted_bytes), res)
            elif is_macro_extension:
                res.macro_detected = True
                res.status = "detected"
                res.warnings.append(f"File uses macro-enabled extension (.{ext}) but VBA project parts could not be unpacked.")
                res.explanation = "Document has macro-enabled packaging format."
            else:
                res.macro_detected = False
                res.status = "not_detected"
                res.explanation = "Document package examined. Standard Office Open XML file with no embedded VBA projects."

            if ole_parts:
                res.embedded_objects_detected.extend(ole_parts)
                res.affected_components.extend(ole_parts)
                for op in ole_parts:
                    if any(op.lower().endswith(bad) for bad in [".bin", ".exe", ".scr", ".bat"]):
                        res.suspicious_indicators.append(f"Embedded binary OLE object detected: {op}")

            # Inspect external relationships in .rels files
            for rel_file in rels_parts:
                try:
                    rel_content = zf.read(rel_file).decode("utf-8", errors="ignore")
                    # Check for TargetMode="External" with suspicious targets
                    for match in re.finditer(r'Target="([^"]+)"[^>]*TargetMode="External"', rel_content, re.IGNORECASE):
                        target = match.group(1)
                        if any(target.lower().startswith(p) for p in ["http://", "https://", "ftp://", "file://", "\\\\"]):
                            res.suspicious_indicators.append(f"External package relationship pointing to: {target}")
                            res.affected_components.append(f"{rel_file} -> {target}")
                except Exception:
                    pass

    except zipfile.BadZipFile:
        res.status = "unable_to_inspect"
        res.explanation = "Corrupted or non-standard ZIP archive header encountered during OOXML inspection."
        res.warnings.append("Archive decompression failed.")
    except Exception as e:
        res.status = "unable_to_inspect"
        res.explanation = "Inspection halted due to internal package parser limitation."
        res.warnings.append(str(e))

    # Formulate plain-language explanation
    if res.macro_detected:
        if res.suspicious_indicators:
            res.explanation = (
                f"Warning: This document contains an embedded macro. Static analysis identified "
                f"{len(res.suspicious_indicators)} suspicious indicator(s) including "
                f"{', '.join(res.suspicious_indicators[:2])}. "
                f"Do not enable macros unless you trust the source."
            )
        else:
            res.explanation = (
                "Notice: This document contains an embedded macro project. "
                "However, static analysis did not identify high-risk automation routines (such as process execution or file downloads). "
                "Verify sender authenticity before enabling macros."
            )
    res.evidence_count = len(res.suspicious_indicators) + len(res.embedded_objects_detected)
    return res


def _analyze_raw_macro_stream(macro_bytes: bytes, res: MacroInspectionResult):
    """
    Scans macro binary streams for suspicious indicators using regex on decompressed/ASCII strings.
    """
    text_content = macro_bytes.decode("latin1", errors="ignore")
    found_patterns = set()

    for pattern, description, severity in SUSPICIOUS_EXEC_PATTERNS:
        matches = list(re.finditer(pattern, text_content))
        if matches:
            found_patterns.add(description)
            for m in matches[:3]:
                snippet = m.group(0).strip()
                res.extracted_snippets.append(f"[{severity.upper()}] {description}: '{snippet}'")

    if found_patterns:
        res.suspicious_indicators.extend(sorted(list(found_patterns)))
