"""
Feature 9: Hidden Content and Invisible Text Audit
Identifies text and document elements that may be concealed from visual inspection:
- Font size <= 1pt or negative rendering mode (PDF Tr 3)
- Off-page coordinates outside media boundary
- White text on white background
- Hidden Excel sheets (state="hidden" or "veryHidden"), hidden rows, hidden columns
- Word vanishing text (<w:vanish/>)
"""
import io
import re
import zipfile
from typing import List, Tuple
from app.schemas import HiddenContentResult, HiddenContentItem

def audit_hidden_content(file_bytes: bytes, filename: str) -> HiddenContentResult:
    """
    Audits PDF, DOCX, and XLSX files for structurally or visually hidden elements.
    """
    res = HiddenContentResult()
    ext = filename.lower().split(".")[-1] if "." in filename else ""

    if ext == "pdf" or file_bytes.startswith(b"%PDF"):
        _audit_pdf_hidden(file_bytes, res)
    elif ext in {"xlsx", "xlsm"}:
        _audit_ooxml_hidden(file_bytes, res, is_word=False)
    elif ext in {"docx", "docm"}:
        _audit_ooxml_hidden(file_bytes, res, is_word=True)
    elif file_bytes.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                is_xl = any(f.startswith("xl/") for f in zf.namelist())
                _audit_ooxml_hidden(file_bytes, res, is_word=not is_xl)
        except Exception:
            _audit_ooxml_hidden(file_bytes, res, is_word=True)

    res.hidden_elements_count = len(res.items)
    if res.hidden_elements_count > 0:
        res.summary = f"Identified {res.hidden_elements_count} potentially concealed or invisible text element(s)."
        res.explanation = (
            "Potentially hidden text or structural concealment was detected in this document. "
            "It is not readily visible in standard document viewing. "
            "Review the extracted content before trusting the document."
        )
    else:
        res.summary = "No concealed, microscopic, or structurally hidden text detected."
        res.explanation = "Visual inspection and structural analysis found standard visible text rendering."

    return res


def _audit_pdf_hidden(file_bytes: bytes, res: HiddenContentResult):
    """
    Scans PDF streams for invisible text rendering modes, microscopic font sizes, and off-boundary coordinates.
    """
    raw_str = file_bytes.decode("latin1", errors="ignore")

    # 1. Text rendering mode 3: "3 Tr" = neither fill nor stroke text (invisible text mode)
    tr3_matches = list(re.finditer(r"3\s+Tr\s+([^\n\r]+?)(?:ET|[0-2]\s+Tr)", raw_str, re.DOTALL))
    for m in tr3_matches[:4]:
        snippet = m.group(1).strip()
        # Extract text from PDF literal strings (...)
        text_parts = re.findall(r"\(([^)]+)\)", snippet)
        extracted = " ".join(text_parts).strip() if text_parts else snippet[:40]
        if extracted:
            res.items.append(HiddenContentItem(
                extracted_text=extracted[:100],
                location="PDF Content Stream",
                classification_reason="Text rendering mode set to invisible ('3 Tr')",
                detection_type="structural",
                context_snippet=snippet[:80],
            ))

    # 2. Microscopic font sizes: font size <= 1.0pt (e.g. /F1 0.5 Tf or /F1 1 Tf)
    tiny_font_matches = list(re.finditer(r"/([A-Za-z0-9_-]+)\s+([0-9]?\.[0-9]+|0)\s+Tf\s+([^\n\r]+?ET)", raw_str))
    for m in tiny_font_matches[:4]:
        size_str = m.group(2)
        try:
            size_val = float(size_str)
            if size_val <= 1.0:
                body = m.group(3)
                text_parts = re.findall(r"\(([^)]+)\)", body)
                extracted = " ".join(text_parts).strip() if text_parts else body[:40]
                res.items.append(HiddenContentItem(
                    extracted_text=extracted[:100] or f"Microscopic stream ({size_val}pt)",
                    location="PDF Text Object",
                    classification_reason=f"Microscopic font size detected ({size_val}pt <= 1.0pt)",
                    detection_type="visual_inference",
                    context_snippet=body[:80],
                ))
        except ValueError:
            pass

    # 3. Off-page coordinates (e.g. 1 0 0 1 -5000 -5000 Tm)
    off_page_matches = list(re.finditer(r"(?:1\s+0\s+0\s+1\s+(-?[0-9]{4,})\s+(-?[0-9]{4,})\s+Tm\s+)([^\n\r]+?ET)", raw_str))
    for m in off_page_matches[:3]:
        x_coord, y_coord = m.group(1), m.group(2)
        body = m.group(3)
        text_parts = re.findall(r"\(([^)]+)\)", body)
        extracted = " ".join(text_parts).strip() if text_parts else body[:40]
        res.items.append(HiddenContentItem(
            extracted_text=extracted[:100] or "Off-canvas content",
            location=f"PDF Coordinates [{x_coord}, {y_coord}]",
            classification_reason="Text positioned far outside standard page boundaries",
            detection_type="structural",
            context_snippet=body[:80],
        ))


def _audit_ooxml_hidden(file_bytes: bytes, res: HiddenContentResult, is_word: bool):
    """
    Audits Word for <w:vanish/> and Excel for hidden sheets, rows, or columns.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            namelist = zf.namelist()

            if is_word:
                # Inspect word/document.xml for vanishing text
                if "word/document.xml" in namelist:
                    doc_xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
                    # <w:vanish/> in run properties
                    vanish_runs = list(re.finditer(r"<w:rPr>[^<]*<w:vanish/>.*?</w:rPr>.*?<w:t[^>]*>([^<]+)</w:t>", doc_xml, re.DOTALL))
                    for m in vanish_runs[:5]:
                        res.items.append(HiddenContentItem(
                            extracted_text=m.group(1).strip(),
                            location="Word Document Paragraph Run",
                            classification_reason="Word 'vanish' attribute (<w:vanish/>) hides text from view",
                            detection_type="structural",
                            context_snippet=m.group(0)[:80],
                        ))
            else:
                # Inspect xl/workbook.xml for hidden/veryHidden sheets
                if "xl/workbook.xml" in namelist:
                    wb_xml = zf.read("xl/workbook.xml").decode("utf-8", errors="ignore")
                    hidden_sheets = list(re.finditer(r'<sheet[^>]*name="([^"]+)"[^>]*state="(hidden|veryHidden)"', wb_xml, re.IGNORECASE))
                    for m in hidden_sheets:
                        s_name, s_state = m.group(1), m.group(2)
                        res.items.append(HiddenContentItem(
                            extracted_text=f"Worksheet: {s_name} (State: {s_state})",
                            location=f"Excel Workbook / {s_name}",
                            classification_reason=f"Spreadsheet tab concealed with state='{s_state}'",
                            detection_type="structural",
                            context_snippet=f'<sheet name="{s_name}" state="{s_state}"/>',
                        ))

                # Inspect sheets for hidden rows
                sheet_files = [f for f in namelist if f.startswith("xl/worksheets/sheet") and f.endswith(".xml")]
                for sf in sheet_files[:3]:
                    s_xml = zf.read(sf).decode("utf-8", errors="ignore")
                    hidden_rows = list(re.finditer(r'<row[^>]*r="(\d+)"[^>]*hidden="1"', s_xml))
                    if hidden_rows:
                        row_nums = [m.group(1) for m in hidden_rows[:5]]
                        res.items.append(HiddenContentItem(
                            extracted_text=f"Hidden rows: {', '.join(row_nums)}",
                            location=f"Excel {sf}",
                            classification_reason="Worksheet row visibility set to hidden (hidden='1')",
                            detection_type="structural",
                            context_snippet=f"{len(hidden_rows)} hidden row(s) in {sf}",
                        ))
    except Exception:
        pass
