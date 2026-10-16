"""
Feature 6: Zero-Interaction Secure Document Flattening — Safe-View Preview
Generates safe, non-interactive static image renderings of documents.
Prevents script execution, macro invocation, external requests, and active exploits.
"""
import base64
import io
import time
import uuid
from typing import List, Dict, Any, Optional
from PIL import Image, ImageDraw, ImageFont
from app.schemas import SafeViewResult, SafeViewPage

MAX_PAGES_TO_RENDER = 5
CANVAS_WIDTH = 800
CANVAS_HEIGHT = 1050

def generate_safe_view_preview(file_bytes: bytes, filename: str) -> SafeViewResult:
    """
    Renders static page preview images for PDF, Office, and HTML files without executing active content.
    """
    res = SafeViewResult(
        preview_id=f"preview-{uuid.uuid4().hex[:12]}",
        status="available",
    )

    ext = filename.lower().split(".")[-1] if "." in filename else ""
    pages_text: List[List[str]] = []

    try:
        if ext == "pdf" or file_bytes.startswith(b"%PDF"):
            pages_text = _extract_pdf_pages_text(file_bytes)
        elif ext in {"docx", "docm"} or file_bytes.startswith(b"PK\x03\x04"):
            pages_text = _extract_docx_pages_text(file_bytes)
        elif ext in {"xlsx", "xlsm"}:
            pages_text = _extract_xlsx_pages_text(file_bytes)
        elif ext in {"html", "htm", "txt"}:
            pages_text = _extract_html_pages_text(file_bytes)
        else:
            pages_text = [["[Static Preview for Unsupported Document Format]", f"Filename: {filename}", f"File Size: {len(file_bytes)} bytes"]]

        if not pages_text:
            pages_text = [["[Document Contains No Readable Visual Text Layer]"]]

        # Limit page count
        pages_to_render = pages_text[:MAX_PAGES_TO_RENDER]
        rendered_pages: List[SafeViewPage] = []

        for idx, lines in enumerate(pages_to_render):
            page_num = idx + 1
            data_url = _render_page_image(lines, page_num, len(pages_to_render), filename)
            snippet = " ".join(lines[:3])[:120]
            rendered_pages.append(SafeViewPage(
                page_number=page_num,
                image_data_url=data_url,
                width=CANVAS_WIDTH,
                height=CANVAS_HEIGHT,
                extracted_text_snippet=snippet,
            ))

        res.total_pages = len(rendered_pages)
        res.pages = rendered_pages
        res.status = "available"

    except Exception as e:
        res.status = "rendering_failed"
        res.disclaimer = f"Safe-View flattening could not be completed: {str(e)[:100]}"

    return res


def _extract_pdf_pages_text(file_bytes: bytes) -> List[List[str]]:
    pages_lines: List[List[str]] = []
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        for p in reader.pages[:MAX_PAGES_TO_RENDER]:
            text = p.extract_text() or ""
            lines = [l.strip() for l in text.split("\n") if l.strip()]
            pages_lines.append(lines if lines else ["[Blank or Image-Only Page]"])
    except Exception:
        # Fallback text extraction
        raw = file_bytes.decode("latin1", errors="ignore")
        import re
        parts = re.findall(r"\(([^)]+)\)", raw)
        lines = [p.strip() for p in parts if len(p.strip()) > 2][:40]
        pages_lines.append(lines if lines else ["[Text stream could not be extracted]"])
    return pages_lines


def _extract_docx_pages_text(file_bytes: bytes) -> List[List[str]]:
    import zipfile, re
    lines: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            if "word/document.xml" in zf.namelist():
                xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
                for p in re.finditer(r"<w:p[^>]*>(.*?)</w:p>", xml):
                    p_text = "".join(re.findall(r"<w:t[^>]*>([^<]+)</w:t>", p.group(1)))
                    if p_text.strip():
                        lines.append(p_text.strip())
    except Exception:
        pass
    # Chunk into pages of ~25 lines
    chunk_size = 22
    if not lines:
        return [["[Document Body Contains No Direct Text Elements]"]]
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    return chunks[:MAX_PAGES_TO_RENDER]


def _extract_xlsx_pages_text(file_bytes: bytes) -> List[List[str]]:
    import zipfile, re
    lines: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            if "xl/sharedStrings.xml" in zf.namelist():
                xml = zf.read("xl/sharedStrings.xml").decode("utf-8", errors="ignore")
                for t in re.findall(r"<t[^>]*>([^<]+)</t>", xml):
                    if t.strip():
                        lines.append(t.strip())
    except Exception:
        pass
    chunk_size = 20
    if not lines:
        return [["[Spreadsheet with No Shared String Values]"]]
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    return chunks[:MAX_PAGES_TO_RENDER]


def _extract_html_pages_text(file_bytes: bytes) -> List[List[str]]:
    from html.parser import HTMLParser
    class TextOnlyParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.lines = []
        def handle_data(self, data):
            clean = data.strip()
            if clean:
                self.lines.append(clean)
    parser = TextOnlyParser()
    try:
        parser.feed(file_bytes.decode("utf-8", errors="replace"))
    except Exception:
        pass
    chunk_size = 22
    lines = parser.lines if parser.lines else ["[No Textual Content Extracted from HTML]"]
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    return chunks[:MAX_PAGES_TO_RENDER]


def _render_page_image(lines: List[str], page_num: int, total_pages: int, filename: str) -> str:
    """
    Renders lines into a crisp static 800x1050 PNG image canvas and returns a base64 Data URL.
    """
    img = Image.new("RGB", (CANVAS_WIDTH, CANVAS_HEIGHT), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Monochromatic B2B border and security banner
    # Top banner: #FAFAFA bar with #E5E5E5 border
    draw.rectangle([0, 0, CANVAS_WIDTH, 52], fill=(250, 250, 250), outline=(229, 229, 229))
    draw.rectangle([0, CANVAS_HEIGHT - 36, CANVAS_WIDTH, CANVAS_HEIGHT], fill=(250, 250, 250), outline=(229, 229, 229))

    # Banner header text
    header_title = f"CYCLOPS SECURE FLATTENED PREVIEW — {filename[:30]}"
    draw.text((24, 18), header_title, fill=(115, 115, 115))
    page_tag = f"PAGE {page_num} OF {total_pages}"
    draw.text((CANVAS_WIDTH - 140, 18), page_tag, fill=(115, 115, 115))

    # Watermark text across center: subtle near-white/gray
    watermark = "SAFE-VIEW • ISOLATED • NON-INTERACTIVE"
    draw.text((CANVAS_WIDTH // 2 - 160, CANVAS_HEIGHT // 2), watermark, fill=(240, 240, 240))

    # Document contents
    y_pos = 80
    line_height = 36

    for line in lines:
        if y_pos > CANVAS_HEIGHT - 60:
            break

        clean_line = line[:85]
        # Distinguish headings vs body
        if len(clean_line) < 40 and (clean_line.isupper() or any(k in clean_line.lower() for k in ["invoice", "report", "statement", "policy", "agreement"])):
            draw.text((48, y_pos), clean_line, fill=(17, 17, 17))
            y_pos += int(line_height * 1.2)
        else:
            draw.text((48, y_pos), clean_line, fill=(45, 45, 45))
            y_pos += line_height

    # Footer notice
    footer_text = "Static rendering only. JavaScript, macros, launch actions, and form submissions are disabled."
    draw.text((24, CANVAS_HEIGHT - 24), footer_text, fill=(160, 160, 160))

    # Convert to base64 Data URL
    buffered = io.BytesIO()
    img.save(buffered, format="PNG", optimize=True)
    img_b64 = base64.b64encode(buffered.getvalue()).decode("ascii")
    return f"data:image/png;base64,{img_b64}"
