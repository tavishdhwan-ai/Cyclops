"""
Feature 3: One-Click Misdirection — Embedded Hyperlink Analysis
Feature 7: Deep Hyperlink Analysis & Domain Matcher
Extracts and verifies embedded links in PDFs, Office documents, and HTML attachments.
Detects visible text vs actual destination mismatches and brand impersonation.
"""
import io
import re
import zipfile
from html.parser import HTMLParser
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Any, Optional
from app.schemas import EmbeddedLinkItem, EmbeddedLinksResult, BrandDomainConsistencyResult
from app.scanner.ssrf import is_ip_blocked
import ipaddress

def _is_safe_destination(domain: str) -> Tuple[bool, str]:
    if not domain:
        return False, "Missing hostname"
    try:
        ip_obj = ipaddress.ip_address(domain.strip("[]"))
        blocked, reason = is_ip_blocked(ip_obj)
        if blocked:
            return False, reason
    except ValueError:
        pass
    if domain.lower() in {"localhost", "127.0.0.1", "::1", "metadata.google.internal"}:
        return False, "Non-routable or loopback host"
    return True, ""

URL_REGEX = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)

KNOWN_CLOUD_AND_PAYMENT_DOMAINS = {
    "stripe.com", "paypal.com", "microsoft.com", "office.com", "live.com",
    "google.com", "docusign.net", "docusign.com", "adobe.com", "amazon.com",
    "aws.amazon.com", "dropbox.com", "sharepoint.com", "cloudflare.com"
}

def extract_document_links(file_bytes: bytes, filename: str) -> Tuple[EmbeddedLinksResult, BrandDomainConsistencyResult]:
    """
    Extracts embedded hyperlinks from PDF, Office XML (DOCX, XLSX), or HTML.
    Performs mismatch detection and domain consistency matching.
    """
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    raw_links: List[Dict[str, str]] = []
    claimed_brand: Optional[str] = None

    if ext == "pdf" or file_bytes.startswith(b"%PDF"):
        raw_links, claimed_brand = _extract_pdf_links(file_bytes)
    elif ext in {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm"} or file_bytes.startswith(b"PK\x03\x04"):
        raw_links, claimed_brand = _extract_ooxml_links(file_bytes)
    elif ext in {"html", "htm", "xhtml", "mhtml"} or b"<html" in file_bytes[:1024].lower():
        raw_links, claimed_brand = _extract_html_links(file_bytes)
    else:
        # Fallback raw byte scan for URLs in unsupported/plain text formats
        text = file_bytes.decode("utf-8", errors="ignore")
        for m in URL_REGEX.finditer(text):
            u = m.group(0)
            raw_links.append({"visible_text": u, "destination_url": u, "location": "Raw Document Text"})

    # Process extracted links
    processed_items: List[EmbeddedLinkItem] = []
    mismatch_count = 0
    all_domains = set()

    for item in raw_links:
        v_text = item.get("visible_text", "").strip()
        dest_url = item.get("destination_url", "").strip()
        loc = item.get("location", "Document body")

        if not dest_url or not (dest_url.lower().startswith("http://") or dest_url.lower().startswith("https://")):
            continue

        parsed = urlparse(dest_url)
        domain = parsed.hostname or ""
        all_domains.add(domain.lower())

        mismatch_warning = None
        threat_verdict = "clean"
        recommended_action = "Standard verification."

        # SSRF / Dangerous destination check
        is_safe, ssrf_err = _is_safe_destination(domain)
        if not is_safe:
            threat_verdict = "suspicious"
            mismatch_warning = f"URL targets private or non-routable host ({ssrf_err})"
            recommended_action = "Do not open. Block access to non-routable address."

        # Check for visible text vs destination mismatch
        # e.g. text says "https://microsoft.com/login" or "paypal.com" but href is "evil.com"
        v_text_clean = v_text.lower().replace("http://", "").replace("https://", "").split("/")[0].strip()
        if ("." in v_text_clean and len(v_text_clean) > 3) and not v_text_clean.endswith("."):
            # Visible text looks like a domain or URL
            if domain and domain.lower() != v_text_clean and not domain.lower().endswith("." + v_text_clean):
                mismatch_warning = f"Visible link text displays '{v_text}' but the destination points to an unrelated domain '{domain}'."
                mismatch_count += 1
                threat_verdict = "suspicious"
                recommended_action = "Verify the destination before opening. Clickable destination differs from displayed URL."

        # Check for URL shorteners
        if domain.lower() in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly"}:
            if not mismatch_warning:
                mismatch_warning = "Link uses an external URL shortener that masks the ultimate landing address."
            recommended_action = "Inspect expanded redirect target before proceeding."

        processed_items.append(EmbeddedLinkItem(
            visible_text=v_text or "(No label / icon)",
            destination_url=dest_url,
            destination_domain=domain,
            location=loc,
            mismatch_warning=mismatch_warning,
            threat_verdict=threat_verdict,
            recommended_action=recommended_action,
        ))

    # Build Feature 3 EmbeddedLinksResult
    links_res = EmbeddedLinksResult(
        total_links_found=len(processed_items),
        mismatched_links_count=mismatch_count,
        links=processed_items[:50],
    )
    if mismatch_count > 0:
        links_res.summary = f"Detected {len(processed_items)} embedded link(s), with {mismatch_count} misleading text-to-destination mismatch(es)."
        links_res.warnings.append("At least one hyperlink displays a misleading URL label that conceals its real destination.")
    elif processed_items:
        links_res.summary = f"Extracted {len(processed_items)} embedded link(s). Destinations align with anchor text."
    else:
        links_res.summary = "No clickable hyperlinks found in the document."

    # Build Feature 7 BrandDomainConsistencyResult
    brand_res = _analyze_brand_consistency(claimed_brand, list(all_domains), processed_items)

    return links_res, brand_res


def _extract_pdf_links(file_bytes: bytes) -> Tuple[List[Dict[str, str]], Optional[str]]:
    links: List[Dict[str, str]] = []
    claimed_brand: Optional[str] = None
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        meta = reader.metadata or {}
        title = meta.get("/Title") or ""
        author = meta.get("/Author") or ""
        subject = meta.get("/Subject") or ""
        claimed_brand = title or author or subject or None

        for page_idx, page in enumerate(reader.pages):
            page_num = page_idx + 1
            annots = page.get("/Annots")
            if not annots:
                continue

            for annot_ref in annots:
                try:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    if annot.get("/Subtype") == "/Link":
                        action = annot.get("/A")
                        if action:
                            action_obj = action.get_object() if hasattr(action, "get_object") else action
                            if action_obj.get("/S") == "/URI":
                                uri = str(action_obj.get("/URI", "")).strip()
                                # Visible text fallback or coordinate label
                                rect = str(annot.get("/Rect", ""))
                                links.append({
                                    "visible_text": f"PDF Link (Page {page_num})",
                                    "destination_url": uri,
                                    "location": f"Page {page_num} [{rect}]"
                                })
                except Exception:
                    pass
    except Exception:
        # Fallback to regex scan if pypdf fails on malformed file
        for m in URL_REGEX.finditer(file_bytes.decode("latin1", errors="ignore")):
            links.append({
                "visible_text": m.group(0),
                "destination_url": m.group(0),
                "location": "PDF Stream"
            })
    return links, claimed_brand


def _extract_ooxml_links(file_bytes: bytes) -> Tuple[List[Dict[str, str]], Optional[str]]:
    links: List[Dict[str, str]] = []
    claimed_brand: Optional[str] = None
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            # Check app.xml or core.xml for metadata
            for core_file in ["docProps/core.xml", "docProps/app.xml"]:
                if core_file in zf.namelist():
                    core_xml = zf.read(core_file).decode("utf-8", errors="ignore")
                    m = re.search(r"<(?:dc:creator|dc:title|Company)>([^<]+)</", core_xml)
                    if m:
                        claimed_brand = m.group(1).strip()
                        break

            # Check rels files for hyperlinks
            rel_files = [f for f in zf.namelist() if f.endswith(".rels")]
            for rf in rel_files:
                content = zf.read(rf).decode("utf-8", errors="ignore")
                for match in re.finditer(r'Id="([^"]+)"[^>]*Type="[^"]*hyperlink"[^>]*Target="([^"]+)"', content, re.IGNORECASE):
                    r_id, target = match.group(1), match.group(2)
                    links.append({
                        "visible_text": f"Hyperlink {r_id}",
                        "destination_url": target,
                        "location": rf.replace("_rels/", "")
                    })
    except Exception:
        pass
    return links, claimed_brand


class _HtmlLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current_href = None
        self._current_text = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True
        elif tag.lower() == "a":
            ad = {k.lower(): (v or "") for k, v in attrs}
            self._current_href = ad.get("href")
            self._current_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "a" and self._current_href:
            self.links.append({
                "visible_text": " ".join(self._current_text).strip(),
                "destination_url": self._current_href,
                "location": "HTML Anchor Link"
            })
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._in_title:
            self.title += " " + data.strip()
        elif self._current_href is not None:
            self._current_text.append(data.strip())


def _extract_html_links(file_bytes: bytes) -> Tuple[List[Dict[str, str]], Optional[str]]:
    parser = _HtmlLinkParser()
    try:
        parser.feed(file_bytes.decode("utf-8", errors="replace"))
    except Exception:
        pass
    return parser.links, parser.title.strip() or None


def _analyze_brand_consistency(
    claimed_brand: Optional[str],
    destination_domains: List[str],
    items: List[EmbeddedLinkItem]
) -> BrandDomainConsistencyResult:
    """
    Feature 7: Assesses whether claimed organization / header branding matches hyperlink destinations.
    """
    res = BrandDomainConsistencyResult(
        claimed_organization=claimed_brand,
        destination_domains=destination_domains,
    )

    if not destination_domains:
        res.domain_relationship_assessment = "No external hyperlink destinations present in the document."
        return res

    if claimed_brand:
        claimed_lower = claimed_brand.lower()
        # Clean brand keywords (e.g. "DocuSign, Inc." -> "docusign")
        brand_tokens = re.findall(r"[a-z0-9]+", claimed_lower)
        significant_tokens = [t for t in brand_tokens if len(t) > 3 and t not in {"corp", "corporation", "inc", "llc", "group", "document", "invoice", "statement"}]

        mismatched_domains = []
        for d in destination_domains:
            # Check if domain contains any significant token or is known vendor
            is_matched = any(tok in d for tok in significant_tokens) or any(k in d for k in KNOWN_CLOUD_AND_PAYMENT_DOMAINS)
            if not is_matched:
                mismatched_domains.append(d)

        if mismatched_domains:
            res.mismatches = mismatched_domains
            res.domain_relationship_assessment = (
                f"The document references '{claimed_brand}', but one or more embedded links "
                f"point to unrelated domain(s): {', '.join(mismatched_domains[:3])}. "
                f"We could not verify the relationship between these domains."
            )
            res.supporting_evidence.append(f"Claimed organization: '{claimed_brand}'")
            res.supporting_evidence.append(f"Target domains without clear affiliation: {', '.join(mismatched_domains)}")
        else:
            res.domain_relationship_assessment = (
                f"Hyperlink destinations align with claimed organization '{claimed_brand}' "
                f"or standard cloud/vendor infrastructure."
            )
    else:
        res.domain_relationship_assessment = (
            f"No specific corporate entity was declared in document metadata. "
            f"Hyperlink destinations point to: {', '.join(destination_domains[:4])}."
        )

    return res
