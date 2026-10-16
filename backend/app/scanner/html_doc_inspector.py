"""
Feature 2: Local Phishing Page — HTML Attachment Inspection
Safely parses HTML files without rendering in an executable browser context.
Inspects forms, credentials, external actions, obfuscation, and stealthy redirects.
"""
from html.parser import HTMLParser
import re
from urllib.parse import urlparse
from app.schemas import HtmlAttachmentSafetyResult

COMMON_BRANDS = [
    "Microsoft", "Office 365", "Outlook", "Google", "Google Workspace",
    "DocuSign", "Adobe", "PayPal", "Bank of America", "Chase", "Wells Fargo",
    "Apple", "iCloud", "Dropbox", "Amazon", "Citrix"
]

class SafeHtmlDocumentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.login_fields = []
        self.password_fields = []
        self.form_actions = []
        self.remote_scripts = []
        self.hidden_iframes = []
        self.meta_redirects = []
        self.script_contents = []
        self.title_text = []
        self.body_text = []
        self._in_title = False
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "title":
            self._in_title = True
        elif tag_lower == "script":
            self._in_script = True
            src = attr_dict.get("src", "").strip()
            if src:
                self.remote_scripts.append(src)

        elif tag_lower == "input":
            itype = attr_dict.get("type", "text").lower()
            iname = attr_dict.get("name", "").lower()
            iid = attr_dict.get("id", "").lower()
            ipl = attr_dict.get("placeholder", "").lower()

            if itype == "password" or "password" in iname or "pwd" in iname:
                self.password_fields.append(f"<input type='{itype}' name='{iname}'>")
            elif any(k in iname or k in iid or k in ipl for k in ["login", "email", "user", "username", "account"]):
                self.login_fields.append(f"<input type='{itype}' name='{iname}'>")

        elif tag_lower == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            if action:
                self.form_actions.append({"action": action, "method": method})

        elif tag_lower == "iframe":
            style = attr_dict.get("style", "").lower()
            w = attr_dict.get("width", "")
            h = attr_dict.get("height", "")
            src = attr_dict.get("src", "")
            is_hidden = "display:none" in style or "visibility:hidden" in style or w in {"0", "1"} or h in {"0", "1"}
            if is_hidden:
                self.hidden_iframes.append(f"<iframe src='{src}'> (hidden: style='{style}' w='{w}')")

        elif tag_lower == "meta":
            http_equiv = attr_dict.get("http-equiv", "").lower()
            content = attr_dict.get("content", "")
            if http_equiv == "refresh":
                self.meta_redirects.append(content)

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title_text.append(data.strip())
        elif self._in_script:
            self.script_contents.append(data)
        else:
            self.body_text.append(data.strip())


def inspect_html_attachment(file_bytes: bytes, filename: str) -> HtmlAttachmentSafetyResult:
    """
    Statically analyzes HTML attachments for credential harvesting forms,
    remote submission targets, obfuscated JavaScript, and stealth frames.
    """
    res = HtmlAttachmentSafetyResult()
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_html_file = ext in {"html", "htm", "mhtml", "mht", "xhtml"}

    # Also detect HTML by sniffing tags if extension is ambiguous
    content_sample = file_bytes[:1024].lower()
    has_html_tags = b"<html" in content_sample or b"<!doctype html" in content_sample or b"<head" in content_sample
    if not (is_html_file or has_html_tags):
        res.is_html = False
        res.explanation = "File is not an HTML document or attachment."
        return res

    res.is_html = True
    html_text = file_bytes.decode("utf-8", errors="replace")
    parser = SafeHtmlDocumentParser()

    try:
        parser.feed(html_text)
    except Exception as e:
        res.inspection_limitations.append(f"HTML parsing note: {str(e)}")

    res.login_fields_found = parser.login_fields[:10]
    res.password_fields_found = parser.password_fields[:10]
    res.remote_scripts_detected = parser.remote_scripts[:10]
    res.suspicious_redirects_or_frames.extend(parser.hidden_iframes[:5])

    for r in parser.meta_redirects:
        res.suspicious_redirects_or_frames.append(f"Meta refresh redirect: {r}")

    # Inspect form actions for external or dangerous submission destinations
    for f in parser.form_actions:
        action = f["action"]
        parsed = urlparse(action)
        if parsed.scheme in ["http", "https"]:
            res.external_form_destinations.append(f"{f['method']} -> {action}")
        elif action.lower().startswith("data:") or action.lower().startswith("blob:"):
            res.external_form_destinations.append(f"{f['method']} -> {action[:40]}... (dangerous data/blob URI)")

    # Static JavaScript obfuscation analysis (without executing JS)
    all_scripts = "\n".join(parser.script_contents)
    obf_patterns = [
        (r"(?i)\beval\s*\(", "Use of eval() for dynamic code execution"),
        (r"(?i)\bdocument\.write\s*\(", "document.write() DOM injection"),
        (r"(?i)\bunescape\s*\(", "unescape() legacy hex string decoder"),
        (r"(?i)\b(?:string\.fromcharcode|fromcharcode)\b", "String.fromCharCode obfuscation"),
        (r"(?:\\x[0-9a-fA-F]{2}){8,}", "Chained hex escape sequences (\\xNN)"),
        (r"(?:\\u[0-9a-fA-F]{4}){6,}", "Chained Unicode escape sequences (\\uNNNN)"),
        (r"(?i)\batob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]\s*\)", "Inline base64 payload decoding via atob()"),
        (r"(?i)\bwindow\.location(?:\.replace|\.href)?\s*=", "Client-side script redirection"),
    ]

    for pat, desc in obf_patterns:
        if re.search(pat, all_scripts):
            res.obfuscated_scripts.append(desc)

    # Heuristic brand impersonation check
    full_text = " ".join(parser.title_text + parser.body_text[:100]).lower()
    matched_brands = [b for b in COMMON_BRANDS if re.search(rf"\b{re.escape(b.lower())}\b", full_text)]

    if matched_brands and res.password_fields_found:
        if res.external_form_destinations:
            for b in matched_brands:
                for dest in res.external_form_destinations:
                    # Check if destination matches brand name domain
                    brand_simple = b.lower().replace(" ", "").replace("365", "")
                    if brand_simple not in dest.lower():
                        res.brand_domain_mismatches.append(
                            f"Page mentions brand '{b}' with password field, but submits to unverified destination: {dest}"
                        )

    # Risk level determination
    if res.password_fields_found and res.external_form_destinations:
        res.risk_level = "critical"
        res.explanation = (
            f"This HTML attachment contains a login form with {len(res.password_fields_found)} password field(s) "
            f"that submits data to external destinations ({', '.join(res.external_form_destinations[:2])}). "
            f"Verify the destination before entering any credentials."
        )
    elif res.password_fields_found:
        res.risk_level = "warning"
        res.explanation = (
            f"HTML document contains interactive password/login input fields. "
            f"Inspect source and origin carefully before supplying credentials."
        )
    elif res.obfuscated_scripts:
        res.risk_level = "warning"
        res.explanation = (
            f"Static analysis detected {len(res.obfuscated_scripts)} obfuscated script pattern(s) "
            f"commonly associated with stealth delivery or local phishing."
        )
    else:
        res.risk_level = "safe"
        res.explanation = "Static HTML analysis completed. No credential fields or external form submissions found."

    res.inspection_limitations.append("JavaScript execution engine disabled for safety; dynamic DOM rendering not performed.")
    return res
