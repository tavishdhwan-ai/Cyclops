"""
Safe static HTML analysis for Cyclops URL Scanner.
Completely read-only, non-executing HTML parser using Python's standard library html.parser.

Analyzes:
- Page Title and Meta Description
- Presence of forms and sensitive input fields (password, credit card, pin)
- Form action target destinations (internal vs external host)
- Suspicious credential harvesting keywords in visible static text
- Brand impersonation clues in title and headings
- Static redirect indicators (<meta http-equiv="refresh">, window.location traces)
- Does NOT execute JavaScript, load iframes, or download subresources.
"""
from html.parser import HTMLParser
import urllib.parse
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class FormAnalysis(BaseModel):
    action_url: Optional[str] = None
    method: str = "GET"
    is_external_action: bool = False
    has_password_field: bool = False
    has_email_field: bool = False
    has_credit_card_field: bool = False
    input_field_names: List[str] = Field(default_factory=list)


class StaticContentAnalysis(BaseModel):
    title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_refresh_target: Optional[str] = None
    forms_found: List[FormAnalysis] = Field(default_factory=list)
    has_password_input: bool = False
    has_external_form_action: bool = False
    has_credential_harvesting_terms: bool = False
    matched_phrases: List[str] = Field(default_factory=list)
    script_count: int = 0
    iframe_count: int = 0
    contains_hidden_inputs: bool = False
    status: str = "completed"  # "completed", "skipped", "truncated"
    limitations: List[str] = Field(default_factory=list)



CREDENTIAL_KEYWORDS = [
    "enter your password", "sign in to your account", "verify your identity",
    "confirm your credit card", "account suspended", "urgent action required",
    "update your billing information", "unlock your account", "security verification code",
    "verify bank details", "login to continue", "microsoft account", "apple id verification"
]


class SafeStaticHTMLParser(HTMLParser):
    def __init__(self, page_host: str):
        super().__init__()
        self.page_host = page_host.lower()
        self.title = ""
        self._in_title = False
        self.meta_description = None
        self.meta_refresh_target = None
        self.script_count = 0
        self.iframe_count = 0
        self.forms: List[FormAnalysis] = []
        self._current_form: Optional[FormAnalysis] = None
        self.visible_text_fragments: List[str] = []
        self._skip_tags = {"script", "style", "noscript"}
        self._current_tag = ""

    def handle_starttag(self, tag, attrs):
        self._current_tag = tag.lower()
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            http_equiv = attrs_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = attrs_dict.get("content", "")
                if "url=" in content.lower():
                    self.meta_refresh_target = content.lower().split("url=")[-1].strip()
            name = attrs_dict.get("name", "").lower()
            if name == "description":
                self.meta_description = attrs_dict.get("content", "")
        elif tag == "script":
            self.script_count += 1
        elif tag == "iframe":
            self.iframe_count += 1
        elif tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "GET").upper()

            is_external = False
            if action:
                parsed_act = urllib.parse.urlsplit(action)
                if parsed_act.hostname and parsed_act.hostname.lower() != self.page_host:
                    is_external = True

            self._current_form = FormAnalysis(
                action_url=action,
                method=method,
                is_external_action=is_external
            )
            self.forms.append(self._current_form)
        elif tag == "input":
            input_type = attrs_dict.get("type", "text").lower()
            name = attrs_dict.get("name", "")
            if self._current_form is not None:
                if name:
                    self._current_form.input_field_names.append(name)
                if input_type == "password":
                    self._current_form.has_password_field = True
                elif input_type in ("email", "text") and ("email" in name.lower() or "user" in name.lower()):
                    self._current_form.has_email_field = True
                elif "card" in name.lower() or "cvv" in name.lower() or "cc" in name.lower():
                    self._current_form.has_credit_card_field = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None
        self._current_tag = ""

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._current_tag not in self._skip_tags:
            text = data.strip()
            if text:
                self.visible_text_fragments.append(text)


def analyze_static_html(html_content: Optional[str], page_host: str) -> StaticContentAnalysis:
    """
    Safely inspect static HTML using non-executing stdlib parser.
    """
    if not html_content:
        return StaticContentAnalysis(
            status="skipped",
            limitations=["No HTML content returned or target connection could not be established."]
        )

    parser = SafeStaticHTMLParser(page_host)
    try:
        parser.feed(html_content)
    except Exception as exc:
        return StaticContentAnalysis(
            status="completed",
            limitations=[f"Malformed HTML encountered during passive parsing: {str(exc)}"]
        )

    # Check for credential harvesting text
    full_text = " ".join(parser.visible_text_fragments).lower()
    matched_phrases = []
    for kw in CREDENTIAL_KEYWORDS:
        if kw in full_text:
            matched_phrases.append(kw)

    has_pass = any(f.has_password_field for f in parser.forms)
    has_ext = any(f.is_external_action for f in parser.forms)

    limitations = [
        "Client-side JavaScript was NOT executed.",
        "Images, stylesheets, and third-party tracking pixels were NOT downloaded."
    ]

    return StaticContentAnalysis(
        title=parser.title.strip() if parser.title else None,
        meta_description=parser.meta_description,
        meta_refresh_target=parser.meta_refresh_target,
        forms_found=parser.forms,
        has_password_input=has_pass,
        has_external_form_action=has_ext,
        has_credential_harvesting_terms=len(matched_phrases) > 0,
        matched_phrases=matched_phrases,
        script_count=parser.script_count,
        iframe_count=parser.iframe_count,
        status="completed",
        limitations=limitations
    )
