"""
Safe static HTML analysis and Sensitive Input Auditing for Cyclops URL Scanner.
Completely read-only, non-executing HTML parser using Python's standard library html.parser.

Features:
- Page Title and Meta Description
- Sensitive input detection: Password fields, Login/Email fields, Payment/Card fields
- Form submission action auditing: local vs cross-origin targets, plain HTTP targets
- Contextual correlation with domain age, HTTPS, and threat intelligence
- Never executes JavaScript, loads subresources, or submits forms
- Never collects, stores, or transmits actual user credentials
"""
from html.parser import HTMLParser
import urllib.parse
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class FormAnalysis(BaseModel):
    action_url: Optional[str] = None
    method: str = "GET"
    is_external_action: bool = False
    action_host: Optional[str] = None
    has_password_field: bool = False
    has_email_field: bool = False
    has_credit_card_field: bool = False
    has_hidden_fields: bool = False
    submits_to_http: bool = False
    input_field_names: List[str] = Field(default_factory=list)


class SensitiveInputAudit(BaseModel):
    password_fields_detected: int = 0
    email_login_fields_detected: int = 0
    payment_fields_detected: int = 0
    form_submission_destinations: List[str] = Field(default_factory=list)
    cross_origin_submission_detected: bool = False
    cross_origin_details: List[str] = Field(default_factory=list)
    submits_over_insecure_http: bool = False
    is_https_page: bool = True
    evidence_based_explanation: str = "No sensitive credential or payment collection inputs were detected."
    warnings: List[str] = Field(default_factory=list)
    contextual_notes: List[str] = Field(default_factory=list)


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
    sensitive_input_audit: Optional[SensitiveInputAudit] = None
    status: str = "completed"  # "completed", "skipped", "truncated"
    limitations: List[str] = Field(default_factory=list)


CREDENTIAL_KEYWORDS = [
    "enter your password", "sign in to your account", "verify your identity",
    "confirm your credit card", "account suspended", "urgent action required",
    "update your billing information", "unlock your account", "security verification code",
    "verify bank details", "login to continue", "microsoft account", "apple id verification",
    "security question", "one-time password", "enter verification code"
]

PAYMENT_TERMS = ["card", "cvv", "cvc", "expir", "credit", "debit", "cc_", "pan", "account_num", "routing", "billing"]
LOGIN_TERMS = ["user", "login", "email", "account", "username", "identifier", "signin"]


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
        self.contains_hidden_inputs = False
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
            action = attrs_dict.get("action", "").strip()
            method = attrs_dict.get("method", "GET").upper()

            is_external = False
            action_host = None
            submits_http = False
            if action:
                parsed_act = urllib.parse.urlsplit(action)
                if parsed_act.scheme:
                    if parsed_act.scheme.lower() == "http":
                        submits_http = True
                if parsed_act.hostname:
                    action_host = parsed_act.hostname.lower()
                    if action_host != self.page_host:
                        is_external = True

            self._current_form = FormAnalysis(
                action_url=action or None,
                method=method,
                is_external_action=is_external,
                action_host=action_host,
                submits_to_http=submits_http
            )
            self.forms.append(self._current_form)
        elif tag == "input":
            input_type = attrs_dict.get("type", "text").lower()
            name = attrs_dict.get("name", "").lower()
            autocomplete = attrs_dict.get("autocomplete", "").lower()

            if input_type == "hidden":
                self.contains_hidden_inputs = True
                if self._current_form is not None:
                    self._current_form.has_hidden_fields = True

            if self._current_form is not None:
                if name:
                    self._current_form.input_field_names.append(name)

                # Password check
                if input_type == "password":
                    self._current_form.has_password_field = True

                # Login/Email check
                elif input_type in ("email", "text") and (
                    input_type == "email" or
                    any(term in name for term in LOGIN_TERMS) or
                    "username" in autocomplete or
                    "email" in autocomplete
                ):
                    self._current_form.has_email_field = True

                # Payment field check
                elif any(term in name for term in PAYMENT_TERMS) or any(term in autocomplete for term in ["cc-number", "cc-exp", "cc-csc"]):
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


def build_sensitive_input_audit(
    forms: List[FormAnalysis],
    page_host: str,
    is_https: bool,
    domain_age_days: Optional[int] = None,
    threat_intel_flagged: bool = False
) -> SensitiveInputAudit:
    """
    Builds Feature 3: Sensitive Input Audit based on static HTML inspection.
    Adheres strictly to contextual risk interpretation rules.
    """
    pass_count = sum(1 for f in forms if f.has_password_field)
    email_count = sum(1 for f in forms if f.has_email_field)
    pay_count = sum(1 for f in forms if f.has_credit_card_field)

    destinations = []
    cross_origin_details = []
    submits_insecure = False
    has_cross_origin = False

    for f in forms:
        if f.action_url:
            destinations.append(f.action_url)
        if f.is_external_action and f.action_host:
            has_cross_origin = True
            cross_origin_details.append(
                f"Form submits to external domain '{f.action_host}' (different from page host '{page_host}')."
            )
        if f.submits_to_http:
            submits_insecure = True

    warnings: List[str] = []
    notes: List[str] = []

    # Cross-origin submission warning
    if has_cross_origin:
        warnings.append(
            f"Cross-origin form action detected: form inputs are submitted to a third-party host ({', '.join(set(cross_origin_details))})."
        )

    # Insecure submission warning
    if submits_insecure:
        warnings.append("Form action submits credentials over unencrypted HTTP protocol.")

    # Password input contextual analysis
    if pass_count > 0:
        if not is_https:
            warnings.append("Password input detected on an unencrypted HTTP connection. Credentials can be intercepted in transit.")
            explanation = "This page contains a password field on an unencrypted HTTP connection. Entering credentials puts your account at immediate risk."
        elif has_cross_origin:
            warnings.append("Password field submits credentials across origins to an external domain.")
            explanation = f"This page collects passwords and transmits them to external host '{cross_origin_details[0]}'. This is a common pattern in phishing credential harvesters."
        elif threat_intel_flagged:
            warnings.append("Password field detected on a URL flagged as malicious by threat intelligence providers.")
            explanation = "This page contains a password field, and external security intelligence providers report active threats for this target."
        elif domain_age_days is not None and 0 <= domain_age_days < 30:
            warnings.append("Password field detected on a newly registered domain (less than 30 days old).")
            explanation = "This page contains a password field on a recently registered domain. Exercise heightened caution before entering credentials."
        else:
            notes.append("Password field detected. The page uses HTTPS and internal submission targets; verify you are on the intended authentic domain.")
            explanation = "This page contains a password field. We could not independently establish that the website is trustworthy. Verify the domain before entering credentials."
    elif pay_count > 0:
        if not is_https:
            warnings.append("Payment card fields detected on an unencrypted HTTP connection.")
            explanation = "Payment details submitted over plaintext HTTP can be stolen in transit."
        elif has_cross_origin:
            warnings.append("Payment form submits data to an external origin.")
            explanation = "Payment data is submitted to an external third-party destination."
        else:
            notes.append("Payment card input fields detected over HTTPS.")
            explanation = "Payment form inputs detected. Verify business authenticity before submitting credit card information."
    elif email_count > 0:
        notes.append("Account or email identifier inputs detected.")
        explanation = "Account identifier or email input fields detected."
    else:
        explanation = "No password, login credential, or payment card input fields were detected in static HTML."

    return SensitiveInputAudit(
        password_fields_detected=pass_count,
        email_login_fields_detected=email_count,
        payment_fields_detected=pay_count,
        form_submission_destinations=destinations[:5],
        cross_origin_submission_detected=has_cross_origin,
        cross_origin_details=cross_origin_details,
        submits_over_insecure_http=submits_insecure,
        is_https_page=is_https,
        evidence_based_explanation=explanation,
        warnings=warnings,
        contextual_notes=notes
    )


def analyze_static_html(
    html_content: Optional[str],
    page_host: str,
    is_https: bool = True,
    domain_age_days: Optional[int] = None,
    threat_intel_flagged: bool = False
) -> StaticContentAnalysis:
    """
    Safely inspect static HTML using non-executing stdlib parser.
    Audits forms, sensitive inputs, and visible static text.
    """
    if not html_content:
        audit = SensitiveInputAudit(
            is_https_page=is_https,
            evidence_based_explanation="No HTML content available to inspect sensitive input fields."
        )
        return StaticContentAnalysis(
            sensitive_input_audit=audit,
            status="skipped",
            limitations=["No HTML content returned or target connection could not be established."]
        )

    parser = SafeStaticHTMLParser(page_host)
    try:
        parser.feed(html_content)
    except Exception as exc:
        audit = SensitiveInputAudit(
            is_https_page=is_https,
            evidence_based_explanation="HTML parsing halted due to malformed markup."
        )
        return StaticContentAnalysis(
            sensitive_input_audit=audit,
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

    # Sensitive input audit
    audit = build_sensitive_input_audit(
        forms=parser.forms,
        page_host=page_host,
        is_https=is_https,
        domain_age_days=domain_age_days,
        threat_intel_flagged=threat_intel_flagged
    )

    limitations = [
        "Client-side JavaScript was NOT executed.",
        "Images, stylesheets, and third-party tracking pixels were NOT downloaded.",
        "Form submission endpoints were audited by URL syntax and host matching; forms were NOT submitted."
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
        contains_hidden_inputs=parser.contains_hidden_inputs,
        sensitive_input_audit=audit,
        status="completed",
        limitations=limitations
    )
