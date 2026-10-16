from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class AttachmentInput(BaseModel):
    name: Optional[str] = None
    file_type: Optional[str] = None
    size_bytes: Optional[int] = None


class EmailScanRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    links: List[str] = Field(default_factory=list)
    link_details: Optional[List[Dict[str, str]]] = None
    attachments: List[AttachmentInput] = Field(default_factory=list)
    reply_to: Optional[str] = None


class Finding(BaseModel):
    type: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    description: str
    id: Optional[str] = None
    category: Optional[str] = None
    explanation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    score_contribution: Optional[float] = None

    def model_post_init(self, __context):
        if not self.id:
            self.id = self.type
        if not self.explanation and self.description:
            self.explanation = self.description
        elif not self.description and self.explanation:
            self.description = self.explanation


class AttachmentResult(BaseModel):
    filename: str
    threat_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    findings: List[Finding] = Field(default_factory=list)
    summary: str = "No suspicious indicators detected."
    name: Optional[str] = None
    status: str = "scanned"
    threat_found: bool = False

    def model_post_init(self, __context):
        if not self.name and self.filename:
            self.name = self.filename
        elif not self.filename and self.name:
            self.filename = self.name


class EmailScanResponse(BaseModel):
    scan_id: str = "demo-scan"
    mode: Literal["demo"] = "demo"
    status: str = "completed"
    threat_score: float = Field(..., ge=0.0, le=10.0)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    summary: str
    findings: List[Finding] = Field(default_factory=list)
    attachments: List[AttachmentResult] = Field(default_factory=list)
    recommendation: str


class UrlScanRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain name to inspect", min_length=1)


class DocumentScanPayload(BaseModel):
    file_name: str = Field(..., description="Name of the file being scanned")
    file_content_base64: Optional[str] = Field(None, description="Base64 encoded file bytes")
    preset: Optional[str] = Field(None, description="Optional sample preset identifier")


# ===========================================================================
# Advanced Document Security Scanner Schemas (9 Features)
# ===========================================================================

class MacroInspectionResult(BaseModel):
    macro_detected: bool = False
    status: Literal["detected", "not_detected", "unable_to_inspect", "unsupported"] = "not_detected"
    embedded_objects_detected: List[str] = Field(default_factory=list)
    suspicious_indicators: List[str] = Field(default_factory=list)
    extracted_code_status: str = "No macro code found"
    extracted_snippets: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    explanation: str = "No executable macros or suspicious embedded automation detected."
    warnings: List[str] = Field(default_factory=list)


class HtmlAttachmentSafetyResult(BaseModel):
    is_html: bool = False
    login_fields_found: List[str] = Field(default_factory=list)
    password_fields_found: List[str] = Field(default_factory=list)
    external_form_destinations: List[str] = Field(default_factory=list)
    remote_scripts_detected: List[str] = Field(default_factory=list)
    suspicious_redirects_or_frames: List[str] = Field(default_factory=list)
    brand_domain_mismatches: List[str] = Field(default_factory=list)
    obfuscated_scripts: List[str] = Field(default_factory=list)
    inspection_limitations: List[str] = Field(default_factory=list)
    explanation: str = "Static inspection completed. Scanned without script execution or external downloads."
    risk_level: Literal["safe", "warning", "critical", "neutral"] = "safe"


class EmbeddedLinkItem(BaseModel):
    visible_text: str = ""
    destination_url: str
    destination_domain: str = ""
    location: str = "Document body"
    mismatch_warning: Optional[str] = None
    threat_verdict: str = "clean"
    recommended_action: str = "Verify domain identity before opening."


class EmbeddedLinksResult(BaseModel):
    total_links_found: int = 0
    mismatched_links_count: int = 0
    links: List[EmbeddedLinkItem] = Field(default_factory=list)
    summary: str = "No embedded links detected."
    warnings: List[str] = Field(default_factory=list)


class ExploitIndicatorResult(BaseModel):
    structural_anomalies: List[str] = Field(default_factory=list)
    suspicious_actions: List[str] = Field(default_factory=list)
    embedded_payloads: List[str] = Field(default_factory=list)
    known_signature_matches: List[str] = Field(default_factory=list)
    parser_warnings: List[str] = Field(default_factory=list)
    compression_ratio: float = 1.0
    engine_version: str = "Cyclops Document Engine 1.0 (Static Analyzer)"
    coverage_and_limitations: str = "Static structural audit cannot guarantee discovery of novel zero-day exploits. No content was executed."
    explanation: str = "Document structure conforms to normal specifications."


class FormSubmissionResult(BaseModel):
    interactive_forms_detected: bool = False
    form_type: str = "None"
    sensitive_fields_detected: List[str] = Field(default_factory=list)
    submission_actions: List[str] = Field(default_factory=list)
    external_destinations: List[str] = Field(default_factory=list)
    event_triggered_behavior: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    limitations: str = "Analysis strictly passive; form inputs are never submitted or stored."
    explanation: str = "No interactive form or submission actions found."


class SafeViewPage(BaseModel):
    page_number: int
    image_data_url: str
    width: int = 800
    height: int = 1050
    extracted_text_snippet: str = ""


class SafeViewResult(BaseModel):
    preview_id: str = ""
    status: Literal["available", "unavailable", "rendering_failed"] = "available"
    total_pages: int = 0
    pages: List[SafeViewPage] = Field(default_factory=list)
    disclaimer: str = (
        "Safe View displays a static rendering of the document. "
        "It does not execute the document's intended interactive features. "
        "This preview reduces exposure to active content but is not a guarantee that the original file is harmless."
    )
    retention_policy: str = "Temporary preview cache pruned automatically after analysis."


class BrandDomainConsistencyResult(BaseModel):
    claimed_organization: Optional[str] = None
    primary_domain: Optional[str] = None
    destination_domains: List[str] = Field(default_factory=list)
    domain_relationship_assessment: str = "No brand mismatch or identity claim identified."
    mismatches: List[str] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    confidence_or_uncertainty_explanation: str = (
        "Domain differences alone do not prove fraud because organizations routinely use third-party vendors and CDNs."
    )


class ScriptTranslationResult(BaseModel):
    has_script: bool = False
    language: str = "None"
    plain_english_summary: str = "No executable scripts or macro commands were detected in this document."
    observed_operations: List[str] = Field(default_factory=list)
    inferred_intent_warning: str = "Analysis reflects observed static operations, not verified runtime intent."
    evidence_lines: List[str] = Field(default_factory=list)


class HiddenContentItem(BaseModel):
    extracted_text: str
    location: str
    classification_reason: str
    detection_type: Literal["structural", "visual_inference"]
    context_snippet: str = ""


class HiddenContentResult(BaseModel):
    hidden_elements_count: int = 0
    items: List[HiddenContentItem] = Field(default_factory=list)
    summary: str = "No hidden or invisible text elements detected."
    explanation: str = "Text content and structural layers appear consistently visible."


class DocumentScanResponse(BaseModel):
    id: str
    file_name: str
    file_size_bytes: int
    file_size_formatted: str
    file_type: str
    sha256_hash: str
    timestamp: str
    verdict: Literal["clean", "suspicious", "malicious"]
    risk_level: Literal["safe", "warning", "critical", "neutral"]
    risk_score: float = Field(..., ge=0.0, le=100.0)
    detected_signals: List[str] = Field(default_factory=list)
    executive_summary: str
    recommended_action: str

    # 9 Advanced Capabilities
    macro_inspection: MacroInspectionResult
    html_safety: HtmlAttachmentSafetyResult
    embedded_links: EmbeddedLinksResult
    exploit_indicators: ExploitIndicatorResult
    forms_and_submission: FormSubmissionResult
    safe_view: SafeViewResult
    brand_domain_consistency: BrandDomainConsistencyResult
    script_translator: ScriptTranslationResult
    hidden_content: HiddenContentResult


