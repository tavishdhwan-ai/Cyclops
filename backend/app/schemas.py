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

