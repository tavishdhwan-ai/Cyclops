from typing import List
import uuid
from app.schemas import (
    EmailScanRequest,
    EmailScanResponse,
    Finding,
    AttachmentResult,
)


def analyze_demo_email(request: EmailScanRequest) -> EmailScanResponse:
    """
    Controlled demo scanner for SentinelAI Phase 3A.
    Returns deterministic demo security analysis without external scanning calls.
    """
    # Build findings list matching demo scenario specifications
    findings: List[Finding] = [
        Finding(
            type="sender_impersonation",
            severity="high",
            title="Possible sender impersonation",
            description="The sender information may require verification.",
        ),
        Finding(
            type="suspicious_link",
            severity="high",
            title="Suspicious link detected",
            description="A link requires verification before opening.",
        ),
        Finding(
            type="credential_request",
            severity="critical",
            title="Credential request",
            description="The message asks the recipient to verify a password.",
        ),
        Finding(
            type="urgency",
            severity="medium",
            title="Urgency-based language",
            description="The message creates pressure to act quickly.",
        ),
    ]

    # Map request attachments to scan results
    attachment_results: List[AttachmentResult] = []
    if request.attachments:
        for att in request.attachments:
            att_name = att.name if att.name else "unnamed_attachment"
            attachment_results.append(
                AttachmentResult(
                    name=att_name,
                    status="scanned",
                    threat_found=False,
                )
            )

    scan_id = f"demo-scan-{uuid.uuid4().hex[:8]}"

    return EmailScanResponse(
        scan_id=scan_id,
        mode="demo",
        status="completed",
        threat_score=8.7,
        risk_level="HIGH",
        summary="Demo analysis detected several suspicious indicators.",
        findings=findings,
        attachments=attachment_results,
        recommendation="Do not click links or open attachments until the sender is verified.",
    )
