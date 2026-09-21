"""
Models module for SentinelAI.
Re-exports schemas from app.schemas for compatibility.
"""
from app.schemas import (
    AttachmentInput,
    EmailScanRequest,
    Finding,
    AttachmentResult,
    EmailScanResponse,
)

__all__ = [
    "AttachmentInput",
    "EmailScanRequest",
    "Finding",
    "AttachmentResult",
    "EmailScanResponse",
]
