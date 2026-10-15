"""
SentinelAI Modular Scanner Engine Package.
Re-exports entry points for FastAPI backend and unit tests.
"""
from app.scanner.engine import scan_email_engine as analyze_demo_email
from app.scanner.scoring import calculate_risk_level, calculate_overall_score
from app.scanner.sender import analyze_sender, parse_sender_info
from app.scanner.content import analyze_urgency, analyze_credential_request, analyze_account_pressure
from app.scanner.urls import analyze_urls
from app.scanner.attachments import analyze_attachments

from app.scanner.url_pipeline import orchestrate_url_scan
from app.scanner.url_validator import normalize_and_validate_url
from app.scanner.ssrf import safe_fetch_url, resolve_and_validate_hostname, SSRFValidationError

__all__ = [
    "analyze_demo_email",
    "calculate_risk_level",
    "calculate_overall_score",
    "analyze_sender",
    "parse_sender_info",
    "analyze_urgency",
    "analyze_credential_request",
    "analyze_account_pressure",
    "analyze_urls",
    "analyze_attachments",
    "orchestrate_url_scan",
    "normalize_and_validate_url",
    "safe_fetch_url",
    "resolve_and_validate_hostname",
    "SSRFValidationError",
]

