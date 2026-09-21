"""
Email content rules analyzer (urgency, credential requests, account/payment pressure) for SentinelAI scanner.
Preserves Phase 3B detections.
"""
from typing import List, Optional
from app.schemas import Finding


def analyze_urgency(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    """Detect high-urgency psychological manipulation language."""
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    urgency_phrases = [
        "within 10 minutes",
        "immediate action required",
        "account will be suspended",
        "final warning",
        "expires today",
        "respond now",
        "act now",
        "immediately",
        "urgent"
    ]

    for phrase in urgency_phrases:
        if phrase in text:
            findings.append(Finding(
                id="urgency_language",
                category="content",
                type="urgency",
                severity="medium",
                title="Urgency-based language",
                description=f"Email uses high-urgency language (\"{phrase}\") to create pressure to act quickly without verification.",
                explanation=f"Email uses high-urgency language (\"{phrase}\") to create pressure to act quickly without verification.",
                evidence={"matched_phrase": phrase},
                score_contribution=1.5,
            ))
            break

    return findings


def analyze_credential_request(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    """Detect requests for login credentials, passwords, or identity verification."""
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    credential_phrases = [
        "verify your password",
        "confirm your password",
        "enter your password",
        "login verification",
        "verify your account",
        "confirm your login",
        "security verification",
        "reset your password",
        "enter your credentials",
        "confirm your identity"
    ]

    for phrase in credential_phrases:
        if phrase in text:
            findings.append(Finding(
                id="credential_request",
                category="content",
                type="credential_request",
                severity="critical",
                title="Credential request",
                description=f"The message requests account, password, login, or identity information (\"{phrase}\").",
                explanation=f"The message requests account, password, login, or identity information (\"{phrase}\").",
                evidence={"matched_phrase": phrase},
                score_contribution=3.0,
            ))
            break

    return findings


def analyze_account_pressure(subject: Optional[str], body: Optional[str]) -> List[Finding]:
    """Detect artificial account suspension or payment billing pressure."""
    findings: List[Finding] = []
    text = f"{subject or ''} {body or ''}".lower()

    pressure_phrases = [
        "account suspended",
        "account will be suspended",
        "account disabled",
        "unusual activity",
        "payment failed",
        "verify billing",
        "invoice overdue",
        "confirm identity",
        "payment required",
        "billing issue"
    ]

    for phrase in pressure_phrases:
        if phrase in text:
            findings.append(Finding(
                id="account_action",
                category="content",
                type="account_action",
                severity="high",
                title="Suspicious account or payment action",
                description=f"The email warns of account or payment issues (\"{phrase}\"), creating pressure to take immediate action.",
                explanation=f"The email warns of account or payment issues (\"{phrase}\"), creating pressure to take immediate action.",
                evidence={"matched_phrase": phrase},
                score_contribution=2.5,
            ))
            break

    return findings
