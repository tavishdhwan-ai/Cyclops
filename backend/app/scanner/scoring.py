"""
Centralized threat score calculation and risk level boundaries for SentinelAI scanner.
"""
from typing import List
from app.schemas import Finding


def calculate_risk_level(threat_score: float) -> str:
    """
    Exact risk level thresholds:
    0.0 <= score <= 2.49 -> LOW
    2.5 <= score <= 4.99 -> MEDIUM
    5.0 <= score <= 7.49 -> HIGH
    7.5 <= score <= 10.0 -> CRITICAL
    """
    if threat_score < 2.5:
        return "LOW"
    elif threat_score < 5.0:
        return "MEDIUM"
    elif threat_score < 7.5:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_overall_score(findings: List[Finding]) -> float:
    """
    Calculate continuous decimal threat score (0.0 - 10.0).
    Uses deterministic severity weights:
    - critical: +3.0
    - high: +2.5
    - medium: +1.5
    - low: +0.5

    Applies per-category caps to prevent duplicate findings from inflating the score endlessly.
    """
    if not findings:
        return 0.5

    score = 1.0  # Baseline when security indicators are detected

    category_scores = {}
    for f in findings:
        contrib = f.score_contribution
        if contrib is None:
            if f.severity == "critical":
                contrib = 3.0
            elif f.severity == "high":
                contrib = 2.5
            elif f.severity == "medium":
                contrib = 1.5
            else:
                contrib = 0.5

        cat = getattr(f, "category", None) or "general"
        category_scores[cat] = category_scores.get(cat, 0.0) + contrib

    category_caps = {
        "sender": 5.0,
        "urls": 4.0,
        "content": 5.0,
        "attachments": 4.0,
        "general": 4.0,
    }

    total_contrib = 0.0
    for cat, cat_score in category_scores.items():
        cap = category_caps.get(cat, 4.5)
        total_contrib += min(cat_score, cap)

    score += total_contrib
    final_score = round(min(10.0, max(0.0, score)), 1)
    return final_score
