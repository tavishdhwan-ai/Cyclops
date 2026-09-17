import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.schemas import EmailScanResponse, Finding

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinelai-backend"
    assert data["mode"] == "demo"


def test_options_preflight_chrome_extension():
    """Verify that OPTIONS /scan-email handles CORS preflight from Chrome extensions successfully."""
    headers = {
        "Origin": "chrome-extension://abcdefghijklmnopqrstuvwxyz123456",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    response = client.options("/scan-email", headers=headers)
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] in ["*", "chrome-extension://abcdefghijklmnopqrstuvwxyz123456"]
    assert "access-control-allow-methods" in response.headers


def test_scan_email_endpoint():
    payload = {
        "sender": "billing@example.com",
        "subject": "Urgent account verification required",
        "body": "Please verify your password immediately.",
        "links": ["http://suspicious-link.test"],
        "attachments": [{"name": "invoice.pdf", "file_type": "pdf", "size_bytes": 1024}],
    }
    response = client.post("/scan-email", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["mode"] == "demo"
    assert data["status"] == "completed"
    assert "threat_score" in data
    assert 0.0 <= data["threat_score"] <= 10.0
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) > 0
    assert "recommendation" in data
    assert isinstance(data["attachments"], list)
    assert len(data["attachments"]) == 1
    assert data["attachments"][0]["name"] == "invoice.pdf"


def test_invalid_threat_score_schema_validation():
    """Verify that threat_score > 10 fails validation."""
    with pytest.raises(ValidationError):
        EmailScanResponse(
            scan_id="test-id",
            mode="demo",
            status="completed",
            threat_score=15.0,  # Invalid: > 10.0
            risk_level="HIGH",
            summary="Test summary",
            findings=[
                Finding(
                    type="urgency",
                    severity="medium",
                    title="Test title",
                    description="Test desc",
                )
            ],
            recommendation="Test recommendation",
        )


def test_invalid_risk_level_schema_validation():
    """Verify that invalid risk level string fails validation."""
    with pytest.raises(ValidationError):
        EmailScanResponse(
            scan_id="test-id",
            mode="demo",
            status="completed",
            threat_score=5.0,
            risk_level="EXTREME",  # Invalid: Not in enum
            summary="Test summary",
            findings=[],
            recommendation="Test recommendation",
        )
