import io
import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
import jwt

client = TestClient(app)

TEST_USER_ID = "usr_test_profile_123"
SUPABASE_JWT_SECRET = "super-secret-jwt-token-with-at-least-32-bytes-long"

def make_test_token(user_id=TEST_USER_ID, email="tester@example.com"):
    payload = {
        "sub": user_id,
        "email": email,
        "role": "authenticated",
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")


def test_username_check_available_and_invalid():
    # Valid and unique
    res = client.get("/api/user/check-username?username=cyber_hero_99")
    assert res.status_code == 200
    assert res.json()["available"] is True
    assert res.json()["username"] == "cyber_hero_99"

    # Too short
    res = client.get("/api/user/check-username?username=ab")
    assert res.status_code == 200
    assert res.json()["available"] is False

    # Invalid characters
    res = client.get("/api/user/check-username?username=invalid.name!")
    assert res.status_code == 200
    assert res.json()["available"] is False


def test_profile_update_and_get():
    token = make_test_token(TEST_USER_ID, "tester@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    # Update profile
    payload = {
        "fullName": "Agent Sentinel",
        "username": "sentinel_lead",
        "country": "United States",
        "preferredLanguage": "en",
        "timeZone": "America/New_York",
        "goal": "personal",
        "concerns": ["phishing", "identity_theft"],
        "experience": "intermediate",
        "onboardingCompleted": True,
    }
    res = client.post("/api/user/profile", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["profile"]["fullName"] == "Agent Sentinel"
    assert data["profile"]["username"] == "sentinel_lead"
    assert data["profile"]["onboardingCompleted"] is True

    # Retrieve profile
    get_res = client.get("/api/user/profile", headers=headers)
    assert get_res.status_code == 200
    profile_data = get_res.json()
    assert profile_data["fullName"] == "Agent Sentinel"
    assert profile_data["country"] == "United States"


def test_duplicate_username_rejected():
    token1 = make_test_token("usr_user_1", "user1@example.com")
    token2 = make_test_token("usr_user_2", "user2@example.com")

    # User 1 sets username
    client.post(
        "/api/user/profile",
        json={"username": "unique_agent_007"},
        headers={"Authorization": f"Bearer {token1}"},
    )

    # User 2 tries to take the same username
    res = client.post(
        "/api/user/profile",
        json={"username": "unique_agent_007"},
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert res.status_code == 409
    assert "already taken" in res.json()["detail"]


def test_avatar_upload():
    token = make_test_token("usr_avatar_user", "avatar@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    # Create dummy image bytes (minimal 1x1 png)
    dummy_png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    files = {"file": ("avatar.png", dummy_png, "image/png")}
    res = client.post("/api/user/avatar", files=files, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["avatarUrl"].startswith("data:image/png;base64,")


def test_security_dashboard_passkeys_and_devices():
    user_id = "usr_sec_dashboard_user"
    token = make_test_token(user_id, "sec_user@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    # Passkeys
    res = client.get("/api/security/passkeys", headers=headers)
    assert res.status_code == 200
    assert "passkeys" in res.json()

    # Devices
    res = client.get("/api/security/devices", headers=headers)
    assert res.status_code == 200
    assert "devices" in res.json()

    # Activity
    res = client.get("/api/security/activity", headers=headers)
    assert res.status_code == 200
    assert "activity" in res.json()

    # Security notification preferences
    res = client.get("/api/security/preferences", headers=headers)
    assert res.status_code == 200
    assert "notifyNewDevice" in res.json()["preferences"]

    # Update preferences
    update_res = client.post(
        "/api/security/preferences",
        json={"notifyNewDevice": False, "notifyFailedLogin": True},
        headers=headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["preferences"]["notifyNewDevice"] is False
