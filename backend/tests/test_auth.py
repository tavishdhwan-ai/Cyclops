"""
Unit tests for Cyclops Authentication, Authorization, and User Data Isolation.
"""
import time
import pytest
import jwt
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def make_jwt(user_id: str, email: str, expired: bool = False) -> str:
    """Generate a test JWT token."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": "authenticated",
        "exp": time.time() - 3600 if expired else time.time() + 3600,
        "user_metadata": {
            "display_name": f"User {user_id}",
        },
    }
    # Dev test key (at least 32 bytes for HMAC-SHA256)
    return jwt.encode(payload, "cyclops-test-secret-32-bytes-long-key!", algorithm="HS256")


def test_profile_requires_auth_header():
    """Unauthenticated requests must be rejected with 401."""
    response = client.get("/api/user/profile")
    assert response.status_code == 401
    assert "detail" in response.json()


def test_profile_rejects_malformed_token():
    """Malformed tokens must return 401 Unauthorized."""
    response = client.get(
        "/api/user/profile",
        headers={"Authorization": "Bearer not-a-valid-token-format"},
    )
    assert response.status_code == 401


def test_profile_rejects_expired_token():
    """Expired tokens must return 401 Unauthorized."""
    expired_token = make_jwt("expired-user", "expired@example.com", expired=True)
    response = client.get(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


def test_profile_access_with_valid_token():
    """Valid tokens must authenticate and return the user profile."""
    valid_token = make_jwt("alice-123", "alice@example.com")
    response = client.get(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["userId"] == "alice-123"


def test_user_data_isolation():
    """Verify that User A cannot see or tamper with User B's profile data."""
    token_alice = make_jwt("alice-id", "alice@example.com")
    token_bob = make_jwt("bob-id", "bob@example.com")

    # 1. Alice sets her goal to personal
    resp_a = client.post(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={
            "userId": "alice-id",
            "displayName": "Alice Vance",
            "goal": "personal",
            "concerns": ["phishing"],
            "experience": "intermediate",
        },
    )
    assert resp_a.status_code == 200

    # 2. Bob sets his goal to family
    resp_b = client.post(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_bob}"},
        json={
            "userId": "bob-id",
            "displayName": "Bob Builder",
            "goal": "family",
            "concerns": ["documents", "downloads"],
            "experience": "beginner",
        },
    )
    assert resp_b.status_code == 200

    # 3. Alice retrieves profile: only gets her own data
    get_a = client.get(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert get_a.status_code == 200
    assert get_a.json()["displayName"] == "Alice Vance"
    assert get_a.json()["goal"] == "personal"

    # 4. Bob retrieves profile: only gets his own data
    get_b = client.get(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_bob}"},
    )
    assert get_b.status_code == 200
    assert get_b.json()["displayName"] == "Bob Builder"
    assert get_b.json()["goal"] == "family"

    # 5. Alice attempts to overwrite Bob's profile -> 403 Forbidden
    tamper_attempt = client.post(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={
            "userId": "bob-id",
            "displayName": "Hacked Bob",
        },
    )
    assert tamper_attempt.status_code == 403


def test_account_deletion_clears_records():
    """Verify that deleting an account purges user data."""
    token_charlie = make_jwt("charlie-id", "charlie@example.com")

    # Save data first
    client.post(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_charlie}"},
        json={"userId": "charlie-id", "displayName": "Charlie"},
    )

    # Delete account
    del_resp = client.delete(
        "/api/user/account",
        headers={"Authorization": f"Bearer {token_charlie}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Check profile is reset
    get_resp = client.get(
        "/api/user/profile",
        headers={"Authorization": f"Bearer {token_charlie}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["displayName"] == ""
