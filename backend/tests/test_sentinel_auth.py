"""
Comprehensive Test Suite for Sentinel AI Dual-Channel Authentication Engine.
Validates:
1. Sequential Gate enforcement (Gate 1 before Gate 2).
2. WhatsApp unconfigured provider handling (no fabricated success).
3. Desktop-denied policy with exact headline: 'Access Denied: Mobile Authorization Required'.
4. WebAuthn platform authenticator challenge generation & assertion validation.
5. Atomic challenge consumption & replay protection.
6. Cross-device session finalization.
"""
import time
import json
import hashlib
import secrets
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth_engine import (
    STATE_EMAIL_PENDING,
    STATE_MOBILE_CHALLENGE_ISSUED,
    STATE_AUTHENTICATED,
    hash_token,
    _CHALLENGES,
)
from app.webauthn import (
    generate_webauthn_challenge,
    base64url_encode,
    WEBAUTHN_RP_ID,
    WEBAUTHN_ORIGIN,
)

client = TestClient(app)


def test_start_auth_generates_transaction():
    """Step 1: Start auth returns transaction ID and sets state to EMAIL_PENDING."""
    response = client.post(
        "/api/auth/start",
        json={"email": "agent@sentinel.ai", "phoneNumber": "+14155552671"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "transactionId" in data
    assert data["state"] == STATE_EMAIL_PENDING
    assert data["expiresAt"] > time.time()


def test_confirm_email_transitions_to_mobile_challenge():
    """Step 2: Gate 1 confirmation transitions to MOBILE_CHALLENGE_ISSUED and sets unconfigured WhatsApp status."""
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "sarah.connor@sentinel.ai", "phoneNumber": "+14155559999"},
    )
    tx_id = start_resp.json()["transactionId"]

    confirm_resp = client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "sarah.connor@sentinel.ai"},
    )
    assert confirm_resp.status_code == 200
    confirm_data = confirm_resp.json()
    assert confirm_data["emailVerified"] is True
    assert confirm_data["state"] == STATE_MOBILE_CHALLENGE_ISSUED
    # In test environment without Twilio/Meta keys, provider is cleanly reported as unconfigured
    assert confirm_data["whatsappConfigured"] is False
    assert confirm_data["whatsappDeliveryStatus"] == "unconfigured"


def test_desktop_user_agent_denied_with_exact_headline():
    """Step 3: Desktop User-Agent is denied access with exact headline."""
    # Start and confirm email to issue mobile challenge
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "desktop.user@sentinel.ai", "phoneNumber": "+14155551234"},
    )
    tx_id = start_resp.json()["transactionId"]
    confirm_resp = client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "desktop.user@sentinel.ai"},
    )

    # Grab the generated raw token from backend challenge index for testing
    from app.auth_engine import _TRANSACTIONS
    tx = _TRANSACTIONS[tx_id]
    token_h = tx["mobileChallengeTokenHash"]

    # Invert hash mapping to find the raw token in test
    raw_token = None
    for h, challenge in _CHALLENGES.items():
        if challenge["transactionId"] == tx_id:
            # We can test by setting a known token
            test_token = "test_desktop_token_" + secrets.token_hex(8)
            new_hash = hash_token(test_token)
            challenge["tokenHash"] = new_hash
            _CHALLENGES[new_hash] = challenge
            raw_token = test_token
            break

    assert raw_token is not None

    # Request with Desktop User-Agent (Windows NT 10.0; Win64; x64)
    desktop_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    resp_desktop = client.get(
        f"/api/auth/mobile-challenge?t={raw_token}",
        headers={"User-Agent": desktop_ua},
    )
    assert resp_desktop.status_code == 200
    data = resp_desktop.json()
    assert data["desktopDenied"] is True
    assert data["headline"] == "Access Denied: Mobile Authorization Required"
    assert "mobile device" in data["message"].lower()


def test_mobile_user_agent_permitted_for_webauthn():
    """Step 3b: Mobile User-Agent receives WebAuthn challenge."""
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "mobile.user@sentinel.ai", "phoneNumber": "+14155554321"},
    )
    tx_id = start_resp.json()["transactionId"]
    client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "mobile.user@sentinel.ai"},
    )

    test_token = "test_mobile_token_" + secrets.token_hex(8)
    new_hash = hash_token(test_token)
    for h, challenge in list(_CHALLENGES.items()):
        if challenge["transactionId"] == tx_id:
            challenge["tokenHash"] = new_hash
            _CHALLENGES[new_hash] = challenge
            break

    # Request with Mobile User-Agent (iPhone iOS Safari)
    iphone_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    resp_mobile = client.get(
        f"/api/auth/mobile-challenge?t={test_token}",
        headers={"User-Agent": iphone_ua},
    )
    assert resp_mobile.status_code == 200
    data = resp_mobile.json()
    assert data["desktopDenied"] is False
    assert "webauthnChallenge" in data
    assert data["rpId"] == WEBAUTHN_RP_ID


def test_webauthn_assertion_and_replay_prevention():
    """Step 4: WebAuthn assertion completes Gate 2 and prevents replay attacks."""
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "biometric.user@sentinel.ai", "phoneNumber": "+14155557777"},
    )
    tx_id = start_resp.json()["transactionId"]
    client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "biometric.user@sentinel.ai"},
    )

    test_token = "test_biometric_token_" + secrets.token_hex(8)
    new_hash = hash_token(test_token)
    expected_challenge = None
    for h, challenge in list(_CHALLENGES.items()):
        if challenge["transactionId"] == tx_id:
            challenge["tokenHash"] = new_hash
            _CHALLENGES[new_hash] = challenge
            expected_challenge = challenge["webauthnChallenge"]
            break

    assert expected_challenge is not None

    # Construct standard WebAuthn clientDataJSON
    client_data = {
        "type": "webauthn.get",
        "challenge": expected_challenge,
        "origin": WEBAUTHN_ORIGIN,
    }
    client_data_b64 = base64url_encode(json.dumps(client_data).encode("utf-8"))

    # Construct valid authenticatorData:
    # 32 bytes RP ID hash + 1 byte flags (0x05: UP=1, UV=1) + 4 bytes counter
    rp_id_hash = hashlib.sha256(WEBAUTHN_RP_ID.encode("utf-8")).digest()
    flags = bytes([0x05])  # User Present + User Verified
    counter = (1).to_bytes(4, byteorder="big")
    auth_data_b64 = base64url_encode(rp_id_hash + flags + counter)

    payload = {
        "mobileToken": test_token,
        "credentialId": base64url_encode(b"test-credential-id"),
        "clientDataJSON": client_data_b64,
        "authenticatorData": auth_data_b64,
        "signature": base64url_encode(b"simulated-signature-bytes"),
    }

    # First submission: should succeed
    verify_resp = client.post("/api/auth/webauthn/verify", json=payload)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["success"] is True
    assert verify_resp.json()["state"] == STATE_AUTHENTICATED

    # Second submission: Replay attempt MUST fail
    replay_resp = client.post("/api/auth/webauthn/verify", json=payload)
    assert replay_resp.status_code == 400
    assert "replay detected" in replay_resp.json()["detail"].lower()


def test_session_completion_requires_both_gates():
    """Step 5: Computer session finalization rejects uncompleted gates and accepts completed gates."""
    # 1. Reject session when gates are incomplete
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "incomplete@sentinel.ai", "phoneNumber": "+14155550000"},
    )
    incomplete_tx = start_resp.json()["transactionId"]

    fail_resp = client.post("/api/auth/complete", json={"transactionId": incomplete_tx})
    assert fail_resp.status_code == 400
    assert "incomplete" in fail_resp.json()["detail"].lower()

    # 2. Complete both gates
    client.post(
        "/api/auth/confirm-email",
        json={"transactionId": incomplete_tx, "email": "incomplete@sentinel.ai"},
    )

    test_token = "complete_tx_token_" + secrets.token_hex(8)
    new_hash = hash_token(test_token)
    expected_challenge = None
    for h, challenge in list(_CHALLENGES.items()):
        if challenge["transactionId"] == incomplete_tx:
            challenge["tokenHash"] = new_hash
            _CHALLENGES[new_hash] = challenge
            expected_challenge = challenge["webauthnChallenge"]
            break

    client_data_b64 = base64url_encode(json.dumps({
        "type": "webauthn.get",
        "challenge": expected_challenge,
        "origin": WEBAUTHN_ORIGIN,
    }).encode("utf-8"))

    rp_id_hash = hashlib.sha256(WEBAUTHN_RP_ID.encode("utf-8")).digest()
    auth_data_b64 = base64url_encode(rp_id_hash + bytes([0x05]) + (1).to_bytes(4, byteorder="big"))

    client.post("/api/auth/webauthn/verify", json={
        "mobileToken": test_token,
        "credentialId": base64url_encode(b"cred-id"),
        "clientDataJSON": client_data_b64,
        "authenticatorData": auth_data_b64,
        "signature": base64url_encode(b"sig"),
    })

    # Now finalize computer session
    success_resp = client.post("/api/auth/complete", json={"transactionId": incomplete_tx})
    assert success_resp.status_code == 200
    sess_data = success_resp.json()
    assert sess_data["success"] is True
    assert "sessionToken" in sess_data
    assert sess_data["user"]["securityTier"] == 2
    assert sess_data["user"]["email"] == "incomplete@sentinel.ai"


def test_worldwide_international_phone_numbers():
    """Verify phone normalization supports India, US, UK, Germany, Australia and rejects invalid numbers."""
    # 1. India (+91)
    resp_india = client.post(
        "/api/auth/start",
        json={"email": "india@sentinel.ai", "phoneNumber": "+91 98765 43210"},
    )
    assert resp_india.status_code == 200
    assert "transactionId" in resp_india.json()

    # 2. United Kingdom (+44)
    resp_uk = client.post(
        "/api/auth/start",
        json={"email": "uk@sentinel.ai", "phoneNumber": "+44 7911 123456"},
    )
    assert resp_uk.status_code == 200

    # 3. Germany (+49)
    resp_de = client.post(
        "/api/auth/start",
        json={"email": "germany@sentinel.ai", "phoneNumber": "+49 151 23456789"},
    )
    assert resp_de.status_code == 200

    # 4. Australia (+61)
    resp_au = client.post(
        "/api/auth/start",
        json={"email": "australia@sentinel.ai", "phoneNumber": "+61 412 345 678"},
    )
    assert resp_au.status_code == 200

    # 5. Invalid / malformed numbers rejected with 400
    resp_invalid = client.post(
        "/api/auth/start",
        json={"email": "bad@sentinel.ai", "phoneNumber": "+91 123"},
    )
    assert resp_invalid.status_code == 400
    assert "not a valid international mobile number" in resp_invalid.json()["detail"].lower()


def test_logout_revokes_session():
    """Verify that logging out revokes the session on the server."""
    # Start and complete session
    start_resp = client.post(
        "/api/auth/start",
        json={"email": "logout.test@sentinel.ai", "phoneNumber": "+919876543210"},
    )
    tx_id = start_resp.json()["transactionId"]
    client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "logout.test@sentinel.ai"},
    )

    test_token = "logout_test_tok_" + secrets.token_hex(8)
    new_hash = hash_token(test_token)
    expected_challenge = None
    for h, challenge in list(_CHALLENGES.items()):
        if challenge["transactionId"] == tx_id:
            challenge["tokenHash"] = new_hash
            _CHALLENGES[new_hash] = challenge
            expected_challenge = challenge["webauthnChallenge"]
            break

    client_data_b64 = base64url_encode(json.dumps({
        "type": "webauthn.get",
        "challenge": expected_challenge,
        "origin": WEBAUTHN_ORIGIN,
    }).encode("utf-8"))
    rp_id_hash = hashlib.sha256(WEBAUTHN_RP_ID.encode("utf-8")).digest()
    auth_data_b64 = base64url_encode(rp_id_hash + bytes([0x05]) + (1).to_bytes(4, byteorder="big"))

    client.post("/api/auth/webauthn/verify", json={
        "mobileToken": test_token,
        "credentialId": base64url_encode(b"logout-cred"),
        "clientDataJSON": client_data_b64,
        "authenticatorData": auth_data_b64,
        "signature": base64url_encode(b"sig"),
    })

    comp_resp = client.post("/api/auth/complete", json={"transactionId": tx_id})
    session_token = comp_resp.json()["sessionToken"]

    # Call logout endpoint with Bearer token
    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["success"] is True
    assert logout_resp.json()["revoked"] is True


def test_server_email_validation():
    """Verify server-side email validation rejects malformed, empty, or malicious inputs."""
    # 1. Invalid email missing @
    resp_no_at = client.post(
        "/api/auth/start",
        json={"email": "invalidemail.com", "phoneNumber": "+919876543210"},
    )
    assert resp_no_at.status_code == 400
    assert "valid email" in resp_no_at.json()["detail"].lower()

    # 2. Invalid email with spaces
    resp_spaces = client.post(
        "/api/auth/start",
        json={"email": "user @company.com", "phoneNumber": "+919876543210"},
    )
    assert resp_spaces.status_code == 400

    # 3. Invalid email with Windows backslash evasion
    resp_backslash = client.post(
        "/api/auth/start",
        json={"email": "user\\name@company.com", "phoneNumber": "+919876543210"},
    )
    assert resp_backslash.status_code == 400

    # 4. Valid email with trimming and case normalization
    resp_valid = client.post(
        "/api/auth/start",
        json={"email": "  Agent.Security+Sentinel@Sentinel.AI  ", "phoneNumber": "+919876543210"},
    )
    assert resp_valid.status_code == 200
    assert "transactionId" in resp_valid.json()


def test_database_persistence_of_transactions():
    """Verify transaction and challenge records are genuinely written to the SQL database."""
    from app.database import load_transaction, load_challenge

    resp = client.post(
        "/api/auth/start",
        json={"email": "persistence.test@sentinel.ai", "phoneNumber": "+919876543210"},
    )
    assert resp.status_code == 200
    tx_id = resp.json()["transactionId"]

    # Verify transaction was saved to database
    db_record = load_transaction(tx_id)
    assert db_record is not None, "Transaction must exist in SQL database"
    assert db_record["id"] == tx_id
    assert db_record["email"] == "persistence.test@sentinel.ai"
    assert db_record["phoneNumber"] == "+919876543210"
    assert db_record["state"] == STATE_EMAIL_PENDING

    # Confirm email gate and verify challenge persistence
    confirm_resp = client.post(
        "/api/auth/confirm-email",
        json={"transactionId": tx_id, "email": "persistence.test@sentinel.ai"},
    )
    assert confirm_resp.status_code == 200

    from app.auth_engine import _TRANSACTIONS
    token_h = _TRANSACTIONS[tx_id]["mobileChallengeTokenHash"]
    assert token_h is not None

    db_challenge = load_challenge(token_h)
    assert db_challenge is not None, "Challenge must exist in SQL database"
    assert db_challenge["transactionId"] == tx_id
    assert db_challenge["consumedAt"] is None


