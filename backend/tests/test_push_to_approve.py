import time
import base64
import hashlib
import secrets
import json
import pytest
import cbor2
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from app.main import app
from app import database
from app.webauthn import WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN
from app.push_auth_engine import (
    STATE_PENDING_APPROVAL,
    STATE_AWAITING_PASSKEY,
    STATE_AUTHENTICATED,
    STATE_REJECTED,
    STATE_EXPIRED,
    STATE_COMPLETED,
)

client = TestClient(app)

def _generate_test_assertion(private_key, cred_id, rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN, challenge="auth_challenge_32_bytes_random__", sign_count=15, uv=True):
    client_data = json.dumps({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
    }).encode("utf-8")

    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0x05 if uv else 0x01])  # UP + UV or UP only
    auth_data = rp_hash + flags + sign_count.to_bytes(4, "big")

    signed_data = auth_data + hashlib.sha256(client_data).digest()
    signature = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    return {
        "id": bytes_to_base64url(cred_id) if isinstance(cred_id, bytes) else cred_id,
        "rawId": bytes_to_base64url(cred_id) if isinstance(cred_id, bytes) else cred_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "authenticatorData": bytes_to_base64url(auth_data),
            "signature": bytes_to_base64url(signature),
        },
    }

# Helper to create a user with a registered passkey and push subscription
def setup_test_user_with_passkey_and_push(phone="+14155552671", user_id="usr_push_test_1"):
    now = time.time()
    # Save user profile
    database.save_or_update_user_profile(user_id, {
        "email": f"{user_id}@example.com",
        "phoneNumber": phone,
        "fullName": "Push Test User",
        "displayName": "PushTester",
        "onboardingCompleted": True,
    })

    # Generate real EC P-256 keypair for testing WebAuthn assertion
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x = public_numbers.x.to_bytes(32, "big")
    y = public_numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    cose_bytes = cbor2.dumps(cose_key)
    b64_public_key = bytes_to_base64url(cose_bytes)

    cred_raw = b"cred_push_" + secrets.token_bytes(8)
    credential_id = bytes_to_base64url(cred_raw)

    dev_id = f"dev_{user_id}_{secrets.token_hex(4)}"
    # Save registered device
    database.save_verified_passkey_device(
        user_id=user_id,
        device_id=dev_id,
        credential_id=credential_id,
        public_key=b64_public_key,
        sign_count=10,
        device_name="Test Pixel 8 Pro",
        platform="Android",
    )

    # Save push subscription
    database.save_push_subscription({
        "user_id": user_id,
        "endpoint": f"https://fcm.googleapis.com/fcm/send/test_{user_id}_{secrets.token_hex(4)}",
        "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QT9AcDnVwTJaWwBaMO_Sc64v6bEtR32j5W6K1g7k1_7M6-8w",
        "auth": "tBHItJI5svbpez7KI4CCXg",
        "device_id": dev_id,
        "user_agent": "Mozilla/5.0 (Android)",
    })

    return {
        "userId": user_id,
        "phoneNumber": phone,
        "credentialId": credential_id,
        "privateKey": private_key,
        "publicKeyB64": b64_public_key,
    }


def test_push_login_invalid_phone():
    # Missing/invalid format
    res = client.post("/api/auth/push-login/start", json={"phoneNumber": "123"})
    assert res.status_code == 400
    assert "Invalid phone number" in res.json()["detail"] or "phone" in res.json()["detail"].lower()


def test_push_login_unregistered_phone_lookup():
    # Valid phone syntax but unknown account
    unregistered_phone = "+12025550199"
    res = client.post("/api/auth/push-login/start", json={"phoneNumber": unregistered_phone})
    assert res.status_code == 404
    data = res.json()
    detail = data["detail"]
    title = detail.get("title", "") if isinstance(detail, dict) else detail
    message = detail.get("message", "") if isinstance(detail, dict) else detail

    assert "No account associated with this number" in title
    assert "We couldn't find a SentinelAI account registered with this phone number. Please check the number or sign up for SentinelAI." in message

    # Verify no transaction was created in database
    tx = database.get_user_by_phone(unregistered_phone)
    assert tx is None


def test_push_login_success_lifecycle():
    user_info = setup_test_user_with_passkey_and_push(phone="+14155558899", user_id="usr_lifecycle_1")

    # Step 1: Start Push Login
    res = client.post(
        "/api/auth/push-login/start",
        json={"phoneNumber": user_info["phoneNumber"]},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"},
    )
    assert res.status_code == 200
    start_data = res.json()
    assert start_data["success"] is True
    assert start_data["isConfiguredForPush"] is True
    tx_id = start_data["transactionId"]
    approval_url = start_data["mobileApprovalUrl"]
    assert "tok=" in approval_url
    mobile_token = approval_url.split("tok=")[1]

    # Status should be PENDING_APPROVAL
    status_res = client.get(f"/api/auth/push-login/status/{tx_id}")
    assert status_res.status_code == 200
    assert status_res.json()["state"] == STATE_PENDING_APPROVAL
    assert status_res.json()["authenticated"] is False

    # Step 2: Mobile opens notification URL and fetches details
    details_res = client.get(f"/api/auth/push-login/details?tx={tx_id}&tok={mobile_token}")
    assert details_res.status_code == 200
    details = details_res.json()
    assert details["transactionId"] == tx_id
    assert details["browser"] == "Google Chrome"
    assert details["os"] == "Windows"
    assert details["state"] == STATE_PENDING_APPROVAL

    # Step 3: User taps "Yes, it's me" (Approve)
    approve_res = client.post(
        "/api/auth/push-login/approve",
        json={"transactionId": tx_id, "token": mobile_token},
    )
    assert approve_res.status_code == 200
    approve_data = approve_res.json()
    assert approve_data["state"] == STATE_AWAITING_PASSKEY
    assert "webauthnOptions" in approve_data
    challenge = approve_data["webauthnOptions"]["challenge"]

    # Status polling from computer now sees AWAITING_PASSKEY
    status_res = client.get(f"/api/auth/push-login/status/{tx_id}")
    assert status_res.json()["state"] == STATE_AWAITING_PASSKEY

    # Step 4: Perform WebAuthn assertion cryptographic signing
    assertion = _generate_test_assertion(
        private_key=user_info["privateKey"],
        cred_id=base64url_to_bytes(user_info["credentialId"]),
        challenge=challenge,
        sign_count=15,
    )

    # Submit passkey verification
    verify_res = client.post(
        "/api/auth/push-login/verify-passkey",
        json={
            "transactionId": tx_id,
            "token": mobile_token,
            "credentialId": user_info["credentialId"],
            "clientDataJSON": assertion["response"]["clientDataJSON"],
            "authenticatorData": assertion["response"]["authenticatorData"],
            "signature": assertion["response"]["signature"],
        },
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["state"] == STATE_AUTHENTICATED

    # Status polling from computer confirms AUTHENTICATED
    status_res = client.get(f"/api/auth/push-login/status/{tx_id}")
    assert status_res.json()["state"] == STATE_AUTHENTICATED
    assert status_res.json()["authenticated"] is True

    # Step 5: Original device establishes session
    complete_res = client.post(
        "/api/auth/push-login/complete",
        json={"transactionId": tx_id},
    )
    assert complete_res.status_code == 200
    complete_data = complete_res.json()
    assert complete_data["success"] is True
    assert "sessionToken" in complete_data
    assert complete_data["user"]["phoneNumber"] == user_info["phoneNumber"]

    # Replay protection: Calling complete again fails
    repeat_complete = client.post(
        "/api/auth/push-login/complete",
        json={"transactionId": tx_id},
    )
    assert repeat_complete.status_code == 400
    assert "already" in repeat_complete.json()["detail"].lower()


def test_push_login_rejection_flow():
    user_info = setup_test_user_with_passkey_and_push(phone="+14155557766", user_id="usr_reject_1")

    # Start login
    res = client.post(
        "/api/auth/push-login/start",
        json={"phoneNumber": user_info["phoneNumber"]},
    )
    start_data = res.json()
    tx_id = start_data["transactionId"]
    mobile_token = start_data["mobileApprovalUrl"].split("tok=")[1]

    # User clicks "No, it's not me"
    reject_res = client.post(
        "/api/auth/push-login/reject",
        json={"transactionId": tx_id, "token": mobile_token},
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["state"] == STATE_REJECTED

    # Status check confirms REJECTED
    status_res = client.get(f"/api/auth/push-login/status/{tx_id}")
    assert status_res.json()["state"] == STATE_REJECTED
    assert status_res.json()["rejected"] is True

    # Cannot approve after rejection
    approve_res = client.post(
        "/api/auth/push-login/approve",
        json={"transactionId": tx_id, "token": mobile_token},
    )
    assert approve_res.status_code == 400
    assert "rejected" in approve_res.json()["detail"].lower()

    # Cannot complete session after rejection
    complete_res = client.post(
        "/api/auth/push-login/complete",
        json={"transactionId": tx_id},
    )
    assert complete_res.status_code == 400


def test_push_login_cross_account_passkey_blocked():
    user_a = setup_test_user_with_passkey_and_push(phone="+14155551111", user_id="usr_acc_a")
    user_b = setup_test_user_with_passkey_and_push(phone="+14155552222", user_id="usr_acc_b")

    # Start login for user A
    res = client.post(
        "/api/auth/push-login/start",
        json={"phoneNumber": user_a["phoneNumber"]},
    )
    tx_id = res.json()["transactionId"]
    mobile_token = res.json()["mobileApprovalUrl"].split("tok=")[1]

    # User A approves
    app_res = client.post(
        "/api/auth/push-login/approve",
        json={"transactionId": tx_id, "token": mobile_token},
    )
    challenge = app_res.json()["webauthnOptions"]["challenge"]

    # Attacker tries to submit user B's credential
    bad_assertion = _generate_test_assertion(
        private_key=user_b["privateKey"],
        cred_id=base64url_to_bytes(user_b["credentialId"]),
        challenge=challenge,
        sign_count=15,
    )

    bad_verify = client.post(
        "/api/auth/push-login/verify-passkey",
        json={
            "transactionId": tx_id,
            "token": mobile_token,
            "credentialId": user_b["credentialId"],
            "clientDataJSON": bad_assertion["response"]["clientDataJSON"],
            "authenticatorData": bad_assertion["response"]["authenticatorData"],
            "signature": bad_assertion["response"]["signature"],
        },
    )
    assert bad_verify.status_code == 403
    assert "does not belong" in bad_verify.json()["detail"].lower()


def test_push_login_rate_limiting():
    # 5 rapid attempts from same client IP should be allowed, 6th must return 429
    phone = "+14155559999"
    responses = []
    for _ in range(6):
        r = client.post("/api/auth/push-login/start", json={"phoneNumber": phone})
        responses.append(r.status_code)
    assert 429 in responses
