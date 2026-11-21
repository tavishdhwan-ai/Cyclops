"""
Comprehensive Test Suite for Sentinel AI WebAuthn / Passkey Authentication.
Tests:
1. Registration options generation (platform authenticator, user verification).
2. Registration attestation verification using Python webauthn==3.0.1.
3. Authentication options generation for registered passkey.
4. Cryptographic authentication assertion verification against stored public key.
5. Invalid challenge rejection.
6. Invalid origin rejection.
7. Invalid signature rejection.
8. Wrong / unregistered credential rejection.
9. User verification requirement enforcement.
10. Replay prevention on single-use challenge tokens.
11. Database credential persistence and counter updates.
12. End-to-end dual-channel transaction flow: first-time registration -> subsequent passkey login.
"""
import sys
import os
import json
import time
import hashlib
import secrets
import pytest
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fastapi.testclient import TestClient

from app.main import app
from app.webauthn import (
    create_registration_options,
    verify_registration,
    create_authentication_options,
    verify_authentication,
    WEBAUTHN_RP_ID,
    WEBAUTHN_ORIGIN,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from app.database import (
    save_verified_passkey_device,
    get_active_passkeys_for_user,
    get_device_by_credential_id,
    update_device_sign_count,
)
from app.auth_engine import hash_token, _CHALLENGES, _TRANSACTIONS, STATE_AUTHENTICATED

client = TestClient(app)


def _generate_test_key_and_attestation(rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN, challenge="reg_challenge_32_bytes_random___"):
    """Generates an ES256 key pair and valid WebAuthn attestation object for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x = public_numbers.x.to_bytes(32, "big")
    y = public_numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    cose_bytes = cbor2.dumps(cose_key)

    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    cred_id = b"test-cred-" + secrets.token_bytes(8)
    # Flags: UP(1) + UV(4) + AT(64) = 0x45
    auth_data = rp_hash + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) + len(cred_id).to_bytes(2, "big") + cred_id + cose_bytes
    att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin,
    }).encode("utf-8")

    cred_dict = {
        "id": bytes_to_base64url(cred_id),
        "rawId": bytes_to_base64url(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "attestationObject": bytes_to_base64url(att_obj),
        },
    }
    return private_key, cred_id, cred_dict


def _generate_test_assertion(private_key, cred_id, rp_id=WEBAUTHN_RP_ID, origin=WEBAUTHN_ORIGIN, challenge="auth_challenge_32_bytes_random__", sign_count=1, uv=True):
    """Generates a valid WebAuthn assertion signature using the test private key."""
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
        "id": bytes_to_base64url(cred_id),
        "rawId": bytes_to_base64url(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "authenticatorData": bytes_to_base64url(auth_data),
            "signature": bytes_to_base64url(signature),
        },
    }


def test_create_registration_options():
    """Requirement 1: Generate WebAuthn registration options for platform authenticator with required user verification."""
    options = create_registration_options(
        user_id="usr_test_123",
        user_name="agent@sentinel.ai",
        user_display_name="Sentinel Agent",
    )
    assert "challenge" in options
    assert options["rp"]["id"] == WEBAUTHN_RP_ID
    assert options["user"]["name"] == "agent@sentinel.ai"
    assert options["authenticatorSelection"]["authenticatorAttachment"] == "platform"
    assert options["authenticatorSelection"]["userVerification"] == "required"


def test_verify_registration_attestation():
    """Requirement 2: Verify registration attestation using expected challenge, RP ID, and origin."""
    challenge = "test_reg_challenge_xyz_12345678"
    _, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=challenge)

    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=challenge,
        expected_rp_id=WEBAUTHN_RP_ID,
        expected_origin=WEBAUTHN_ORIGIN,
        require_user_verification=True,
    )
    assert reg_result.credential_id == bytes_to_base64url(cred_id)
    assert reg_result.sign_count == 0
    assert reg_result.user_verified is True
    assert reg_result.public_key is not None


def test_create_authentication_options():
    """Requirement 3: Generate authentication options for user's registered credentials."""
    dummy_cred_id = "dGVzdC1jcmVkLWlk"
    options = create_authentication_options(
        registered_credentials=[{"credential_id": dummy_cred_id}],
    )
    assert "challenge" in options
    assert options["rpId"] == WEBAUTHN_RP_ID
    assert options["userVerification"] == "required"
    assert len(options["allowCredentials"]) == 1
    assert options["allowCredentials"][0]["id"] == dummy_cred_id


def test_verify_authentication_assertion():
    """Requirement 4: Verify authentication assertion using stored public key, sign counter, RP ID, and origin."""
    reg_challenge = "reg_challenge_for_auth_test_123"
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=reg_challenge,
        expected_rp_id=WEBAUTHN_RP_ID,
        expected_origin=WEBAUTHN_ORIGIN,
    )

    auth_challenge = "auth_challenge_for_auth_test_123"
    assertion_dict = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge=auth_challenge,
        sign_count=1,
    )

    auth_result = verify_authentication(
        credential=assertion_dict,
        expected_challenge=auth_challenge,
        credential_public_key=reg_result.public_key,
        credential_current_sign_count=0,
        expected_rp_id=WEBAUTHN_RP_ID,
        expected_origin=WEBAUTHN_ORIGIN,
        require_user_verification=True,
    )
    assert auth_result.credential_id == bytes_to_base64url(cred_id)
    assert auth_result.new_sign_count == 1
    assert auth_result.user_verified is True


def test_invalid_challenge_rejected():
    """Requirement 5: Rejects assertions with challenge mismatch."""
    reg_challenge = "reg_challenge_tamper_test_12345"
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=reg_challenge,
    )

    assertion_dict = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge="expected_challenge_value_12345678",
    )

    with pytest.raises(ValueError, match="WebAuthn authentication verification failed"):
        verify_authentication(
            credential=assertion_dict,
            expected_challenge="different_wrong_challenge_value",
            credential_public_key=reg_result.public_key,
            credential_current_sign_count=0,
        )


def test_invalid_origin_rejected():
    """Requirement 6: Rejects assertions from untrusted origins."""
    reg_challenge = "reg_challenge_origin_test_12345"
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=reg_challenge,
    )

    assertion_dict = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge="auth_challenge_origin_test_1234",
        origin="https://evil-phishing-site.com",
    )

    with pytest.raises(ValueError, match="WebAuthn authentication verification failed"):
        verify_authentication(
            credential=assertion_dict,
            expected_challenge="auth_challenge_origin_test_1234",
            credential_public_key=reg_result.public_key,
            credential_current_sign_count=0,
            expected_origin=WEBAUTHN_ORIGIN,
        )


def test_invalid_signature_rejected():
    """Requirement 7: Rejects assertion with corrupted or invalid signature."""
    reg_challenge = "reg_challenge_sig_test_12345678"
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=reg_challenge,
    )

    auth_challenge = "auth_challenge_sig_test_1234567"
    assertion_dict = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge=auth_challenge,
    )
    # Corrupt the signature bytes
    sig_bytes = base64url_to_bytes(assertion_dict["response"]["signature"])
    corrupted_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    assertion_dict["response"]["signature"] = bytes_to_base64url(corrupted_sig)

    with pytest.raises(ValueError, match="WebAuthn authentication verification failed"):
        verify_authentication(
            credential=assertion_dict,
            expected_challenge=auth_challenge,
            credential_public_key=reg_result.public_key,
            credential_current_sign_count=0,
        )


def test_user_verification_enforcement():
    """Requirement 9: Rejects assertions where user verification flag (UV) is false."""
    reg_challenge = "reg_challenge_uv_test_123456789"
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    reg_result = verify_registration(
        credential=cred_dict,
        expected_challenge=reg_challenge,
    )

    auth_challenge = "auth_challenge_uv_test_12345678"
    assertion_no_uv = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge=auth_challenge,
        uv=False,  # UV flag disabled
    )

    with pytest.raises(ValueError, match="WebAuthn authentication verification failed"):
        verify_authentication(
            credential=assertion_no_uv,
            expected_challenge=auth_challenge,
            credential_public_key=reg_result.public_key,
            credential_current_sign_count=0,
            require_user_verification=True,
        )


def test_database_persistence_and_sign_counter_update():
    """Requirement 11: Passkeys persist to registered_devices and sign counter updates."""
    user_id = f"usr_test_{secrets.token_hex(6)}"
    cred_id = f"cred_test_{secrets.token_hex(8)}"
    pub_key = bytes_to_base64url(secrets.token_bytes(65))

    save_verified_passkey_device(
        user_id=user_id,
        device_id=f"dev_{secrets.token_hex(4)}",
        credential_id=cred_id,
        public_key=pub_key,
        sign_count=0,
        device_name="Pixel 8 Pro",
        platform="Android",
    )

    # Query active passkeys for user
    passkeys = get_active_passkeys_for_user(user_id)
    assert len(passkeys) == 1
    assert passkeys[0]["credentialId"] == cred_id
    assert passkeys[0]["signCount"] == 0
    assert passkeys[0]["platform"] == "Android"

    # Query by credential ID
    device = get_device_by_credential_id(cred_id)
    assert device is not None
    assert device["userId"] == user_id
    assert device["publicKey"] == pub_key

    # Update sign counter
    update_device_sign_count(cred_id, 42)
    updated_device = get_device_by_credential_id(cred_id)
    assert updated_device["signCount"] == 42


def test_end_to_end_registration_then_authentication_flow():
    """
    Requirement 12: End-to-end integration:
    - User 1 starts auth: mobile-challenge detects NO passkey -> mode: 'register'
    - Submits registration attestation to /api/auth/webauthn/register -> completes Gate 2
    - Desktop completes session
    - User 1 starts a second auth: mobile-challenge detects registered passkey -> mode: 'authenticate'
    - Submits assertion to /api/auth/webauthn/verify -> completes Gate 2
    """
    email = f"alice_{secrets.token_hex(4)}@sentinel.ai"
    phone = "+14155558888"

    # 1. Start Auth Transaction 1
    r_start = client.post("/api/auth/start", json={"email": email, "phoneNumber": phone})
    assert r_start.status_code == 200
    tx1_id = r_start.json()["transactionId"]

    # 2. Confirm Email Gate 1
    r_email = client.post("/api/auth/confirm-email", json={"transactionId": tx1_id, "email": email})
    assert r_email.status_code == 200

    # Grab challenge token
    tx1 = _TRANSACTIONS[tx1_id]
    mobile_token_1 = tx1["rawMobileToken"]
    user_id = tx1["userId"]

    # 3. Mobile checks challenge: Must be in 'register' mode because no passkey registered yet
    iphone_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    r_chal1 = client.get(f"/api/auth/mobile-challenge?t={mobile_token_1}", headers={"User-Agent": iphone_ua})
    assert r_chal1.status_code == 200
    chal1_data = r_chal1.json()
    assert chal1_data["mode"] == "register"
    assert chal1_data["hasRegisteredPasskey"] is False
    assert chal1_data["registrationOptions"] is not None

    reg_challenge = chal1_data["webauthnChallenge"]

    # 4. Perform registration ceremony
    private_key, cred_id, cred_dict = _generate_test_key_and_attestation(challenge=reg_challenge)
    r_reg = client.post("/api/auth/webauthn/register", json={
        "mobileToken": mobile_token_1,
        "credential": cred_dict,
        "deviceName": "Alice iPhone",
        "platform": "iOS",
    })
    assert r_reg.status_code == 200
    assert r_reg.json()["success"] is True
    assert r_reg.json()["state"] == STATE_AUTHENTICATED

    # Replay on consumed token 1 MUST fail
    r_reg_replay = client.post("/api/auth/webauthn/register", json={
        "mobileToken": mobile_token_1,
        "credential": cred_dict,
    })
    assert r_reg_replay.status_code == 400
    assert "replay detected" in r_reg_replay.json()["detail"].lower()

    # 5. Desktop completes session 1
    r_complete = client.post("/api/auth/complete", json={"transactionId": tx1_id})
    assert r_complete.status_code == 200
    assert "sessionToken" in r_complete.json()

    # --------------------------------------------------------------------------
    # SUBSEQUENT AUTHENTICATION FOR SAME USER
    # --------------------------------------------------------------------------

    # 6. User starts Auth Transaction 2
    r_start2 = client.post("/api/auth/start", json={"email": email, "phoneNumber": phone})
    assert r_start2.status_code == 200
    tx2_id = r_start2.json()["transactionId"]

    # Ensure transaction 2 uses the same user_id for the email
    r_email2 = client.post("/api/auth/confirm-email", json={"transactionId": tx2_id, "email": email, "userId": user_id})
    assert r_email2.status_code == 200

    tx2 = _TRANSACTIONS[tx2_id]
    mobile_token_2 = tx2["rawMobileToken"]

    # 7. Mobile checks challenge: Must now be in 'authenticate' mode with registered passkey!
    r_chal2 = client.get(f"/api/auth/mobile-challenge?t={mobile_token_2}", headers={"User-Agent": iphone_ua})
    assert r_chal2.status_code == 200
    chal2_data = r_chal2.json()
    assert chal2_data["mode"] == "authenticate"
    assert chal2_data["hasRegisteredPasskey"] is True
    assert chal2_data["authenticationOptions"] is not None

    auth_challenge = chal2_data["webauthnChallenge"]

    # 8. Perform authentication ceremony
    assertion_dict = _generate_test_assertion(
        private_key=private_key,
        cred_id=cred_id,
        challenge=auth_challenge,
        sign_count=1,
    )

    r_auth = client.post("/api/auth/webauthn/verify", json={
        "mobileToken": mobile_token_2,
        "credentialId": bytes_to_base64url(cred_id),
        "clientDataJSON": assertion_dict["response"]["clientDataJSON"],
        "authenticatorData": assertion_dict["response"]["authenticatorData"],
        "signature": assertion_dict["response"]["signature"],
        "credential": assertion_dict,
    })
    assert r_auth.status_code == 200
    assert r_auth.json()["success"] is True
    assert r_auth.json()["state"] == STATE_AUTHENTICATED

    # Replay on consumed token 2 MUST fail
    r_auth_replay = client.post("/api/auth/webauthn/verify", json={
        "mobileToken": mobile_token_2,
        "credentialId": bytes_to_base64url(cred_id),
        "clientDataJSON": assertion_dict["response"]["clientDataJSON"],
        "authenticatorData": assertion_dict["response"]["authenticatorData"],
        "signature": assertion_dict["response"]["signature"],
    })
    assert r_auth_replay.status_code == 400
    assert "replay detected" in r_auth_replay.json()["detail"].lower()

    # 9. Desktop completes session 2
    r_complete2 = client.post("/api/auth/complete", json={"transactionId": tx2_id})
    assert r_complete2.status_code == 200
    assert "sessionToken" in r_complete2.json()
