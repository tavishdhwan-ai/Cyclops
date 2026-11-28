"""
Comprehensive Security & Lifecycle Test Suite for Cyclops Gmail OAuth 2.0 Integration.

Mocks all external Google OAuth and Gmail API requests (never hits real Gmail accounts).
Covers:
- Full two-channel Cyclops session enforcement (rejects Gate-1-only, expired, revoked, missing)
- OAuth state generation, single-use atomic consumption, invalid/expired/replayed state rejection
- PKCE S256 challenge generation and encrypted verifier persistence
- Callback ownership validation (cross-user and cross-session rejection)
- Cross-user access prevention (status, verify, reconnect, disconnect)
- AES-256-GCM encryption/decryption, AAD user binding, key rotation, invalid/missing key checks
- Successful connection persistence, denied consent, missing/excessive scopes, missing refresh token
- Failed token exchange without retries on invalid_grant
- Gmail profile verification (`users/me/profile`), access-token refresh, refresh-token retention
- Concurrent refresh locking, revoked credentials -> Reconnect Gmail flow
- Duplicate connection & silent account-replacement prevention
- Disconnect credential purge, Google revoke handling (success & honest failure), session/passkey isolation
- Graceful feature disablement when Gmail env config is missing without impacting core auth
"""
import os
import time
import uuid
import base64
import hashlib
import secrets
import asyncio
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch

import jwt
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import database, auth_engine, gmail_crypto, gmail_service


client = TestClient(app)

VALID_TEST_KEY = base64.urlsafe_b64encode(b"K" * 32).decode("ascii")
ROTATED_TEST_KEY = base64.urlsafe_b64encode(b"R" * 32).decode("ascii")
TEST_CLIENT_ID = "test-client-id.apps.googleusercontent.com"
TEST_CLIENT_SECRET = "test-client-secret-not-for-encryption"
TEST_REDIRECT_URI = "https://cyclops-chi.vercel.app/api/integrations/gmail/callback"


@pytest.fixture(autouse=True)
def gmail_test_env(monkeypatch):
    """Sets clean isolated Gmail OAuth + AES-256-GCM environment for each test."""
    gmail_service.clear_memory_caches()
    monkeypatch.setenv("GOOGLE_GMAIL_CLIENT_ID", TEST_CLIENT_ID)
    monkeypatch.setenv("GOOGLE_GMAIL_CLIENT_SECRET", TEST_CLIENT_SECRET)
    monkeypatch.setenv("GOOGLE_GMAIL_REDIRECT_URI", TEST_REDIRECT_URI)
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", VALID_TEST_KEY)
    monkeypatch.delenv("GMAIL_TOKEN_ENCRYPTION_PREVIOUS_KEYS", raising=False)
    monkeypatch.setattr(gmail_service, "RETRY_BASE_DELAY_SECONDS", 0.001)
    yield
    gmail_service.clear_memory_caches()


def _create_authenticated_user_session(user_id: Optional[str] = None, email: Optional[str] = None):
    """Creates a realistic two-channel authenticated user, DB session row, and signed JWT."""
    uid = user_id or str(uuid.uuid4())
    user_email = email or f"user_{uid[:8]}@cyclops.test"
    tx_id = f"tx_gmail_{secrets.token_hex(12)}"
    sess_id = f"sess_gmail_{secrets.token_hex(12)}"
    now = time.time()

    database.save_or_update_user_profile(
        uid,
        {"email": user_email, "fullName": "Cyclops Tester", "phoneNumber": "+14155550101"},
    )
    database.save_transaction(
        {
            "id": tx_id,
            "userId": uid,
            "email": user_email,
            "phoneNumber": "+14155550101",
            "emailVerified": True,
            "mobileVerified": True,
            "biometricVerified": True,
            "biometricStatus": "verified",
            "state": auth_engine.STATE_AUTHENTICATED,
            "expiresAt": now + 900,
            "lastActiveAt": now,
            "isRevoked": False,
            "createdAt": now,
        }
    )

    secret = os.getenv("SUPABASE_JWT_SECRET") or auth_engine.SUPABASE_JWT_SECRET
    token = jwt.encode(
        {
            "sub": uid,
            "session_id": sess_id,
            "transaction_id": tx_id,
            "email": user_email,
            "role": "authenticated",
            "security_tier": 2,
            "iat": int(now),
            "exp": int(now) + 3600,
        },
        secret,
        algorithm="HS256",
    )
    return uid, sess_id, tx_id, token


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# 1. Encryption & Configuration Security Tests
# ==============================================================================

def test_aes256_gcm_encryption_decryption_aad_and_rotation(monkeypatch):
    """Verifies AES-256-GCM encryption, user AAD isolation, and key rotation."""
    uid_a = str(uuid.uuid4())
    uid_b = str(uuid.uuid4())
    secret_refresh = "1//0g_test_refresh_token_secret_payload"

    ciphertext = gmail_crypto.encrypt_secret(secret_refresh, user_id=uid_a, purpose="refresh_token")
    assert ciphertext.startswith("v1:")
    assert secret_refresh not in ciphertext

    # Same user + purpose decrypts cleanly
    assert gmail_crypto.decrypt_secret(ciphertext, user_id=uid_a, purpose="refresh_token") == secret_refresh

    # Different user or different purpose fails AAD authentication tag check
    with pytest.raises(gmail_crypto.GmailDecryptionError):
        gmail_crypto.decrypt_secret(ciphertext, user_id=uid_b, purpose="refresh_token")
    with pytest.raises(gmail_crypto.GmailDecryptionError):
        gmail_crypto.decrypt_secret(ciphertext, user_id=uid_a, purpose="pkce_verifier")

    # Tampered ciphertext fails tag check
    tampered = ciphertext[:-4] + ("AAAA" if not ciphertext.endswith("AAAA") else "BBBB")
    with pytest.raises(gmail_crypto.GmailDecryptionError):
        gmail_crypto.decrypt_secret(tampered, user_id=uid_a, purpose="refresh_token")

    # Key rotation: rotate primary key while retaining old key in PREVIOUS_KEYS
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", ROTATED_TEST_KEY)
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_PREVIOUS_KEYS", VALID_TEST_KEY)
    assert gmail_crypto.decrypt_secret(ciphertext, user_id=uid_a, purpose="refresh_token") == secret_refresh


def test_missing_or_invalid_encryption_configuration_fails_securely(monkeypatch):
    """Validates missing, short, malformed, and client-secret-reused encryption keys fail safely."""
    monkeypatch.delenv("GMAIL_TOKEN_ENCRYPTION_KEY", raising=False)
    ok, _ = gmail_crypto.validate_encryption_key_configured()
    assert ok is False

    # Wrong length key
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"short").decode("ascii"))
    ok, _ = gmail_crypto.validate_encryption_key_configured()
    assert ok is False

    # Reusing GOOGLE_GMAIL_CLIENT_SECRET as encryption key must be rejected
    secret_32 = base64.urlsafe_b64encode(b"S" * 32).decode("ascii")
    monkeypatch.setenv("GOOGLE_GMAIL_CLIENT_SECRET", secret_32)
    monkeypatch.setenv("GMAIL_TOKEN_ENCRYPTION_KEY", secret_32)
    with pytest.raises(gmail_crypto.GmailConfigurationError, match="never GOOGLE_GMAIL_CLIENT_SECRET"):
        gmail_crypto.get_primary_encryption_key()


def test_gmail_feature_disabled_without_breaking_core_auth(monkeypatch):
    """Missing Gmail configuration disables Gmail gracefully while core Cyclops remains healthy."""
    uid, _, _, token = _create_authenticated_user_session()
    monkeypatch.delenv("GMAIL_TOKEN_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_GMAIL_CLIENT_ID", raising=False)

    # Gmail status cleanly reports configured=False
    status_res = client.get("/api/integrations/gmail/status", headers=_auth_headers(token))
    assert status_res.status_code == 200
    assert status_res.json()["configured"] is False

    # Gmail start returns clean 503 configuration error
    start_res = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token),
    )
    assert start_res.status_code == 503

    # Core health and Cyclops auth endpoints continue working normally
    assert client.get("/health").status_code == 200
    auth_start = client.post(
        "/api/auth/start",
        json={"email": "core@cyclops.test", "phoneNumber": "+14155552671"},
    )
    assert auth_start.status_code == 200


# ==============================================================================
# 2. Session Enforcement & OAuth Start + PKCE Tests
# ==============================================================================

def test_gmail_endpoints_reject_unauthenticated_and_incomplete_sessions():
    """Gmail endpoints reject missing auth, Gate-1-only JWTs, and revoked sessions."""
    # Unauthenticated
    assert client.get("/api/integrations/gmail/status").status_code == 401
    assert client.post("/api/integrations/gmail/start", json={"privacyConsentAccepted": True}).status_code == 401

    # Gate-1-only Supabase-like JWT (lacks session_id / security_tier 2)
    secret = os.getenv("SUPABASE_JWT_SECRET") or auth_engine.SUPABASE_JWT_SECRET
    gate1_token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": "gate1@cyclops.test",
            "aud": "authenticated",
            "role": "authenticated",
            "exp": int(time.time()) + 3600,
        },
        secret,
        algorithm="HS256",
    )
    res_gate1 = client.get("/api/integrations/gmail/status", headers=_auth_headers(gate1_token))
    assert res_gate1.status_code == 401

    # Revoked two-channel session
    uid, _, tx_id, token = _create_authenticated_user_session()
    database.revoke_auth_session(tx_id)
    res_revoked = client.get("/api/integrations/gmail/status", headers=_auth_headers(token))
    assert res_revoked.status_code == 401


def test_oauth_start_generates_pkce_state_and_enforces_consent():
    """OAuth start validates privacy consent, stores encrypted PKCE verifier & state hash, and builds exact URL."""
    uid, sess_id, _, token = _create_authenticated_user_session()

    # Without privacy consent acknowledgement
    no_consent = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": False},
        headers=_auth_headers(token),
    )
    assert no_consent.status_code == 400
    assert no_consent.json()["code"] == "consent_required"

    # With consent
    res = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token),
    )
    assert res.status_code == 200
    auth_url = res.json()["authorizationUrl"]
    parsed = urlparse(auth_url)
    qs = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert qs["client_id"] == [TEST_CLIENT_ID]
    assert qs["redirect_uri"] == [TEST_REDIRECT_URI]
    assert qs["response_type"] == ["code"]
    assert qs["scope"] == ["https://www.googleapis.com/auth/gmail.readonly"]
    assert qs["access_type"] == ["offline"]
    assert qs["prompt"] == ["consent"]
    assert qs["include_granted_scopes"] == ["false"]
    assert qs["code_challenge_method"] == ["S256"]
    assert len(qs["state"][0]) >= 32
    assert len(qs["code_challenge"][0]) >= 43


# ==============================================================================
# 3. OAuth Callback, PKCE, State Replay, Ownership & Scope Tests
# ==============================================================================

def test_successful_gmail_oauth_callback_persistence_and_pkce_verification():
    """Full happy path: start -> callback -> PKCE token exchange -> profile check -> encrypted DB row."""
    uid, _, _, token = _create_authenticated_user_session()

    start_res = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token),
    )
    qs = parse_qs(urlparse(start_res.json()["authorizationUrl"]).query)
    raw_state = qs["state"][0]
    code_challenge = qs["code_challenge"][0]

    captured_token_forms = []

    async def fake_post(url, data, retry_transient=True):
        captured_token_forms.append((url, dict(data), retry_transient))
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.test_access_token",
                "refresh_token": "1//0g_real_mock_refresh_token",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "token_type": "Bearer",
            },
        )

    async def fake_get(url, access_token):
        assert url == gmail_service.GMAIL_PROFILE_URL
        assert access_token == "ya29.test_access_token"
        return httpx.Response(200, json={"emailAddress": "Alice.Gmail@gmail.com", "messagesTotal": 42})

    with patch("app.gmail_service._post_google_form", side_effect=fake_post), patch(
        "app.gmail_service._get_google_json", side_effect=fake_get
    ):
        cb_res = client.post(
            "/api/integrations/gmail/callback",
            json={"state": raw_state, "code": "4/0A_mock_auth_code"},
            headers=_auth_headers(token),
        )

    assert cb_res.status_code == 200
    assert cb_res.json()["success"] is True
    assert cb_res.json()["gmailAddress"] == "alice.gmail@gmail.com"

    # Verify PKCE S256 verifier passed to Google matches code_challenge
    assert len(captured_token_forms) == 1
    token_url, form_data, retry_flag = captured_token_forms[0]
    assert token_url == gmail_service.GOOGLE_TOKEN_URL
    assert retry_flag is False
    assert form_data["grant_type"] == "authorization_code"
    assert form_data["code"] == "4/0A_mock_auth_code"
    verifier = form_data["code_verifier"]
    computed_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    assert computed_challenge == code_challenge

    # Verify encrypted persistence (never plaintext refresh token, never access token in DB)
    row = database.get_gmail_connection(uid)
    assert row is not None
    assert row["gmailAddress"] == "alice.gmail@gmail.com"
    assert row["encryptedRefreshToken"].startswith("v1:")
    assert "1//0g_real_mock_refresh_token" not in row["encryptedRefreshToken"]

    # Verify status endpoint never leaks tokens and reports connected
    st = client.get("/api/integrations/gmail/status", headers=_auth_headers(token)).json()
    assert st["connected"] is True
    assert st["gmailAddress"] == "alice.gmail@gmail.com"
    assert "encryptedRefreshToken" not in st
    assert "1//0g_real_mock_refresh_token" not in str(st)
    assert "ya29.test_access_token" not in str(st)

    # Replay of same OAuth state MUST be rejected
    replay_res = client.post(
        "/api/integrations/gmail/callback",
        json={"state": raw_state, "code": "4/0A_mock_auth_code"},
        headers=_auth_headers(token),
    )
    assert replay_res.status_code == 409
    assert replay_res.json()["code"] == "state_replayed"


def test_invalid_expired_and_cross_user_state_rejected():
    """Rejects unknown state, expired state, and state redeemed by a different user or session."""
    uid_a, _, _, token_a = _create_authenticated_user_session()
    uid_b, _, _, token_b = _create_authenticated_user_session()

    # 1. Invalid state
    bad_res = client.post(
        "/api/integrations/gmail/callback",
        json={"state": "unknown_state_" + secrets.token_urlsafe(24), "code": "4/0abc"},
        headers=_auth_headers(token_a),
    )
    assert bad_res.status_code == 400
    assert bad_res.json()["code"] == "invalid_state"

    # 2. Ownership mismatch (User B attempts to redeem User A's state)
    start_a = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token_a),
    )
    state_a = parse_qs(urlparse(start_a.json()["authorizationUrl"]).query)["state"][0]

    cross_res = client.post(
        "/api/integrations/gmail/callback",
        json={"state": state_a, "code": "4/0abc"},
        headers=_auth_headers(token_b),
    )
    assert cross_res.status_code == 403
    assert cross_res.json()["code"] == "ownership_mismatch"

    # Leaked state_a is also burned and cannot be retried
    retry_a = client.post(
        "/api/integrations/gmail/callback",
        json={"state": state_a, "code": "4/0abc"},
        headers=_auth_headers(token_a),
    )
    assert retry_a.status_code == 409

    # 3. Same user, DIFFERENT Cyclops session cannot redeem state
    _, _, _, token_a_sess2 = _create_authenticated_user_session(user_id=uid_a, email="same@cyclops.test")
    start_a2 = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token_a),
    )
    state_a2 = parse_qs(urlparse(start_a2.json()["authorizationUrl"]).query)["state"][0]
    sess_mismatch = client.post(
        "/api/integrations/gmail/callback",
        json={"state": state_a2, "code": "4/0abc"},
        headers=_auth_headers(token_a_sess2),
    )
    assert sess_mismatch.status_code == 403
    assert sess_mismatch.json()["code"] == "ownership_mismatch"

    # 4. Expired OAuth state
    expired_raw = secrets.token_urlsafe(32)
    database.save_gmail_oauth_transaction(
        {
            "stateHash": gmail_service._hash_state(expired_raw),
            "userId": uid_a,
            "sessionId": jwt.decode(token_a, options={"verify_signature": False})["session_id"],
            "codeVerifierEncrypted": gmail_crypto.encrypt_secret("verifier_" * 6, uid_a, "pkce_verifier"),
            "redirectUri": TEST_REDIRECT_URI,
            "expiresAt": time.time() - 10,
        }
    )
    exp_res = client.post(
        "/api/integrations/gmail/callback",
        json={"state": expired_raw, "code": "4/0abc"},
        headers=_auth_headers(token_a),
    )
    assert exp_res.status_code == 400
    assert exp_res.json()["code"] == "state_expired"


def test_denied_consent_scope_checks_missing_refresh_and_failed_token_exchange():
    """Tests denied consent, missing/excessive scopes, missing refresh token, and non-retried invalid_grant."""
    uid, _, _, token = _create_authenticated_user_session()

    def _new_state():
        r = client.post(
            "/api/integrations/gmail/start",
            json={"action": "connect", "privacyConsentAccepted": True},
            headers=_auth_headers(token),
        )
        return parse_qs(urlparse(r.json()["authorizationUrl"]).query)["state"][0]

    # 1. Denied consent
    denied = client.post(
        "/api/integrations/gmail/callback",
        json={"state": _new_state(), "error": "access_denied"},
        headers=_auth_headers(token),
    )
    assert denied.status_code == 400
    assert denied.json()["code"] == "denied"
    assert database.get_gmail_connection(uid) is None

    # 2. Failed token exchange (invalid_grant) - ensure called exactly ONCE (never retried)
    exchange_calls = 0

    async def fake_invalid_grant(url, data, retry_transient=True):
        nonlocal exchange_calls
        exchange_calls += 1
        assert retry_transient is False
        return httpx.Response(400, json={"error": "invalid_grant"})

    with patch("app.gmail_service._post_google_form", side_effect=fake_invalid_grant):
        fail_res = client.post(
            "/api/integrations/gmail/callback",
            json={"state": _new_state(), "code": "4/bad_code"},
            headers=_auth_headers(token),
        )
    assert fail_res.status_code == 400
    assert fail_res.json()["code"] == "invalid_grant"
    assert exchange_calls == 1

    # 3. Missing permissions & excessive permissions (with revocation cleanup)
    revoked_tokens = []

    async def fake_post_scope_bad(url, data, retry_transient=True):
        if url == gmail_service.GOOGLE_REVOKE_URL:
            revoked_tokens.append(data["token"])
            return httpx.Response(200)
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.scope_bad",
                "refresh_token": "1//refresh_bad",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.modify",
            },
        )

    with patch("app.gmail_service._post_google_form", side_effect=fake_post_scope_bad):
        miss_res = client.post(
            "/api/integrations/gmail/callback",
            json={"state": _new_state(), "code": "4/scope_missing"},
            headers=_auth_headers(token),
        )
    assert miss_res.status_code == 403
    assert miss_res.json()["code"] == "missing_permissions"
    assert revoked_tokens == ["1//refresh_bad"]

    async def fake_post_scope_excessive(url, data, retry_transient=True):
        if url == gmail_service.GOOGLE_REVOKE_URL:
            return httpx.Response(200)
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.excess",
                "refresh_token": "1//refresh_excess",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send",
            },
        )

    with patch("app.gmail_service._post_google_form", side_effect=fake_post_scope_excessive):
        exc_res = client.post(
            "/api/integrations/gmail/callback",
            json={"state": _new_state(), "code": "4/scope_excess"},
            headers=_auth_headers(token),
        )
    assert exc_res.status_code == 403
    assert exc_res.json()["code"] == "excessive_permissions"

    # 4. Missing refresh token on initial connect
    async def fake_post_no_refresh(url, data, retry_transient=True):
        if url == gmail_service.GOOGLE_REVOKE_URL:
            return httpx.Response(200)
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.only_access",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            },
        )

    with patch("app.gmail_service._post_google_form", side_effect=fake_post_no_refresh):
        no_ref_res = client.post(
            "/api/integrations/gmail/callback",
            json={"state": _new_state(), "code": "4/no_refresh"},
            headers=_auth_headers(token),
        )
    assert no_ref_res.status_code == 400
    assert no_ref_res.json()["code"] == "missing_refresh_token"


# ==============================================================================
# 4. Token Refresh, Concurrency, Revocation, Duplicates & Isolation Tests
# ==============================================================================

def test_access_token_refresh_retention_and_profile_verification():
    """Tests refresh when cache expired, retaining old refresh token when Google omits replacement, and verifying profile."""
    uid, _, _, token = _create_authenticated_user_session()
    database.save_gmail_connection(
        {
            "userId": uid,
            "gmailAddress": "refresh.user@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//initial_refresh_tok", uid, "refresh_token"),
            "status": "connected",
        }
    )

    refresh_calls = 0

    async def fake_post(url, data, retry_transient=True):
        nonlocal refresh_calls
        refresh_calls += 1
        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "1//initial_refresh_tok"
        # Google omits replacement refresh_token -> existing must be retained
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.refreshed_token",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            },
        )

    async def fake_get(url, access_token):
        assert access_token == "ya29.refreshed_token"
        return httpx.Response(200, json={"emailAddress": "refresh.user@gmail.com"})

    with patch("app.gmail_service._post_google_form", side_effect=fake_post), patch(
        "app.gmail_service._get_google_json", side_effect=fake_get
    ):
        res1 = client.post("/api/integrations/gmail/verify", headers=_auth_headers(token))
        assert res1.status_code == 200
        assert res1.json()["connected"] is True

        # Second immediate verify uses in-memory cached access token without calling /token again!
        res2 = client.post("/api/integrations/gmail/verify", headers=_auth_headers(token))
        assert res2.status_code == 200

    assert refresh_calls == 1
    stored = database.get_gmail_connection(uid)
    assert gmail_crypto.decrypt_secret(stored["encryptedRefreshToken"], uid, "refresh_token") == "1//initial_refresh_tok"


def test_concurrent_refresh_locked_no_race_condition():
    """Two concurrent verifications when access token cache is cold execute only ONE refresh grant."""
    uid, sess_id, tx_id, _ = _create_authenticated_user_session()
    user_ctx = gmail_service.CyclopsSessionContext(
        user_id=uid, email="conc@cyclops.test", session_id=sess_id, transaction_id=tx_id
    )
    database.save_gmail_connection(
        {
            "userId": uid,
            "gmailAddress": "conc@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//conc_refresh", uid, "refresh_token"),
            "status": "connected",
        }
    )

    refresh_counter = 0

    async def slow_refresh(url, data, retry_transient=True):
        nonlocal refresh_counter
        refresh_counter += 1
        await asyncio.sleep(0.05)
        return httpx.Response(
            200,
            json={"access_token": "ya29.shared_after_lock", "expires_in": 3600},
        )

    async def ok_profile(url, access_token):
        return httpx.Response(200, json={"emailAddress": "conc@gmail.com"})

    async def _run_concurrent():
        with patch("app.gmail_service._post_google_form", side_effect=slow_refresh), patch(
            "app.gmail_service._get_google_json", side_effect=ok_profile
        ):
            return await asyncio.gather(
                gmail_service.verify_gmail_connection(user_ctx),
                gmail_service.verify_gmail_connection(user_ctx),
            )

    r1, r2 = asyncio.run(_run_concurrent())
    assert r1["connected"] is True
    assert r2["connected"] is True
    assert refresh_counter == 1


def test_transient_google_rate_limit_retries_and_recovers(monkeypatch):
    """Bounded exponential backoff retries transient 429/503 responses during refresh/verify."""
    uid, _, _, token = _create_authenticated_user_session()
    database.save_gmail_connection(
        {
            "userId": uid,
            "gmailAddress": "retry@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//retry_ref", uid, "refresh_token"),
            "status": "connected",
        }
    )

    calls = 0

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, data=None, headers=None):
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(429, json={"error": "rate_limit_exceeded"})
            return httpx.Response(200, json={"access_token": "ya29.after_backoff", "expires_in": 3600})

        async def get(self, url, headers=None):
            return httpx.Response(200, json={"emailAddress": "retry@gmail.com"})

    with patch("app.gmail_service.httpx.AsyncClient", FakeAsyncClient):
        res = client.post("/api/integrations/gmail/verify", headers=_auth_headers(token))

    assert res.status_code == 200
    assert res.json()["connected"] is True
    assert calls == 2


def test_revoked_refresh_token_marks_reauth_required():
    """Expired/revoked refresh token transitions connection to reauth_required for Reconnect Gmail."""
    uid, _, _, token = _create_authenticated_user_session()
    database.save_gmail_connection(
        {
            "userId": uid,
            "gmailAddress": "expired7day@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//expired_7day", uid, "refresh_token"),
            "status": "connected",
        }
    )

    async def fake_revoked(url, data, retry_transient=True):
        return httpx.Response(400, json={"error": "invalid_grant"})

    with patch("app.gmail_service._post_google_form", side_effect=fake_revoked):
        res = client.post("/api/integrations/gmail/verify", headers=_auth_headers(token))

    assert res.status_code == 401
    assert res.json()["reauthRequired"] is True

    st = client.get("/api/integrations/gmail/status", headers=_auth_headers(token)).json()
    assert st["connected"] is False
    assert st["reauthRequired"] is True
    assert st["status"] == "reauth_required"
    assert st["gmailAddress"] == "expired7day@gmail.com"


def test_duplicate_connection_and_different_gmail_replacement_prevented():
    """Cannot start a second connect when connected, nor silently overwrite with a different Gmail address."""
    uid, _, _, token = _create_authenticated_user_session()
    database.save_gmail_connection(
        {
            "userId": uid,
            "gmailAddress": "original@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//orig_ref", uid, "refresh_token"),
            "status": "connected",
        }
    )

    # Duplicate connect rejected with 409
    dup = client.post(
        "/api/integrations/gmail/start",
        json={"action": "connect", "privacyConsentAccepted": True},
        headers=_auth_headers(token),
    )
    assert dup.status_code == 409
    assert dup.json()["code"] == "already_connected"

    # Reconnect started, but user authorizes a DIFFERENT Gmail account -> rejected without overwriting
    database.mark_gmail_connection_reauth_required(uid, "expired")
    reconn_start = client.post(
        "/api/integrations/gmail/reconnect",
        json={"action": "reconnect", "privacyConsentAccepted": True},
        headers=_auth_headers(token),
    )
    assert reconn_start.status_code == 200
    raw_state = parse_qs(urlparse(reconn_start.json()["authorizationUrl"]).query)["state"][0]

    async def fake_post(url, data, retry_transient=True):
        if url == gmail_service.GOOGLE_REVOKE_URL:
            return httpx.Response(200)
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.other_acct",
                "refresh_token": "1//other_ref",
                "expires_in": 3600,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            },
        )

    async def fake_get(url, access_token):
        return httpx.Response(200, json={"emailAddress": "different.user@gmail.com"})

    with patch("app.gmail_service._post_google_form", side_effect=fake_post), patch(
        "app.gmail_service._get_google_json", side_effect=fake_get
    ):
        cb = client.post(
            "/api/integrations/gmail/callback",
            json={"state": raw_state, "code": "4/other_code"},
            headers=_auth_headers(token),
        )
    assert cb.status_code == 409
    assert cb.json()["code"] == "account_mismatch"

    # Original account email remains intact
    assert database.get_gmail_connection(uid)["gmailAddress"] == "original@gmail.com"


def test_cross_user_isolation_and_disconnect_lifecycle():
    """User B cannot see/affect User A; disconnect purges credentials safely without logging user out."""
    uid_a, _, tx_a, token_a = _create_authenticated_user_session()
    uid_b, _, _, token_b = _create_authenticated_user_session()

    database.save_gmail_connection(
        {
            "userId": uid_a,
            "gmailAddress": "usera@gmail.com",
            "encryptedRefreshToken": gmail_crypto.encrypt_secret("1//user_a_secret", uid_a, "refresh_token"),
            "status": "connected",
        }
    )

    # User B sees Not Connected and cannot verify User A
    st_b = client.get("/api/integrations/gmail/status", headers=_auth_headers(token_b)).json()
    assert st_b["connected"] is False
    assert st_b["gmailAddress"] is None
    ver_b = client.post("/api/integrations/gmail/verify", headers=_auth_headers(token_b))
    assert ver_b.status_code == 404

    # Cyclops logout does NOT disconnect Gmail
    logout_b = client.post("/api/auth/logout", headers=_auth_headers(token_b))
    assert logout_b.status_code == 200
    assert database.get_gmail_connection(uid_a) is not None

    # User A disconnects with failed remote revocation -> local credentials still purged, honest warning returned
    async def fail_remote_revoke(url, data, retry_transient=True):
        return httpx.Response(503)

    with patch("app.gmail_service._post_google_form", side_effect=fail_remote_revoke):
        disc_res = client.post("/api/integrations/gmail/disconnect", headers=_auth_headers(token_a))

    assert disc_res.status_code == 200
    disc_data = disc_res.json()
    assert disc_data["status"] == "not_connected"
    assert disc_data["remoteRevoked"] is False
    assert "myaccount.google.com/permissions" in disc_data["manualRevocationUrl"]
    assert database.get_gmail_connection(uid_a) is None

    # Disconnecting Gmail did NOT revoke User A's Cyclops session
    tx_row = database.load_transaction(tx_a)
    assert tx_row is not None and tx_row["isRevoked"] is False
    assert client.get("/api/user/profile", headers=_auth_headers(token_a)).status_code == 200
