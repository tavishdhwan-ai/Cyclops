"""
Gmail OAuth 2.0 Integration & Token Lifecycle Service for Cyclops.

Implements:
- Strict two-channel Cyclops session enforcement (never trusts browser-supplied userId)
- Server-side Google OAuth 2.0 Authorization Code + PKCE (S256) flow
- Restricted read-only Gmail scope (`https://www.googleapis.com/auth/gmail.readonly`)
- AES-256-GCM encrypted refresh token and PKCE verifier persistence
- In-memory short-lived access token cache (never persisted to DB)
- Per-user concurrency locking for token refresh and verification
- Bounded retries with exponential backoff on transient failures
- Clean disconnection with local purge and remote Google revocation
"""
import os
import time
import uuid
import hashlib
import secrets
import asyncio
import logging
import threading
from urllib.parse import urlencode
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

import httpx
import jwt
from fastapi import Header, HTTPException, status

from app import database
from app import auth_engine
from app.gmail_crypto import (
    GmailConfigurationError,
    GmailDecryptionError,
    encrypt_secret,
    decrypt_secret,
    validate_encryption_key_configured,
)

logger = logging.getLogger("sentinel.gmail")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
GOOGLE_ACCOUNT_PERMISSIONS_URL = "https://myaccount.google.com/permissions"

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
OAUTH_STATE_TTL_SECONDS = 600  # 10 minutes
TESTING_REFRESH_TTL_ESTIMATE_SECONDS = 7 * 86400  # 7 days in Google Testing mode
ACCESS_TOKEN_REFRESH_MARGIN_SECONDS = 60
RETRY_BASE_DELAY_SECONDS = 0.25
MAX_TRANSIENT_RETRIES = 3

# Short-lived Google access tokens remain strictly in backend memory (never persisted to DB)
_ACCESS_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = threading.RLock()
_USER_ASYNC_LOCKS: Dict[Tuple[int, str], asyncio.Lock] = {}
_ASYNC_LOCKS_GUARD = threading.Lock()


@dataclass(frozen=True)
class CyclopsSessionContext:
    user_id: str
    email: str
    session_id: str
    transaction_id: str


@dataclass(frozen=True)
class GmailOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str


class GmailIntegrationError(Exception):
    """Sanitized, safe-to-expose domain error for Gmail OAuth & API operations."""

    def __init__(
        self,
        code: str,
        message: str,
        http_status: int = status.HTTP_400_BAD_REQUEST,
        reauth_required: bool = False,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.reauth_required = reauth_required


def _get_user_async_lock(user_id: str) -> asyncio.Lock:
    """Returns an asyncio.Lock scoped to the active running event loop and user_id."""
    loop = asyncio.get_running_loop()
    key = (id(loop), user_id)
    with _ASYNC_LOCKS_GUARD:
        lock = _USER_ASYNC_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _USER_ASYNC_LOCKS[key] = lock
        return lock


def clear_memory_caches() -> None:
    """Clears in-memory access token cache (used in tests and disconnect)."""
    with _CACHE_LOCK:
        _ACCESS_TOKEN_CACHE.clear()


def _evict_cached_access_token(user_id: str) -> None:
    with _CACHE_LOCK:
        _ACCESS_TOKEN_CACHE.pop(user_id, None)


def _get_cached_access_token(user_id: str) -> Optional[Tuple[str, float]]:
    now = time.time()
    with _CACHE_LOCK:
        entry = _ACCESS_TOKEN_CACHE.get(user_id)
        if not entry:
            return None
        expires_at = float(entry.get("expires_at", 0.0))
        if expires_at - now <= ACCESS_TOKEN_REFRESH_MARGIN_SECONDS:
            _ACCESS_TOKEN_CACHE.pop(user_id, None)
            return None
        return entry["access_token"], expires_at


def _set_cached_access_token(user_id: str, access_token: str, expires_in: int) -> float:
    safe_ttl = max(60, min(int(expires_in or 3600), 86400))
    expires_at = time.time() + safe_ttl
    with _CACHE_LOCK:
        _ACCESS_TOKEN_CACHE[user_id] = {
            "access_token": access_token,
            "expires_at": expires_at,
        }
    return expires_at


def _hash_state(raw_state: str) -> str:
    return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()


def _s256_challenge(code_verifier: str) -> str:
    import base64
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _normalize_id_for_comparison(uid: Optional[str]) -> Optional[str]:
    if not uid:
        return None
    if database.use_postgres():
        from app import postgres_database
        return postgres_database.normalize_uuid(uid)
    return str(uid).strip()


def get_gmail_config_status() -> Dict[str, Any]:
    """
    Non-throwing configuration check.
    Missing Gmail config cleanly disables Gmail integration without affecting core Cyclops.
    """
    client_id = os.getenv("GOOGLE_GMAIL_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_GMAIL_CLIENT_SECRET", "").strip()
    redirect_uri = os.getenv("GOOGLE_GMAIL_REDIRECT_URI", "").strip()

    missing: list[str] = []
    if not client_id:
        missing.append("GOOGLE_GMAIL_CLIENT_ID")
    if not client_secret:
        missing.append("GOOGLE_GMAIL_CLIENT_SECRET")
    if not redirect_uri:
        missing.append("GOOGLE_GMAIL_REDIRECT_URI")

    if missing:
        return {
            "configured": False,
            "reason": "gmail_unconfigured",
            "message": "Gmail integration is not configured on the server.",
        }

    if not (redirect_uri.startswith("https://") or redirect_uri.startswith("http://localhost")):
        return {
            "configured": False,
            "reason": "invalid_redirect_uri",
            "message": "Gmail OAuth redirect URI configuration is invalid.",
        }

    enc_ok, _ = validate_encryption_key_configured()
    if not enc_ok:
        return {
            "configured": False,
            "reason": "encryption_key_invalid",
            "message": "Gmail credential encryption is not properly configured on the server.",
        }

    return {"configured": True, "reason": None, "message": None}


def _require_gmail_config() -> GmailOAuthConfig:
    status_info = get_gmail_config_status()
    if not status_info["configured"]:
        raise GmailIntegrationError(
            code=status_info["reason"] or "configuration_error",
            message=status_info["message"] or "Gmail integration is unavailable due to server configuration.",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    # Validate encryption key raises GmailConfigurationError if invalid
    from app.gmail_crypto import get_primary_encryption_key
    get_primary_encryption_key()

    return GmailOAuthConfig(
        client_id=os.getenv("GOOGLE_GMAIL_CLIENT_ID", "").strip(),
        client_secret=os.getenv("GOOGLE_GMAIL_CLIENT_SECRET", "").strip(),
        redirect_uri=os.getenv("GOOGLE_GMAIL_REDIRECT_URI", "").strip(),
    )


def _record_gmail_audit(
    user_id: Optional[str],
    event_type: str,
    audit_status: str,
    details: Optional[Dict[str, Any]] = None,
    tx_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Records safe audit events without ever persisting secrets, codes, or tokens."""
    auth_engine.record_audit(
        tx_id=tx_id,
        user_id=user_id,
        event=event_type,
        status=audit_status,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
    )


# ==============================================================================
# Strict Two-Channel Cyclops Session Dependency
# ==============================================================================

async def get_verified_cyclops_session(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> CyclopsSessionContext:
    """
    FastAPI dependency enforcing an existing, fully authenticated two-channel
    Cyclops session (`sentinel_session`).

    Rejects:
    - Missing or malformed tokens
    - Unsigned or invalidly signed JWTs
    - Gate-1-only Supabase tokens (missing session_id, transaction_id, or security_tier < 2)
    - Revoked or unauthenticated auth_sessions records
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Full two-channel Cyclops authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = authorization.strip()
    if raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Cyclops session bearer token.",
        )

    secret = os.getenv("SUPABASE_JWT_SECRET") or auth_engine.SUPABASE_JWT_SECRET
    try:
        claims = jwt.decode(
            raw_token,
            secret,
            algorithms=["HS256"],
            options={"verify_aud": False, "require": ["sub", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cyclops session has expired. Please sign in again.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Cyclops session token.",
        )

    user_id = str(claims.get("sub") or "").strip()
    session_id = str(claims.get("session_id") or "").strip()
    transaction_id = str(claims.get("transaction_id") or "").strip()
    security_tier = int(claims.get("security_tier") or 0)

    if not user_id or not session_id or not transaction_id or security_tier < 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gmail integration requires a completed two-channel biometric Cyclops session.",
        )

    # Check in-memory revocation table from auth_engine.revoke_session
    with auth_engine._lock:
        mem_sess = auth_engine._ACTIVE_SESSIONS.get(session_id)
        if mem_sess and mem_sess.get("isRevoked"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Cyclops session has been revoked.",
            )

    # Verify authoritative DB transaction record
    tx = database.load_transaction(transaction_id)
    if not tx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Associated Cyclops session record was not found.",
        )

    if tx.get("isRevoked") or tx.get("state") == auth_engine.STATE_REVOKED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This Cyclops session has been revoked.",
        )

    if not (tx.get("emailVerified") and tx.get("mobileVerified") and tx.get("biometricVerified")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Two-channel verification is incomplete for this session.",
        )

    if tx.get("state") != auth_engine.STATE_AUTHENTICATED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cyclops session is not in an authenticated state.",
        )

    tx_uid = _normalize_id_for_comparison(tx.get("userId"))
    claim_uid = _normalize_id_for_comparison(user_id)
    if not tx_uid or tx_uid != claim_uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session ownership mismatch.",
        )

    return CyclopsSessionContext(
        user_id=user_id,
        email=str(claims.get("email") or tx.get("email") or ""),
        session_id=session_id,
        transaction_id=transaction_id,
    )


# ==============================================================================
# Google HTTP Helpers with Bounded Retries & Timeouts
# ==============================================================================

async def _post_google_form(
    url: str,
    data: Dict[str, str],
    retry_transient: bool = True,
) -> httpx.Response:
    """Executes an HTTPS POST to a Google endpoint with timeouts and optional bounded backoff."""
    attempts = MAX_TRANSIENT_RETRIES if retry_transient else 1
    last_exc: Optional[Exception] = None

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False) as client:
        for attempt in range(attempts):
            try:
                res = await client.post(
                    url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if retry_transient and res.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                    await asyncio.sleep(RETRY_BASE_DELAY_SECONDS * (2 ** attempt))
                    continue
                return res
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if not retry_transient or attempt >= attempts - 1:
                    raise
                await asyncio.sleep(RETRY_BASE_DELAY_SECONDS * (2 ** attempt))

    if last_exc:
        raise last_exc
    raise RuntimeError("Unexpected HTTP retry termination")


async def _get_google_json(url: str, access_token: str) -> httpx.Response:
    """Executes an HTTPS GET to Gmail API with Bearer token and bounded retries on transient errors."""
    last_exc: Optional[Exception] = None

    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as client:
        for attempt in range(MAX_TRANSIENT_RETRIES):
            try:
                res = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if res.status_code in (429, 500, 502, 503, 504) and attempt < MAX_TRANSIENT_RETRIES - 1:
                    await asyncio.sleep(RETRY_BASE_DELAY_SECONDS * (2 ** attempt))
                    continue
                return res
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt >= MAX_TRANSIENT_RETRIES - 1:
                    raise
                await asyncio.sleep(RETRY_BASE_DELAY_SECONDS * (2 ** attempt))

    if last_exc:
        raise last_exc
    raise RuntimeError("Unexpected HTTP GET retry termination")


async def _best_effort_revoke_google_token(token: str) -> bool:
    """Calls Google's official OAuth revocation endpoint. Never logs tokens."""
    if not token:
        return False
    try:
        res = await _post_google_form(GOOGLE_REVOKE_URL, {"token": token}, retry_transient=True)
        return res.status_code == 200
    except Exception:
        return False


def _validate_granted_scopes(raw_scope: Optional[str]) -> Tuple[bool, str, list[str]]:
    """
    Verifies granted permissions match `gmail.readonly` cleanly:
    - Rejects missing gmail.readonly scope (insufficient)
    - Rejects any scope outside gmail.readonly (excessive)
    """
    if not raw_scope or not isinstance(raw_scope, str):
        return False, "missing_permissions", []

    scopes = [s.strip() for s in raw_scope.split() if s.strip()]
    scope_set = set(scopes)

    if GMAIL_READONLY_SCOPE not in scope_set:
        return False, "missing_permissions", scopes

    unexpected = scope_set - {GMAIL_READONLY_SCOPE}
    if unexpected:
        return False, "excessive_permissions", scopes

    return True, "ok", [GMAIL_READONLY_SCOPE]


async def _fetch_gmail_profile_email(access_token: str) -> Tuple[Optional[str], int, Optional[str]]:
    """
    Fetches minimal profile verification from Gmail API (`users/me/profile`).
    Returns (email_address, http_status, error_code).
    """
    try:
        res = await _get_google_json(GMAIL_PROFILE_URL, access_token)
    except httpx.TimeoutException:
        return None, 504, "temporary_unavailable"
    except httpx.TransportError:
        return None, 503, "temporary_unavailable"

    if res.status_code == 200:
        try:
            payload = res.json()
        except Exception:
            return None, 502, "invalid_provider_response"
        email_addr = str(payload.get("emailAddress") or "").strip().lower()
        if not email_addr or "@" not in email_addr:
            return None, 502, "invalid_provider_response"
        return email_addr, 200, None

    if res.status_code == 401:
        return None, 401, "access_token_invalid"
    if res.status_code == 403:
        return None, 403, "insufficient_permissions"
    if res.status_code == 429:
        return None, 429, "rate_limited"
    return None, res.status_code, "temporary_unavailable"


# ==============================================================================
# Core Operations: Status, Start, Callback, Verify, Reconnect, Disconnect
# ==============================================================================

def get_gmail_connection_status(user_ctx: CyclopsSessionContext) -> Dict[str, Any]:
    """
    Returns sanitized Gmail connection metadata strictly from local storage.
    Never calls Google APIs on page load and never returns tokens.
    """
    cfg_status = get_gmail_config_status()
    conn = database.get_gmail_connection(user_ctx.user_id)

    if not conn:
        return {
            "configured": cfg_status["configured"],
            "configIssue": cfg_status["reason"],
            "connected": False,
            "status": "not_connected",
            "gmailAddress": None,
            "grantedScopes": [],
            "connectedAt": None,
            "lastVerifiedAt": None,
            "reauthRequired": False,
            "reauthReason": None,
            "accessTokenExpiresAt": None,
            "refreshTokenIssuedAt": None,
            "refreshTokenExpiresEstimateAt": None,
            "testingModeNotice": "Google OAuth app is currently in Testing mode; authorisations may expire after 7 days.",
        }

    return {
        "configured": cfg_status["configured"],
        "configIssue": cfg_status["reason"],
        "connected": conn["status"] == "connected" and not conn["reauthRequired"],
        "status": conn["status"],
        "gmailAddress": conn["gmailAddress"],
        "grantedScopes": conn["grantedScopes"],
        "connectedAt": conn["connectedAt"],
        "lastVerifiedAt": conn["lastVerifiedAt"],
        "reauthRequired": conn["reauthRequired"],
        "reauthReason": conn["reauthReason"],
        "accessTokenExpiresAt": conn["accessTokenExpiresAt"],
        "refreshTokenIssuedAt": conn["refreshTokenIssuedAt"],
        "refreshTokenExpiresEstimateAt": conn["refreshTokenExpiresEstimateAt"],
        "testingModeNotice": "Google OAuth app is currently in Testing mode; authorisations may expire after 7 days.",
    }


def start_gmail_oauth(
    user_ctx: CyclopsSessionContext,
    action: str = "connect",
    privacy_consent_accepted: bool = False,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Initiates server-side OAuth 2.0 + PKCE (S256) flow bound to the authenticated
    Cyclops user and initiating session.
    """
    if action not in ("connect", "reconnect"):
        raise GmailIntegrationError("invalid_action", "Unsupported Gmail OAuth action.")

    if not privacy_consent_accepted:
        raise GmailIntegrationError(
            "consent_required",
            "Please review and acknowledge the read-only Gmail access disclosure before continuing.",
        )

    cfg = _require_gmail_config()

    existing = database.get_gmail_connection(user_ctx.user_id)
    if action == "connect" and existing and existing["status"] == "connected" and not existing["reauthRequired"]:
        raise GmailIntegrationError(
            "already_connected",
            "A Gmail account is already connected to this Cyclops profile. Disconnect it first before connecting another account.",
            http_status=status.HTTP_409_CONFLICT,
        )

    if action == "reconnect" and not existing:
        # Allow seamless fallback to connect semantics if no connection row exists yet
        action = "connect"

    # Generate high-entropy cryptographic state and PKCE verifier
    raw_state = secrets.token_urlsafe(32)
    state_hash = _hash_state(raw_state)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _s256_challenge(code_verifier)

    try:
        verifier_encrypted = encrypt_secret(
            code_verifier,
            user_id=_normalize_id_for_comparison(user_ctx.user_id) or user_ctx.user_id,
            purpose="pkce_verifier",
        )
    except GmailConfigurationError:
        raise GmailIntegrationError(
            "encryption_key_invalid",
            "Gmail integration encryption is not properly configured.",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    now = time.time()
    tx_record = {
        "id": f"goauth_{secrets.token_hex(12)}",
        "stateHash": state_hash,
        "userId": user_ctx.user_id,
        "sessionId": user_ctx.session_id,
        "codeVerifierEncrypted": verifier_encrypted,
        "redirectUri": cfg.redirect_uri,
        "requestedScope": GMAIL_READONLY_SCOPE,
        "actionType": action,
        "expiresAt": now + OAUTH_STATE_TTL_SECONDS,
        "consumedAt": None,
        "createdAt": now,
    }
    database.save_gmail_oauth_transaction(tx_record)

    params = {
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "false",
        "state": raw_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    _record_gmail_audit(
        user_id=user_ctx.user_id,
        event_type="GMAIL_OAUTH_STARTED",
        audit_status="SUCCESS",
        details={"action": action, "scope": GMAIL_READONLY_SCOPE},
        tx_id=user_ctx.transaction_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "authorizationUrl": auth_url,
        "expiresIn": OAUTH_STATE_TTL_SECONDS,
    }


async def process_gmail_oauth_callback(
    user_ctx: CyclopsSessionContext,
    state: Optional[str],
    code: Optional[str] = None,
    oauth_error: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validates authenticated Cyclops session ownership, atomically consumes OAuth state,
    exchanges authorization code with PKCE verifier, validates exact scope, verifies
    mailbox profile via Gmail API, and persists AES-256-GCM encrypted refresh token.
    """
    if not state or not isinstance(state, str) or len(state) < 16:
        _record_gmail_audit(
            user_id=user_ctx.user_id,
            event_type="GMAIL_OAUTH_REJECTED",
            audit_status="FAILURE",
            details={"reason": "invalid_state"},
            tx_id=user_ctx.transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise GmailIntegrationError("invalid_state", "OAuth verification state is missing or malformed.")

    cfg = _require_gmail_config()

    state_hash = _hash_state(state.strip())
    consume_res = database.consume_gmail_oauth_transaction(
        state_hash=state_hash,
        user_id=user_ctx.user_id,
        session_id=user_ctx.session_id,
    )
    outcome = consume_res["outcome"]

    if outcome != "consumed":
        _record_gmail_audit(
            user_id=user_ctx.user_id,
            event_type="GMAIL_OAUTH_REJECTED",
            audit_status="DENIED" if outcome == "ownership_mismatch" else "FAILURE",
            details={"reason": outcome},
            tx_id=user_ctx.transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        error_map = {
            "not_found": ("invalid_state", "OAuth authorization session was not found.", status.HTTP_400_BAD_REQUEST),
            "replayed": ("state_replayed", "This OAuth callback has already been processed.", status.HTTP_409_CONFLICT),
            "expired": ("state_expired", "The Gmail authorization request has expired. Please try again.", status.HTTP_400_BAD_REQUEST),
            "ownership_mismatch": ("ownership_mismatch", "This authorization response does not match your active Cyclops session.", status.HTTP_403_FORBIDDEN),
        }
        err_code, err_msg, err_status = error_map.get(
            outcome, ("invalid_state", "OAuth state validation failed.", status.HTTP_400_BAD_REQUEST)
        )
        raise GmailIntegrationError(err_code, err_msg, http_status=err_status)

    oauth_tx = consume_res["transaction"]

    # Handle explicit user consent denial or Google OAuth error
    if oauth_error:
        clean_err = oauth_error.strip().lower()
        mapped_code = "denied" if clean_err == "access_denied" else "oauth_error"
        _record_gmail_audit(
            user_id=user_ctx.user_id,
            event_type="GMAIL_OAUTH_DENIED",
            audit_status="DENIED",
            details={"reason": mapped_code},
            tx_id=user_ctx.transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise GmailIntegrationError(
            mapped_code,
            "Gmail access permission was declined." if mapped_code == "denied" else "Google did not complete authorization.",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    if not code or not isinstance(code, str) or not code.strip():
        raise GmailIntegrationError("missing_code", "Authorization code is missing from Google callback.")

    # Decrypt PKCE verifier bound to this user
    norm_uid = _normalize_id_for_comparison(user_ctx.user_id) or user_ctx.user_id
    try:
        code_verifier = decrypt_secret(
            oauth_tx["codeVerifierEncrypted"],
            user_id=norm_uid,
            purpose="pkce_verifier",
        )
    except GmailDecryptionError:
        raise GmailIntegrationError(
            "decryption_failed",
            "Could not decrypt OAuth verification state.",
            http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Exchange authorization code at Google's token endpoint (NEVER retry authorization_code)
    token_form = {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "code": code.strip(),
        "code_verifier": code_verifier,
        "redirect_uri": oauth_tx["redirectUri"],
        "grant_type": "authorization_code",
    }

    try:
        token_res = await _post_google_form(GOOGLE_TOKEN_URL, token_form, retry_transient=False)
    except (httpx.TimeoutException, httpx.TransportError):
        raise GmailIntegrationError(
            "temporary_unavailable",
            "Google OAuth service is temporarily unreachable. Please try again.",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if token_res.status_code != 200:
        err_kind = "token_exchange_failed"
        try:
            body_err = token_res.json().get("error", "")
            if body_err == "invalid_grant":
                err_kind = "invalid_grant"
        except Exception:
            pass
        _record_gmail_audit(
            user_id=user_ctx.user_id,
            event_type="GMAIL_OAUTH_REJECTED",
            audit_status="FAILURE",
            details={"reason": err_kind},
            tx_id=user_ctx.transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise GmailIntegrationError(
            err_kind,
            "Failed to exchange Gmail authorization code with Google.",
            http_status=status.HTTP_400_BAD_REQUEST if token_res.status_code < 500 else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    try:
        token_data = token_res.json()
    except Exception:
        raise GmailIntegrationError("invalid_provider_response", "Invalid response received from Google OAuth.", http_status=status.HTTP_502_BAD_GATEWAY)

    access_token = str(token_data.get("access_token") or "").strip()
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    expires_in = int(token_data.get("expires_in") or 3600)
    raw_scope = token_data.get("scope")

    if not access_token:
        raise GmailIntegrationError("token_exchange_failed", "Google did not return an access credential.", http_status=status.HTTP_502_BAD_GATEWAY)

    # Validate exact granted scope (sufficient and does not exceed gmail.readonly)
    scope_ok, scope_err, granted_scopes = _validate_granted_scopes(raw_scope)
    if not scope_ok:
        # Discard & best-effort revoke token if scope mismatch/excessive
        await _best_effort_revoke_google_token(refresh_token or access_token)
        _record_gmail_audit(
            user_id=user_ctx.user_id,
            event_type="GMAIL_OAUTH_REJECTED",
            audit_status="FAILURE",
            details={"reason": scope_err},
            tx_id=user_ctx.transaction_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        msg = (
            "Read-only Gmail permission was not granted."
            if scope_err == "missing_permissions"
            else "Granted permissions exceeded the restricted read-only Gmail scope."
        )
        raise GmailIntegrationError(scope_err, msg, http_status=status.HTTP_403_FORBIDDEN)

    existing_conn = database.get_gmail_connection(user_ctx.user_id)

    # Require refresh_token for persistent offline connection (unless reconnecting same account with retained token)
    if not refresh_token and not (existing_conn and existing_conn.get("encryptedRefreshToken")):
        await _best_effort_revoke_google_token(access_token)
        raise GmailIntegrationError(
            "missing_refresh_token",
            "Google did not issue an offline refresh token. Please revoke Cyclops in your Google Account and reconnect with consent.",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # Verify Gmail account using minimal read-only profile endpoint
    gmail_address, profile_status, profile_err = await _fetch_gmail_profile_email(access_token)
    if not gmail_address:
        await _best_effort_revoke_google_token(refresh_token or access_token)
        raise GmailIntegrationError(
            profile_err or "profile_verification_failed",
            "Connected credentials could not be verified with Gmail API.",
            http_status=profile_status if profile_status >= 400 else status.HTTP_502_BAD_GATEWAY,
        )

    # Enforce single connection per Cyclops user; never silently replace with a different Gmail account
    if existing_conn:
        if existing_conn["gmailAddress"].strip().lower() != gmail_address:
            await _best_effort_revoke_google_token(refresh_token or access_token)
            raise GmailIntegrationError(
                "account_mismatch",
                "Another Gmail account is already linked to this Cyclops profile. Disconnect it first before connecting a different Gmail address.",
                http_status=status.HTTP_409_CONFLICT,
            )
        if (
            oauth_tx["actionType"] == "connect"
            and existing_conn["status"] == "connected"
            and not existing_conn["reauthRequired"]
        ):
            raise GmailIntegrationError(
                "already_connected",
                "Gmail is already connected.",
                http_status=status.HTTP_409_CONFLICT,
            )

    # Encrypt refresh token (or retain existing if Google omitted replacement during reconnect)
    if refresh_token:
        encrypted_refresh = encrypt_secret(refresh_token, user_id=norm_uid, purpose="refresh_token")
        refresh_issued_at = time.time()
    else:
        encrypted_refresh = existing_conn["encryptedRefreshToken"]
        refresh_issued_at = existing_conn.get("refreshTokenIssuedAt") or time.time()

    now = time.time()
    access_exp_ts = _set_cached_access_token(user_ctx.user_id, access_token, expires_in)

    saved = database.save_gmail_connection(
        {
            "id": existing_conn["id"] if existing_conn else f"gmconn_{secrets.token_hex(12)}",
            "userId": user_ctx.user_id,
            "gmailAddress": gmail_address,
            "encryptedRefreshToken": encrypted_refresh,
            "grantedScopes": granted_scopes,
            "status": "connected",
            "connectedAt": existing_conn["connectedAt"] if existing_conn else now,
            "lastVerifiedAt": now,
            "reauthRequired": False,
            "reauthReason": None,
            "accessTokenExpiresAt": access_exp_ts,
            "refreshTokenIssuedAt": refresh_issued_at,
            "refreshTokenExpiresEstimateAt": refresh_issued_at + TESTING_REFRESH_TTL_ESTIMATE_SECONDS,
            "lastErrorCode": None,
            "createdAt": existing_conn["createdAt"] if existing_conn else now,
        }
    )

    _record_gmail_audit(
        user_id=user_ctx.user_id,
        event_type="GMAIL_CONNECTED",
        audit_status="SUCCESS",
        details={
            "gmail_address": gmail_address,
            "action": oauth_tx["actionType"],
            "scope": GMAIL_READONLY_SCOPE,
        },
        tx_id=user_ctx.transaction_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "success": True,
        "status": "connected",
        "gmailAddress": saved["gmailAddress"],
        "lastVerifiedAt": saved["lastVerifiedAt"],
    }


async def _refresh_access_token_locked(
    user_ctx: CyclopsSessionContext,
    conn: Dict[str, Any],
    cfg: GmailOAuthConfig,
) -> Tuple[str, float, Optional[str], Optional[float]]:
    """
    Refreshes short-lived Google access token using the stored encrypted refresh token.
    Caller MUST hold `_get_user_async_lock(user_ctx.user_id)`.
    Returns (access_token, access_expires_at, new_encrypted_refresh_or_none, refresh_issued_at_or_none).
    """
    norm_uid = _normalize_id_for_comparison(user_ctx.user_id) or user_ctx.user_id
    try:
        refresh_token = decrypt_secret(
            conn["encryptedRefreshToken"],
            user_id=norm_uid,
            purpose="refresh_token",
        )
    except GmailDecryptionError:
        _evict_cached_access_token(user_ctx.user_id)
        database.mark_gmail_connection_reauth_required(
            user_ctx.user_id,
            reason="credential_decryption_failed",
            error_code="decryption_failed",
        )
        raise GmailIntegrationError(
            "reauth_required",
            "Stored Gmail credentials could not be decrypted. Please reconnect your Gmail account.",
            http_status=status.HTTP_401_UNAUTHORIZED,
            reauth_required=True,
        )

    form_data = {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    try:
        res = await _post_google_form(GOOGLE_TOKEN_URL, form_data, retry_transient=True)
    except (httpx.TimeoutException, httpx.TransportError):
        raise GmailIntegrationError(
            "temporary_unavailable",
            "Unable to reach Google token service right now. Please try again shortly.",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if res.status_code != 200:
        err_name = ""
        try:
            err_name = str(res.json().get("error") or "").lower()
        except Exception:
            pass

        if res.status_code in (400, 401) and err_name in ("invalid_grant", "unauthorized_client", "invalid_token", ""):
            _evict_cached_access_token(user_ctx.user_id)
            database.mark_gmail_connection_reauth_required(
                user_ctx.user_id,
                reason="refresh_token_expired_or_revoked",
                error_code=err_name or "invalid_grant",
            )
            _record_gmail_audit(
                user_id=user_ctx.user_id,
                event_type="GMAIL_REAUTH_REQUIRED",
                audit_status="FAILURE",
                details={"reason": err_name or "invalid_grant"},
                tx_id=user_ctx.transaction_id,
            )
            raise GmailIntegrationError(
                "reauth_required",
                "Gmail authorisation has expired or been revoked. Please reconnect your Gmail account.",
                http_status=status.HTTP_401_UNAUTHORIZED,
                reauth_required=True,
            )

        if res.status_code == 429:
            raise GmailIntegrationError(
                "rate_limited",
                "Google API rate limit reached. Please wait a moment and try again.",
                http_status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        raise GmailIntegrationError(
            "temporary_unavailable",
            "Google token service is temporarily unavailable.",
            http_status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    try:
        token_data = res.json()
    except Exception:
        raise GmailIntegrationError(
            "invalid_provider_response",
            "Invalid response from Google token service.",
            http_status=status.HTTP_502_BAD_GATEWAY,
        )

    access_token = str(token_data.get("access_token") or "").strip()
    if not access_token:
        raise GmailIntegrationError(
            "invalid_provider_response",
            "Google did not return a refreshed access token.",
            http_status=status.HTTP_502_BAD_GATEWAY,
        )

    # Validate scope if included in refresh response
    if token_data.get("scope"):
        scope_ok, scope_err, _ = _validate_granted_scopes(token_data.get("scope"))
        if not scope_ok:
            _evict_cached_access_token(user_ctx.user_id)
            database.mark_gmail_connection_reauth_required(
                user_ctx.user_id,
                reason=scope_err,
                error_code=scope_err,
            )
            raise GmailIntegrationError(
                "reauth_required",
                "Gmail permissions changed or are insufficient. Please reconnect your Gmail account.",
                http_status=status.HTTP_403_FORBIDDEN,
                reauth_required=True,
            )

    expires_in = int(token_data.get("expires_in") or 3600)
    access_exp_ts = _set_cached_access_token(user_ctx.user_id, access_token, expires_in)

    # Retain existing valid refresh token unless Google explicitly returned a replacement
    new_refresh = str(token_data.get("refresh_token") or "").strip()
    new_encrypted_refresh: Optional[str] = None
    refresh_issued_at: Optional[float] = None
    if new_refresh:
        new_encrypted_refresh = encrypt_secret(new_refresh, user_id=norm_uid, purpose="refresh_token")
        refresh_issued_at = time.time()

    return access_token, access_exp_ts, new_encrypted_refresh, refresh_issued_at


async def verify_gmail_connection(
    user_ctx: CyclopsSessionContext,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verifies the user's connected Gmail account using `GET /gmail/v1/users/me/profile`.
    Uses backend in-memory access token if valid; otherwise refreshes once under per-user lock.
    """
    cfg = _require_gmail_config()

    async with _get_user_async_lock(user_ctx.user_id):
        conn = database.get_gmail_connection(user_ctx.user_id)
        if not conn:
            raise GmailIntegrationError(
                "not_connected",
                "No Gmail account is connected to this Cyclops profile.",
                http_status=status.HTTP_404_NOT_FOUND,
            )

        if conn["reauthRequired"] or conn["status"] == "reauth_required":
            raise GmailIntegrationError(
                "reauth_required",
                "Gmail authorisation has expired or been revoked. Please reconnect Gmail.",
                http_status=status.HTTP_401_UNAUTHORIZED,
                reauth_required=True,
            )

        new_encrypted_refresh: Optional[str] = None
        new_refresh_issued_at: Optional[float] = None
        cached = _get_cached_access_token(user_ctx.user_id)

        if cached:
            access_token, access_exp_ts = cached
        else:
            access_token, access_exp_ts, new_encrypted_refresh, new_refresh_issued_at = await _refresh_access_token_locked(
                user_ctx, conn, cfg
            )

        gmail_address, profile_status, profile_err = await _fetch_gmail_profile_email(access_token)

        # If cached access token returned 401 unexpectedly, evict & refresh once
        if profile_status == 401:
            _evict_cached_access_token(user_ctx.user_id)
            access_token, access_exp_ts, new_encrypted_refresh, new_refresh_issued_at = await _refresh_access_token_locked(
                user_ctx, conn, cfg
            )
            gmail_address, profile_status, profile_err = await _fetch_gmail_profile_email(access_token)

        if not gmail_address:
            if profile_status in (401, 403):
                _evict_cached_access_token(user_ctx.user_id)
                database.mark_gmail_connection_reauth_required(
                    user_ctx.user_id,
                    reason=profile_err or "verification_unauthorized",
                    error_code=profile_err,
                )
                _record_gmail_audit(
                    user_id=user_ctx.user_id,
                    event_type="GMAIL_REAUTH_REQUIRED",
                    audit_status="FAILURE",
                    details={"reason": profile_err or "verification_unauthorized"},
                    tx_id=user_ctx.transaction_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                raise GmailIntegrationError(
                    "reauth_required",
                    "Gmail credentials are no longer valid. Please reconnect Gmail.",
                    http_status=status.HTTP_401_UNAUTHORIZED,
                    reauth_required=True,
                )
            raise GmailIntegrationError(
                profile_err or "temporary_unavailable",
                "Unable to verify Gmail connection right now. Please try again shortly.",
                http_status=profile_status if profile_status >= 400 else status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        if gmail_address != conn["gmailAddress"].strip().lower():
            _evict_cached_access_token(user_ctx.user_id)
            database.mark_gmail_connection_reauth_required(
                user_ctx.user_id,
                reason="account_mismatch",
                error_code="account_mismatch",
            )
            raise GmailIntegrationError(
                "reauth_required",
                "Verified Gmail address no longer matches the connected account. Please reconnect Gmail.",
                http_status=status.HTTP_409_CONFLICT,
                reauth_required=True,
            )

        now = time.time()
        refresh_est = (
            new_refresh_issued_at + TESTING_REFRESH_TTL_ESTIMATE_SECONDS
            if new_refresh_issued_at
            else None
        )
        database.update_gmail_connection_verified(
            user_id=user_ctx.user_id,
            verified_at=now,
            access_token_expires_at=access_exp_ts,
            encrypted_refresh_token=new_encrypted_refresh,
            refresh_token_issued_at=new_refresh_issued_at,
            refresh_token_expires_estimate_at=refresh_est,
        )

    _record_gmail_audit(
        user_id=user_ctx.user_id,
        event_type="GMAIL_CONNECTION_VERIFIED",
        audit_status="SUCCESS",
        details={"gmail_address": gmail_address},
        tx_id=user_ctx.transaction_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return get_gmail_connection_status(user_ctx)


async def disconnect_gmail_connection(
    user_ctx: CyclopsSessionContext,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Disconnects the user's Gmail connection:
    1. Evicts in-memory access token and immediately deletes local Gmail credentials
       and pending OAuth transactions so further Gmail API access ceases at once.
    2. Calls Google's official OAuth revocation endpoint (`oauth2.googleapis.com/revoke`).
    3. Handles failed remote revocation honestly while keeping local state disconnected.
    4. Never modifies the user's Cyclops session or registered passkeys.
    """
    token_to_revoke: Optional[str] = None

    async with _get_user_async_lock(user_ctx.user_id):
        cached = _get_cached_access_token(user_ctx.user_id)
        _evict_cached_access_token(user_ctx.user_id)

        conn = database.get_gmail_connection(user_ctx.user_id)
        if conn and conn.get("encryptedRefreshToken"):
            norm_uid = _normalize_id_for_comparison(user_ctx.user_id) or user_ctx.user_id
            try:
                token_to_revoke = decrypt_secret(
                    conn["encryptedRefreshToken"],
                    user_id=norm_uid,
                    purpose="refresh_token",
                )
            except Exception:
                token_to_revoke = cached[0] if cached else None
        elif cached:
            token_to_revoke = cached[0]

        # Immediately remove local credentials and any outstanding OAuth transactions
        deleted_conn = database.delete_gmail_connection(user_ctx.user_id)
        database.delete_user_gmail_oauth_transactions(user_ctx.user_id)

    if not deleted_conn and not token_to_revoke:
        return {
            "success": True,
            "status": "not_connected",
            "remoteRevoked": False,
            "manualRevocationUrl": GOOGLE_ACCOUNT_PERMISSIONS_URL,
            "message": "No active Gmail connection was stored locally.",
        }

    remote_revoked = False
    if token_to_revoke:
        remote_revoked = await _best_effort_revoke_google_token(token_to_revoke)

    _record_gmail_audit(
        user_id=user_ctx.user_id,
        event_type="GMAIL_DISCONNECTED",
        audit_status="SUCCESS",
        details={"remote_revoked": remote_revoked},
        tx_id=user_ctx.transaction_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if remote_revoked:
        msg = "Gmail has been disconnected, Google OAuth access was revoked, and local credentials were deleted."
    else:
        msg = (
            "Local Gmail credentials were deleted, but remote revocation with Google could not be confirmed. "
            "You can manually revoke Cyclops access in your Google Account permissions."
        )

    return {
        "success": True,
        "status": "not_connected",
        "remoteRevoked": remote_revoked,
        "manualRevocationUrl": GOOGLE_ACCOUNT_PERMISSIONS_URL,
        "message": msg,
    }
