import logging
import secrets
import base64
import time
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, status, UploadFile, File, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app import database

logger = logging.getLogger("sentinel.main")

from app.schemas import (
    EmailScanRequest,
    EmailScanResponse,
    UrlScanRequest,
    DocumentScanResponse,
    DocumentScanPayload,
)
from app.scanner import analyze_demo_email


app = FastAPI(
    title="SentinelAI Backend",
    description="FastAPI Backend for SentinelAI Email Security Analysis",
    version="0.1.0",
)

# Configure CORS to allow Chrome Extensions and local development endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Clean validation error response without exposing stack traces."""
    msg = "The request body failed schema validation."
    if exc.errors():
        first_err = exc.errors()[0]
        field = ".".join(str(loc) for loc in first_err.get("loc", []))
        msg = f"Validation failed for {field}: {first_err.get('msg', 'invalid value')}"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": msg,
            "detail": msg,
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Generic error handler to prevent stack traces leaking to client."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An error occurred while processing the request.",
            "detail": "An internal error occurred. Please try again.",
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Clean validation error response for invalid URLs or unsupported schemes."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Bad Request",
            "message": str(exc),
            "detail": str(exc),
        },
    )


@app.get("/health", tags=["Health"])
async def health_check():
    """Health status endpoint."""
    return {
        "status": "ok",
        "service": "sentinelai-backend",
        "mode": "demo",
    }


@app.post("/scan-email", response_model=EmailScanResponse, tags=["Scanner"])
async def scan_email(request: EmailScanRequest = EmailScanRequest()):
    """
    Perform security analysis on provided email metadata/body.
    Returns deterministic rule-based scan response.
    """
    return analyze_demo_email(request)


@app.post("/scan-url", tags=["Scanner"])
async def scan_url_endpoint(request: UrlScanRequest):
    """
    Perform comprehensive, SSRF-protected website URL security analysis.
    Safely inspects domain age, DNS, redirect hops, static HTML, and external intelligence.
    """
    from app.scanner.url_pipeline import orchestrate_url_scan
    return await orchestrate_url_scan(request.url)


@app.post("/scan-document", response_model=DocumentScanResponse, tags=["Document Scanner"])
async def scan_document_upload(
    file: UploadFile = File(..., description="Document file to safely analyze")
):
    """
    Perform comprehensive 9-feature static security analysis on an uploaded document file.
    Inspects macros, embedded scripts, HTML phishing, hyperlinks, exploits, forms, and hidden text.
    Renders safe static preview without executing active content.
    """
    from app.scanner.doc_pipeline import orchestrate_document_scan
    file_bytes = await file.read()
    filename = file.filename or "uploaded_document.bin"
    return orchestrate_document_scan(file_bytes, filename)


@app.post("/scan-document-json", response_model=DocumentScanResponse, tags=["Document Scanner"])
async def scan_document_json(payload: DocumentScanPayload):
    """
    Perform comprehensive 9-feature static security analysis via JSON payload.
    Supports base64 file bytes or pre-configured test fixtures.
    """
    import base64
    from app.scanner.doc_pipeline import orchestrate_document_scan
    from app.scanner.presets import get_fixture_bytes

    if payload.file_content_base64:
        try:
            file_bytes = base64.b64decode(payload.file_content_base64)
        except Exception:
            raise ValueError("Invalid base64 encoding in file_content_base64.")
    else:
        # Load synthetic benign test fixture corresponding to requested preset or filename
        file_bytes = get_fixture_bytes(payload.preset or payload.file_name)

    return orchestrate_document_scan(file_bytes, payload.file_name)


# ==============================================================================
# Authenticated User Profile & Privacy Controls
# ==============================================================================
from fastapi import Depends
from app.auth import (
    UserContext,
    UserProfileUpdate,
    AccountDeleteRequest,
    get_current_user,
    get_user_profile,
    save_user_profile,
    delete_user_account,
)


@app.get("/api/user/profile", tags=["User Profile"])
async def get_profile_endpoint(user: UserContext = Depends(get_current_user)):
    """
    Retrieve current authenticated user's isolated profile.
    Requires verified Authorization Bearer token.
    """
    return get_user_profile(user.user_id)


@app.post("/api/user/profile", tags=["User Profile"])
async def update_profile_endpoint(
    payload: UserProfileUpdate,
    user: Optional[UserContext] = Depends(lambda: None),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Update personal onboarding preferences and display name.
    Enforces user data isolation and ownership checks.
    """
    target_user_id: Optional[str] = None

    if authorization:
        user_ctx = await get_current_user(authorization)
        target_user_id = user_ctx.user_id
    elif payload.userId:
        # Fallback in local development without header
        target_user_id = payload.userId
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to update profile.",
        )

    # Prevent modifying another user's profile
    if payload.userId and payload.userId != target_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot modify another user's profile.",
        )

    updated = save_user_profile(target_user_id, payload.model_dump(exclude_unset=True))
    return {
        "status": "success",
        "message": "User profile preferences saved.",
        "profile": updated,
    }


@app.delete("/api/user/account", tags=["User Profile"])
async def delete_account_endpoint(
    payload: Optional[AccountDeleteRequest] = None,
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Permanently erase user profile and associated account data.
    Enforces server-side authorization check.
    """
    target_user_id: Optional[str] = None

    if authorization:
        user_ctx = await get_current_user(authorization)
        target_user_id = user_ctx.user_id
    elif payload and payload.userId:
        target_user_id = payload.userId
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to delete account.",
        )

    deleted = delete_user_account(target_user_id)
    return {
        "status": "success",
        "deleted": deleted,
        "message": "User account and associated profile data have been permanently erased.",
    }


@app.get("/api/user/check-username", tags=["User Profile"])
async def check_username_endpoint(
    username: str = Query(..., min_length=1, max_length=50),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Check if a given username is valid and available across all accounts.
    Allows current user to keep their own username if editing.
    """
    exclude_user_id = None
    if authorization:
        try:
            user_ctx = await get_current_user(authorization)
            exclude_user_id = user_ctx.user_id
        except Exception:
            pass

    clean_user = username.strip().lower()
    is_avail = database.check_username_available(clean_user, exclude_user_id=exclude_user_id)
    return {
        "username": clean_user,
        "available": is_avail,
    }


@app.post("/api/user/avatar", tags=["User Profile"])
async def upload_avatar_endpoint(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Accepts an uploaded image file (JPEG, PNG, WEBP), validates size (<= 5MB),
    and stores it as a secure data URL in the user's profile.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to upload profile avatar.",
        )
    user_ctx = await get_current_user(authorization)

    allowed_types = {"image/jpeg", "image/png", "image/webp", "image/gif"}
    content_type = file.content_type or ""
    if content_type.lower() not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid image format. Allowed formats: JPEG, PNG, WEBP, GIF.",
        )

    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds the 5MB maximum limit.",
        )

    b64_encoded = base64.b64encode(contents).decode("utf-8")
    data_uri = f"data:{content_type};base64,{b64_encoded}"

    # Persist avatar into user profile
    save_user_profile(user_ctx.user_id, {"profilePictureUrl": data_uri})

    return {
        "success": True,
        "avatarUrl": data_uri,
        "message": "Profile picture updated successfully.",
    }


# ==============================================================================
# Security & Devices Management Endpoints
# ==============================================================================

@app.get("/api/security/passkeys", tags=["Security Dashboard"])
async def get_passkeys_endpoint(user: UserContext = Depends(get_current_user)):
    """Retrieve all active WebAuthn passkeys registered to the current user."""
    passkeys = database.get_user_registered_passkeys(user.user_id)
    return {"passkeys": passkeys}


@app.delete("/api/security/passkeys/{credential_id}", tags=["Security Dashboard"])
async def revoke_passkey_endpoint(
    credential_id: str,
    user: UserContext = Depends(get_current_user),
):
    """Revoke a specific WebAuthn passkey belonging to the current user."""
    revoked = database.revoke_passkey_credential(user.user_id, credential_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey credential not found or already revoked.",
        )
    return {"success": True, "message": "Passkey credential has been revoked."}


@app.get("/api/security/devices", tags=["Security Dashboard"])
async def get_trusted_devices_endpoint(user: UserContext = Depends(get_current_user)):
    """Retrieve all trusted devices enrolled for the current user."""
    devices = database.get_user_trusted_devices(user.user_id)
    return {"devices": devices}


@app.delete("/api/security/devices/{device_id}", tags=["Security Dashboard"])
async def revoke_device_endpoint(
    device_id: str,
    user: UserContext = Depends(get_current_user),
):
    """Revoke a specific trusted device and its associated push subscriptions."""
    revoked = database.revoke_trusted_device(user.user_id, device_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found or already revoked.",
        )
    return {"success": True, "message": "Device access revoked."}


@app.get("/api/security/sessions", tags=["Security Dashboard"])
async def get_sessions_endpoint(user: UserContext = Depends(get_current_user)):
    """Retrieve all active sessions for the current user."""
    sessions = database.get_user_active_sessions(user.user_id)
    return {"sessions": sessions}


@app.delete("/api/security/sessions/{session_id}", tags=["Security Dashboard"])
async def revoke_session_endpoint(
    session_id: str,
    user: UserContext = Depends(get_current_user),
):
    """Revoke a specific active session."""
    revoked = database.revoke_user_session(user.user_id, session_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already revoked.",
        )
    return {"success": True, "message": "Session revoked."}


@app.post("/api/security/sessions/revoke-others", tags=["Security Dashboard"])
async def revoke_other_sessions_endpoint(
    payload: Dict[str, Any] = {},
    user: UserContext = Depends(get_current_user),
):
    """Revoke all sessions for this user except the current active session."""
    current_session_id = payload.get("currentSessionId", "")
    revoked_count = database.revoke_all_other_sessions(user.user_id, current_session_id)
    return {
        "success": True,
        "revokedCount": revoked_count,
        "message": f"Revoked {revoked_count} other active session(s).",
    }


@app.get("/api/security/activity", tags=["Security Dashboard"])
async def get_activity_endpoint(
    limit: int = Query(50, ge=1, le=100),
    user: UserContext = Depends(get_current_user),
):
    """Retrieve real security and login audit history for the authenticated user."""
    events = database.get_user_audit_events(user.user_id, limit=limit)
    return {"activity": events}


@app.get("/api/security/preferences", tags=["Security Dashboard"])
async def get_security_preferences_endpoint(user: UserContext = Depends(get_current_user)):
    """Retrieve security notification preferences for the user."""
    prefs = database.get_security_preferences(user.user_id)
    return {"preferences": prefs}


@app.post("/api/security/preferences", tags=["Security Dashboard"])
async def update_security_preferences_endpoint(
    payload: Dict[str, bool],
    user: UserContext = Depends(get_current_user),
):
    """Update security notification preferences for the user."""
    updated = database.update_security_preferences(user.user_id, payload)
    return {"success": True, "preferences": updated}


# ==============================================================================
# Sentinel AI Authoritative Dual-Channel Authentication Endpoints
# ==============================================================================

from app.auth_engine import (
    StartAuthRequest,
    VerifyCallbackRequest,
    WebAuthnVerificationPayload,
    WebAuthnRegistrationPayload,
    SessionCompleteRequest,
    start_auth_transaction,
    confirm_email_gate,
    validate_mobile_challenge_access,
    complete_mobile_registration_gate,
    complete_mobile_biometric_gate,
    finalize_computer_session,
    get_transaction_status,
    revoke_session,
)


@app.post("/api/auth/start", tags=["Sentinel Auth"])
async def auth_start_endpoint(
    payload: StartAuthRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 1: Start 2-channel authentication transaction with email and mobile number.
    Returns opaque transactionId and initiates Gate 1.
    """
    t0 = time.perf_counter()
    ip_address = request.client.host if request.client else None
    correlation_id = f"corr_{secrets.token_hex(8)}"
    try:
        result = start_auth_transaction(
            email=payload.email,
            phone_number=payload.phoneNumber,
            user_agent=user_agent or payload.userAgent,
            ip_address=ip_address,
            transaction_id=payload.transactionId,
        )
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        result["durationMs"] = duration_ms
        logger.info(f"[{correlation_id}] Initiated auth transaction: {result.get('transactionId')} in {duration_ms}ms")
        return result
    except ValueError as e:
        logger.warning(f"[{correlation_id}] Auth transaction rejected: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"[{correlation_id}] Unexpected error in auth_start_endpoint: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate authentication transaction. Please try again shortly.",
        )


@app.post("/api/auth/confirm-email", tags=["Sentinel Auth"])
async def auth_confirm_email_endpoint(
    payload: VerifyCallbackRequest,
    request: Request,
):
    """
    Step 2: Gate 1 confirmation. Marks email verified and issues WhatsApp mobile challenge.
    """
    try:
        app_origin = request.headers.get("origin") or request.headers.get("referer")
        result = await confirm_email_gate(
            transaction_id=payload.transactionId,
            user_id=payload.userId,
            override_app_url=app_origin.rstrip("/") if app_origin else None,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get("/api/auth/status/{transaction_id}", tags=["Sentinel Auth"])
async def auth_status_endpoint(transaction_id: str):
    """
    Authoritative state check for waiting computer screen.
    """
    status_info = get_transaction_status(transaction_id)
    return status_info


@app.get("/api/auth/mobile-challenge", tags=["Sentinel Auth"])
async def auth_mobile_challenge_endpoint(
    t: str,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 3: Opened on mobile via WhatsApp link.
    Inspects User-Agent; returns Access Denied if opened on desktop.
    """
    result = validate_mobile_challenge_access(mobile_token=t, user_agent=user_agent)
    if not result.get("valid"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "Invalid verification link."),
        )
    return result


@app.post("/api/auth/webauthn/register", tags=["Sentinel Auth"])
async def auth_webauthn_register_endpoint(
    payload: WebAuthnRegistrationPayload,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Submits WebAuthn attestation for first-time platform passkey registration.
    Validates attestation, saves credential, consumes challenge, completes Gate 2.
    """
    ip_address = request.client.host if request.client else None
    try:
        result = complete_mobile_registration_gate(
            payload=payload,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/auth/webauthn/verify", tags=["Sentinel Auth"])
async def auth_webauthn_verify_endpoint(
    payload: WebAuthnVerificationPayload,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 4: Submits WebAuthn assertion from mobile platform authenticator.
    Validates assertion, consumes challenge atomically, completes Gate 2.
    """
    ip_address = request.client.host if request.client else None
    try:
        result = complete_mobile_biometric_gate(
            payload=payload,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/auth/complete", tags=["Sentinel Auth"])
async def auth_complete_endpoint(
    payload: SessionCompleteRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 5: Finalize authenticated session for computer browser after both gates pass.
    """
    ip_address = request.client.host if request.client else None
    try:
        session_info = finalize_computer_session(
            transaction_id=payload.transactionId,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return session_info
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.post("/api/auth/logout", tags=["Sentinel Auth"])
async def auth_logout_endpoint(
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Step 6: Revokes the authenticated session on the server.
    """
    t0 = time.perf_counter()
    raw_token = authorization
    if raw_token and raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    revoked = revoke_session(token=raw_token)
    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    logger.info(f"Session logout completed in {duration_ms}ms (revoked={revoked})")
    return {"success": True, "revoked": revoked, "durationMs": duration_ms, "message": "Session invalidated."}


# ------------------------------------------------------------------------------
# Web Push & Mobile Device Registration Endpoints
# ------------------------------------------------------------------------------

from pydantic import BaseModel
from app.push import get_vapid_public_key
from app.database import (
    save_push_subscription,
    register_device,
    get_devices_for_user,
)


class PushKeysModel(BaseModel):
    p256dh: str
    auth: str


class PushSubscriptionModel(BaseModel):
    endpoint: str
    keys: PushKeysModel


class PushSubscribeRequest(BaseModel):
    userId: str
    subscription: PushSubscriptionModel
    deviceId: Optional[str] = None
    userAgent: Optional[str] = None


class DeviceRegisterRequest(BaseModel):
    deviceId: str
    userId: str
    deviceName: Optional[str] = "Mobile Device"
    deviceType: Optional[str] = "mobile"
    platform: Optional[str] = "Unknown"
    credentialId: Optional[str] = None
    publicKey: Optional[str] = None


@app.get("/api/auth/push/vapid-public-key", tags=["Web Push"])
async def push_vapid_key_endpoint():
    """Returns VAPID public key for browser Push API subscription."""
    return {"publicKey": get_vapid_public_key()}


@app.post("/api/auth/push/subscribe", tags=["Web Push"])
async def push_subscribe_endpoint(payload: PushSubscribeRequest):
    """Registers or updates a user's browser push subscription."""
    try:
        sub_record = {
            "user_id": payload.userId,
            "endpoint": payload.subscription.endpoint,
            "p256dh": payload.subscription.keys.p256dh,
            "auth": payload.subscription.keys.auth,
            "device_id": payload.deviceId,
            "user_agent": payload.userAgent,
        }
        save_push_subscription(sub_record)
        return {"success": True, "message": "Push subscription registered."}
    except Exception as e:
        logger.error(f"Error subscribing to push: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to register push subscription: {str(e)}",
        )


@app.post("/api/auth/devices/register", tags=["Device Registration"])
async def device_register_endpoint(payload: DeviceRegisterRequest):
    """Enrolls a trusted mobile device and platform authenticator credential."""
    try:
        device_record = {
            "device_id": payload.deviceId,
            "user_id": payload.userId,
            "device_name": payload.deviceName or "Mobile Device",
            "device_type": payload.deviceType or "mobile",
            "platform": payload.platform or "Unknown",
            "credential_id": payload.credentialId,
            "public_key": payload.publicKey,
        }
        register_device(device_record)
        return {"success": True, "message": "Device registered successfully."}
    except Exception as e:
        logger.error(f"Error registering device: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to register device: {str(e)}",
        )


@app.get("/api/auth/devices/{user_id}", tags=["Device Registration"])
async def list_user_devices_endpoint(user_id: str):
    """Lists enrolled mobile devices for an authenticated user."""
    devices = get_devices_for_user(user_id)
    return {"userId": user_id, "devices": devices}


# ==============================================================================
# Push-To-Approve Mobile Passkey Login Endpoints
# ==============================================================================

from app.push_auth_engine import (
    start_push_login_transaction,
    get_push_transaction_status,
    get_push_transaction_details,
    reject_push_login,
    approve_push_login,
    verify_push_login_passkey,
    finalize_push_login_session,
)


class PushLoginStartRequest(BaseModel):
    phoneNumber: str


class PushLoginRejectRequest(BaseModel):
    transactionId: str
    token: str


class PushLoginApproveRequest(BaseModel):
    transactionId: str
    token: str


class PushLoginVerifyPasskeyRequest(BaseModel):
    transactionId: str
    token: str
    credentialId: str
    clientDataJSON: str
    authenticatorData: str
    signature: str
    userHandle: Optional[str] = None


class PushLoginCompleteRequest(BaseModel):
    transactionId: str


@app.post("/api/auth/push-login/start", tags=["Push Login"])
async def push_login_start_endpoint(
    payload: PushLoginStartRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 1: Start Push-To-Approve Login.
    Validates registered phone, creates expiring transaction, and dispatches real Web Push.
    """
    ip_address = request.client.host if request.client else None
    return start_push_login_transaction(
        raw_phone=payload.phoneNumber,
        ip_address=ip_address,
        user_agent=user_agent,
    )


@app.get("/api/auth/push-login/status/{transaction_id}", tags=["Push Login"])
async def push_login_status_endpoint(transaction_id: str):
    """
    Polled by original waiting device. Returns current state of login transaction.
    """
    return get_push_transaction_status(transaction_id)


@app.get("/api/auth/push-login/details", tags=["Push Login"])
async def push_login_details_endpoint(
    tx: str = Query(...),
    tok: str = Query(...),
):
    """
    Called by registered mobile browser opening notification URL.
    Returns request metadata (device, browser, request time, status).
    """
    return get_push_transaction_details(transaction_id=tx, mobile_token=tok)


@app.post("/api/auth/push-login/reject", tags=["Push Login"])
async def push_login_reject_endpoint(
    payload: PushLoginRejectRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 2B: Mobile user taps 'No, it's not me'.
    Immediately blocks the transaction and prevents any further authentication.
    """
    ip_address = request.client.host if request.client else None
    return reject_push_login(
        transaction_id=payload.transactionId,
        mobile_token=payload.token,
        ip_address=ip_address,
        user_agent=user_agent,
    )


@app.post("/api/auth/push-login/approve", tags=["Push Login"])
async def push_login_approve_endpoint(
    payload: PushLoginApproveRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 2A: Mobile user taps 'Yes, it's me'.
    Does NOT authorize by itself! Transitions to AWAITING_PASSKEY and returns WebAuthn options.
    """
    ip_address = request.client.host if request.client else None
    return approve_push_login(
        transaction_id=payload.transactionId,
        mobile_token=payload.token,
        ip_address=ip_address,
        user_agent=user_agent,
    )


@app.post("/api/auth/push-login/verify-passkey", tags=["Push Login"])
async def push_login_verify_passkey_endpoint(
    payload: PushLoginVerifyPasskeyRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 3: Cryptographically verifies the mobile passkey assertion.
    Marks transaction AUTHENTICATED on success.
    """
    ip_address = request.client.host if request.client else None
    return verify_push_login_passkey(
        transaction_id=payload.transactionId,
        mobile_token=payload.token,
        credential_id=payload.credentialId,
        client_data_json=payload.clientDataJSON,
        authenticator_data=payload.authenticatorData,
        signature=payload.signature,
        user_handle=payload.userHandle,
        ip_address=ip_address,
        user_agent=user_agent,
    )


@app.post("/api/auth/push-login/complete", tags=["Push Login"])
async def push_login_complete_endpoint(
    payload: PushLoginCompleteRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Step 4: Finalizes session on original device after mobile passkey succeeds.
    Single-use consumption: marks COMPLETED and creates authenticated session token.
    """
    ip_address = request.client.host if request.client else None
    return finalize_push_login_session(
        transaction_id=payload.transactionId,
        ip_address=ip_address,
        user_agent=user_agent,
    )


# ==============================================================================
# Gmail OAuth 2.0 Integration Endpoints (Stage 1: Secure Account Connection)
# ==============================================================================

from app.gmail_routes import router as gmail_integration_router

app.include_router(gmail_integration_router)





