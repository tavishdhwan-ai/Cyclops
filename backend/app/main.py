import logging
import secrets
from typing import Optional
from fastapi import FastAPI, Request, status, UploadFile, File, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

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


# ==============================================================================
# Sentinel AI Authoritative Dual-Channel Authentication Endpoints
# ==============================================================================

from app.auth_engine import (
    StartAuthRequest,
    VerifyCallbackRequest,
    WebAuthnVerificationPayload,
    SessionCompleteRequest,
    start_auth_transaction,
    confirm_email_gate,
    validate_mobile_challenge_access,
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
    ip_address = request.client.host if request.client else None
    correlation_id = f"corr_{secrets.token_hex(8)}"
    try:
        result = start_auth_transaction(
            email=payload.email,
            phone_number=payload.phoneNumber,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        logger.info(f"[{correlation_id}] Initiated auth transaction: {result.get('transactionId')}")
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
    raw_token = authorization
    if raw_token and raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    revoked = revoke_session(token=raw_token)
    return {"success": True, "revoked": revoked, "message": "Session invalidated."}




