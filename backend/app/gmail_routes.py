"""
FastAPI Router for Cyclops Gmail OAuth 2.0 Integration & Connection Management.
All endpoints enforce verified two-channel Cyclops session identity.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.gmail_service import (
    CyclopsSessionContext,
    GmailIntegrationError,
    get_verified_cyclops_session,
    get_gmail_connection_status,
    start_gmail_oauth,
    process_gmail_oauth_callback,
    verify_gmail_connection,
    disconnect_gmail_connection,
)

router = APIRouter(prefix="/api/integrations/gmail", tags=["Gmail Integration"])


class GmailStartRequest(BaseModel):
    action: str = "connect"
    privacyConsentAccepted: bool = False


class GmailCallbackRequest(BaseModel):
    state: Optional[str] = None
    code: Optional[str] = None
    error: Optional[str] = None


def _error_response(exc: GmailIntegrationError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "success": False,
            "error": exc.code,
            "code": exc.code,
            "message": exc.message,
            "detail": exc.message,
            "reauthRequired": exc.reauth_required,
        },
    )


@router.get("/status")
async def gmail_status_endpoint(
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """Returns current Gmail connection status from local DB without calling Google APIs."""
    return get_gmail_connection_status(session)


@router.post("/start")
async def gmail_start_endpoint(
    payload: GmailStartRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """Initiates server-side Google OAuth 2.0 + PKCE flow for connecting Gmail."""
    ip_address = request.client.host if request.client else None
    try:
        return start_gmail_oauth(
            user_ctx=session,
            action=payload.action,
            privacy_consent_accepted=payload.privacyConsentAccepted,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except GmailIntegrationError as exc:
        return _error_response(exc)


@router.post("/reconnect")
async def gmail_reconnect_endpoint(
    payload: GmailStartRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """Initiates server-side Google OAuth 2.0 + PKCE flow specifically to reauthorise an existing connection."""
    ip_address = request.client.host if request.client else None
    try:
        return start_gmail_oauth(
            user_ctx=session,
            action="reconnect",
            privacy_consent_accepted=payload.privacyConsentAccepted,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except GmailIntegrationError as exc:
        return _error_response(exc)


@router.post("/callback")
async def gmail_callback_endpoint(
    payload: GmailCallbackRequest,
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """
    Processes OAuth callback forwarded by Next.js server route.
    Validates session, state ownership, replay protection, exchanges code, verifies profile, and persists encrypted credentials.
    """
    ip_address = request.client.host if request.client else None
    try:
        return await process_gmail_oauth_callback(
            user_ctx=session,
            state=payload.state,
            code=payload.code,
            oauth_error=payload.error,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except GmailIntegrationError as exc:
        return _error_response(exc)


@router.post("/verify")
async def gmail_verify_endpoint(
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """Explicitly verifies the live Gmail connection using the read-only Gmail profile endpoint."""
    ip_address = request.client.host if request.client else None
    try:
        return await verify_gmail_connection(
            user_ctx=session,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except GmailIntegrationError as exc:
        return _error_response(exc)


@router.post("/disconnect")
@router.delete("")
async def gmail_disconnect_endpoint(
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    session: CyclopsSessionContext = Depends(get_verified_cyclops_session),
):
    """Disconnects Gmail, revokes Google OAuth token if possible, and purges local credentials."""
    ip_address = request.client.host if request.client else None
    try:
        return await disconnect_gmail_connection(
            user_ctx=session,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except GmailIntegrationError as exc:
        return _error_response(exc)
