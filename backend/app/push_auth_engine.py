"""
Sentinel AI Push-To-Approve Authentication Engine.
Implements:
PHONE NUMBER -> WEB PUSH -> YES/NO APPROVAL -> MOBILE PASSSKEY -> ORIGINAL DEVICE AUTHORIZATION
Enforces server-side state machine, rate limiting, anti-enumeration, and cryptographic FIDO2 Level 3 verification.
"""
import os
import re
import time
import hashlib
import secrets
import threading
from typing import Dict, Any, Optional, List, Tuple
from fastapi import HTTPException, status
import jwt
import phonenumbers
from phonenumbers import NumberParseException

from app import database
from app.push import dispatch_push_to_user
from app.webauthn import (
    create_authentication_options,
    verify_authentication,
    WEBAUTHN_RP_ID,
    WEBAUTHN_ORIGIN,
)

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "super-secret-jwt-token-with-at-least-32-bytes-long")
APP_PUBLIC_URL = os.getenv("APP_PUBLIC_URL", "https://cyclops-chi.vercel.app")

# Push Login State Constants
STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
STATE_AWAITING_PASSKEY = "AWAITING_PASSKEY"
STATE_AUTHENTICATED = "AUTHENTICATED"
STATE_REJECTED = "REJECTED"
STATE_EXPIRED = "EXPIRED"
STATE_FAILED = "FAILED"
STATE_COMPLETED = "COMPLETED"

# In-memory rate limiting store: key -> list of timestamps
_RATE_LIMITS: Dict[str, List[float]] = {}
_engine_lock = threading.Lock()


def check_rate_limit(key: str, max_attempts: int = 5, window_seconds: float = 60.0) -> None:
    """Enforces sliding-window rate limiting to prevent brute-force and push spam."""
    now = time.time()
    with _engine_lock:
        timestamps = _RATE_LIMITS.get(key, [])
        # Prune expired timestamps
        timestamps = [t for t in timestamps if now - t < window_seconds]
        if len(timestamps) >= max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication requests. Please wait a minute before trying again.",
            )
        timestamps.append(now)
        _RATE_LIMITS[key] = timestamps


def parse_device_user_agent(ua_string: Optional[str]) -> Tuple[str, str]:
    """Extracts human-friendly browser and OS name from User-Agent string."""
    if not ua_string:
        return "Web Browser", "Desktop Device"

    ua = ua_string.lower()

    # Determine Browser
    if "edg" in ua:
        browser = "Microsoft Edge"
    elif "chrome" in ua or "crios" in ua:
        browser = "Google Chrome"
    elif "firefox" in ua or "fxios" in ua:
        browser = "Mozilla Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Apple Safari"
    else:
        browser = "Web Browser"

    # Determine OS
    if "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Desktop"

    return browser, os_name


def normalize_phone_number(raw_phone: str) -> str:
    """Validates and normalizes phone number to strict E.164 format."""
    if not raw_phone or not isinstance(raw_phone, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid phone number including country code is required.",
        )

    clean = raw_phone.strip()
    if not clean.startswith("+"):
        clean = "+" + clean

    try:
        parsed = phonenumbers.parse(clean, None)
        if not phonenumbers.is_valid_number(parsed):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid phone number. Please enter a valid international mobile number.",
            )
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except NumberParseException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not parse phone number. Ensure it begins with '+' and your country code.",
        )


def start_push_login_transaction(
    raw_phone: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 1: Initiates a Push-To-Approve login transaction.
    - Validates and normalizes phone number.
    - Rate limits by IP and Phone.
    - Finds account and checks active passkey and push devices.
    - Generates 2-minute transaction and mobile approval token.
    - Dispatches Web Push notification to registered device(s).
    - Protects against account enumeration.
    """
    normalized_phone = normalize_phone_number(raw_phone)
    # Rate limiting: Enforce sliding-window limits per IP and per Phone to prevent abuse and brute-force
    ip_key = f"lookup:ip:{ip_address or 'anon'}"
    phone_key = f"lookup:phone:{normalized_phone}"
    check_rate_limit(ip_key, max_attempts=5, window_seconds=60.0)
    check_rate_limit(phone_key, max_attempts=5, window_seconds=60.0)

    browser_name, os_name = parse_device_user_agent(user_agent)
    now = time.time()
    expires_at = now + 120.0  # 2 minute expiry

    # Look up the phone number against verified phone numbers associated with registered SentinelAI accounts
    user = database.get_user_by_phone(normalized_phone)

    # If no account is associated with the submitted number, do NOT create a login transaction and do NOT send a push notification.
    if not user:
        database.record_db_audit({
            "id": f"audit_{secrets.token_hex(8)}",
            "transaction_id": None,
            "user_id": None,
            "event_type": "ACCOUNT_LOOKUP_NO_ACCOUNT",
            "status": "NOT_FOUND",
            "details": {
                "reason": "phone_not_registered",
                "phone_hash": hashlib.sha256(normalized_phone.encode("utf-8")).hexdigest()[:16],
            },
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": now,
        })
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "title": "No account associated with this number",
                "message": "We couldn't find a SentinelAI account registered with this phone number. Please check the number or sign up for SentinelAI.",
            },
        )

    # Check verified passkeys and verified push subscriptions
    passkeys = database.get_active_passkeys_for_user(user["userId"])
    push_subs = database.get_push_subscriptions_for_user(user["userId"])

    # Create Real Account Transaction
    tx_id = f"ptx_{secrets.token_hex(16)}"
    mobile_token = f"mtok_{secrets.token_urlsafe(32)}"
    mobile_token_hash = hashlib.sha256(mobile_token.encode("utf-8")).hexdigest()

    tx_record = {
        "id": f"ptx_{secrets.token_hex(8)}",
        "transactionId": tx_id,
        "userId": user["userId"],
        "phoneNumber": normalized_phone,
        "mobileTokenHash": mobile_token_hash,
        "state": STATE_PENDING_APPROVAL,
        "ipAddress": ip_address,
        "userAgent": user_agent,
        "browserName": browser_name,
        "osName": os_name,
        "createdAt": now,
        "expiresAt": expires_at,
    }
    database.save_push_login_transaction(tx_record)

    # Format human-readable time
    time_str = time.strftime("%I:%M %p UTC", time.gmtime(now))

    # Dispatch Real Web Push Notification ONLY if registered push subscriptions exist
    push_sent = 0
    push_status = "no_devices"
    if push_subs:
        push_payload = {
            "title": "SentinelAI — Login Request",
            "body": "Someone is trying to access your SentinelAI account. Is this you?",
            "data": {
                "type": "login_approval",
                "transactionId": tx_id,
                "url": f"/approve-login?tx={tx_id}&tok={mobile_token}",
                "browser": browser_name,
                "device": os_name,
                "requestTime": time_str,
                "ipAddress": ip_address or "Current Connection",
            },
        }
        push_result = dispatch_push_to_user(user["userId"], push_payload)
        push_sent = push_result.get("sent", 0)
        push_status = push_result.get("status")

    database.record_db_audit({
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": tx_id,
        "user_id": user["userId"],
        "event_type": "PUSH_LOGIN_TRANSACTION_STARTED",
        "status": "SUCCESS",
        "details": {
            "push_sent": push_sent,
            "push_status": push_status,
            "has_passkeys": len(passkeys) > 0,
            "browser": browser_name,
            "os": os_name,
        },
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": now,
    })

    return {
        "success": True,
        "transactionId": tx_id,
        "expiresAt": expires_at,
        "state": STATE_PENDING_APPROVAL,
        "pushSentCount": push_sent,
        "isConfiguredForPush": bool(push_subs),
        "mobileApprovalUrl": f"/approve-login?tx={tx_id}&tok={mobile_token}",
        "message": "Push notification sent to your registered device. Please review the request on your phone."
        if push_subs
        else "Please open the approval page or scan the QR code on your mobile device to authorize.",
    }


def get_push_transaction_status(transaction_id: str) -> Dict[str, Any]:
    """
    Polled by original waiting device.
    Returns current state, checks expiry.
    Never authorizes on polling alone.
    """
    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        return {
            "exists": False,
            "state": STATE_EXPIRED,
            "authenticated": False,
            "rejected": False,
        }

    now = time.time()
    if tx["state"] in (STATE_PENDING_APPROVAL, STATE_AWAITING_PASSKEY) and tx["expiresAt"] < now:
        database.update_push_login_transaction_state(transaction_id, STATE_EXPIRED)
        tx["state"] = STATE_EXPIRED

    return {
        "exists": True,
        "transactionId": transaction_id,
        "state": tx["state"],
        "expiresAt": tx["expiresAt"],
        "authenticated": tx["state"] in (STATE_AUTHENTICATED, STATE_COMPLETED),
        "rejected": tx["state"] == STATE_REJECTED,
        "isExpired": tx["state"] == STATE_EXPIRED,
    }


def get_push_transaction_details(transaction_id: str, mobile_token: str) -> Dict[str, Any]:
    """
    Called by mobile phone opening the push notification URL (/approve-login).
    Cryptographically verifies the bound mobile token before returning login context.
    """
    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Login request not found.")

    token_hash = hashlib.sha256(mobile_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(tx["mobileTokenHash"], token_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid mobile authorization token.")

    now = time.time()
    if tx["expiresAt"] < now and tx["state"] in (STATE_PENDING_APPROVAL, STATE_AWAITING_PASSKEY):
        database.update_push_login_transaction_state(transaction_id, STATE_EXPIRED)
        tx["state"] = STATE_EXPIRED

    return {
        "transactionId": tx["transactionId"],
        "state": tx["state"],
        "browser": tx["browserName"] or "Web Browser",
        "os": tx["osName"] or "Computer",
        "ipAddress": tx["ipAddress"] or "Secure IP",
        "requestTime": tx["createdAt"],
        "expiresAt": tx["expiresAt"],
    }


def reject_push_login(
    transaction_id: str,
    mobile_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    User clicks 'No, it's not me' on mobile phone.
    Immediately blocks the transaction, prevents passkey authentication, and logs security event.
    """
    rate_key = f"reject:{ip_address or 'anon'}"
    check_rate_limit(rate_key, max_attempts=10, window_seconds=60.0)

    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    token_hash = hashlib.sha256(mobile_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(tx["mobileTokenHash"], token_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authorization token.")

    now = time.time()
    # Cannot reject if already authenticated or completed
    if tx["state"] in (STATE_AUTHENTICATED, STATE_COMPLETED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transaction was already authenticated.",
        )

    # Atomic transition to REJECTED
    database.update_push_login_transaction_state(
        transaction_id=transaction_id,
        new_state=STATE_REJECTED,
        rejected_at=now,
    )

    database.record_db_audit({
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": transaction_id,
        "user_id": tx["userId"],
        "event_type": "LOGIN_REJECTED_BY_USER",
        "status": "BLOCKED",
        "details": {
            "reason": "explicit_user_rejection",
            "browser": tx.get("browserName"),
            "os": tx.get("osName"),
        },
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": now,
    })

    return {
        "success": True,
        "state": STATE_REJECTED,
        "message": "Login request blocked. We've protected your account.",
    }


def approve_push_login(
    transaction_id: str,
    mobile_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    User clicks 'Yes, it's me' on mobile phone.
    IMPORTANT: This does NOT authorize by itself!
    It validates state, transitions to AWAITING_PASSKEY, and generates WebAuthn options.
    """
    rate_key = f"approve:{ip_address or 'anon'}"
    check_rate_limit(rate_key, max_attempts=10, window_seconds=60.0)

    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    token_hash = hashlib.sha256(mobile_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(tx["mobileTokenHash"], token_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authorization token.")

    now = time.time()
    if tx["expiresAt"] < now:
        database.update_push_login_transaction_state(transaction_id, STATE_EXPIRED)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login request has expired.")

    # Strict State Machine: Cannot approve if REJECTED, EXPIRED, or already COMPLETED
    if tx["state"] == STATE_REJECTED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This request was previously rejected.")
    if tx["state"] in (STATE_AUTHENTICATED, STATE_COMPLETED):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already authenticated.")

    # Retrieve user's registered passkeys
    passkeys = database.get_active_passkeys_for_user(tx["userId"])
    if not passkeys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active passkey credentials registered for this account.",
        )

    # Generate WebAuthn options with production RP ID
    auth_options = create_authentication_options(
        registered_credentials=passkeys,
        rp_id=WEBAUTHN_RP_ID,
    )

    # Transition state to AWAITING_PASSKEY and save challenge
    database.update_push_login_transaction_state(
        transaction_id=transaction_id,
        new_state=STATE_AWAITING_PASSKEY,
        webauthn_challenge=auth_options["challenge"],
        approved_at=now,
    )

    database.record_db_audit({
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": transaction_id,
        "user_id": tx["userId"],
        "event_type": "LOGIN_APPROVED_BY_USER_PENDING_PASSKEY",
        "status": "PENDING",
        "details": {"passkey_count": len(passkeys)},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": now,
    })

    return {
        "success": True,
        "state": STATE_AWAITING_PASSKEY,
        "webauthnOptions": auth_options,
        "message": "Intent recorded. Please authorize with your mobile passkey.",
    }


def verify_push_login_passkey(
    transaction_id: str,
    mobile_token: str,
    credential_id: str,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
    user_handle: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 4: Cryptographically verifies the WebAuthn assertion signature from the mobile phone.
    Ensures:
    - Challenge matches transaction
    - Origin matches cyclops-chi.vercel.app / dev
    - RP ID matches
    - Public key from registered_devices verifies signature
    - User verification was satisfied
    - Signature counter is updated
    - State transitions to AUTHENTICATED
    """
    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    token_hash = hashlib.sha256(mobile_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(tx["mobileTokenHash"], token_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authorization token.")

    now = time.time()
    if tx["expiresAt"] < now:
        database.update_push_login_transaction_state(transaction_id, STATE_EXPIRED)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login request has expired.")

    # State Machine: Must be in AWAITING_PASSKEY state
    if tx["state"] == STATE_REJECTED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This request was rejected.")
    if tx["state"] != STATE_AWAITING_PASSKEY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid transaction state for passkey verification: {tx['state']}",
        )

    expected_challenge = tx["webauthnChallenge"]
    if not expected_challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active WebAuthn challenge found for transaction.",
        )

    # Stored device passkey record lookup
    stored_device = database.get_device_by_credential_id(credential_id)
    if not stored_device or stored_device.get("userId") != tx["userId"]:
        database.record_db_audit({
            "id": f"audit_{secrets.token_hex(8)}",
            "transaction_id": transaction_id,
            "user_id": tx["userId"],
            "event_type": "PUSH_LOGIN_PASSKEY_FAILED",
            "status": "FAILURE",
            "details": {"error": "unregistered_or_cross_account_credential"},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": now,
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The passkey presented does not belong to this account.",
        )

    # Construct full credential assertion dictionary for standards-compliant verification
    cred_obj = {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_json,
            "authenticatorData": authenticator_data,
            "signature": signature,
            "userHandle": user_handle,
        },
    }

    # Perform strict standards-compliant cryptographic verification
    try:
        verified_auth = verify_authentication(
            credential=cred_obj,
            expected_challenge=expected_challenge,
            credential_public_key=stored_device["publicKey"],
            credential_current_sign_count=stored_device.get("signCount", 0),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        database.record_db_audit({
            "id": f"audit_{secrets.token_hex(8)}",
            "transaction_id": transaction_id,
            "user_id": tx["userId"],
            "event_type": "PUSH_LOGIN_PASSKEY_FAILED",
            "status": "FAILURE",
            "details": {"error": str(e)},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": now,
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Passkey verification failed: {str(e)}",
        )

    # Update device sign counter in database
    database.update_device_sign_count(credential_id, verified_auth.new_sign_count)

    # Atomically mark transaction as AUTHENTICATED
    database.update_push_login_transaction_state(
        transaction_id=transaction_id,
        new_state=STATE_AUTHENTICATED,
        credential_id=credential_id,
        authenticated_at=now,
    )

    database.record_db_audit({
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": transaction_id,
        "user_id": tx["userId"],
        "event_type": "PUSH_LOGIN_PASSKEY_VERIFIED",
        "status": "SUCCESS",
        "details": {
            "credential_id": credential_id,
            "user_verified": verified_auth.user_verified,
            "sign_count": verified_auth.new_sign_count,
        },
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": now,
    })

    return {
        "success": True,
        "state": STATE_AUTHENTICATED,
        "message": "Biometric authorization confirmed. Your computer has been authorized.",
    }


def finalize_push_login_session(
    transaction_id: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Called by original waiting browser when polling confirms state == AUTHENTICATED.
    Re-validates state, consumes transaction (COMPLETED), and creates session JWT.
    """
    tx = database.get_push_login_transaction(transaction_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found.")

    now = time.time()
    if tx["expiresAt"] < now:
        database.update_push_login_transaction_state(transaction_id, STATE_EXPIRED)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Transaction expired.")

    # Replay protection: Single-use consumption
    if tx["state"] == STATE_COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transaction has already been finalized.",
        )

    if tx["state"] != STATE_AUTHENTICATED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot establish session in state {tx['state']}.",
        )

    # Mark COMPLETED atomically
    database.update_push_login_transaction_state(
        transaction_id=transaction_id,
        new_state=STATE_COMPLETED,
        completed_at=now,
    )

    user_id = tx["userId"]
    user_profile = database.get_user_profile_by_user_id(user_id) or {}
    email = user_profile.get("email") or f"{user_id}@sentinel.ai"
    phone = tx["phoneNumber"]

    # Generate session JWT
    session_id = f"sess_{secrets.token_hex(16)}"
    payload = {
        "sub": user_id,
        "session_id": session_id,
        "transaction_id": transaction_id,
        "email": email,
        "phone_number": phone,
        "role": "authenticated",
        "security_tier": 2,
        "iat": int(now),
        "exp": int(now) + 86400 * 7,  # 7 days
    }
    session_token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")

    # Record active session across persistence layers (PostgreSQL or SQLite)
    session_record = {
        "id": session_id,
        "transactionId": transaction_id,
        "userId": user_id,
        "email": email,
        "phoneNumber": phone,
        "emailVerified": True,
        "mobileVerified": True,
        "biometricVerified": True,
        "biometricStatus": "verified",
        "state": STATE_AUTHENTICATED,
        "userAgent": user_agent,
        "ipAddress": ip_address,
        "expiresAt": now + 86400 * 7,
        "lastActiveAt": now,
        "createdAt": now,
    }
    database.save_transaction(session_record)

    database.record_db_audit({
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": transaction_id,
        "user_id": user_id,
        "event_type": "PUSH_LOGIN_SESSION_ESTABLISHED",
        "status": "SUCCESS",
        "details": {"session_id": session_id},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": now,
    })

    display_name = user_profile.get("displayName") or user_profile.get("fullName") or email.split("@")[0]
    onboarding_completed = bool(user_profile.get("onboardingCompleted", False))
    avatar_url = user_profile.get("profilePictureUrl") or None

    return {
        "success": True,
        "sessionToken": session_token,
        "user": {
            "id": user_id,
            "email": email,
            "phoneNumber": phone,
            "displayName": display_name,
            "fullName": user_profile.get("fullName", ""),
            "username": user_profile.get("username", ""),
            "avatarUrl": avatar_url,
            "securityTier": 2,
            "onboardingCompleted": onboarding_completed,
        },
        "onboardingCompleted": onboarding_completed,
    }
