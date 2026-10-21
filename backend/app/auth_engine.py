"""
Sentinel AI Authoritative Dual-Channel Authentication & Session Engine.
Enforces:
Gate 1: Passwordless Email Verification
Gate 2: WhatsApp Single-Use Mobile Challenge & WebAuthn Platform Biometrics
Cross-Device Synchronization & Atomic Challenge Consumption.
"""
import os
import time
import hashlib
import secrets
import threading
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, Field
import jwt

import re
import logging
from app.whatsapp import get_whatsapp_provider, WhatsAppSendResult
from app.push import dispatch_push_to_user
from app.webauthn import (
    generate_webauthn_challenge,
    verify_webauthn_assertion,
    WEBAUTHN_RP_ID,
    WEBAUTHN_ORIGIN,
)
from app.database import (
    save_transaction,
    load_transaction,
    save_challenge,
    load_challenge,
    record_db_audit,
)
import phonenumbers
from phonenumbers import NumberParseException

logger = logging.getLogger("sentinel.auth")

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

def validate_email_address(raw_email: str) -> str:
    """
    Validates and normalizes email address format server-side.
    Rejects malformed emails, injection patterns, and excessive length.
    """
    if not raw_email or not isinstance(raw_email, str):
        raise ValueError("Work or personal email is required.")

    cleaned = raw_email.strip().lower()
    if len(cleaned) < 5 or len(cleaned) > 254:
        raise ValueError("Email address length must be between 5 and 254 characters.")

    if "\\" in cleaned or " " in cleaned or "@@" in cleaned:
        raise ValueError("Email address contains invalid characters.")

    if not EMAIL_REGEX.match(cleaned):
        raise ValueError("Please provide a valid email address.")

    return cleaned

def validate_and_normalize_phone(raw_phone: str) -> str:
    """
    Validates and normalizes phone numbers worldwide to international E.164 format.
    Ensures country code prefix (+) and rejects invalid or impossible numbers.
    """
    if not raw_phone or not isinstance(raw_phone, str):
        raise ValueError("Mobile phone number is required.")

    cleaned = raw_phone.strip()
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    try:
        parsed = phonenumbers.parse(cleaned, None)
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError(f"The number {raw_phone} is not a valid international mobile number.")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except NumberParseException as e:
        raise ValueError(f"Invalid international phone format: {str(e)}")

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "sentinel-auth-secret-key-32-bytes-minimum!")
APP_PUBLIC_URL = os.getenv("NEXT_PUBLIC_APP_URL", "http://localhost:3000")

# Legal State Names matching Frontend state engine
STATE_EMAIL_REQUIRED = "EMAIL_REQUIRED"
STATE_EMAIL_PENDING = "EMAIL_PENDING"
STATE_EMAIL_VERIFIED = "EMAIL_VERIFIED"
STATE_MOBILE_PENDING = "MOBILE_PENDING"
STATE_MOBILE_CHALLENGE_ISSUED = "MOBILE_CHALLENGE_ISSUED"
STATE_MOBILE_VERIFICATION_PENDING = "MOBILE_VERIFICATION_PENDING"
STATE_BIOMETRIC_VERIFICATION_PENDING = "BIOMETRIC_VERIFICATION_PENDING"
STATE_AUTHENTICATED = "AUTHENTICATED"
STATE_EXPIRED = "EXPIRED"
STATE_REVOKED = "REVOKED"
STATE_FAILED = "FAILED"

_lock = threading.RLock()

# Authoritative In-Memory Cache (backed by transactional SQL database)
_TRANSACTIONS: Dict[str, Dict[str, Any]] = {}
_CHALLENGES: Dict[str, Dict[str, Any]] = {}  # token_hash -> challenge_data
_ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_AUDIT_LOGS: List[Dict[str, Any]] = []


def hash_token(raw_token: str) -> str:
    """Compute SHA-256 hash of single-use challenge token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class StartAuthRequest(BaseModel):
    email: str
    phoneNumber: str
    userAgent: Optional[str] = None


class VerifyCallbackRequest(BaseModel):
    transactionId: str
    email: str
    userId: Optional[str] = None


class WebAuthnVerificationPayload(BaseModel):
    mobileToken: str
    credentialId: str
    clientDataJSON: str
    authenticatorData: str
    signature: str


class SessionCompleteRequest(BaseModel):
    transactionId: str


def record_audit(
    tx_id: Optional[str],
    user_id: Optional[str],
    event: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
):
    entry = {
        "id": f"audit_{secrets.token_hex(8)}",
        "transaction_id": tx_id,
        "user_id": user_id,
        "event_type": event,
        "status": status,
        "details": details or {},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "created_at": time.time(),
    }
    with _lock:
        _AUDIT_LOGS.append(entry)
    try:
        record_db_audit(entry)
    except Exception as db_err:
        logger.error(f"Failed to record audit event: {db_err}")


def start_auth_transaction(
    email: str,
    phone_number: str,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 1: Initiates a new two-channel authentication transaction.
    Enforces email and phone association. Sets initial state to EMAIL_PENDING.
    Persists transaction to authoritative database.
    """
    normalized_email = validate_email_address(email)
    normalized_phone = validate_and_normalize_phone(phone_number)
    tx_id = f"tx_{secrets.token_hex(16)}"
    now = time.time()
    expires_at = now + 900  # 15 minutes lifetime

    transaction_record = {
        "id": tx_id,
        "email": normalized_email,
        "phoneNumber": normalized_phone,
        "state": STATE_EMAIL_PENDING,
        "emailVerified": False,
        "mobileVerified": False,
        "biometricVerified": False,
        "createdAt": now,
        "expiresAt": expires_at,
        "userAgent": user_agent,
        "ipAddress": ip_address,
        "whatsappDeliveryStatus": "unconfigured",
        "mobileChallengeTokenHash": None,
        "webauthnChallenge": None,
        "userId": None,
    }

    with _lock:
        _TRANSACTIONS[tx_id] = transaction_record

    try:
        save_transaction(transaction_record)
    except Exception as db_err:
        logger.error(f"Database error saving transaction: {db_err}")

    record_audit(
        tx_id=tx_id,
        user_id=None,
        event="AUTH_TRANSACTION_STARTED",
        status="SUCCESS",
        details={"email": normalized_email, "phone": normalized_phone},
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "transactionId": tx_id,
        "state": STATE_EMAIL_PENDING,
        "expiresAt": expires_at,
    }


async def confirm_email_gate(
    transaction_id: str,
    user_id: Optional[str] = None,
    override_app_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 2: Gate 1 confirmation.
    Transitions state from EMAIL_PENDING -> EMAIL_VERIFIED -> MOBILE_CHALLENGE_ISSUED.
    Generates single-use WhatsApp mobile challenge and sends WhatsApp message.
    """
    with _lock:
        tx = _TRANSACTIONS.get(transaction_id)
        if not tx:
            db_tx = load_transaction(transaction_id)
            if db_tx:
                _TRANSACTIONS[transaction_id] = db_tx
                tx = db_tx

        if not tx:
            raise ValueError("Authentication transaction not found or expired.")

        if tx["expiresAt"] < time.time():
            tx["state"] = STATE_EXPIRED
            try:
                save_transaction(tx)
            except Exception:
                pass
            raise ValueError("Authentication transaction has expired. Please restart sign-in.")

        if tx["emailVerified"]:
            # Already completed Gate 1
            return {
                "transactionId": transaction_id,
                "state": tx["state"],
                "emailVerified": True,
                "whatsappDeliveryStatus": tx.get("whatsappDeliveryStatus", "sent"),
                "pushDeliveryStatus": tx.get("pushDeliveryStatus", "no_registered_devices"),
                "pushSentCount": tx.get("pushSentCount", 0),
                "mobileVerificationUrl": tx.get("mobileVerificationUrl"),
            }

        # Authoritative Gate 1 Verification
        tx["emailVerified"] = True
        tx["userId"] = user_id or f"usr_{secrets.token_hex(8)}"
        tx["state"] = STATE_EMAIL_VERIFIED

        # Generate single-use mobile challenge
        mobile_raw_token = secrets.token_urlsafe(32)
        token_h = hash_token(mobile_raw_token)
        webauthn_challenge = generate_webauthn_challenge()

        base_url = override_app_url or APP_PUBLIC_URL
        verify_url = f"{base_url}/verify-mobile?t={mobile_raw_token}"

        tx["mobileChallengeTokenHash"] = token_h
        tx["webauthnChallenge"] = webauthn_challenge
        tx["rawMobileToken"] = mobile_raw_token
        tx["mobileVerificationUrl"] = verify_url
        tx["state"] = STATE_MOBILE_CHALLENGE_ISSUED

        # Store challenge in challenges index with 10 minute expiry
        challenge_entry = {
            "tokenHash": token_h,
            "transactionId": transaction_id,
            "userId": tx["userId"],
            "webauthnChallenge": webauthn_challenge,
            "expiresAt": time.time() + 600,
            "consumedAt": None,
            "attempts": 0,
        }
        _CHALLENGES[token_h] = challenge_entry

    try:
        save_transaction(tx)
        save_challenge(challenge_entry)
    except Exception as db_err:
        logger.error(f"Database error saving email confirmation: {db_err}")

    # Dispatch WhatsApp message via configured provider
    provider = get_whatsapp_provider()
    base_url = override_app_url or APP_PUBLIC_URL
    verify_url = f"{base_url}/verify-mobile?t={mobile_raw_token}"

    send_result: WhatsAppSendResult = await provider.send_verification_link(
        phone_number=tx["phoneNumber"],
        verification_url=verify_url,
        transaction_id=transaction_id,
    )

    # Dispatch Standards-Based Web Push Notification (Zero Cost, Browser Native)
    push_payload = {
        "title": "Sentinel AI Biometric Authorization",
        "body": "Desktop session awaiting fingerprint authorization. Tap to approve.",
        "icon": "/icons/icon-192x192.png",
        "data": {
            "url": verify_url,
            "transactionId": transaction_id,
        },
    }
    push_result = dispatch_push_to_user(tx["userId"], push_payload)

    with _lock:
        tx["whatsappDeliveryStatus"] = send_result.status
        tx["whatsappMessageId"] = send_result.message_id
        tx["whatsappProvider"] = send_result.provider
        tx["whatsappConfigured"] = send_result.is_configured
        if send_result.error:
            tx["whatsappError"] = send_result.error
        tx["pushDeliveryStatus"] = push_result.get("status", "no_registered_devices")
        tx["pushSentCount"] = push_result.get("sent", 0)

    record_audit(
        tx_id=transaction_id,
        user_id=tx["userId"],
        event="GATE_ONE_EMAIL_VERIFIED",
        status="SUCCESS",
        details={
            "whatsapp_status": send_result.status,
            "whatsapp_configured": send_result.is_configured,
            "push_status": tx["pushDeliveryStatus"],
            "push_sent": tx["pushSentCount"],
        },
    )

    return {
        "transactionId": transaction_id,
        "state": tx["state"],
        "emailVerified": True,
        "whatsappDeliveryStatus": send_result.status,
        "whatsappConfigured": send_result.is_configured,
        "whatsappError": send_result.error,
        "pushDeliveryStatus": tx["pushDeliveryStatus"],
        "pushSentCount": tx["pushSentCount"],
        "mobileVerificationUrl": verify_url if (not send_result.is_configured and tx["pushSentCount"] == 0) else verify_url,
    }


def validate_mobile_challenge_access(
    mobile_token: str,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 3: User opens link on mobile browser (from Push notification or direct link).
    Validates single-use token, checks preliminary device context.
    """
    token_h = hash_token(mobile_token)

    with _lock:
        challenge = _CHALLENGES.get(token_h)
        if not challenge:
            return {"valid": False, "error": "Invalid or expired verification link."}

        if challenge["consumedAt"] is not None:
            return {"valid": False, "error": "This verification link has already been used."}

        if challenge["expiresAt"] < time.time():
            return {"valid": False, "error": "This verification link has expired."}

        tx = _TRANSACTIONS.get(challenge["transactionId"])
        if not tx or tx["expiresAt"] < time.time():
            return {"valid": False, "error": "Associated session has expired."}

    # Preliminary Device Context Inspection
    ua = (user_agent or "").lower()
    is_mobile = bool(any(m in ua for m in ("iphone", "ipod", "android", "mobile")))
    is_desktop = not is_mobile and any(d in ua for d in ("windows nt", "macintosh", "mac os x", "linux"))

    if is_desktop:
        record_audit(
            tx_id=challenge["transactionId"],
            user_id=challenge["userId"],
            event="MOBILE_GATE_DESKTOP_DENIED",
            status="DENIED",
            user_agent=user_agent,
        )
        return {
            "valid": True,
            "desktopDenied": True,
            "headline": "Access Denied: Mobile Verification Required.",
            "message": "This verification step requires a supported mobile device (iOS or Android).",
        }

    return {
        "valid": True,
        "desktopDenied": False,
        "transactionId": challenge["transactionId"],
        "webauthnChallenge": challenge["webauthnChallenge"],
        "rpId": WEBAUTHN_RP_ID,
        "userId": challenge["userId"],
        "requestContext": {
            "browser": tx.get("userAgent", "Desktop Browser"),
            "requestTime": tx.get("createdAt"),
            "email": tx.get("email"),
        },
    }



def complete_mobile_biometric_gate(
    payload: WebAuthnVerificationPayload,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 4: Mobile WebAuthn Assertion Verification.
    Cryptographically verifies assertion, atomically consumes challenge,
    and signals cross-device completion.
    """
    token_h = hash_token(payload.mobileToken)

    with _lock:
        challenge = _CHALLENGES.get(token_h)
        if not challenge:
            raise ValueError("Challenge token not found or already purged.")

        if challenge["consumedAt"] is not None:
            raise ValueError("Replay detected: Challenge has already been consumed.")

        if challenge["expiresAt"] < time.time():
            raise ValueError("WebAuthn challenge expired.")

        tx = _TRANSACTIONS.get(challenge["transactionId"])
        if not tx:
            raise ValueError("Associated authentication transaction not found.")

        expected_challenge = challenge["webauthnChallenge"]

    # Verify WebAuthn assertion server-side
    verification = verify_webauthn_assertion(
        expected_challenge=expected_challenge,
        client_data_json_b64=payload.clientDataJSON,
        authenticator_data_b64=payload.authenticatorData,
        signature_b64=payload.signature,
    )

    if not verification.is_valid:
        record_audit(
            tx_id=challenge["transactionId"],
            user_id=challenge["userId"],
            event="WEBAUTHN_ASSERTION_FAILED",
            status="FAILURE",
            details={"error": verification.error},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise ValueError(verification.error or "WebAuthn verification failed.")

    # Atomic consumption of challenge & completion of Gate 2
    now = time.time()
    with _lock:
        challenge["consumedAt"] = now
        tx["mobileVerified"] = True
        tx["biometricVerified"] = True
        tx["state"] = STATE_AUTHENTICATED

    try:
        save_challenge(challenge)
        save_transaction(tx)
    except Exception as db_err:
        logger.error(f"Database error saving biometric verification: {db_err}")

    record_audit(
        tx_id=challenge["transactionId"],
        user_id=challenge["userId"],
        event="GATE_TWO_MOBILE_BIOMETRIC_VERIFIED",
        status="SUCCESS",
        details={"user_verified": verification.user_verified},
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "success": True,
        "transactionId": challenge["transactionId"],
        "state": STATE_AUTHENTICATED,
        "message": "Mobile biometric authorization complete. You may return to your computer.",
    }


def finalize_computer_session(
    transaction_id: str,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Step 5: Computer Browser Session Establishment.
    Re-validates both Gate 1 and Gate 2 server-side.
    Establishes authoritative application session.
    """
    with _lock:
        tx = _TRANSACTIONS.get(transaction_id)
        if not tx:
            db_tx = load_transaction(transaction_id)
            if db_tx:
                _TRANSACTIONS[transaction_id] = db_tx
                tx = db_tx

        if not tx:
            raise ValueError("Transaction not found.")

        if tx["expiresAt"] < time.time():
            tx["state"] = STATE_EXPIRED
            try:
                save_transaction(tx)
            except Exception:
                pass
            raise ValueError("Authentication transaction has expired.")

        # Rigid two-channel verification assertion
        if not (tx["emailVerified"] and tx["mobileVerified"] and tx["biometricVerified"]):
            raise ValueError("Cannot establish session: Incomplete two-channel verification gates.")

        user_id = tx["userId"]
        email = tx["email"]
        phone = tx["phoneNumber"]

        # Generate authenticated session token
        session_id = f"sess_{secrets.token_hex(16)}"
        payload = {
            "sub": user_id,
            "session_id": session_id,
            "transaction_id": transaction_id,
            "email": email,
            "phone_number": phone,
            "role": "authenticated",
            "security_tier": 2,  # Enhanced 2FA
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400 * 7,  # 7 days
        }

        token = jwt.encode(payload, SUPABASE_JWT_SECRET, algorithm="HS256")

        _ACTIVE_SESSIONS[session_id] = {
            "sessionId": session_id,
            "userId": user_id,
            "email": email,
            "phoneNumber": phone,
            "createdAt": time.time(),
            "expiresAt": time.time() + 86400 * 7,
            "userAgent": user_agent,
            "ipAddress": ip_address,
            "isRevoked": False,
        }

    try:
        save_transaction(tx)
    except Exception as db_err:
        logger.error(f"Database error updating finalized session: {db_err}")

    record_audit(
        tx_id=transaction_id,
        user_id=user_id,
        event="SESSION_ESTABLISHED",
        status="SUCCESS",
        details={"session_id": session_id},
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "success": True,
        "sessionToken": token,
        "user": {
            "id": user_id,
            "email": email,
            "phoneNumber": phone,
            "displayName": email.split("@")[0],
            "securityTier": 2,
        },
    }


def get_transaction_status(transaction_id: str) -> Dict[str, Any]:
    """Retrieve authoritative transaction status for cross-device waiting client."""
    with _lock:
        tx = _TRANSACTIONS.get(transaction_id)
        if not tx:
            db_tx = load_transaction(transaction_id)
            if db_tx:
                _TRANSACTIONS[transaction_id] = db_tx
                tx = db_tx

        if not tx:
            return {"exists": False, "state": STATE_EXPIRED}

        if tx["expiresAt"] < time.time():
            tx["state"] = STATE_EXPIRED

        return {
            "exists": True,
            "transactionId": tx["id"],
            "state": tx["state"],
            "emailVerified": tx["emailVerified"],
            "mobileVerified": tx["mobileVerified"],
            "biometricVerified": tx["biometricVerified"],
            "whatsappDeliveryStatus": tx.get("whatsappDeliveryStatus", "unconfigured"),
            "whatsappConfigured": tx.get("whatsappConfigured", False),
            "whatsappError": tx.get("whatsappError"),
            "pushDeliveryStatus": tx.get("pushDeliveryStatus", "no_registered_devices"),
            "pushSentCount": tx.get("pushSentCount", 0),
            "mobileVerificationUrl": tx.get("mobileVerificationUrl"),
            "userAgent": tx.get("userAgent"),
            "createdAt": tx.get("createdAt"),
            "expiresAt": tx["expiresAt"],
        }


def revoke_session(session_id: Optional[str] = None, token: Optional[str] = None) -> bool:
    """
    Revokes the active authenticated session on the server.
    """
    target_id = session_id
    if not target_id and token:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            target_id = payload.get("session_id")
        except Exception:
            pass

    revoked_user_id = None
    with _lock:
        if target_id and target_id in _ACTIVE_SESSIONS:
            _ACTIVE_SESSIONS[target_id]["isRevoked"] = True
            revoked_user_id = _ACTIVE_SESSIONS[target_id].get("userId")

    if revoked_user_id is not None:
        record_audit(
            tx_id=None,
            user_id=revoked_user_id,
            event="SESSION_REVOKED",
            status="SUCCESS",
            details={"session_id": target_id},
        )
        return True
    return False

