"""
Sentinel AI PostgreSQL Persistence Layer for Supabase.
Implements the exact identical database interface as database.py.
Enforces strict tenant isolation, parameter sanitization, and Row-Level Security compatibility.
"""
import os
import re
import json
import time
import uuid
import secrets
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

logger = logging.getLogger("sentinel.postgres")

# PostgreSQL Driver Abstraction (psycopg v3 or psycopg2)
_driver = None
try:
    import psycopg
    from psycopg.rows import dict_row
    _driver = "psycopg"
except ImportError:
    try:
        import psycopg2
        import psycopg2.extras
        _driver = "psycopg2"
    except ImportError:
        _driver = None

def get_postgres_url() -> str:
    """Returns the configured PostgreSQL connection URL from environment variables."""
    return os.getenv("SENTINEL_STAGING_DATABASE_URL", os.getenv("SENTINEL_DATABASE_URL", os.getenv("DATABASE_URL", ""))).strip()


POSTGRES_URL = get_postgres_url()


def is_driver_available() -> bool:
    """Returns True if a supported PostgreSQL DB-API driver is installed."""
    return _driver is not None


def get_pg_connection(custom_url: Optional[str] = None):
    """
    Creates a thread-safe connection to PostgreSQL / Supabase.
    Enforces SSL mode 'require' for secure transport in production.
    """
    if not is_driver_available():
        raise RuntimeError(
            "No PostgreSQL driver installed. Install psycopg (v3) or psycopg2 to use PostgreSQL persistence."
        )
    conn_url = (custom_url or get_postgres_url()).strip()
    if not conn_url:
        raise ValueError("SENTINEL_DATABASE_URL or DATABASE_URL must be set.")

    # Clean connection URL for Supabase
    if "sslmode=" not in conn_url.lower():
        separator = "&" if "?" in conn_url else "?"
        conn_url = f"{conn_url}{separator}sslmode=require"

    if _driver == "psycopg":
        return psycopg.connect(conn_url, connect_timeout=10, row_factory=dict_row)
    else:
        conn = psycopg2.connect(conn_url, connect_timeout=10)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return conn


def _ts_to_dt(ts: Optional[float]) -> Optional[datetime]:
    """Converts unix timestamp float to timezone-aware UTC datetime."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return None


def _dt_to_ts(dt: Any) -> Optional[float]:
    """Converts datetime or timestamp string to unix timestamp float."""
    if dt is None:
        return None
    if isinstance(dt, (int, float)):
        return float(dt)
    if isinstance(dt, datetime):
        return dt.timestamp()
    try:
        # Parse ISO string
        clean = str(dt).replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        return time.time()


# ==============================================================================
# Transaction & Challenge Operations
# ==============================================================================

def save_transaction(tx_data: Dict[str, Any]) -> None:
    """Inserts or updates an authentication transaction record in auth_sessions."""
    now_dt = _ts_to_dt(time.time())
    expires_dt = _ts_to_dt(tx_data.get("expiresAt", tx_data.get("expires_at", time.time() + 900)))
    last_active_dt = _ts_to_dt(tx_data.get("lastActiveAt", tx_data.get("last_active_at", time.time())))
    revoked_dt = _ts_to_dt(tx_data.get("revokedAt", tx_data.get("revoked_at")))
    created_dt = _ts_to_dt(tx_data.get("createdAt", tx_data.get("created_at", time.time())))

    tx_id = tx_data.get("transactionId") or tx_data.get("transaction_id") or tx_data.get("id")
    user_id = tx_data.get("userId") or tx_data.get("user_id")
    email = tx_data.get("email")
    phone = tx_data.get("phoneNumber") or tx_data.get("phone_number")
    email_ver = bool(tx_data.get("emailVerified", tx_data.get("email_verified", False)))
    mobile_ver = bool(tx_data.get("mobileVerified", tx_data.get("mobile_verified", False)))
    bio_ver = bool(tx_data.get("biometricVerified", tx_data.get("biometric_verified", False)))
    bio_status = tx_data.get("biometricStatus", tx_data.get("biometric_status", "pending"))
    state = tx_data.get("state")
    user_agent = tx_data.get("userAgent", tx_data.get("user_agent"))
    ip_addr = tx_data.get("ipAddress", tx_data.get("ip_address"))
    is_revoked = bool(tx_data.get("isRevoked", tx_data.get("is_revoked", False)))
    mob_url = tx_data.get("mobileVerificationUrl", tx_data.get("mobile_verification_url"))

    query = """
    INSERT INTO public.auth_sessions (
        transaction_id, user_id, email, phone_number,
        email_verified, mobile_verified, biometric_verified,
        biometric_status, state, user_agent, ip_address,
        expires_at, last_active_at, revoked_at, is_revoked, created_at,
        mobile_verification_url
    ) VALUES (
        %s, %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s
    )
    ON CONFLICT(transaction_id) DO UPDATE SET
        user_id = COALESCE(EXCLUDED.user_id, public.auth_sessions.user_id),
        email = EXCLUDED.email,
        phone_number = EXCLUDED.phone_number,
        email_verified = EXCLUDED.email_verified,
        mobile_verified = EXCLUDED.mobile_verified,
        biometric_verified = EXCLUDED.biometric_verified,
        biometric_status = EXCLUDED.biometric_status,
        state = EXCLUDED.state,
        last_active_at = EXCLUDED.last_active_at,
        revoked_at = EXCLUDED.revoked_at,
        is_revoked = EXCLUDED.is_revoked,
        mobile_verification_url = EXCLUDED.mobile_verification_url;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            # Defensively check foreign key constraint: user_id must be a valid UUID that exists in user_profiles
            safe_user_id = None
            if user_id:
                try:
                    parsed_uuid = str(uuid.UUID(str(user_id)))
                    cur.execute("SELECT 1 FROM public.user_profiles WHERE user_id = %s LIMIT 1;", (parsed_uuid,))
                    if cur.fetchone():
                        safe_user_id = parsed_uuid
                except Exception:
                    safe_user_id = None

            params = (
                tx_id,
                safe_user_id,
                email,
                phone,
                email_ver,
                mobile_ver,
                bio_ver,
                bio_status,
                state,
                user_agent,
                ip_addr,
                expires_dt,
                last_active_dt,
                revoked_dt,
                is_revoked,
                created_dt,
                mob_url,
            )
            cur.execute(query, params)
        conn.commit()


def load_transaction(tx_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an authentication transaction from auth_sessions."""
    query = "SELECT * FROM public.auth_sessions WHERE transaction_id = %s LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (tx_id,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row["transaction_id"],
                "userId": str(row["user_id"]) if row.get("user_id") else None,
                "email": row["email"],
                "phoneNumber": row["phone_number"],
                "emailVerified": bool(row["email_verified"]),
                "mobileVerified": bool(row["mobile_verified"]),
                "biometricVerified": bool(row["biometric_verified"]),
                "biometricStatus": row["biometric_status"],
                "state": row["state"],
                "userAgent": row["user_agent"],
                "ipAddress": row["ip_address"],
                "expiresAt": _dt_to_ts(row["expires_at"]),
                "lastActiveAt": _dt_to_ts(row["last_active_at"]),
                "revokedAt": _dt_to_ts(row["revoked_at"]),
                "isRevoked": bool(row["is_revoked"]),
                "createdAt": _dt_to_ts(row["created_at"]),
                "mobileVerificationUrl": row.get("mobile_verification_url"),
            }


def save_challenge(challenge_data: Dict[str, Any]) -> None:
    """Inserts or updates an authentication challenge in auth_challenges."""
    expires_dt = _ts_to_dt(challenge_data.get("expiresAt", time.time() + 600))
    consumed_dt = _ts_to_dt(challenge_data.get("consumedAt"))
    created_dt = _ts_to_dt(challenge_data.get("createdAt", time.time()))

    raw_uid = challenge_data.get("userId") or challenge_data.get("user_id")
    safe_uid = None
    if raw_uid:
        try:
            safe_uid = str(uuid.UUID(str(raw_uid)))
        except Exception:
            safe_uid = None

    token_h = challenge_data.get("tokenHash")
    tx_id = challenge_data.get("transactionId")
    c_type = challenge_data.get("challengeType", "whatsapp_mobile_link")
    webauthn_c = challenge_data.get("webauthnChallenge")
    attempts = challenge_data.get("attempts", 0)
    max_attempts = challenge_data.get("maxAttempts", 3)

    query = """
    INSERT INTO public.auth_challenges (
        transaction_id, user_id, challenge_type,
        token_hash, webauthn_challenge, attempts, max_attempts,
        expires_at, consumed_at, created_at
    ) VALUES (
        %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s
    )
    ON CONFLICT(token_hash) DO UPDATE SET
        attempts = EXCLUDED.attempts,
        consumed_at = EXCLUDED.consumed_at,
        webauthn_challenge = COALESCE(EXCLUDED.webauthn_challenge, public.auth_challenges.webauthn_challenge);
    """
    params = (
        tx_id,
        safe_uid,
        c_type,
        token_h,
        webauthn_c,
        attempts,
        max_attempts,
        expires_dt,
        consumed_dt,
        created_dt,
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(query, params)
            except Exception as e:
                # If unique constraint on token_hash is not yet applied, fallback to manual update/insert
                if "no unique or exclusion constraint" in str(e).lower() and "token_hash" in str(e).lower():
                    conn.rollback()
                    cur.execute(
                        "SELECT id FROM public.auth_challenges WHERE token_hash = %s LIMIT 1;",
                        (token_h,),
                    )
                    existing = cur.fetchone()
                    if existing:
                        cur.execute(
                            """
                            UPDATE public.auth_challenges
                            SET attempts = %s, consumed_at = %s, webauthn_challenge = COALESCE(%s, webauthn_challenge)
                            WHERE token_hash = %s;
                            """,
                            (attempts, consumed_dt, webauthn_c, token_h),
                        )
                    else:
                        cur.execute(
                            """
                            INSERT INTO public.auth_challenges (
                                transaction_id, user_id, challenge_type,
                                token_hash, webauthn_challenge, attempts, max_attempts,
                                expires_at, consumed_at, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                            """,
                            params,
                        )
                else:
                    raise
        conn.commit()


def load_challenge(token_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieves an authentication challenge by token hash."""
    query = "SELECT * FROM public.auth_challenges WHERE token_hash = %s LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (token_hash,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": str(row["id"]),
                "transactionId": row["transaction_id"],
                "userId": str(row["user_id"]) if row.get("user_id") else None,
                "challengeType": row["challenge_type"],
                "tokenHash": row["token_hash"],
                "webauthnChallenge": row.get("webauthn_challenge"),
                "attempts": row["attempts"],
                "maxAttempts": row["max_attempts"],
                "expiresAt": _dt_to_ts(row["expires_at"]),
                "consumedAt": _dt_to_ts(row["consumed_at"]),
                "createdAt": _dt_to_ts(row["created_at"]),
            }


def record_db_audit(audit_entry: Optional[Dict[str, Any]] = None, **kwargs) -> None:
    """Records an immutable audit event in auth_audit_events."""
    entry = dict(audit_entry or {})
    entry.update(kwargs)
    created_dt = _ts_to_dt(entry.get("created_at", entry.get("createdAt", time.time())))
    details = entry.get("details", {})
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {}

    query = """
    INSERT INTO public.auth_audit_events (
        transaction_id, user_id, event_type,
        status, details, ip_address, user_agent, created_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
    """
    params = (
        entry.get("transaction_id", entry.get("transactionId")),
        entry.get("user_id", entry.get("userId")),
        entry.get("event_type", entry.get("eventType")),
        entry.get("status"),
        json.dumps(details),
        entry.get("ip_address", entry.get("ipAddress")),
        entry.get("user_agent", entry.get("userAgent")),
        created_dt,
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()


# ==============================================================================
# Web Push & Device Registration Operations
# ==============================================================================

def save_push_subscription(sub_data: Dict[str, Any]) -> None:
    """Inserts or updates a browser push subscription for a user."""
    now_dt = _ts_to_dt(time.time())
    query = """
    INSERT INTO public.push_subscriptions (
        user_id, endpoint, p256dh, auth, device_id, user_agent, created_at, updated_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT(endpoint) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        p256dh = EXCLUDED.p256dh,
        auth = EXCLUDED.auth,
        device_id = EXCLUDED.device_id,
        user_agent = EXCLUDED.user_agent,
        updated_at = EXCLUDED.updated_at;
    """
    params = (
        sub_data["user_id"],
        sub_data["endpoint"],
        sub_data["p256dh"],
        sub_data["auth"],
        sub_data.get("device_id"),
        sub_data.get("user_agent"),
        _ts_to_dt(sub_data.get("created_at", time.time())),
        now_dt,
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()


def get_push_subscriptions_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all active push subscriptions for a user (tenant-isolated)."""
    query = "SELECT * FROM public.push_subscriptions WHERE user_id = %s;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "userId": str(r["user_id"]),
                    "endpoint": r["endpoint"],
                    "p256dh": r["p256dh"],
                    "auth": r["auth"],
                    "deviceId": r["device_id"],
                    "userAgent": r["user_agent"],
                    "createdAt": _dt_to_ts(r["created_at"]),
                    "updatedAt": _dt_to_ts(r["updated_at"]),
                }
                for r in rows
            ]


def delete_push_subscription(endpoint: str) -> None:
    """Deletes an invalid or expired push subscription."""
    query = "DELETE FROM public.push_subscriptions WHERE endpoint = %s;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (endpoint,))
        conn.commit()


def register_device(device_data: Dict[str, Any]) -> None:
    """Registers or updates a trusted mobile device."""
    now_dt = _ts_to_dt(time.time())
    query = """
    INSERT INTO public.registered_devices (
        device_id, user_id, device_name, device_type, platform,
        credential_id, public_key, sign_count, is_active, last_used_at, created_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT(device_id) DO UPDATE SET
        device_name = EXCLUDED.device_name,
        platform = EXCLUDED.platform,
        credential_id = EXCLUDED.credential_id,
        public_key = EXCLUDED.public_key,
        sign_count = EXCLUDED.sign_count,
        is_active = EXCLUDED.is_active,
        last_used_at = EXCLUDED.last_used_at;
    """
    params = (
        device_data["device_id"],
        device_data["user_id"],
        device_data.get("device_name", "Mobile Device"),
        device_data.get("device_type", "mobile"),
        device_data.get("platform", "Unknown"),
        device_data.get("credential_id"),
        device_data.get("public_key"),
        device_data.get("sign_count", 0),
        bool(device_data.get("is_active", True)),
        _ts_to_dt(device_data.get("last_used_at", time.time())),
        _ts_to_dt(device_data.get("created_at", time.time())),
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()


def get_devices_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all registered devices for a user."""
    query = "SELECT * FROM public.registered_devices WHERE user_id = %s AND is_active = TRUE;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "deviceId": r["device_id"],
                    "userId": str(r["user_id"]),
                    "deviceName": r["device_name"],
                    "deviceType": r["device_type"],
                    "platform": r["platform"],
                    "credentialId": r["credential_id"],
                    "publicKey": r["public_key"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": _dt_to_ts(r["last_used_at"]),
                    "createdAt": _dt_to_ts(r["created_at"]),
                }
                for r in rows
            ]


def get_active_passkeys_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all active WebAuthn passkey credentials for a user."""
    query = """
    SELECT * FROM public.registered_devices
    WHERE user_id = %s AND is_active = TRUE AND credential_id IS NOT NULL AND public_key IS NOT NULL
    ORDER BY created_at DESC;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "deviceId": r["device_id"],
                    "userId": str(r["user_id"]),
                    "deviceName": r["device_name"],
                    "deviceType": r["device_type"],
                    "platform": r["platform"],
                    "credentialId": r["credential_id"],
                    "publicKey": r["public_key"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": _dt_to_ts(r["last_used_at"]),
                    "createdAt": _dt_to_ts(r["created_at"]),
                }
                for r in rows
            ]


def get_device_by_credential_id(credential_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active registered device by its WebAuthn credential ID."""
    query = "SELECT * FROM public.registered_devices WHERE credential_id = %s AND is_active = TRUE LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (credential_id,))
            r = cur.fetchone()
            if not r:
                return None
            return {
                "id": str(r["id"]),
                "deviceId": r["device_id"],
                "userId": str(r["user_id"]),
                "deviceName": r["device_name"],
                "deviceType": r["device_type"],
                "platform": r["platform"],
                "credentialId": r["credential_id"],
                "publicKey": r["public_key"],
                "signCount": r["sign_count"],
                "isActive": bool(r["is_active"]),
                "lastUsedAt": _dt_to_ts(r["last_used_at"]),
                "createdAt": _dt_to_ts(r["created_at"]),
            }


def save_verified_passkey_device(
    user_id: str,
    device_id: Optional[str],
    credential_id: str,
    public_key: str,
    sign_count: int = 0,
    device_name: str = "Mobile Platform Authenticator",
    platform: str = "Mobile",
    device_type: str = "mobile",
    **kwargs,
) -> Dict[str, Any]:
    """Saves a cryptographically verified WebAuthn credential to registered_devices."""
    final_device_id = device_id or f"dev_{secrets.token_hex(8)}"
    now_dt = _ts_to_dt(time.time())

    # Handle cases where device_name might be passed as positional sign_count
    if isinstance(sign_count, str):
        device_name = sign_count
        sign_count = 0

    actual_device_type = device_type or kwargs.get("deviceType", "mobile")

    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            # Check if device_id exists
            cur.execute("SELECT id FROM public.registered_devices WHERE device_id = %s LIMIT 1;", (final_device_id,))
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    UPDATE public.registered_devices
                    SET user_id = %s, credential_id = %s, public_key = %s, sign_count = %s,
                        is_active = TRUE, last_used_at = %s, device_name = %s, platform = %s,
                        device_type = %s
                    WHERE device_id = %s;
                    """,
                    (user_id, credential_id, public_key, sign_count, now_dt, device_name, platform, actual_device_type, final_device_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO public.registered_devices (
                        device_id, user_id, device_name, device_type, platform,
                        credential_id, public_key, sign_count, is_active, last_used_at, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s, %s)
                    ON CONFLICT(credential_id) DO UPDATE SET
                        device_id = EXCLUDED.device_id,
                        user_id = EXCLUDED.user_id,
                        public_key = EXCLUDED.public_key,
                        sign_count = EXCLUDED.sign_count,
                        is_active = TRUE,
                        last_used_at = EXCLUDED.last_used_at;
                    """,
                    (
                        final_device_id,
                        user_id,
                        device_name,
                        actual_device_type,
                        platform,
                        credential_id,
                        public_key,
                        sign_count,
                        now_dt,
                        now_dt,
                    ),
                )
        conn.commit()

    return {
        "deviceId": final_device_id,
        "credentialId": credential_id,
        "userId": user_id,
        "signCount": sign_count,
    }


def update_device_sign_count(credential_id: str, new_sign_count: int) -> None:
    """Updates the signature counter and last_used_at timestamp for a registered passkey."""
    now_dt = _ts_to_dt(time.time())
    query = """
    UPDATE public.registered_devices
    SET sign_count = %s, last_used_at = %s
    WHERE credential_id = %s;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (new_sign_count, now_dt, credential_id))
        conn.commit()


# ==============================================================================
# User Profile Operations
# ==============================================================================

def get_user_profile_by_user_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full user profile by user_id from PostgreSQL."""
    query = "SELECT * FROM public.user_profiles WHERE user_id = %s LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            r = cur.fetchone()
            if not r:
                return None
            concerns = r.get("concerns") or []
            if isinstance(concerns, str):
                try:
                    concerns = json.loads(concerns)
                except Exception:
                    concerns = []

            return {
                "userId": str(r["user_id"]),
                "email": r["email"],
                "phoneNumber": r["phone_number"],
                "phoneVerified": bool(r["phone_verified"]),
                "displayName": r["display_name"] or "",
                "fullName": r.get("full_name") or "",
                "username": r.get("username") or "",
                "country": r.get("country") or "",
                "profilePictureUrl": r.get("profile_picture_url") or "",
                "dateOfBirth": r.get("date_of_birth") or "",
                "preferredLanguage": r.get("preferred_language") or "en",
                "timeZone": r.get("time_zone") or "UTC",
                "goal": r["goal"] or "",
                "concerns": concerns,
                "experience": r["experience"] or "",
                "onboardingCompleted": bool(r["onboarding_completed"]),
                "securityTier": r.get("security_tier", 1),
                "accountStatus": r.get("account_status", "active"),
                "createdAt": _dt_to_ts(r["created_at"]),
                "updatedAt": _dt_to_ts(r["updated_at"]),
            }


def get_user_profile_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by normalized email address."""
    query = "SELECT user_id FROM public.user_profiles WHERE LOWER(email) = LOWER(%s) LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (email.strip(),))
            r = cur.fetchone()
            if not r:
                return None
            return get_user_profile_by_user_id(str(r["user_id"]))


def check_username_available(username: str, exclude_user_id: Optional[str] = None) -> bool:
    """Checks if a username is valid and available (unique across all accounts)."""
    clean_username = username.strip().lower()
    if not clean_username or len(clean_username) < 3 or len(clean_username) > 30:
        return False
    if not re.match(r"^[a-zA-Z0-9_]+$", clean_username):
        return False

    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            if exclude_user_id:
                cur.execute(
                    "SELECT id FROM public.user_profiles WHERE LOWER(username) = %s AND user_id::text != %s LIMIT 1;",
                    (clean_username, str(exclude_user_id)),
                )
            else:
                cur.execute(
                    "SELECT id FROM public.user_profiles WHERE LOWER(username) = %s LIMIT 1;",
                    (clean_username,),
                )
            return cur.fetchone() is None


def save_or_update_user_profile(user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    """Upserts full user profile into user_profiles in PostgreSQL."""
    now_dt = _ts_to_dt(time.time())
    existing = get_user_profile_by_user_id(user_id)

    email = profile_data.get("email") or (existing.get("email") if existing else "")
    phone = profile_data.get("phoneNumber") or (existing.get("phoneNumber") if existing else "")
    display_name = profile_data.get("displayName") or (existing.get("displayName") if existing else "")
    full_name = profile_data.get("fullName") or (existing.get("fullName") if existing else "")
    username = profile_data.get("username") or (existing.get("username") if existing else "")
    country = profile_data.get("country") or (existing.get("country") if existing else "")
    profile_picture_url = profile_data.get("profilePictureUrl") or (existing.get("profilePictureUrl") if existing else "")
    date_of_birth = profile_data.get("dateOfBirth") or (existing.get("dateOfBirth") if existing else "")
    preferred_language = profile_data.get("preferredLanguage") or (existing.get("preferredLanguage") if existing else "en")
    time_zone = profile_data.get("timeZone") or (existing.get("timeZone") if existing else "UTC")
    goal = profile_data.get("goal") or (existing.get("goal") if existing else "")
    experience = profile_data.get("experience") or (existing.get("experience") if existing else "")

    concerns = profile_data.get("concerns") if "concerns" in profile_data else (existing.get("concerns") if existing else [])
    if not isinstance(concerns, list):
        concerns = []

    onboarding_completed = bool(profile_data.get("onboardingCompleted", False) or (existing and existing.get("onboardingCompleted")))
    raw_tier = profile_data.get("securityTier", profile_data.get("security_tier"))
    security_tier = int(raw_tier) if raw_tier is not None else (existing.get("securityTier", 1) if existing else 1)

    query = """
    INSERT INTO public.user_profiles (
        user_id, email, phone_number, display_name, full_name, username,
        country, profile_picture_url, date_of_birth, preferred_language, time_zone,
        goal, concerns, experience, onboarding_completed, security_tier, created_at, updated_at
    ) VALUES (
        %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s
    )
    ON CONFLICT(user_id) DO UPDATE SET
        email = COALESCE(NULLIF(EXCLUDED.email, ''), public.user_profiles.email),
        phone_number = COALESCE(NULLIF(EXCLUDED.phone_number, ''), public.user_profiles.phone_number),
        display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), public.user_profiles.display_name),
        full_name = COALESCE(NULLIF(EXCLUDED.full_name, ''), public.user_profiles.full_name),
        username = COALESCE(NULLIF(EXCLUDED.username, ''), public.user_profiles.username),
        country = COALESCE(NULLIF(EXCLUDED.country, ''), public.user_profiles.country),
        profile_picture_url = COALESCE(NULLIF(EXCLUDED.profile_picture_url, ''), public.user_profiles.profile_picture_url),
        date_of_birth = COALESCE(NULLIF(EXCLUDED.date_of_birth, ''), public.user_profiles.date_of_birth),
        preferred_language = COALESCE(NULLIF(EXCLUDED.preferred_language, ''), public.user_profiles.preferred_language),
        time_zone = COALESCE(NULLIF(EXCLUDED.time_zone, ''), public.user_profiles.time_zone),
        goal = COALESCE(NULLIF(EXCLUDED.goal, ''), public.user_profiles.goal),
        concerns = EXCLUDED.concerns,
        experience = COALESCE(NULLIF(EXCLUDED.experience, ''), public.user_profiles.experience),
        onboarding_completed = (public.user_profiles.onboarding_completed OR EXCLUDED.onboarding_completed),
        security_tier = EXCLUDED.security_tier,
        updated_at = EXCLUDED.updated_at;
    """
    params = (
        user_id,
        email,
        phone,
        display_name,
        full_name,
        username,
        country,
        profile_picture_url,
        date_of_birth,
        preferred_language,
        time_zone,
        goal,
        concerns,
        experience,
        onboarding_completed,
        security_tier,
        now_dt,
        now_dt,
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()

    return get_user_profile_by_user_id(user_id) or {}


# ==============================================================================
# Security Dashboard & Session Revocation Operations
# ==============================================================================

def get_user_registered_passkeys(user_id: str) -> List[Dict[str, Any]]:
    """Returns registered passkeys for security dashboard, redacting private keys."""
    query = """
    SELECT id, device_id, device_name, platform, credential_id, sign_count,
           is_active, last_used_at, created_at, revoked_at
    FROM public.registered_devices
    WHERE user_id = %s AND credential_id IS NOT NULL
    ORDER BY created_at DESC;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
            return [
                {
                    "id": str(r["id"]),
                    "deviceId": r["device_id"],
                    "deviceName": r["device_name"] or "Platform Passkey",
                    "platform": r["platform"] or "Mobile",
                    "credentialIdPreview": r["credential_id"][:12] + "..." if r.get("credential_id") else "",
                    "credentialId": r["credential_id"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": _dt_to_ts(r["last_used_at"]),
                    "createdAt": _dt_to_ts(r["created_at"]),
                    "revokedAt": _dt_to_ts(r["revoked_at"]),
                }
                for r in rows
            ]


def revoke_passkey_credential(user_id: str, credential_id: str) -> bool:
    """Revokes a specific WebAuthn passkey credential for a user."""
    now_dt = _ts_to_dt(time.time())
    query = """
    UPDATE public.registered_devices
    SET is_active = FALSE, revoked_at = %s
    WHERE user_id = %s AND credential_id = %s;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (now_dt, user_id, credential_id))
            affected = cur.rowcount
        conn.commit()
    return affected > 0


def get_user_trusted_devices(user_id: str) -> List[Dict[str, Any]]:
    """Returns trusted devices list for user."""
    query = """
    SELECT id, device_id, device_name, device_type, platform,
           is_active, last_used_at, created_at, revoked_at,
           credential_id
    FROM public.registered_devices
    WHERE user_id = %s
    ORDER BY created_at DESC;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()

            cur.execute("SELECT device_id FROM public.push_subscriptions WHERE user_id = %s;", (user_id,))
            push_rows = cur.fetchall()
            push_device_ids = {p["device_id"] for p in push_rows if p.get("device_id")}

            return [
                {
                    "id": str(r["id"]),
                    "deviceId": r["device_id"],
                    "deviceName": r["device_name"] or "Mobile Device",
                    "deviceType": r["device_type"] or "mobile",
                    "platform": r["platform"] or "Mobile",
                    "hasPasskey": bool(r["credential_id"]),
                    "hasWebPush": r["device_id"] in push_device_ids,
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": _dt_to_ts(r["last_used_at"]),
                    "createdAt": _dt_to_ts(r["created_at"]),
                    "revokedAt": _dt_to_ts(r["revoked_at"]),
                }
                for r in rows
            ]


def revoke_trusted_device(user_id: str, device_id: str) -> bool:
    """Revokes a trusted device and its associated passkeys."""
    now_dt = _ts_to_dt(time.time())
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.registered_devices
                SET is_active = FALSE, revoked_at = %s
                WHERE user_id = %s AND device_id = %s;
                """,
                (now_dt, user_id, device_id),
            )
            affected = cur.rowcount
            cur.execute(
                "DELETE FROM public.push_subscriptions WHERE user_id = %s AND device_id = %s;",
                (user_id, device_id),
            )
        conn.commit()
    return affected > 0


def get_user_audit_events(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves real audit events for the authenticated user from PostgreSQL."""
    query = """
    SELECT id, transaction_id, event_type, status, details, ip_address, user_agent, created_at
    FROM public.auth_audit_events
    WHERE user_id = %s
    ORDER BY created_at DESC
    LIMIT %s;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id, limit))
            rows = cur.fetchall()
            events = []
            for r in rows:
                details = r.get("details", {})
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except Exception:
                        details = {}
                events.append({
                    "id": str(r["id"]),
                    "transactionId": r["transaction_id"],
                    "eventType": r["event_type"],
                    "status": r["status"],
                    "details": details,
                    "ipAddress": r["ip_address"] or "Direct Connection",
                    "userAgent": r["user_agent"] or "Secure Browser",
                    "createdAt": _dt_to_ts(r["created_at"]),
                })
            return events


def get_user_active_sessions(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves active sessions for the user from auth_sessions."""
    now_dt = _ts_to_dt(time.time())
    query = """
    SELECT id, transaction_id, email, user_agent, ip_address,
           created_at, last_active_at, expires_at, is_revoked, state
    FROM public.auth_sessions
    WHERE user_id = %s AND is_revoked = FALSE AND expires_at > %s
    ORDER BY last_active_at DESC;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id, now_dt))
            rows = cur.fetchall()
            return [
                {
                    "sessionId": r["transaction_id"],
                    "transactionId": r["transaction_id"],
                    "email": r["email"],
                    "userAgent": r["user_agent"] or "Desktop Web Browser",
                    "ipAddress": r["ip_address"] or "Active Session",
                    "createdAt": _dt_to_ts(r["created_at"]),
                    "lastActiveAt": _dt_to_ts(r["last_active_at"]),
                    "expiresAt": _dt_to_ts(r["expires_at"]),
                    "state": r["state"],
                }
                for r in rows
            ]


def revoke_user_session(user_id: str, session_id: str) -> bool:
    """Revokes a specific session for a user."""
    now_dt = _ts_to_dt(time.time())
    query = """
    UPDATE public.auth_sessions
    SET is_revoked = TRUE, revoked_at = %s, state = 'REVOKED'
    WHERE user_id = %s AND (transaction_id = %s OR id::text = %s);
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (now_dt, user_id, session_id, session_id))
            affected = cur.rowcount
        conn.commit()
    return affected > 0


def revoke_all_other_sessions(user_id: str, current_session_id: str) -> int:
    """Revokes all active sessions for a user except the current session."""
    now_dt = _ts_to_dt(time.time())
    query = """
    UPDATE public.auth_sessions
    SET is_revoked = TRUE, revoked_at = %s, state = 'REVOKED'
    WHERE user_id = %s AND transaction_id != %s AND id::text != %s AND is_revoked = FALSE;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (now_dt, user_id, current_session_id, current_session_id))
            affected = cur.rowcount
        conn.commit()
    return affected


def get_security_preferences(user_id: str) -> Dict[str, bool]:
    """Retrieves security notification preferences for user."""
    query = """
    SELECT notify_new_device, notify_new_passkey, notify_failed_login, notify_security_changes
    FROM public.user_profiles WHERE user_id = %s LIMIT 1;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            r = cur.fetchone()
            if not r:
                return {
                    "notifyNewDevice": True,
                    "notifyNewPasskey": True,
                    "notifyFailedLogin": True,
                    "notifySecurityChanges": True,
                }
            return {
                "notifyNewDevice": bool(r.get("notify_new_device", True)),
                "notifyNewPasskey": bool(r.get("notify_new_passkey", True)),
                "notifyFailedLogin": bool(r.get("notify_failed_login", True)),
                "notifySecurityChanges": bool(r.get("notify_security_changes", True)),
            }


def update_security_preferences(user_id: str, prefs: Dict[str, bool]) -> Dict[str, bool]:
    """Updates security notification preferences for user."""
    now_dt = _ts_to_dt(time.time())
    current = get_security_preferences(user_id)
    merged = {**current, **prefs}

    query = """
    INSERT INTO public.user_profiles (
        user_id, email, phone_number, display_name, full_name, username,
        country, profile_picture_url, date_of_birth, preferred_language, time_zone,
        goal, concerns, experience, onboarding_completed, created_at, updated_at,
        notify_new_device, notify_new_passkey, notify_failed_login, notify_security_changes
    ) VALUES (
        %s, '', '', '', '', '',
        '', '', '', 'en', 'UTC',
        '', '{}', '', FALSE, %s, %s,
        %s, %s, %s, %s
    )
    ON CONFLICT(user_id) DO UPDATE SET
        notify_new_device = EXCLUDED.notify_new_device,
        notify_new_passkey = EXCLUDED.notify_new_passkey,
        notify_failed_login = EXCLUDED.notify_failed_login,
        notify_security_changes = EXCLUDED.notify_security_changes,
        updated_at = EXCLUDED.updated_at;
    """
    params = (
        user_id,
        now_dt,
        now_dt,
        bool(merged.get("notifyNewDevice", True)),
        bool(merged.get("notifyNewPasskey", True)),
        bool(merged.get("notifyFailedLogin", True)),
        bool(merged.get("notifySecurityChanges", True)),
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()

    return get_security_preferences(user_id)


def get_user_by_phone(phone_number: str) -> Optional[Dict[str, Any]]:
    """Retrieves verified user identity by normalized phone number."""
    if not phone_number:
        return None
    clean_digits = re.sub(r"[^\d+]", "", phone_number.strip())

    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            # 1. Check user_profiles
            cur.execute(
                """
                SELECT user_id, email, phone_number, full_name, display_name
                FROM public.user_profiles
                WHERE REPLACE(REPLACE(REPLACE(REPLACE(phone_number, ' ', ''), '-', ''), '(', ''), ')', '') = %s
                   OR phone_number = %s
                LIMIT 1;
                """,
                (clean_digits, phone_number.strip()),
            )
            r = cur.fetchone()
            if r:
                return {
                    "userId": str(r["user_id"]),
                    "email": r["email"],
                    "phoneNumber": r["phone_number"],
                    "displayName": r["display_name"] or r["full_name"] or r["email"].split("@")[0],
                }

            # 2. Fallback to auth_sessions where phone was verified
            cur.execute(
                """
                SELECT user_id, email, phone_number
                FROM public.auth_sessions
                WHERE (REPLACE(REPLACE(REPLACE(REPLACE(phone_number, ' ', ''), '-', ''), '(', ''), ')', '') = %s
                   OR phone_number = %s)
                  AND user_id IS NOT NULL
                  AND mobile_verified = TRUE
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (clean_digits, phone_number.strip()),
            )
            r2 = cur.fetchone()
            if r2:
                return {
                    "userId": str(r2["user_id"]),
                    "email": r2["email"],
                    "phoneNumber": r2["phone_number"],
                    "displayName": r2["email"].split("@")[0],
                }
            return None


# ==============================================================================
# Push Login Transactions (Push-to-Approve)
# ==============================================================================

def save_push_login_transaction(tx: Dict[str, Any]) -> None:
    """Inserts or replaces a push login transaction in PostgreSQL."""
    tx_id = tx.get("transactionId") or tx.get("transaction_id")
    user_id = tx.get("userId") or tx.get("user_id")
    phone = tx.get("phoneNumber") or tx.get("phone_number")
    token_hash = tx.get("mobileTokenHash") or tx.get("mobile_token_hash")
    created_at = tx.get("createdAt", tx.get("created_at", time.time()))
    expires_at = tx.get("expiresAt", tx.get("expires_at", time.time() + 300))
    approved_at = tx.get("approvedAt", tx.get("approved_at"))
    rejected_at = tx.get("rejectedAt", tx.get("rejected_at"))
    authenticated_at = tx.get("authenticatedAt", tx.get("authenticated_at"))
    completed_at = tx.get("completedAt", tx.get("completed_at"))

    query = """
    INSERT INTO public.push_login_transactions (
        transaction_id, user_id, phone_number, mobile_token_hash,
        state, webauthn_challenge, credential_id, ip_address, user_agent,
        browser_name, os_name, created_at, expires_at, approved_at,
        rejected_at, authenticated_at, completed_at
    ) VALUES (
        %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s
    )
    ON CONFLICT(transaction_id) DO UPDATE SET
        state = EXCLUDED.state,
        webauthn_challenge = EXCLUDED.webauthn_challenge,
        credential_id = EXCLUDED.credential_id,
        approved_at = EXCLUDED.approved_at,
        rejected_at = EXCLUDED.rejected_at,
        authenticated_at = EXCLUDED.authenticated_at,
        completed_at = EXCLUDED.completed_at;
    """
    params = (
        tx_id,
        user_id,
        phone,
        token_hash,
        tx.get("state", "PENDING_APPROVAL"),
        tx.get("webauthnChallenge", tx.get("webauthn_challenge")),
        tx.get("credentialId", tx.get("credential_id")),
        tx.get("ipAddress", tx.get("ip_address")),
        tx.get("userAgent", tx.get("user_agent")),
        tx.get("browserName", tx.get("browser_name", "Browser")),
        tx.get("osName", tx.get("os_name", "Device")),
        _ts_to_dt(created_at),
        _ts_to_dt(expires_at),
        _ts_to_dt(approved_at),
        _ts_to_dt(rejected_at),
        _ts_to_dt(authenticated_at),
        _ts_to_dt(completed_at),
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()


def get_push_login_transaction(transaction_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a push login transaction by transaction_id."""
    query = "SELECT * FROM public.push_login_transactions WHERE transaction_id = %s LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (transaction_id,))
            r = cur.fetchone()
            if not r:
                return None
            return {
                "id": str(r["id"]),
                "transactionId": r["transaction_id"],
                "userId": str(r["user_id"]),
                "phoneNumber": r["phone_number"],
                "mobileTokenHash": r["mobile_token_hash"],
                "state": r["state"],
                "webauthnChallenge": r["webauthn_challenge"],
                "credentialId": r["credential_id"],
                "ipAddress": r["ip_address"],
                "userAgent": r["user_agent"],
                "browserName": r["browser_name"],
                "osName": r["os_name"],
                "createdAt": _dt_to_ts(r["created_at"]),
                "expiresAt": _dt_to_ts(r["expires_at"]),
                "approvedAt": _dt_to_ts(r["approved_at"]),
                "rejectedAt": _dt_to_ts(r["rejected_at"]),
                "authenticatedAt": _dt_to_ts(r["authenticated_at"]),
                "completedAt": _dt_to_ts(r["completed_at"]),
            }


def get_push_login_transaction_by_hash(token_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieves a push login transaction by mobile token hash."""
    query = "SELECT * FROM public.push_login_transactions WHERE mobile_token_hash = %s LIMIT 1;"
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (token_hash,))
            r = cur.fetchone()
            if not r:
                return None
            return {
                "id": str(r["id"]),
                "transactionId": r["transaction_id"],
                "userId": str(r["user_id"]),
                "phoneNumber": r["phone_number"],
                "mobileTokenHash": r["mobile_token_hash"],
                "state": r["state"],
                "webauthnChallenge": r["webauthn_challenge"],
                "credentialId": r["credential_id"],
                "ipAddress": r["ip_address"],
                "userAgent": r["user_agent"],
                "browserName": r["browser_name"],
                "osName": r["os_name"],
                "createdAt": _dt_to_ts(r["created_at"]),
                "expiresAt": _dt_to_ts(r["expires_at"]),
                "approvedAt": _dt_to_ts(r["approved_at"]),
                "rejectedAt": _dt_to_ts(r["rejected_at"]),
                "authenticatedAt": _dt_to_ts(r["authenticated_at"]),
                "completedAt": _dt_to_ts(r["completed_at"]),
            }


def update_push_login_transaction_state(
    transaction_id: str,
    new_state: str,
    webauthn_challenge: Optional[str] = None,
    credential_id: Optional[str] = None,
    approved_at: Optional[float] = None,
    rejected_at: Optional[float] = None,
    authenticated_at: Optional[float] = None,
    completed_at: Optional[float] = None,
) -> bool:
    """Updates the state and lifecycle timestamps of a push login transaction."""
    query = """
    UPDATE public.push_login_transactions
    SET state = %s,
        webauthn_challenge = COALESCE(%s, webauthn_challenge),
        credential_id = COALESCE(%s, credential_id),
        approved_at = COALESCE(%s, approved_at),
        rejected_at = COALESCE(%s, rejected_at),
        authenticated_at = COALESCE(%s, authenticated_at),
        completed_at = COALESCE(%s, completed_at)
    WHERE transaction_id = %s;
    """
    params = (
        new_state,
        webauthn_challenge,
        credential_id,
        _ts_to_dt(approved_at),
        _ts_to_dt(rejected_at),
        _ts_to_dt(authenticated_at),
        _ts_to_dt(completed_at),
        transaction_id,
    )
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            affected = cur.rowcount
        conn.commit()
    return affected > 0


def revoke_auth_session(session_or_tx_id: str) -> bool:
    """Revokes an active session by transaction_id or session id."""
    now_dt = _ts_to_dt(time.time())
    query = """
    UPDATE public.auth_sessions
    SET is_revoked = TRUE, revoked_at = %s, state = 'REVOKED'
    WHERE transaction_id = %s OR id::text = %s;
    """
    with get_pg_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (now_dt, session_or_tx_id, session_or_tx_id))
            affected = cur.rowcount
        conn.commit()
    return affected > 0


def delete_user_account(user_id: str) -> bool:
    """Deletes all data for a user across PostgreSQL tables respecting foreign keys."""
    with get_pg_connection() as conn:
        with conn:
            with conn.cursor() as cur:
                # 1. Child authentication tables
                cur.execute("DELETE FROM public.auth_challenges WHERE user_id::text = %s;", (str(user_id),))
                cur.execute("DELETE FROM public.auth_sessions WHERE user_id::text = %s;", (str(user_id),))
                cur.execute("DELETE FROM public.registered_devices WHERE user_id::text = %s;", (str(user_id),))
                cur.execute("DELETE FROM public.push_subscriptions WHERE user_id::text = %s;", (str(user_id),))
                cur.execute("DELETE FROM public.push_login_transactions WHERE user_id::text = %s;", (str(user_id),))
                cur.execute("DELETE FROM public.auth_audit_events WHERE user_id::text = %s;", (str(user_id),))
                # 2. Groundwork tables (if present)
                try:
                    cur.execute("DELETE FROM public.connected_accounts WHERE user_id::text = %s;", (str(user_id),))
                    cur.execute("DELETE FROM public.trust_edges WHERE user_id::text = %s;", (str(user_id),))
                    cur.execute("DELETE FROM public.behavioral_baselines WHERE user_id::text = %s;", (str(user_id),))
                    cur.execute("DELETE FROM public.trust_nodes WHERE user_id::text = %s;", (str(user_id),))
                except Exception:
                    pass
                # 3. User profile
                cur.execute("DELETE FROM public.user_profiles WHERE user_id::text = %s;", (str(user_id),))
    return True


# Method aliases for parity across layers
revoke_device = revoke_trusted_device
load_push_login_transaction_by_id = get_push_login_transaction
update_push_login_state = update_push_login_transaction_state

