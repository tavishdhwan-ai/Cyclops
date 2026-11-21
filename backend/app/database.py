"""
Sentinel AI Authoritative Database Persistence Layer.
Implements robust SQL persistence adhering to 001_sentinel_auth_schema.sql.
Provides transactional operations for auth_sessions, auth_challenges, user_profiles, and audit events.
"""
import os
import json
import time
import secrets
import sqlite3
import threading
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("sentinel.database")

DB_PATH = os.getenv("SENTINEL_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel_auth.db"))
_db_lock = threading.RLock()


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe SQLite connection with WAL mode and row factory."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initializes tables matching 001_sentinel_auth_schema.sql."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS user_profiles (
                id TEXT PRIMARY KEY,
                user_id TEXT UNIQUE,
                email TEXT NOT NULL,
                phone_number TEXT,
                phone_verified INTEGER NOT NULL DEFAULT 0,
                display_name TEXT DEFAULT '',
                goal TEXT DEFAULT '',
                concerns TEXT DEFAULT '[]',
                experience TEXT DEFAULT '',
                onboarding_completed INTEGER NOT NULL DEFAULT 0,
                security_tier INTEGER NOT NULL DEFAULT 1,
                account_status TEXT NOT NULL DEFAULT 'active',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_profiles_email ON user_profiles(email);

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id TEXT PRIMARY KEY,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id TEXT,
                email TEXT NOT NULL,
                phone_number TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                mobile_verified INTEGER NOT NULL DEFAULT 0,
                biometric_verified INTEGER NOT NULL DEFAULT 0,
                biometric_status TEXT DEFAULT 'pending',
                state TEXT NOT NULL DEFAULT 'EMAIL_REQUIRED',
                user_agent TEXT,
                ip_address TEXT,
                expires_at REAL NOT NULL,
                last_active_at REAL NOT NULL,
                revoked_at REAL,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_tx_id ON auth_sessions(transaction_id);
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_state ON auth_sessions(state);
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS auth_challenges (
                id TEXT PRIMARY KEY,
                transaction_id TEXT NOT NULL,
                user_id TEXT,
                challenge_type TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                webauthn_challenge TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_challenges_hash ON auth_challenges(token_hash);
            CREATE INDEX IF NOT EXISTS idx_auth_challenges_tx ON auth_challenges(transaction_id);

            CREATE TABLE IF NOT EXISTS auth_audit_events (
                id TEXT PRIMARY KEY,
                transaction_id TEXT,
                user_id TEXT,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT DEFAULT '{}',
                ip_address TEXT,
                user_agent TEXT,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                endpoint TEXT UNIQUE NOT NULL,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                device_id TEXT,
                user_agent TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_push_sub_user_id ON push_subscriptions(user_id);
            CREATE INDEX IF NOT EXISTS idx_push_sub_endpoint ON push_subscriptions(endpoint);

            CREATE TABLE IF NOT EXISTS registered_devices (
                id TEXT PRIMARY KEY,
                device_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                device_name TEXT,
                device_type TEXT DEFAULT 'mobile',
                platform TEXT,
                credential_id TEXT UNIQUE,
                public_key TEXT,
                sign_count INTEGER DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                last_used_at REAL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_reg_dev_user_id ON registered_devices(user_id);
            CREATE INDEX IF NOT EXISTS idx_reg_dev_cred_id ON registered_devices(credential_id);
            """)

            # Safe additive migration for mobile_verification_url column
            try:
                conn.execute("ALTER TABLE auth_sessions ADD COLUMN mobile_verification_url TEXT;")
            except Exception:
                pass

            # Safe additive migrations for user_profiles extended fields
            for col, col_def in [
                ("full_name", "TEXT DEFAULT ''"),
                ("username", "TEXT DEFAULT ''"),
                ("country", "TEXT DEFAULT ''"),
                ("profile_picture_url", "TEXT DEFAULT ''"),
                ("date_of_birth", "TEXT DEFAULT ''"),
                ("preferred_language", "TEXT DEFAULT 'en'"),
                ("time_zone", "TEXT DEFAULT 'UTC'"),
                ("notify_new_device", "INTEGER DEFAULT 1"),
                ("notify_new_passkey", "INTEGER DEFAULT 1"),
                ("notify_failed_login", "INTEGER DEFAULT 1"),
                ("notify_security_changes", "INTEGER DEFAULT 1"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE user_profiles ADD COLUMN {col} {col_def};")
                except Exception:
                    pass

            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profiles_username_clean ON user_profiles(username) WHERE username IS NOT NULL AND username != '';"
                )
            except Exception:
                pass

            try:
                conn.execute("ALTER TABLE registered_devices ADD COLUMN revoked_at REAL;")
            except Exception:
                pass


# Initialize database tables immediately on import
init_db()


def save_transaction(tx_data: Dict[str, Any]) -> None:
    """Inserts or updates an authentication transaction record in auth_sessions."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    id, transaction_id, user_id, email, phone_number,
                    email_verified, mobile_verified, biometric_verified,
                    biometric_status, state, user_agent, ip_address,
                    expires_at, last_active_at, revoked_at, is_revoked, created_at,
                    mobile_verification_url
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?
                )
                ON CONFLICT(transaction_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    email = excluded.email,
                    phone_number = excluded.phone_number,
                    email_verified = excluded.email_verified,
                    mobile_verified = excluded.mobile_verified,
                    biometric_verified = excluded.biometric_verified,
                    biometric_status = excluded.biometric_status,
                    state = excluded.state,
                    last_active_at = excluded.last_active_at,
                    revoked_at = excluded.revoked_at,
                    is_revoked = excluded.is_revoked,
                    mobile_verification_url = excluded.mobile_verification_url
                """,
                (
                    tx_data.get("id"),
                    tx_data.get("id"),
                    tx_data.get("userId"),
                    tx_data.get("email"),
                    tx_data.get("phoneNumber"),
                    1 if tx_data.get("emailVerified") else 0,
                    1 if tx_data.get("mobileVerified") else 0,
                    1 if tx_data.get("biometricVerified") else 0,
                    tx_data.get("biometricStatus", "pending"),
                    tx_data.get("state"),
                    tx_data.get("userAgent"),
                    tx_data.get("ipAddress"),
                    tx_data.get("expiresAt", time.time() + 900),
                    tx_data.get("lastActiveAt", time.time()),
                    tx_data.get("revokedAt"),
                    1 if tx_data.get("isRevoked") else 0,
                    tx_data.get("createdAt", time.time()),
                    tx_data.get("mobileVerificationUrl"),
                ),
            )


def load_transaction(tx_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an authentication transaction from auth_sessions."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute("SELECT * FROM auth_sessions WHERE transaction_id = ?", (tx_id,))
            row = cur.fetchone()
            if not row:
                return None
            row_keys = row.keys()
            return {
                "id": row["transaction_id"],
                "userId": row["user_id"],
                "email": row["email"],
                "phoneNumber": row["phone_number"],
                "emailVerified": bool(row["email_verified"]),
                "mobileVerified": bool(row["mobile_verified"]),
                "biometricVerified": bool(row["biometric_verified"]),
                "biometricStatus": row["biometric_status"],
                "state": row["state"],
                "userAgent": row["user_agent"],
                "ipAddress": row["ip_address"],
                "expiresAt": row["expires_at"],
                "lastActiveAt": row["last_active_at"],
                "revokedAt": row["revoked_at"],
                "isRevoked": bool(row["is_revoked"]),
                "createdAt": row["created_at"],
                "mobileVerificationUrl": row["mobile_verification_url"] if "mobile_verification_url" in row_keys else None,
            }



def save_challenge(challenge_data: Dict[str, Any]) -> None:
    """Inserts or updates an authentication challenge in auth_challenges."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO auth_challenges (
                    id, transaction_id, user_id, challenge_type,
                    token_hash, webauthn_challenge, attempts, max_attempts,
                    expires_at, consumed_at, created_at
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?
                )
                ON CONFLICT(token_hash) DO UPDATE SET
                    attempts = excluded.attempts,
                    consumed_at = excluded.consumed_at
                """,
                (
                    f"ch_{challenge_data.get('tokenHash', '')[:16]}",
                    challenge_data.get("transactionId"),
                    challenge_data.get("userId"),
                    challenge_data.get("challengeType", "whatsapp_mobile_link"),
                    challenge_data.get("tokenHash"),
                    challenge_data.get("webauthnChallenge"),
                    challenge_data.get("attempts", 0),
                    challenge_data.get("maxAttempts", 3),
                    challenge_data.get("expiresAt", time.time() + 600),
                    challenge_data.get("consumedAt"),
                    challenge_data.get("createdAt", time.time()),
                ),
            )


def load_challenge(token_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieves an authentication challenge by token hash."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute("SELECT * FROM auth_challenges WHERE token_hash = ?", (token_hash,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "transactionId": row["transaction_id"],
                "userId": row["user_id"],
                "challengeType": row["challenge_type"],
                "tokenHash": row["token_hash"],
                "webauthnChallenge": row["webauthn_challenge"],
                "attempts": row["attempts"],
                "maxAttempts": row["max_attempts"],
                "expiresAt": row["expires_at"],
                "consumedAt": row["consumed_at"],
                "createdAt": row["created_at"],
            }


def record_db_audit(audit_entry: Dict[str, Any]) -> None:
    """Records an immutable audit event in auth_audit_events."""
    with _db_lock:
        with get_db_connection() as conn:
            details_json = json.dumps(audit_entry.get("details", {}))
            conn.execute(
                """
                INSERT INTO auth_audit_events (
                    id, transaction_id, user_id, event_type,
                    status, details, ip_address, user_agent, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_entry.get("id"),
                    audit_entry.get("transaction_id"),
                    audit_entry.get("user_id"),
                    audit_entry.get("event_type"),
                    audit_entry.get("status"),
                    details_json,
                    audit_entry.get("ip_address"),
                    audit_entry.get("user_agent"),
                    audit_entry.get("created_at", time.time()),
                ),
            )


def save_push_subscription(sub_data: Dict[str, Any]) -> None:
    """Inserts or updates a browser push subscription for a user."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO push_subscriptions (
                    id, user_id, endpoint, p256dh, auth, device_id, user_agent, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(endpoint) DO UPDATE SET
                    user_id = excluded.user_id,
                    p256dh = excluded.p256dh,
                    auth = excluded.auth,
                    device_id = excluded.device_id,
                    user_agent = excluded.user_agent,
                    updated_at = excluded.updated_at
                """,
                (
                    sub_data.get("id", f"sub_{secrets.token_hex(8)}"),
                    sub_data["user_id"],
                    sub_data["endpoint"],
                    sub_data["p256dh"],
                    sub_data["auth"],
                    sub_data.get("device_id"),
                    sub_data.get("user_agent"),
                    sub_data.get("created_at", time.time()),
                    time.time(),
                ),
            )


def get_push_subscriptions_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all active push subscriptions for a user."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute("SELECT * FROM push_subscriptions WHERE user_id = ?", (user_id,))
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "userId": r["user_id"],
                    "endpoint": r["endpoint"],
                    "p256dh": r["p256dh"],
                    "auth": r["auth"],
                    "deviceId": r["device_id"],
                    "userAgent": r["user_agent"],
                    "createdAt": r["created_at"],
                    "updatedAt": r["updated_at"],
                }
                for r in rows
            ]


def delete_push_subscription(endpoint: str) -> None:
    """Deletes an invalid or expired push subscription."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (endpoint,))


def register_device(device_data: Dict[str, Any]) -> None:
    """Registers or updates a trusted mobile device."""
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO registered_devices (
                    id, device_id, user_id, device_name, device_type, platform,
                    credential_id, public_key, sign_count, is_active, last_used_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_name = excluded.device_name,
                    platform = excluded.platform,
                    credential_id = excluded.credential_id,
                    public_key = excluded.public_key,
                    sign_count = excluded.sign_count,
                    is_active = excluded.is_active,
                    last_used_at = excluded.last_used_at
                """,
                (
                    device_data.get("id", f"dev_{secrets.token_hex(8)}"),
                    device_data["device_id"],
                    device_data["user_id"],
                    device_data.get("device_name", "Mobile Device"),
                    device_data.get("device_type", "mobile"),
                    device_data.get("platform", "Unknown"),
                    device_data.get("credential_id"),
                    device_data.get("public_key"),
                    device_data.get("sign_count", 0),
                    1 if device_data.get("is_active", True) else 0,
                    device_data.get("last_used_at", time.time()),
                    device_data.get("created_at", time.time()),
                ),
            )


def get_devices_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all registered devices for a user."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM registered_devices WHERE user_id = ? AND is_active = 1", (user_id,)
            )
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "deviceId": r["device_id"],
                    "userId": r["user_id"],
                    "deviceName": r["device_name"],
                    "deviceType": r["device_type"],
                    "platform": r["platform"],
                    "credentialId": r["credential_id"],
                    "publicKey": r["public_key"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": r["last_used_at"],
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]


def get_active_passkeys_for_user(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves all active WebAuthn passkey credentials for a user."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT * FROM registered_devices
                WHERE user_id = ? AND is_active = 1 AND credential_id IS NOT NULL AND public_key IS NOT NULL
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "deviceId": r["device_id"],
                    "userId": r["user_id"],
                    "deviceName": r["device_name"],
                    "deviceType": r["device_type"],
                    "platform": r["platform"],
                    "credentialId": r["credential_id"],
                    "publicKey": r["public_key"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": r["last_used_at"],
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]


def get_device_by_credential_id(credential_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active registered device by its WebAuthn credential ID."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM registered_devices WHERE credential_id = ? AND is_active = 1",
                (credential_id,),
            )
            r = cur.fetchone()
            if not r:
                return None
            return {
                "id": r["id"],
                "deviceId": r["device_id"],
                "userId": r["user_id"],
                "deviceName": r["device_name"],
                "deviceType": r["device_type"],
                "platform": r["platform"],
                "credentialId": r["credential_id"],
                "publicKey": r["public_key"],
                "signCount": r["sign_count"],
                "isActive": bool(r["is_active"]),
                "lastUsedAt": r["last_used_at"],
                "createdAt": r["created_at"],
            }


def save_verified_passkey_device(
    user_id: str,
    device_id: Optional[str],
    credential_id: str,
    public_key: str,
    sign_count: int = 0,
    device_name: str = "Mobile Platform Authenticator",
    platform: str = "Mobile",
) -> Dict[str, Any]:
    """
    Saves a cryptographically verified WebAuthn credential to registered_devices.
    Ensures safe persistence with single credential uniqueness.
    """
    final_device_id = device_id or f"dev_{secrets.token_hex(8)}"
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO registered_devices (
                    id, device_id, user_id, device_name, device_type, platform,
                    credential_id, public_key, sign_count, is_active, last_used_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(credential_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    public_key = excluded.public_key,
                    sign_count = excluded.sign_count,
                    is_active = 1,
                    last_used_at = excluded.last_used_at
                """,
                (
                    f"passkey_{secrets.token_hex(8)}",
                    final_device_id,
                    user_id,
                    device_name,
                    "mobile",
                    platform,
                    credential_id,
                    public_key,
                    sign_count,
                    now,
                    now,
                ),
            )
    return {
        "deviceId": final_device_id,
        "credentialId": credential_id,
        "userId": user_id,
        "signCount": sign_count,
    }


def update_device_sign_count(credential_id: str, new_sign_count: int) -> None:
    """Updates the signature counter and last_used_at timestamp for a registered passkey."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                UPDATE registered_devices
                SET sign_count = ?, last_used_at = ?
                WHERE credential_id = ?
                """,
                (new_sign_count, now, credential_id),
            )


# ==============================================================================
# Extended User Profile & Security Management Persistence
# ==============================================================================

def get_user_profile_by_user_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full user profile by user_id from SQLite."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,))
            r = cur.fetchone()
            if not r:
                return None
            keys = r.keys()
            concerns_raw = r["concerns"] if "concerns" in keys else "[]"
            try:
                concerns = json.loads(concerns_raw) if isinstance(concerns_raw, str) else []
            except Exception:
                concerns = []

            return {
                "userId": r["user_id"],
                "email": r["email"],
                "phoneNumber": r["phone_number"],
                "phoneVerified": bool(r["phone_verified"]),
                "displayName": r["display_name"] or "",
                "fullName": r["full_name"] if "full_name" in keys and r["full_name"] else "",
                "username": r["username"] if "username" in keys and r["username"] else "",
                "country": r["country"] if "country" in keys and r["country"] else "",
                "profilePictureUrl": r["profile_picture_url"] if "profile_picture_url" in keys and r["profile_picture_url"] else "",
                "dateOfBirth": r["date_of_birth"] if "date_of_birth" in keys and r["date_of_birth"] else "",
                "preferredLanguage": r["preferred_language"] if "preferred_language" in keys and r["preferred_language"] else "en",
                "timeZone": r["time_zone"] if "time_zone" in keys and r["time_zone"] else "UTC",
                "goal": r["goal"] or "",
                "concerns": concerns,
                "experience": r["experience"] or "",
                "onboardingCompleted": bool(r["onboarding_completed"]),
                "securityTier": r["security_tier"] if "security_tier" in keys else 1,
                "accountStatus": r["account_status"] if "account_status" in keys else "active",
                "createdAt": r["created_at"],
                "updatedAt": r["updated_at"],
            }


def get_user_profile_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by normalized email address."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute("SELECT user_id FROM user_profiles WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            r = cur.fetchone()
            if not r:
                return None
            return get_user_profile_by_user_id(r["user_id"])


def check_username_available(username: str, exclude_user_id: Optional[str] = None) -> bool:
    """Checks if a username is valid and available (unique across all accounts)."""
    clean_username = username.strip().lower()
    if not clean_username or len(clean_username) < 3 or len(clean_username) > 30:
        return False
    # Only allow alphanumeric and underscore
    import re
    if not re.match(r"^[a-zA-Z0-9_]+$", clean_username):
        return False

    with _db_lock:
        with get_db_connection() as conn:
            if exclude_user_id:
                cur = conn.execute(
                    "SELECT id FROM user_profiles WHERE LOWER(username) = ? AND user_id != ?",
                    (clean_username, exclude_user_id),
                )
            else:
                cur = conn.execute(
                    "SELECT id FROM user_profiles WHERE LOWER(username) = ?",
                    (clean_username,),
                )
            return cur.fetchone() is None


def save_or_update_user_profile(user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    """Upserts full user profile into user_profiles with validation and atomic SQLite commit."""
    now = time.time()
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
    concerns_json = json.dumps(concerns) if isinstance(concerns, list) else "[]"

    onboarding_completed = 1 if (profile_data.get("onboardingCompleted", False) or (existing and existing.get("onboardingCompleted"))) else 0

    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO user_profiles (
                    id, user_id, email, phone_number, display_name, full_name, username,
                    country, profile_picture_url, date_of_birth, preferred_language, time_zone,
                    goal, concerns, experience, onboarding_completed, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    email = COALESCE(NULLIF(excluded.email, ''), user_profiles.email),
                    phone_number = COALESCE(NULLIF(excluded.phone_number, ''), user_profiles.phone_number),
                    display_name = COALESCE(NULLIF(excluded.display_name, ''), user_profiles.display_name),
                    full_name = COALESCE(NULLIF(excluded.full_name, ''), user_profiles.full_name),
                    username = COALESCE(NULLIF(excluded.username, ''), user_profiles.username),
                    country = COALESCE(NULLIF(excluded.country, ''), user_profiles.country),
                    profile_picture_url = COALESCE(NULLIF(excluded.profile_picture_url, ''), user_profiles.profile_picture_url),
                    date_of_birth = COALESCE(NULLIF(excluded.date_of_birth, ''), user_profiles.date_of_birth),
                    preferred_language = COALESCE(NULLIF(excluded.preferred_language, ''), user_profiles.preferred_language),
                    time_zone = COALESCE(NULLIF(excluded.time_zone, ''), user_profiles.time_zone),
                    goal = COALESCE(NULLIF(excluded.goal, ''), user_profiles.goal),
                    concerns = excluded.concerns,
                    experience = COALESCE(NULLIF(excluded.experience, ''), user_profiles.experience),
                    onboarding_completed = MAX(user_profiles.onboarding_completed, excluded.onboarding_completed),
                    updated_at = excluded.updated_at
                """,
                (
                    f"prof_{secrets.token_hex(8)}",
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
                    concerns_json,
                    experience,
                    onboarding_completed,
                    now,
                    now,
                ),
            )

    return get_user_profile_by_user_id(user_id) or {}


def get_user_registered_passkeys(user_id: str) -> List[Dict[str, Any]]:
    """
    Returns registered passkeys for security dashboard.
    Redacts private/public key raw cryptographic secrets.
    """
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, device_id, device_name, platform, credential_id, sign_count,
                       is_active, last_used_at, created_at, revoked_at
                FROM registered_devices
                WHERE user_id = ? AND credential_id IS NOT NULL
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "deviceId": r["device_id"],
                    "deviceName": r["device_name"] or "Platform Passkey",
                    "platform": r["platform"] or "Mobile",
                    "credentialIdPreview": r["credential_id"][:12] + "..." if r["credential_id"] else "",
                    "credentialId": r["credential_id"],
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": r["last_used_at"],
                    "createdAt": r["created_at"],
                    "revokedAt": r["revoked_at"],
                }
                for r in rows
            ]


def revoke_passkey_credential(user_id: str, credential_id: str) -> bool:
    """Revokes a specific WebAuthn passkey credential for a user."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                UPDATE registered_devices
                SET is_active = 0, revoked_at = ?
                WHERE user_id = ? AND credential_id = ?
                """,
                (now, user_id, credential_id),
            )
            return cur.rowcount > 0


def get_user_trusted_devices(user_id: str) -> List[Dict[str, Any]]:
    """Returns trusted devices list for user."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, device_id, device_name, device_type, platform,
                       is_active, last_used_at, created_at, revoked_at,
                       credential_id
                FROM registered_devices
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
            # Also get push subscriptions count for this device
            push_cur = conn.execute("SELECT device_id FROM push_subscriptions WHERE user_id = ?", (user_id,))
            push_device_ids = {p["device_id"] for p in push_cur.fetchall() if p["device_id"]}

            return [
                {
                    "id": r["id"],
                    "deviceId": r["device_id"],
                    "deviceName": r["device_name"] or "Mobile Device",
                    "deviceType": r["device_type"] or "mobile",
                    "platform": r["platform"] or "Mobile",
                    "hasPasskey": bool(r["credential_id"]),
                    "hasWebPush": r["device_id"] in push_device_ids,
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": r["last_used_at"],
                    "createdAt": r["created_at"],
                    "revokedAt": r["revoked_at"],
                }
                for r in rows
            ]


def revoke_trusted_device(user_id: str, device_id: str) -> bool:
    """Revokes a trusted device and its associated passkeys."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                UPDATE registered_devices
                SET is_active = 0, revoked_at = ?
                WHERE user_id = ? AND device_id = ?
                """,
                (now, user_id, device_id),
            )
            # Also delete push subscription for this device if any
            conn.execute(
                "DELETE FROM push_subscriptions WHERE user_id = ? AND device_id = ?",
                (user_id, device_id),
            )
            return cur.rowcount > 0


def get_user_audit_events(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves real audit events for the authenticated user from SQLite."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, transaction_id, event_type, status, details, ip_address, user_agent, created_at
                FROM auth_audit_events
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (user_id, limit),
            )
            rows = cur.fetchall()
            events = []
            for r in rows:
                details = {}
                try:
                    details = json.loads(r["details"]) if r["details"] else {}
                except Exception:
                    pass
                events.append({
                    "id": r["id"],
                    "transactionId": r["transaction_id"],
                    "eventType": r["event_type"],
                    "status": r["status"],
                    "details": details,
                    "ipAddress": r["ip_address"] or "Direct Connection",
                    "userAgent": r["user_agent"] or "Secure Browser",
                    "createdAt": r["created_at"],
                })
            return events


def get_user_active_sessions(user_id: str) -> List[Dict[str, Any]]:
    """Retrieves active sessions for the user from auth_sessions."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, transaction_id, email, user_agent, ip_address,
                       created_at, last_active_at, expires_at, is_revoked, state
                FROM auth_sessions
                WHERE user_id = ? AND is_revoked = 0 AND expires_at > ?
                ORDER BY last_active_at DESC
                """,
                (user_id, now),
            )
            rows = cur.fetchall()
            return [
                {
                    "sessionId": r["transaction_id"],
                    "transactionId": r["transaction_id"],
                    "email": r["email"],
                    "userAgent": r["user_agent"] or "Desktop Web Browser",
                    "ipAddress": r["ip_address"] or "Active Session",
                    "createdAt": r["created_at"],
                    "lastActiveAt": r["last_active_at"],
                    "expiresAt": r["expires_at"],
                    "state": r["state"],
                }
                for r in rows
            ]


def revoke_user_session(user_id: str, session_id: str) -> bool:
    """Revokes a specific session for a user."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                UPDATE auth_sessions
                SET is_revoked = 1, revoked_at = ?, state = 'REVOKED'
                WHERE user_id = ? AND (transaction_id = ? OR id = ?)
                """,
                (now, user_id, session_id, session_id),
            )
            return cur.rowcount > 0


def revoke_all_other_sessions(user_id: str, current_session_id: str) -> int:
    """Revokes all active sessions for a user except the current session."""
    now = time.time()
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                UPDATE auth_sessions
                SET is_revoked = 1, revoked_at = ?, state = 'REVOKED'
                WHERE user_id = ? AND transaction_id != ? AND id != ? AND is_revoked = 0
                """,
                (now, user_id, current_session_id, current_session_id),
            )
            return cur.rowcount


def get_security_preferences(user_id: str) -> Dict[str, bool]:
    """Retrieves security notification preferences for user."""
    with _db_lock:
        with get_db_connection() as conn:
            cur = conn.execute(
                """
                SELECT notify_new_device, notify_new_passkey, notify_failed_login, notify_security_changes
                FROM user_profiles WHERE user_id = ?
                """,
                (user_id,),
            )
            r = cur.fetchone()
            if not r:
                return {
                    "notifyNewDevice": True,
                    "notifyNewPasskey": True,
                    "notifyFailedLogin": True,
                    "notifySecurityChanges": True,
                }
            keys = r.keys()
            return {
                "notifyNewDevice": bool(r["notify_new_device"]) if "notify_new_device" in keys else True,
                "notifyNewPasskey": bool(r["notify_new_passkey"]) if "notify_new_passkey" in keys else True,
                "notifyFailedLogin": bool(r["notify_failed_login"]) if "notify_failed_login" in keys else True,
                "notifySecurityChanges": bool(r["notify_security_changes"]) if "notify_security_changes" in keys else True,
            }


def update_security_preferences(user_id: str, prefs: Dict[str, bool]) -> Dict[str, bool]:
    """Updates security notification preferences for user, creating profile record if absent."""
    now = time.time()
    current = get_security_preferences(user_id)
    # Merge existing preferences with provided updates
    merged = {**current, **prefs}
    with _db_lock:
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO user_profiles (
                    id, user_id, email, phone_number, display_name, full_name, username,
                    country, profile_picture_url, date_of_birth, preferred_language, time_zone,
                    goal, concerns, experience, onboarding_completed, created_at, updated_at,
                    notify_new_device, notify_new_passkey, notify_failed_login, notify_security_changes
                ) VALUES (?, ?, '', '', '', '', '', '', '', '', 'en', 'UTC', '', '[]', '', 0, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    notify_new_device = excluded.notify_new_device,
                    notify_new_passkey = excluded.notify_new_passkey,
                    notify_failed_login = excluded.notify_failed_login,
                    notify_security_changes = excluded.notify_security_changes,
                    updated_at = excluded.updated_at
                """,
                (
                    f"prof_{secrets.token_hex(8)}",
                    user_id,
                    now,
                    now,
                    1 if merged.get("notifyNewDevice", True) else 0,
                    1 if merged.get("notifyNewPasskey", True) else 0,
                    1 if merged.get("notifyFailedLogin", True) else 0,
                    1 if merged.get("notifySecurityChanges", True) else 0,
                ),
            )
    return get_security_preferences(user_id)


