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
                    "signCount": r["sign_count"],
                    "isActive": bool(r["is_active"]),
                    "lastUsedAt": r["last_used_at"],
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]

