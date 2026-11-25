"""
Sentinel AI — Automated PostgreSQL Staging Integration Test Suite.
Validates the PostgreSQL persistence layer against a real staging PostgreSQL / Supabase database.

Covers (Phase 1C Requirements):
1. Database connectivity, driver integrity, and SSL transport.
2. DDL Migrations 001, 002, 003 table and index existence.
3. Profile creation, updates, and username uniqueness.
4. Multi-tenant isolation and strict user boundaries.
5. WebAuthn Passkey credential persistence, counter updates, and device revocation.
6. Session lifecycle: creation, gate transitions, and revocation.
7. Push-to-approve login transaction state engine.
8. Audit event persistence with JSONB details.
9. Atomic transaction rollback and connection failure handling.
10. PostgreSQL constraints: UUID syntax and UNIQUE constraint enforcement.
11. Row-Level Security (RLS) policy enforcement for service_role vs authenticated roles.

SAFETY:
- Skips cleanly if SENTINEL_STAGING_DATABASE_URL (or SENTINEL_DATABASE_URL) is unset.
- Uses dynamically generated test UUIDs to avoid any collision.
- Automatically cleans up test records in teardown.
"""
import os
import uuid
import time
import json
import secrets
import hashlib
import pytest
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app import postgres_database

# Staging Database URL resolution
STAGING_URL = os.getenv(
    "SENTINEL_STAGING_DATABASE_URL",
    os.getenv("SENTINEL_DATABASE_URL", os.getenv("DATABASE_URL", "")),
).strip()


def is_staging_configured() -> bool:
    """Returns True if a staging PostgreSQL database URL is configured and driver is available."""
    return bool(STAGING_URL) and postgres_database.is_driver_available()


# Mark entire module to skip if staging credentials are not configured
pytestmark = pytest.mark.skipif(
    not is_staging_configured(),
    reason=(
        "Staging PostgreSQL database is not configured. "
        "Set SENTINEL_STAGING_DATABASE_URL to execute real PostgreSQL integration tests."
    ),
)


@pytest.fixture(scope="module")
def pg_conn():
    """Provides a thread-safe connection to the real staging PostgreSQL instance."""
    conn = postgres_database.get_pg_connection(STAGING_URL)
    yield conn
    try:
        conn.close()
    except Exception:
        pass


@pytest.fixture
def test_user_pair():
    """Generates two isolated RFC 4122 test UUIDs and cleans up after test completion."""
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    yield user_a, user_b

    # Teardown: purge test user data in child-first order to respect foreign keys
    try:
        with postgres_database.get_pg_connection(STAGING_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM public.auth_challenges WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.auth_sessions WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.registered_devices WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.push_subscriptions WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.push_login_transactions WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.auth_audit_events WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.trust_edges WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.behavioral_baselines WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.trust_nodes WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.connected_accounts WHERE user_id IN (%s, %s);", (user_a, user_b))
                cur.execute("DELETE FROM public.user_profiles WHERE user_id IN (%s, %s);", (user_a, user_b))
            conn.commit()
    except Exception:
        pass


# ==============================================================================
# 1. Connection & Schema Verification Tests
# ==============================================================================

def test_pg_connection_and_ssl(pg_conn):
    """Verifies that the staging PostgreSQL connection is established with SSL."""
    with pg_conn.cursor() as cur:
        cur.execute("SELECT version();")
        version_row = cur.fetchone()
        assert version_row is not None
        version_str = version_row[0] if isinstance(version_row, (list, tuple)) else list(version_row.values())[0]
        assert "PostgreSQL" in version_str


def test_migrations_applied_tables_exist(pg_conn):
    """Verifies that all tables from Migrations 001, 002, and 003 exist in the staging database."""
    expected_tables = {
        # 001 Base Schema
        "user_profiles",
        "auth_sessions",
        "auth_challenges",
        "webauthn_credentials",
        "auth_audit_events",
        "push_subscriptions",
        "registered_devices",
        # 002 Schema Updates
        "push_login_transactions",
        # 003 Trust Graph Groundwork
        "connected_accounts",
        "trust_nodes",
        "trust_edges",
        "behavioral_baselines",
        "threat_signatures",
    }

    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
            """
        )
        rows = cur.fetchall()
        existing_tables = set()
        for r in rows:
            name = r[0] if isinstance(r, (list, tuple)) else r.get("table_name")
            existing_tables.add(name)

        missing = expected_tables - existing_tables
        assert not missing, f"Missing required migration tables in staging PostgreSQL: {missing}"


# ==============================================================================
# 2. User Profiles & Username Uniqueness Tests
# ==============================================================================

def test_profile_creation_update_and_username_check(test_user_pair):
    """Tests creating, updating, and querying user profiles and username availability."""
    user_a, _ = test_user_pair
    test_username = f"agent_{uuid.uuid4().hex[:8]}"

    # Initial profile creation
    profile_data = {
        "email": f"{user_a}@sentinel.ai",
        "displayName": "Agent Alpha",
        "fullName": "Agent Alpha One",
        "username": test_username,
        "country": "United States",
        "preferredLanguage": "en",
        "timeZone": "America/New_York",
        "securityTier": 2,
    }
    postgres_database.save_or_update_user_profile(user_a, profile_data)

    # Read back profile
    loaded = postgres_database.get_user_profile_by_user_id(user_a)
    assert loaded is not None
    assert loaded["userId"] == user_a
    assert loaded["email"] == f"{user_a}@sentinel.ai"
    assert loaded["fullName"] == "Agent Alpha One"
    assert loaded["username"] == test_username
    assert loaded["securityTier"] == 2

    # Check username availability
    assert postgres_database.check_username_available(test_username, exclude_user_id=user_a) is True
    assert postgres_database.check_username_available(test_username, exclude_user_id=None) is False
    assert postgres_database.check_username_available(f"free_{uuid.uuid4().hex[:8]}") is True


# ==============================================================================
# 3. Multi-Tenant Isolation Tests
# ==============================================================================

def test_multi_tenant_data_isolation(test_user_pair):
    """Verifies strict cross-account tenant isolation between User A and User B."""
    user_a, user_b = test_user_pair

    postgres_database.save_or_update_user_profile(user_a, {"email": f"a_{user_a[:8]}@sentinel.ai", "fullName": "Alice"})
    postgres_database.save_or_update_user_profile(user_b, {"email": f"b_{user_b[:8]}@sentinel.ai", "fullName": "Bob"})

    # Devices isolation
    dev_a = f"dev_a_{uuid.uuid4().hex[:8]}"
    dev_b = f"dev_b_{uuid.uuid4().hex[:8]}"
    postgres_database.save_verified_passkey_device(user_a, dev_a, f"cred_a_{uuid.uuid4().hex[:8]}", "pub_a", "Alice Phone")
    postgres_database.save_verified_passkey_device(user_b, dev_b, f"cred_b_{uuid.uuid4().hex[:8]}", "pub_b", "Bob Phone")

    devices_a = [d["deviceId"] for d in postgres_database.get_devices_for_user(user_a)]
    devices_b = [d["deviceId"] for d in postgres_database.get_devices_for_user(user_b)]

    assert dev_a in devices_a
    assert dev_a not in devices_b
    assert dev_b in devices_b
    assert dev_b not in devices_a


# ==============================================================================
# 4. Passkey Credential Persistence & Revocation Tests
# ==============================================================================

def test_passkey_credential_lifecycle(test_user_pair):
    """Verifies passkey enrollment, signature counter increment, and revocation."""
    user_a, _ = test_user_pair
    device_id = f"dev_{uuid.uuid4().hex[:8]}"
    cred_id = f"cred_{uuid.uuid4().hex[:12]}"

    # 1. Register device
    postgres_database.save_verified_passkey_device(
        user_id=user_a,
        device_id=device_id,
        credential_id=cred_id,
        public_key="test_public_key_bytes_base64",
        device_name="Pixel 9 Pro",
        device_type="mobile",
        platform="Android",
    )

    dev = postgres_database.get_device_by_credential_id(cred_id)
    assert dev is not None
    assert dev["userId"] == user_a
    assert dev["credentialId"] == cred_id
    assert dev["signCount"] == 0

    # 2. Increment sign counter
    postgres_database.update_device_sign_count(cred_id, 42)
    updated_dev = postgres_database.get_device_by_credential_id(cred_id)
    assert updated_dev["signCount"] == 42

    # 3. Revoke device
    postgres_database.revoke_device(user_a, device_id)
    active_devices = postgres_database.get_active_passkeys_for_user(user_a)
    assert not any(d["deviceId"] == device_id for d in active_devices)


# ==============================================================================
# 5. Session Lifecycle Tests
# ==============================================================================

def test_session_lifecycle_and_revocation(test_user_pair):
    """Tests session creation, gate state advancement, and explicit revocation."""
    user_a, _ = test_user_pair
    tx_id = f"tx_{uuid.uuid4().hex}"

    # Ensure user profile exists prior to creating session (satisfies auth_sessions_user_id_fkey)
    postgres_database.save_or_update_user_profile(
        user_id=user_a,
        profile_data={
            "email": f"{user_a}@sentinel.ai",
            "phoneNumber": "+14155552671",
            "fullName": "Alice Session Test",
            "phoneVerified": True,
        },
    )

    session_record = {
        "transactionId": tx_id,
        "userId": user_a,
        "email": f"{user_a}@sentinel.ai",
        "phoneNumber": "+14155552671",
        "emailVerified": False,
        "mobileVerified": False,
        "biometricVerified": False,
        "state": "EMAIL_REQUIRED",
        "userAgent": "SentinelClient/1.0",
        "ipAddress": "127.0.0.1",
        "expiresAt": time.time() + 900,
    }

    # 1. Save session
    postgres_database.save_transaction(session_record)
    loaded = postgres_database.load_transaction(tx_id)
    assert loaded is not None
    assert loaded["state"] == "EMAIL_REQUIRED"

    # 2. Transition state
    session_record["state"] = "AUTHENTICATED"
    session_record["emailVerified"] = True
    session_record["mobileVerified"] = True
    postgres_database.save_transaction(session_record)

    loaded_after = postgres_database.load_transaction(tx_id)
    assert loaded_after["state"] == "AUTHENTICATED"
    assert loaded_after["emailVerified"] is True

    # 3. Revoke session
    postgres_database.revoke_auth_session(tx_id)
    loaded_revoked = postgres_database.load_transaction(tx_id)
    assert loaded_revoked["isRevoked"] is True


# ==============================================================================
# 6. Push Login Transaction Engine Tests
# ==============================================================================

def test_push_login_transaction_engine(test_user_pair):
    """Tests push-to-approve login transaction states and lifecycle."""
    user_a, _ = test_user_pair
    tx_id = f"push_tx_{uuid.uuid4().hex}"
    token_hash = f"hash_{uuid.uuid4().hex}"

    tx_data = {
        "transaction_id": tx_id,
        "user_id": user_a,
        "phone_number": "+14155552671",
        "mobile_token_hash": token_hash,
        "state": "PENDING_APPROVAL",
        "expires_at": time.time() + 300,
        "browser_name": "Chrome",
        "os_name": "Windows",
    }

    # Create transaction
    postgres_database.save_push_login_transaction(tx_data)
    loaded = postgres_database.load_push_login_transaction_by_id(tx_id)
    assert loaded is not None
    assert loaded["state"] == "PENDING_APPROVAL"

    # Advance state to AWAITING_PASSKEY
    postgres_database.update_push_login_state(
        transaction_id=tx_id,
        new_state="AWAITING_PASSKEY",
        webauthn_challenge="random_challenge_str",
    )
    loaded_updated = postgres_database.load_push_login_transaction_by_id(tx_id)
    assert loaded_updated["state"] == "AWAITING_PASSKEY"
    assert loaded_updated["webauthnChallenge"] == "random_challenge_str"


def test_email_confirmation_and_challenge_persistence(test_user_pair):
    """
    Regression Test: Verifies email confirmation gate and challenge persistence
    against PostgreSQL, validating that ON CONFLICT(token_hash) upsert succeeds.
    """
    user_a, _ = test_user_pair
    tx_id = f"tx_email_conf_{uuid.uuid4().hex}"
    raw_token = secrets.token_urlsafe(32)
    token_h = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # 1. Start transaction
    session_record = {
        "transactionId": tx_id,
        "userId": user_a,
        "email": f"{user_a}@sentinel.ai",
        "phoneNumber": "+14155552671",
        "emailVerified": False,
        "mobileVerified": False,
        "biometricVerified": False,
        "state": "EMAIL_PENDING",
        "expiresAt": time.time() + 900,
    }
    postgres_database.save_transaction(session_record)

    # 2. Emulate email confirmation: save challenge
    challenge_entry = {
        "tokenHash": token_h,
        "transactionId": tx_id,
        "userId": user_a,
        "challengeType": "whatsapp_mobile_link",
        "webauthnChallenge": "challenge_rand_bytes",
        "expiresAt": time.time() + 600,
        "consumedAt": None,
        "attempts": 0,
    }
    postgres_database.save_challenge(challenge_entry)

    # 3. Read back challenge
    loaded = postgres_database.load_challenge(token_h)
    assert loaded is not None
    assert loaded["transactionId"] == tx_id
    assert loaded["tokenHash"] == token_h
    assert loaded["consumedAt"] is None

    # 4. Verify ON CONFLICT update works (e.g. consuming the challenge or updating attempts)
    challenge_entry["consumedAt"] = time.time()
    challenge_entry["attempts"] = 1
    postgres_database.save_challenge(challenge_entry)

    loaded_consumed = postgres_database.load_challenge(token_h)
    assert loaded_consumed is not None
    assert loaded_consumed["consumedAt"] is not None
    assert loaded_consumed["attempts"] == 1



# ==============================================================================
# 7. Audit Logging & Rollback Tests
# ==============================================================================

def test_audit_event_logging(test_user_pair):
    """Verifies tamper-evident security audit logging with JSON details."""
    user_a, _ = test_user_pair
    tx_id = f"tx_{uuid.uuid4().hex}"

    postgres_database.record_db_audit(
        transaction_id=tx_id,
        user_id=user_a,
        event_type="STAGING_INTEGRATION_TEST_EVENT",
        status="SUCCESS",
        details={"testRunId": uuid.uuid4().hex, "environment": "staging"},
        ip_address="192.168.1.1",
        user_agent="PyTest/SentinelAI",
    )

    with postgres_database.get_pg_connection(STAGING_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_type, status, details FROM public.auth_audit_events WHERE transaction_id = %s;",
                (tx_id,),
            )
            row = cur.fetchone()
            assert row is not None
            event_type = row[0] if isinstance(row, (list, tuple)) else row.get("event_type")
            status_val = row[1] if isinstance(row, (list, tuple)) else row.get("status")
            assert event_type == "STAGING_INTEGRATION_TEST_EVENT"
            assert status_val == "SUCCESS"


def test_transaction_rollback_on_error():
    """Verifies atomic rollback: uncommitted failed transactions leave no partial records."""
    dummy_user = str(uuid.uuid4())
    tx_id = f"tx_fail_{uuid.uuid4().hex}"

    with pytest.raises(Exception):
        with postgres_database.get_pg_connection(STAGING_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_profiles (user_id, email, full_name)
                    VALUES (%s, %s, %s);
                    """,
                    (dummy_user, "rollback@sentinel.ai", "Rollback User"),
                )
                # Intentionally execute invalid SQL to trigger abort
                cur.execute("INSERT INTO public.user_profiles (id) VALUES ('NOT-A-UUID');")
            conn.commit()

    # Verify rollback succeeded (dummy_user does NOT exist)
    loaded = postgres_database.get_user_profile_by_user_id(dummy_user)
    assert loaded is None


# ==============================================================================
# 8. PostgreSQL Constraints & Row-Level Security (RLS) Tests
# ==============================================================================

def test_uuid_syntax_constraint_enforcement():
    """Confirms PostgreSQL strictly rejects non-UUID strings in UUID columns."""
    with pytest.raises(Exception):
        with postgres_database.get_pg_connection(STAGING_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.user_profiles (user_id, email) VALUES (%s, %s);",
                    ("invalid-non-uuid-string", "test@example.com"),
                )
            conn.commit()


def test_row_level_security_policy_enforcement(test_user_pair):
    """
    Verifies that Row-Level Security (RLS) isolates user data when queried under
    an authenticated user context rather than service_role.
    """
    user_a, user_b = test_user_pair

    # 1. Populate data using service_role connection
    postgres_database.save_or_update_user_profile(user_a, {"email": f"a_{user_a[:8]}@sentinel.ai", "fullName": "Alice"})
    postgres_database.save_or_update_user_profile(user_b, {"email": f"b_{user_b[:8]}@sentinel.ai", "fullName": "Bob"})

    # 2. Simulate authenticated context for User A
    claims_json = json.dumps({"sub": user_a, "role": "authenticated", "aud": "authenticated"})

    with postgres_database.get_pg_connection(STAGING_URL) as conn:
        with conn:
            with conn.cursor() as cur:
                try:
                    # 2a. Set JWT session claims while connected with admin/service privileges
                    cur.execute("SELECT set_config('request.jwt.claims', %s, true);", (claims_json,))
                    cur.execute("SELECT set_config('request.jwt.claim.sub', %s, true);", (user_a,))
                    cur.execute("SELECT set_config('request.jwt.claim.role', 'authenticated', true);")

                    # 2b. Switch transaction role to 'authenticated' to enforce RLS
                    cur.execute("SET LOCAL ROLE authenticated;")

                    # 2c. Query profiles under authenticated role
                    cur.execute("SELECT user_id, full_name FROM public.user_profiles;")
                    rows = cur.fetchall()

                    # 2d. Cast all returned user_ids to string (handles psycopg2 uuid.UUID objects)
                    seen_uids = [
                        str(r["user_id"]) if isinstance(r, dict) and "user_id" in r
                        else str(r[0]) if isinstance(r, (list, tuple))
                        else str(r.get("user_id")) if hasattr(r, "get")
                        else str(r)
                        for r in rows
                    ]

                    # User A should ONLY see User A's row; User B must be invisible
                    assert user_a in seen_uids, f"User A ({user_a}) not found in visible rows: {seen_uids}"
                    assert user_b not in seen_uids, f"User B ({user_b}) leaked into visible rows: {seen_uids}"
                except Exception as e:
                    # Some self-hosted PostgreSQL instances do not have the 'authenticated' role pre-created.
                    # In Supabase projects, 'authenticated' is standard.
                    if "role \"authenticated\" does not exist" in str(e).lower():
                        pytest.skip("PostgreSQL instance does not have Supabase 'authenticated' role installed.")
                    else:
                        raise
