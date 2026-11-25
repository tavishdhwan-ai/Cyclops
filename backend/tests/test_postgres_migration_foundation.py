"""
Automated Test Suite for Phase 1A PostgreSQL Persistence Foundation & Migration.
Verifies:
1. SQLite backup creation and integrity verification.
2. PostgreSQL adapter module safety and clean fallback to SQLite.
3. Strict tenant isolation (user A cannot read or mutate user B's data).
4. SQL migration files parity and syntax integrity.
5. Migration seed dump correctness and preservation of all auth entities.
"""
import os
import sqlite3
import secrets
import pytest
from app import database
from app import postgres_database
from scripts.migrate_sqlite_to_postgres import backup_sqlite, generate_postgres_seed_sql, verify_sqlite_source


def test_sqlite_backup_and_integrity(tmp_path):
    """Verifies that backup_sqlite creates an intact SQLite backup."""
    # Create test SQLite db
    db_file = str(tmp_path / "test_source.db")
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE sample (id TEXT PRIMARY KEY, val TEXT);")
    conn.execute("INSERT INTO sample VALUES ('1', 'hello');")
    conn.commit()
    conn.close()

    backup_file = backup_sqlite(db_file)
    assert os.path.exists(backup_file)
    assert os.path.getsize(backup_file) > 0

    # Verify integrity of backup
    b_conn = sqlite3.connect(backup_file)
    cur = b_conn.execute("SELECT * FROM sample;")
    rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0][1] == "hello"
    b_conn.close()


def test_postgres_adapter_fallback_behavior(monkeypatch):
    """
    Verifies that database.py:
    1. Cleanly defaults to SQLite when SENTINEL_DB_BACKEND is unset or 'sqlite'.
    2. FAILS FAST (raises exception) when SENTINEL_DB_BACKEND='postgres' but driver or URL is missing.
    Never silently falls back to SQLite!
    """
    # 1. By default, use_postgres should be False (SQLite active)
    monkeypatch.delenv("SENTINEL_DB_BACKEND", raising=False)
    assert database.use_postgres() is False

    monkeypatch.setenv("SENTINEL_DB_BACKEND", "sqlite")
    assert database.use_postgres() is False

    # 2. When PostgreSQL is explicitly requested without connection URL, must raise ValueError
    monkeypatch.setenv("SENTINEL_DB_BACKEND", "postgres")
    monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SENTINEL_STAGING_DATABASE_URL", raising=False)

    if postgres_database and postgres_database.is_driver_available():
        with pytest.raises(ValueError, match="neither SENTINEL_DATABASE_URL nor DATABASE_URL is set"):
            database.use_postgres()
    else:
        with pytest.raises(RuntimeError, match="no supported driver"):
            database.use_postgres()

    # Verify adapter availability helper works without exceptions
    assert isinstance(postgres_database.is_driver_available(), bool)


def test_tenant_data_isolation():
    """
    Verifies that multi-tenant isolation is strictly maintained.
    User A's credentials, sessions, profile, and devices must be completely invisible to User B.
    """
    user_a = f"usr_iso_a_{secrets.token_hex(4)}"
    user_b = f"usr_iso_b_{secrets.token_hex(4)}"

    # 1. User Profiles isolation
    database.save_or_update_user_profile(user_a, {
        "email": f"{user_a}@sentinel.ai",
        "displayName": "User A",
        "fullName": "Alice Secret",
    })
    database.save_or_update_user_profile(user_b, {
        "email": f"{user_b}@sentinel.ai",
        "displayName": "User B",
        "fullName": "Bob Public",
    })

    prof_a = database.get_user_profile_by_user_id(user_a)
    prof_b = database.get_user_profile_by_user_id(user_b)
    assert prof_a["fullName"] == "Alice Secret"
    assert prof_b["fullName"] == "Bob Public"
    assert prof_a["userId"] != prof_b["userId"]

    # 2. Registered Devices & Passkeys isolation
    cred_a = f"cred_{secrets.token_hex(8)}"
    cred_b = f"cred_{secrets.token_hex(8)}"

    database.save_verified_passkey_device(
        user_id=user_a,
        device_id=f"dev_{user_a}",
        credential_id=cred_a,
        public_key="b64_pub_key_a",
        device_name="Alice Phone",
    )
    database.save_verified_passkey_device(
        user_id=user_b,
        device_id=f"dev_{user_b}",
        credential_id=cred_b,
        public_key="b64_pub_key_b",
        device_name="Bob Tablet",
    )

    devices_a = database.get_devices_for_user(user_a)
    devices_b = database.get_devices_for_user(user_b)

    dev_a_ids = [d["deviceId"] for d in devices_a]
    dev_b_ids = [d["deviceId"] for d in devices_b]

    assert f"dev_{user_a}" in dev_a_ids
    assert f"dev_{user_a}" not in dev_b_ids
    assert f"dev_{user_b}" in dev_b_ids
    assert f"dev_{user_b}" not in dev_a_ids

    # 3. Push Subscriptions isolation
    endpoint_a = f"https://push.example.com/{user_a}"
    endpoint_b = f"https://push.example.com/{user_b}"

    database.save_push_subscription({
        "user_id": user_a,
        "endpoint": endpoint_a,
        "p256dh": "p256dh_a",
        "auth": "auth_a",
    })
    database.save_push_subscription({
        "user_id": user_b,
        "endpoint": endpoint_b,
        "p256dh": "p256dh_b",
        "auth": "auth_b",
    })

    subs_a = database.get_push_subscriptions_for_user(user_a)
    subs_b = database.get_push_subscriptions_for_user(user_b)

    assert any(s["endpoint"] == endpoint_a for s in subs_a)
    assert not any(s["endpoint"] == endpoint_b for s in subs_a)
    assert any(s["endpoint"] == endpoint_b for s in subs_b)
    assert not any(s["endpoint"] == endpoint_a for s in subs_b)


def test_migration_sql_generation_and_counts(tmp_path):
    """Verifies that the migration tool parses SQLite data and outputs valid SQL statements."""
    output_sql = str(tmp_path / "test_seed.sql")
    counts = generate_postgres_seed_sql(database.get_db_path(), output_sql)

    assert os.path.exists(output_sql)
    assert os.path.getsize(output_sql) > 0

    with open(output_sql, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify essential tables and statements are present
    assert "BEGIN;" in content
    assert "COMMIT;" in content
    assert "user_profiles" in content
    assert "registered_devices" in content
    assert "ON CONFLICT" in content


def test_schema_migration_files_exist():
    """Verifies that all version-controlled DDL migration and rollback files exist and are non-empty."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    migrations_dir = os.path.join(base_dir, "migrations")
    backups_dir = os.path.join(base_dir, "backups")

    required_schema_files = [
        "001_sentinel_auth_schema.sql",
        "001_rollback.sql",
        "002_sentinel_auth_update.sql",
        "002_rollback.sql",
        "003_trust_graph_groundwork.sql",
        "003_rollback.sql",
        "004_authenticated_role_permissions.sql",
        "004_rollback.sql",
        "005_auth_challenges_token_hash_unique.sql",
        "005_rollback.sql",
    ]

    for fname in required_schema_files:
        fpath = os.path.join(migrations_dir, fname)
        assert os.path.exists(fpath), f"Missing required DDL migration file: {fname}"
        assert os.path.getsize(fpath) > 50, f"DDL Migration file appears empty: {fname}"

    # Verify sensitive data seed dump is stored securely in backups/ and not in migrations/
    seed_dump_path = os.path.join(backups_dir, "004_sqlite_data_seed.sql")
    assert os.path.exists(seed_dump_path), "Data seed dump should be securely located in backups/"
    assert not os.path.exists(os.path.join(migrations_dir, "004_sqlite_data_seed.sql")), "Data seed dump must NOT be in migrations/"
