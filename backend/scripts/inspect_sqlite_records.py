"""
Inspect SQLite records in sentinel_auth.db for Phase 1B PostgreSQL migration verification.
Classifies records into:
1. Long-lived user data (user_profiles)
2. Security credentials & devices (registered_devices, passkeys)
3. Ephemeral / temporary records (auth_sessions, auth_challenges, push_login_transactions)
4. Test/demo records vs real user accounts
5. UUID validity and orphaned relationships.

STRICT SAFETY: Does NOT print raw tokens, private keys, hashes, or credentials.
"""
import sqlite3
import uuid
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("backend/sentinel_auth.db")

def is_valid_uuid(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    try:
        val_clean = val.strip()
        parsed = uuid.UUID(val_clean)
        return str(parsed) == val_clean.lower()
    except (ValueError, AttributeError):
        return False

def normalize_timestamp_to_epoch(val) -> float:
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.timestamp()
        except Exception:
            return 0.0
    return 0.0

def inspect_database():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH} not found.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    print(f"=== SQLite Database Tables ({len(tables)}) ===")
    print(", ".join(tables))
    print()

    for tbl in tables:
        cols = [r["name"] for r in cursor.execute(f"PRAGMA table_info({tbl})").fetchall()]
        print(f"Table '{tbl}' columns: {cols}")
    print()

    # 1. Inspect user_profiles
    cursor.execute("SELECT * FROM user_profiles")
    profiles = cursor.fetchall()
    print(f"=== User Profiles ({len(profiles)} records) ===")
    uuid_users = set()
    non_uuid_users = set()

    for p in profiles:
        uid = p["user_id"]
        valid = is_valid_uuid(uid)
        email = p["email"] if "email" in p.keys() else ""
        phone = p["phone_number"] if "phone_number" in p.keys() else ""
        masked_email = email[:3] + "***@" + email.split("@")[-1] if email and "@" in email else "none"
        masked_phone = phone[:4] + "***" + phone[-2:] if phone and len(phone) > 6 else "none"
        if valid:
            uuid_users.add(uid)
            print(f"  [VALID UUID] user_id={uid} | email={masked_email} | phone={masked_phone}")
        else:
            non_uuid_users.add(uid)
            print(f"  [NON-UUID / TEST] user_id={uid} | email={masked_email} | phone={masked_phone}")

    print(f"Total UUID Users: {len(uuid_users)}, Non-UUID Users: {len(non_uuid_users)}\n")

    # 2. Inspect registered_devices
    cursor.execute("SELECT * FROM registered_devices")
    devices = cursor.fetchall()
    print(f"=== Registered Devices & Credentials ({len(devices)} records) ===")
    orphaned_devices = []
    test_devices = []
    valid_devices = []

    for d in devices:
        dev_id = d["id"]
        uid = d["user_id"]
        has_cred = bool(d["credential_id"]) if "credential_id" in d.keys() else False
        rev_val = d["revoked_at"] if "revoked_at" in d.keys() else None
        is_revoked = bool(rev_val)
        dev_type = d["device_type"] if "device_type" in d.keys() else "unknown"
        if uid not in uuid_users and uid not in non_uuid_users:
            orphaned_devices.append(dev_id)
        elif uid in non_uuid_users:
            test_devices.append(dev_id)
        else:
            valid_devices.append(dev_id)
    print(f"Valid devices (UUID): {len(valid_devices)}, Test devices (Non-UUID): {len(test_devices)}, Orphaned (no user): {len(orphaned_devices)}\n")

    # 3. Inspect push_subscriptions
    cursor.execute("SELECT * FROM push_subscriptions")
    subs = cursor.fetchall()
    print(f"=== Web Push Subscriptions ({len(subs)} records) ===")
    orphaned_subs = []
    test_subs = []
    valid_subs = []
    for s in subs:
        sid = s["id"]
        uid = s["user_id"]
        if uid not in uuid_users and uid not in non_uuid_users:
            orphaned_subs.append(sid)
        elif uid in non_uuid_users:
            test_subs.append(sid)
        else:
            valid_subs.append(sid)
    print(f"Valid subs (UUID): {len(valid_subs)}, Test subs (Non-UUID): {len(test_subs)}, Orphaned (no user): {len(orphaned_subs)}\n")

    # 4. Inspect auth_sessions
    now_epoch = time.time()
    cursor.execute("SELECT * FROM auth_sessions")
    sessions = cursor.fetchall()
    print(f"=== Auth Sessions ({len(sessions)} records) ===")
    active_valid_sessions = []
    expired_sessions = []
    revoked_sessions = []
    orphaned_sessions = []
    test_sessions = []

    for s in sessions:
        sid = s["id"]
        uid = s["user_id"]
        exp_epoch = normalize_timestamp_to_epoch(s["expires_at"] if "expires_at" in s.keys() else None)
        rev = s["revoked_at"] if "revoked_at" in s.keys() else (s["is_revoked"] if "is_revoked" in s.keys() else 0)
        is_expired = exp_epoch > 0 and exp_epoch < now_epoch
        if uid not in uuid_users and uid not in non_uuid_users:
            orphaned_sessions.append(sid)
        elif rev:
            revoked_sessions.append(sid)
        elif is_expired:
            expired_sessions.append(sid)
        elif uid in non_uuid_users:
            test_sessions.append(sid)
        else:
            active_valid_sessions.append(sid)

    print(f"Active Valid UUID Sessions: {len(active_valid_sessions)}")
    print(f"Expired Sessions (prunable): {len(expired_sessions)}")
    print(f"Revoked Sessions (prunable): {len(revoked_sessions)}")
    print(f"Test Sessions (synthetic): {len(test_sessions)}")
    print(f"Orphaned Sessions (missing user): {len(orphaned_sessions)}\n")

    # 5. Inspect push_login_transactions
    cursor.execute("SELECT * FROM push_login_transactions")
    txs = cursor.fetchall()
    print(f"=== Push Login Transactions ({len(txs)} records) ===")
    active_txs = []
    expired_txs = []
    for tx in txs:
        exp_epoch = normalize_timestamp_to_epoch(tx["expires_at"] if "expires_at" in tx.keys() else None)
        is_expired = exp_epoch > 0 and exp_epoch < now_epoch
        st = tx["state"] if "state" in tx.keys() else (tx["status"] if "status" in tx.keys() else "")
        if is_expired or st in ("approved", "rejected", "expired"):
            expired_txs.append(tx["id"])
        else:
            active_txs.append(tx["id"])
    print(f"Active Transactions: {len(active_txs)}")
    print(f"Completed / Expired Transactions: {len(expired_txs)}\n")

    # 6. Inspect auth_challenges
    cursor.execute("SELECT * FROM auth_challenges")
    chals = cursor.fetchall()
    print(f"=== Auth Challenges ({len(chals)} records) ===")
    active_chals = []
    consumed_or_expired_chals = []
    for c in chals:
        exp_epoch = normalize_timestamp_to_epoch(c["expires_at"] if "expires_at" in c.keys() else None)
        is_expired = exp_epoch > 0 and exp_epoch < now_epoch
        cons = c["consumed_at"] if "consumed_at" in c.keys() else None
        if is_expired or cons:
            consumed_or_expired_chals.append(c["id"])
        else:
            active_chals.append(c["id"])
    print(f"Active Challenges: {len(active_chals)}")
    print(f"Consumed/Expired Challenges: {len(consumed_or_expired_chals)}\n")

    # 7. Audit events
    for evt_table in ["auth_audit_events", "security_audit_events"]:
        if evt_table in tables:
            cursor.execute(f"SELECT count(*) FROM {evt_table}")
            cnt = cursor.fetchone()[0]
            print(f"=== {evt_table} ({cnt} records) ===")

    conn.close()

if __name__ == "__main__":
    inspect_database()
