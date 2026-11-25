#!/usr/bin/env python3
"""
Sentinel AI SQLite -> Supabase PostgreSQL Data Migration & Verification Tool.
Phase 1B Hardened & Sanitized Version:
1. Creates a verified, timestamped backup of sentinel_auth.db.
2. Inspects, classifies, and filters records across all 7 authentication tables.
3. STRICT UUID ENFORCEMENT: Rejects synthetic test accounts (e.g. 'usr_lifecycle_1')
   from production seed files to prevent PostgreSQL UUID syntax and FK constraint failures.
4. AUTOMATIC EXPIRY PRUNING: Filters out expired sessions, consumed/expired challenges,
   and expired push login transactions.
5. PRIMARY KEY UUID SANITIZATION: In PostgreSQL, id columns for audit events and transactions
   are UUIDs. Strips invalid string IDs so PostgreSQL generates clean UUIDs via gen_random_uuid().
6. OPTIONAL STAGING MODE (--deterministic-uuids): Maps non-UUID test identifiers
   to deterministic UUIDv5 strings for isolated staging integration tests.
7. Zero credential exposure: Never prints raw tokens, private keys, or hashes to logs.
"""
import os
import sys
import uuid
import time
import shutil
import sqlite3
import argparse
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Set, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.migrate")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_SQLITE_PATH = os.path.join(BACKEND_DIR, "sentinel_auth.db")
BACKUPS_DIR = os.path.join(BACKEND_DIR, "backups")

TABLE_ORDER = [
    "user_profiles",
    "auth_sessions",
    "auth_challenges",
    "registered_devices",
    "push_subscriptions",
    "push_login_transactions",
    "auth_audit_events",
]

# Namespace for deterministic UUID mapping when running test simulations
TEST_UUID_NAMESPACE = uuid.UUID("a7c1e550-98b4-4b9e-b9b5-c7e4fa9b0e12")


def is_valid_uuid(val: Any) -> bool:
    """Checks whether a value is a valid RFC 4122 UUID string."""
    if not val or not isinstance(val, str):
        return False
    try:
        val_clean = val.strip()
        parsed = uuid.UUID(val_clean)
        return str(parsed).lower() == val_clean.lower()
    except (ValueError, AttributeError):
        return False


def map_to_uuid(val: Any, allow_deterministic: bool = False) -> Optional[str]:
    """
    Returns valid UUID string, or deterministically generates UUIDv5 if allow_deterministic is True.
    Returns None if invalid and deterministic generation is disabled.
    """
    if is_valid_uuid(val):
        return str(uuid.UUID(val.strip())).lower()
    if allow_deterministic and val and isinstance(val, str):
        return str(uuid.uuid5(TEST_UUID_NAMESPACE, val.strip())).lower()
    return None


def parse_timestamp_epoch(val: Any) -> float:
    """Converts int, float, or ISO string to UTC epoch timestamp."""
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


def backup_sqlite(sqlite_path: str) -> str:
    """Creates a verified timestamped backup of the SQLite database."""
    if not os.path.exists(sqlite_path):
        logger.warning(f"SQLite file not found at {sqlite_path}. Nothing to back up.")
        return ""

    os.makedirs(BACKUPS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"sentinel_auth_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUPS_DIR, backup_filename)

    src_conn = sqlite3.connect(sqlite_path)
    dst_conn = sqlite3.connect(backup_path)
    with dst_conn:
        src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()

    verify_conn = sqlite3.connect(backup_path)
    integrity = verify_conn.execute("PRAGMA integrity_check;").fetchone()
    verify_conn.close()

    if not integrity or integrity[0] != "ok":
        raise RuntimeError(f"Backup integrity check failed: {integrity}")

    size_kb = os.path.getsize(backup_path) / 1024
    logger.info(f"Verified SQLite backup created: {backup_path} ({size_kb:.1f} KB)")
    return backup_path


def format_sql_value(val: Any, col_type: str = "") -> str:
    """Formats Python values as valid PostgreSQL literals."""
    if val is None:
        return "NULL"
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if isinstance(val, (int, float)):
        if "at" in col_type.lower() or "expires" in col_type.lower() or "time" in col_type.lower():
            if val > 0:
                return f"to_timestamp({float(val):.3f})"
            return "NULL"
        return str(val)
    if isinstance(val, (dict, list)):
        import json
        escaped = json.dumps(val).replace("'", "''")
        return f"'{escaped}'::jsonb"
    escaped = str(val).replace("'", "''")
    return f"'{escaped}'"


def extract_table_data(conn: sqlite3.Connection, table_name: str) -> List[Dict[str, Any]]:
    """Extracts all rows from an SQLite table with dict keys."""
    try:
        cur = conn.execute(f"SELECT * FROM {table_name};")
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError as e:
        logger.warning(f"Table {table_name} does not exist in SQLite: {e}")
        return []


def generate_postgres_seed_sql(
    sqlite_path: str,
    output_path: str,
    allow_deterministic_uuids: bool = False,
    include_expired: bool = False,
) -> Dict[str, Any]:
    """
    Generates a safe, sanitized, idempotent PostgreSQL seed script from SQLite data.
    - Validates UUIDs against RFC 4122
    - Discards orphaned records
    - Prunes expired sessions/challenges unless explicitly requested
    - Excludes test audit events in production mode
    """
    if not os.path.exists(sqlite_path):
        logger.warning(f"Source SQLite database does not exist: {sqlite_path}")
        return {}

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    now_epoch = time.time()

    lines = [
        "-- ==============================================================================",
        "-- Auto-Generated Sanitized Data Seed for Supabase PostgreSQL",
        f"-- Exported on: {datetime.now(timezone.utc).isoformat()}",
        f"-- Deterministic UUID Mode: {allow_deterministic_uuids}",
        f"-- Include Expired Mode: {include_expired}",
        "-- Safe & Idempotent: Uses ON CONFLICT DO NOTHING to protect existing records.",
        "-- ==============================================================================",
        "",
        "BEGIN;",
        "",
    ]

    stats = {
        "scanned": {},
        "exported": {},
        "filtered_non_uuid": {},
        "filtered_orphaned": {},
        "pruned_expired": {},
    }

    # Pass 1: Identify valid user IDs to enforce referential integrity
    raw_profiles = extract_table_data(conn, "user_profiles")
    valid_user_ids: Set[str] = set()

    for p in raw_profiles:
        mapped_uid = map_to_uuid(p.get("user_id"), allow_deterministic=allow_deterministic_uuids)
        if mapped_uid:
            valid_user_ids.add(mapped_uid)

    logger.info(f"Discovered {len(valid_user_ids)} valid user IDs for export.")

    # Pass 2: Process each table with strict validation
    for table in TABLE_ORDER:
        rows = extract_table_data(conn, table)
        stats["scanned"][table] = len(rows)
        stats["exported"][table] = 0
        stats["filtered_non_uuid"][table] = 0
        stats["filtered_orphaned"][table] = 0
        stats["pruned_expired"][table] = 0

        lines.append(f"-- ----------------------------------------------------------------------")
        lines.append(f"-- Table: public.{table}")
        lines.append(f"-- ----------------------------------------------------------------------")

        exported_in_table = 0

        for r in rows:
            uid_val = r.get("user_id")
            mapped_uid = None

            # Special audit events handling:
            if table == "auth_audit_events":
                # In production mode, if there are no real production users associated, skip test logs
                if uid_val is not None:
                    mapped_uid = map_to_uuid(uid_val, allow_deterministic=allow_deterministic_uuids)
                    if not mapped_uid or mapped_uid not in valid_user_ids:
                        stats["filtered_orphaned"][table] += 1
                        continue
                else:
                    # Anonymous or system events with no real user
                    if not allow_deterministic_uuids and not valid_user_ids:
                        # No production users exist in SQLite; all audit events are from automated test runs
                        stats["filtered_non_uuid"][table] += 1
                        continue
            else:
                if uid_val is not None:
                    mapped_uid = map_to_uuid(uid_val, allow_deterministic=allow_deterministic_uuids)
                    if not mapped_uid:
                        stats["filtered_non_uuid"][table] += 1
                        continue
                    if mapped_uid not in valid_user_ids:
                        stats["filtered_orphaned"][table] += 1
                        continue

            # Check expiration for ephemeral records
            if not include_expired:
                exp_epoch = parse_timestamp_epoch(r.get("expires_at"))
                if exp_epoch > 0 and exp_epoch < now_epoch:
                    stats["pruned_expired"][table] += 1
                    continue
                if table == "auth_challenges" and r.get("consumed_at"):
                    stats["pruned_expired"][table] += 1
                    continue
                if table == "auth_sessions" and (r.get("revoked_at") or r.get("is_revoked")):
                    stats["pruned_expired"][table] += 1
                    continue
                if table == "push_login_transactions":
                    st = r.get("state") or r.get("status")
                    if st in ("approved", "rejected", "expired"):
                        stats["pruned_expired"][table] += 1
                        continue

            # Transform columns
            cols = list(r.keys())
            pg_cols = []
            pg_vals = []
            for col in cols:
                # Omit non-UUID primary keys for tables where PG expects UUID
                if col == "id" and table in ("auth_audit_events", "push_login_transactions"):
                    raw_id = r[col]
                    if not is_valid_uuid(raw_id):
                        if allow_deterministic_uuids and raw_id:
                            val = str(uuid.uuid5(TEST_UUID_NAMESPACE, str(raw_id))).lower()
                            pg_cols.append(col)
                            pg_vals.append(f"'{val}'::uuid")
                        # If not deterministic, omit column to let PG use DEFAULT gen_random_uuid()
                        continue

                val = r[col]
                if col == "user_id" and mapped_uid:
                    val = mapped_uid

                # Boolean conversions
                if col in ("email_verified", "mobile_verified", "biometric_verified", "is_revoked",
                           "is_active", "phone_verified", "onboarding_completed",
                           "notify_new_device", "notify_new_passkey", "notify_failed_login", "notify_security_changes"):
                    val = bool(val)

                # Concerns array conversion for user_profiles
                if table == "user_profiles" and col == "concerns":
                    import json
                    try:
                        parsed = json.loads(val) if isinstance(val, str) else (val or [])
                    except Exception:
                        parsed = []
                    formatted_val = f"ARRAY[{', '.join(repr(str(x)) for x in parsed)}]::text[]" if parsed else "'{}'::text[]"
                    pg_cols.append(col)
                    pg_vals.append(formatted_val)
                    continue

                pg_cols.append(col)
                pg_vals.append(format_sql_value(val, col))

            col_names_str = ", ".join(pg_cols)
            col_vals_str = ", ".join(pg_vals)

            # Conflict target resolution
            conflict_col = "id"
            if table == "user_profiles":
                conflict_col = "user_id"
            elif table in ("auth_sessions", "push_login_transactions"):
                conflict_col = "transaction_id"
            elif table == "auth_challenges":
                conflict_col = "token_hash"
            elif table == "push_subscriptions":
                conflict_col = "endpoint"
            elif table == "registered_devices":
                conflict_col = "device_id"
            elif table == "auth_audit_events":
                conflict_col = "transaction_id" if "transaction_id" in pg_cols else "id"

            lines.append(
                f"INSERT INTO public.{table} ({col_names_str}) VALUES ({col_vals_str}) "
                f"ON CONFLICT ({conflict_col}) DO NOTHING;"
            )
            exported_in_table += 1

        stats["exported"][table] = exported_in_table
        if exported_in_table == 0:
            lines.append(f"-- 0 valid records exported for {table} (all filtered or pruned).")
        lines.append("")

    lines.append("COMMIT;")
    lines.append("")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    conn.close()
    logger.info(f"Generated sanitized PostgreSQL seed script: {output_path}")
    return stats


def verify_sqlite_source(sqlite_path: str) -> Dict[str, Any]:
    """Inspects and returns summary of records in the SQLite database."""
    if not os.path.exists(sqlite_path):
        return {"status": "absent", "counts": {}}

    conn = sqlite3.connect(sqlite_path)
    counts = {}
    for table in TABLE_ORDER:
        try:
            cur = conn.execute(f"SELECT COUNT(*) FROM {table};")
            counts[table] = cur.fetchone()[0]
        except Exception:
            counts[table] = 0
    conn.close()
    return {"status": "ok", "counts": counts}


def main():
    parser = argparse.ArgumentParser(description="Sentinel AI Sanitized SQLite -> PostgreSQL Migration Tool")
    parser.add_argument("--sqlite-path", default=DEFAULT_SQLITE_PATH, help="Path to SQLite database")
    parser.add_argument("--output-sql", default=os.path.join(BACKUPS_DIR, "004_sqlite_data_seed_sanitized.sql"), help="Output SQL dump path")
    parser.add_argument("--deterministic-uuids", action="store_true", help="Generate deterministic UUIDv5 for non-UUID test records (staging simulation only)")
    parser.add_argument("--include-expired", action="store_true", help="Do not prune expired sessions/challenges")
    args = parser.parse_args()

    logger.info("Starting Phase 1B Sanitized SQLite -> PostgreSQL Data Export...")

    # Step 1: Backup SQLite
    backup_file = backup_sqlite(args.sqlite_path)

    # Step 2: Verify Source SQLite Data
    info = verify_sqlite_source(args.sqlite_path)
    logger.info(f"SQLite Source Record Counts: {info['counts']}")

    # Step 3: Generate Sanitized SQL Dump
    stats = generate_postgres_seed_sql(
        args.sqlite_path,
        args.output_sql,
        allow_deterministic_uuids=args.deterministic_uuids,
        include_expired=args.include_expired,
    )

    logger.info("----------------------------------------------------------------")
    logger.info("MIGRATION SANITIZATION & EXPORT COMPLETED")
    logger.info(f"  Backup File:                 {backup_file}")
    logger.info(f"  Sanitized SQL Dump:          {args.output_sql}")
    logger.info(f"  Deterministic UUID Mode:     {args.deterministic_uuids}")
    logger.info(f"  Export Summary by Table:")
    for tbl in TABLE_ORDER:
        scanned = stats['scanned'].get(tbl, 0)
        exported = stats['exported'].get(tbl, 0)
        filtered_uuid = stats['filtered_non_uuid'].get(tbl, 0)
        orphaned = stats['filtered_orphaned'].get(tbl, 0)
        pruned = stats['pruned_expired'].get(tbl, 0)
        logger.info(f"    {tbl:26}: Scanned={scanned:4} | Exported={exported:4} | Non-UUID={filtered_uuid:4} | Orphaned={orphaned:4} | Pruned Expired={pruned:4}")
    logger.info("----------------------------------------------------------------")


if __name__ == "__main__":
    main()
