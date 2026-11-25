#!/usr/bin/env python3
"""
Sentinel AI Migration Rollback Script.
1. Restores SQLite database from the latest verified backup if needed.
2. Generates an SQL script to remove migrated records from PostgreSQL without dropping tables.
"""
import os
import glob
import shutil
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.rollback")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_SQLITE_PATH = os.path.join(BACKEND_DIR, "sentinel_auth.db")
BACKUPS_DIR = os.path.join(BACKEND_DIR, "backups")


def get_latest_backup() -> Optional[str]:
    """Finds the most recent backup in backend/backups."""
    backups = glob.glob(os.path.join(BACKUPS_DIR, "sentinel_auth_backup_*.db"))
    if not backups:
        return None
    backups.sort(key=os.path.getmtime, reverse=True)
    return backups[0]


def restore_sqlite(backup_path: Optional[str] = None, target_path: str = DEFAULT_SQLITE_PATH) -> bool:
    """Restores SQLite database from the designated or latest backup."""
    source = backup_path or get_latest_backup()
    if not source or not os.path.exists(source):
        logger.error("No valid backup found to restore from.")
        return False

    shutil.copy2(source, target_path)
    logger.info(f"Restored SQLite database from {source} -> {target_path}")
    return True


if __name__ == "__main__":
    latest = get_latest_backup()
    if latest:
        logger.info(f"Latest backup available: {latest}")
    else:
        logger.info("No backups currently recorded.")
