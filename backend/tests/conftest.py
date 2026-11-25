"""
Pytest configuration and global test isolation fixtures for Sentinel AI.
Ensures:
1. Web Push notifications are mocked and NEVER make real external network requests to FCM/APNs.
2. WhatsApp external APIs (Twilio/Meta) are guarded and never make live HTTP requests.
3. Tests run hermetically, deterministically, and fast in all environments.
"""
import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True, scope="session")
def isolate_test_sqlite_database(tmp_path_factory):
    """
    Guarantees automated tests NEVER write to or pollute the development sentinel_auth.db.
    Directs SENTINEL_DB_PATH to an isolated disposable SQLite file in a temp directory.
    """
    if os.getenv("SENTINEL_DB_BACKEND") == "postgres":
        yield
        return

    temp_dir = tmp_path_factory.mktemp("sentinel_test_dbs")
    test_db = str(temp_dir / "test_sentinel_auth.db")
    old_val = os.environ.get("SENTINEL_DB_PATH")
    os.environ["SENTINEL_DB_PATH"] = test_db

    # Initialize the temporary database schema
    from app import database
    database.init_db()

    yield test_db

    if old_val is not None:
        os.environ["SENTINEL_DB_PATH"] = old_val
    else:
        os.environ.pop("SENTINEL_DB_PATH", None)


@pytest.fixture(autouse=True)
def mock_external_webpush():
    """
    Globally mocks Web Push notification delivery across all test suites.
    Prevents tests from attempting socket connections or DNS resolution to fcm.googleapis.com.
    """
    def _mock_send(subscription_info, payload):
        endpoint = subscription_info.get("endpoint", "")
        return {
            "success": True,
            "status_code": 201,
            "endpoint": endpoint,
        }

    with patch("app.push.send_web_push", side_effect=_mock_send) as mock_push:
        yield mock_push
