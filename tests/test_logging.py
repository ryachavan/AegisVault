"""Test Security Logging and Monitoring — C9 (Implement Security Logging and Monitoring).

Proves that:
  - Failed logins write [LOGIN_FAILED] entries.
  - Successful logins write [LOGIN_SUCCESS] entries.
  - Role modifications write [ROLE_CHANGED] entries.
  - Blocked SSRF attempts write [SSRF_BLOCKED] entries.
  - Admin users can review the log stream via /admin/logs.
  - A RotatingFileHandler protects against disk exhaustion.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

import pytest

from app.extensions import db
from app.models import User
from app.security.ssrf import SafeFetchError, safe_fetch_url


def _read_security_log(app) -> str:
    """Read contents of the security log file."""
    log_path = app.config.get("SECURITY_LOG_FILE", "logs/test_security.log")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return ""


def test_c9_rotating_log_handler_configured(app):
    """Proves rotating file handler is attached to the security logger."""
    sec_logger = logging.getLogger("security")
    rotating_handlers = [h for h in sec_logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(rotating_handlers) >= 1
    handler = rotating_handlers[0]
    assert handler.maxBytes == 1_048_576  # 1 MB
    assert handler.backupCount == 5


def test_c9_failed_login_logged(client, app, alice_user):
    """Proves failed login attempts log LOGIN_FAILED."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "WrongPassword!"},
    )
    content = _read_security_log(app)
    assert "[LOGIN_FAILED]" in content
    assert "username=alice" in content


def test_c9_successful_login_logged(client, app, alice_user):
    """Proves successful login attempts log LOGIN_SUCCESS."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
    )
    content = _read_security_log(app)
    assert "[LOGIN_SUCCESS]" in content
    assert "username=alice" in content


def test_c9_role_change_logged(client, app, admin_user, bob_user):
    """Proves administrative role modifications log ROLE_CHANGED."""
    client.post(
        "/auth/login",
        data={"username": "secadmin", "password": "AdminSecretPass123!"},
    )

    client.post(
        "/admin/users/change-role",
        data={"user_id": str(bob_user), "role": "admin"},
        follow_redirects=True,
    )

    content = _read_security_log(app)
    assert "[ROLE_CHANGED]" in content
    assert "target_user=bob" in content
    assert "new_role=admin" in content


def test_c9_ssrf_blocked_logged(app):
    """Proves blocked SSRF requests log SSRF_BLOCKED."""
    with pytest.raises(SafeFetchError):
        safe_fetch_url("http://127.0.0.1:8080/probe")

    content = _read_security_log(app)
    assert "[SSRF_BLOCKED]" in content
    assert "127.0.0.1:8080" in content


def test_c9_admin_can_view_logs(client, app, admin_user):
    """Proves admin user can view the security log in the UI."""
    client.post(
        "/auth/login",
        data={"username": "secadmin", "password": "AdminSecretPass123!"},
    )

    resp = client.get("/admin/logs")
    assert resp.status_code == 200
    assert b"SIEM AUDIT TRAIL" in resp.data
    assert b"daemon://logs/security.log" in resp.data
