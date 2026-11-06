"""Test Session Management and Identity Controls — C7 (Secure Digital Identities).

Proves:
  - Session is regenerated on login (anti-session-fixation).
  - Session is thoroughly cleared on logout.
  - Idle session timeout is configured to 30 minutes.
  - Generic login errors prevent username enumeration.
"""

from datetime import timedelta
from flask import session


def test_c7_session_regenerated_on_login(client, alice_user):
    """Proves pre-login session state is purged and regenerated upon authentication."""
    # Seed pre-authentication session state
    with client.session_transaction() as sess:
        sess["pre_login_tracker"] = "pre_auth_probe_token"

    # Authenticate
    resp = client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    # Ensure pre-login session variables were cleared on authentication
    with client.session_transaction() as sess:
        assert "pre_login_tracker" not in sess
        assert "_user_id" in sess
        assert sess.permanent is True


def test_c7_session_cleared_on_logout(client, alice_user):
    """Proves session is completely cleared upon logout."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    with client.session_transaction() as sess:
        assert "_user_id" in sess

    # Logout
    logout_resp = client.post("/auth/logout", follow_redirects=True)
    assert logout_resp.status_code == 200

    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_c7_session_idle_timeout_configured(app):
    """Proves permanent session lifetime is set to 30 minutes."""
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=30)


def test_c7_generic_login_failure_prevents_username_enumeration(client, alice_user):
    """Proves failed login returns identical generic message for wrong password and unknown user."""
    # 1. Known user, wrong password
    resp1 = client.post(
        "/auth/login",
        data={"username": "alice", "password": "WrongPassword!"},
        follow_redirects=True,
    )
    assert b"Invalid credentials." in resp1.data

    # 2. Unknown user
    resp2 = client.post(
        "/auth/login",
        data={"username": "nonexistent_operator", "password": "AnyPassword!"},
        follow_redirects=True,
    )
    assert b"Invalid credentials." in resp2.data

    # Both scenarios produce the exact same visual flash notice
    assert resp1.status_code == resp2.status_code == 200


def test_c7_authenticated_user_redirected_from_login_and_no_cache_headers(client, alice_user):
    """Proves logged-in users cannot access /auth/login and cache headers prevent back-button caching."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    # Visiting /auth/login while authenticated must immediately redirect to vault
    resp_login = client.get("/auth/login")
    assert resp_login.status_code == 302
    assert "/notes/" in resp_login.headers["Location"]

    # Visiting /auth/register while authenticated must immediately redirect to vault
    resp_reg = client.get("/auth/register")
    assert resp_reg.status_code == 302
    assert "/notes/" in resp_reg.headers["Location"]

    # Verify anti-caching headers prevent browser back-forward cache exposure
    cache_ctrl = resp_login.headers.get("Cache-Control", "")
    assert "no-store" in cache_ctrl
    assert "no-cache" in cache_ctrl
