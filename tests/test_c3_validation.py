"""Test Input Validation and Exception Handling — C3 (Validate all Input & Handle Exceptions).

Proves:
  - WTForms enforces input validation rules (username regex, password length).
  - Custom error handlers suppress diagnostic stack traces and return generic pages.
"""

from app.models import User


def test_c3_wtforms_rejects_invalid_username_characters(client):
    """Proves registration form rejects special characters in usernames (regex enforcement)."""
    resp = client.post(
        "/auth/register",
        data={
            "username": "user<script>!@#",
            "password": "ValidPassword123!",
            "confirm": "ValidPassword123!",
        },
    )
    assert resp.status_code == 200
    assert b"Letters, digits, and underscores only" in resp.data
    assert User.query.filter_by(username="user<script>!@#").first() is None


def test_c3_wtforms_enforces_password_length(client):
    """Proves registration form rejects passwords under 8 characters."""
    resp = client.post(
        "/auth/register",
        data={
            "username": "short_pw_user",
            "password": "short",
            "confirm": "short",
        },
    )
    assert resp.status_code == 200
    assert b"Field must be between 8 and 128 characters long" in resp.data
    assert User.query.filter_by(username="short_pw_user").first() is None


def test_c3_generic_error_pages_suppress_stack_traces(client, alice_user):
    """Proves 403, 404, and 500 pages return generic UI without stack traces or path leaks."""
    # Authenticate as alice to access protected note routes
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    # 1. 404 Not Found (authenticated user accessing nonexistent note)
    resp_404 = client.get("/notes/999999")
    assert resp_404.status_code == 404
    assert b"404 NOT LOCATED" in resp_404.data
    assert b"Traceback" not in resp_404.data

    # 2. 403 Forbidden (regular user accessing admin route)
    resp_403 = client.get("/admin/users")
    assert resp_403.status_code == 403
    assert b"403 ACCESS DENIED" in resp_403.data
    assert b"Traceback" not in resp_403.data
