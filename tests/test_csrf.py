"""Test Cross-Site Request Forgery (CSRF) protections — C8 (Leverage Browser Security Features).

Proves that:
  - Any state-changing POST request without a CSRF token is rejected (HTTP 400).
  - Valid CSRF tokens permit state-changing actions.
"""

import re
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db
from app.models import Note, User
from app.security.passwords import hash_password


class CsrfEnabledTestConfig(TestConfig):
    WTF_CSRF_ENABLED = True


@pytest.fixture
def csrf_app():
    """App instance with CSRF protection strictly enabled."""
    app = create_app(CsrfEnabledTestConfig)
    with app.app_context():
        db.create_all()
        user = User(
            username="csrf_user",
            password_hash=hash_password("UserPass123!"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


def _extract_csrf_token(html_text: str) -> str:
    """Extract CSRF token value from HTML form hidden field."""
    match = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html_text)
    if not match:
        match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html_text)
    assert match is not None, "CSRF token not found in response HTML"
    return match.group(1)


def test_c8_post_without_csrf_token_rejected(csrf_app):
    """Proves state-changing POST without CSRF token is blocked with HTTP 400."""
    client = csrf_app.test_client()

    # Attempt to post login credentials without CSRF token
    resp = client.post(
        "/auth/login",
        data={"username": "csrf_user", "password": "UserPass123!"},
    )
    assert resp.status_code == 400
    assert b"CSRF" in resp.data or b"Bad Request" in resp.data


def test_c8_post_with_valid_csrf_token_accepted(csrf_app):
    """Proves state-changing POST with valid CSRF token is accepted."""
    client = csrf_app.test_client()

    # 1. Fetch login form to obtain genuine CSRF token and session cookie
    get_resp = client.get("/auth/login")
    assert get_resp.status_code == 200
    token = _extract_csrf_token(get_resp.get_data(as_text=True))

    # 2. Submit login with the valid CSRF token
    post_resp = client.post(
        "/auth/login",
        data={
            "csrf_token": token,
            "username": "csrf_user",
            "password": "UserPass123!",
        },
        follow_redirects=True,
    )
    assert post_resp.status_code == 200
    assert b"VAULT RECORDS" in post_resp.data
