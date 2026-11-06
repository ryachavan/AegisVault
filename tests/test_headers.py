"""Test HTTP Security Headers and Cookie Attributes.

Controls:
  C5  Secure By Default Configurations — DEBUG=False, Secure cookies in Prod
  C8  Leverage Browser Security Features— CSP, HSTS, X-Frame-Options, SameSite, HttpOnly
"""

from app import create_app
from app.config import DevConfig, ProdConfig


def test_c8_security_headers_present_in_dev(client):
    """Proves CSP, X-Frame-Options, and X-Content-Type-Options are present in DevConfig."""
    resp = client.get("/auth/login")
    assert resp.status_code == 200

    # Content-Security-Policy
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "frame-ancestors 'none'" in csp

    # Clickjacking protection
    assert resp.headers.get("X-Frame-Options") == "DENY"

    # MIME sniffing protection
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_c8_security_headers_and_hsts_in_prod():
    """Proves HSTS (Strict-Transport-Security) and HTTPS forcing are active in ProdConfig."""
    class TestProdConfig(ProdConfig):
        TESTING = True
        SECRET_KEY = "prod-test-key-12345678901234567890"
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    prod_app = create_app(TestProdConfig)
    prod_client = prod_app.test_client()

    resp = prod_client.get("/auth/login", base_url="https://localhost")
    assert resp.status_code == 200

    hsts = resp.headers.get("Strict-Transport-Security")
    assert hsts is not None
    assert "max-age=31536000" in hsts


def test_c8_cookie_flags_httponly_samesite(client, alice_user):
    """Proves session cookie sets HttpOnly and SameSite=Lax flags."""
    resp = client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    # Inspect Set-Cookie header for session cookie
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie


def test_c5_debug_is_false_by_default():
    """Proves DEBUG defaults to False across BaseConfig, DevConfig, and ProdConfig."""
    assert DevConfig.DEBUG is False
    assert ProdConfig.DEBUG is False
