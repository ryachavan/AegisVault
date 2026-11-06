"""Configuration — C2 (Use Cryptography), C5 (Secure By Default Configurations).

SECRET_KEY is loaded from the environment and NEVER hardcoded.
The app factory refuses to start without one (except in TestConfig).
DEBUG defaults to False in every config class.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    # ── C2: Use Cryptography to Protect Data ───────────────────────
    # SECRET_KEY must come from the environment; no default.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # ── Database (C3: ORM-only, no raw SQL) ────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///secure_notes.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── C5: Secure By Default Configurations ───────────────────────
    DEBUG = False
    TESTING = False

    # ── C7: Secure Digital Identities — session settings ───────────
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # ── C8: Leverage Browser Security Features — CSRF always on ────
    WTF_CSRF_ENABLED = True

    # ── C7: Rate limiting storage ──────────────────────────────────
    RATELIMIT_STORAGE_URI = "memory://"

    # ── C9: Security Logging and Monitoring ────────────────────────
    SECURITY_LOG_FILE = os.environ.get("SECURITY_LOG_FILE", "logs/security.log")


class DevConfig(BaseConfig):
    """Development: works on http://localhost (no TLS redirect).

    CSP, X-Frame-Options, HttpOnly, SameSite, and CSRF remain ON.
    """

    SESSION_COOKIE_SECURE = False
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_HSTS = False


class ProdConfig(BaseConfig):
    """Production: TLS redirect, HSTS, Secure cookies enabled."""

    SESSION_COOKIE_SECURE = True
    TALISMAN_FORCE_HTTPS = True
    TALISMAN_HSTS = True
    TALISMAN_HSTS_MAX_AGE = 31_536_000  # 1 year


class TestConfig(BaseConfig):
    """Testing: in-memory DB, hardcoded key, CSRF off by default.

    CSRF is tested explicitly in test_csrf.py (creates its own app).
    Rate limiting is off globally; test_rate_limit.py enables it.
    """

    TESTING = True
    SECRET_KEY = "test-secret-key-not-for-production"  # noqa: S105
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_HSTS = False
    RATELIMIT_ENABLED = True
    SECURITY_LOG_FILE = "logs/test_security.log"
