"""App factory — assembles config, extensions, blueprints, and security controls.

Controls wired here:
  C1  Implement Access Control          — deny-by-default via before_request
  C2  Use Cryptography to Protect Data  — SECRET_KEY requirement enforced
  C3  Validate all Input & Exceptions   — generic error handlers
  C5  Secure By Default Configurations  — DEBUG off, secure cookies, CLI commands
  C7  Secure Digital Identities         — permanent sessions, idle timeout
  C8  Leverage Browser Security Features— Talisman CSP / HSTS / X-Frame-Options
  C9  Implement Security Logging        — rotating file log initialised here
"""

import os

from dotenv import load_dotenv
from flask import Flask, redirect, request, session, url_for
from flask_login import current_user
from flask_talisman import Talisman

from .config import DevConfig, ProdConfig, TestConfig
from .extensions import db, login_manager, csrf, limiter


# Load environment variables from .env file (if present)
load_dotenv()


# ── Content-Security-Policy (C8) ──────────────────────────────────
# No 'unsafe-inline' anywhere.  All JS/CSS is in external files.
_CSP = {
    "default-src": "'self'",
    "script-src":  "'self'",
    "style-src":   "'self'",
    "img-src":     "'self'",
    "font-src":    "'self'",
    "object-src":  "'none'",
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri":    "'self'",
}


def create_app(config=None):
    """Application factory.

    Args:
        config: A config class, dict, or None (auto-detect from FLASK_ENV).
    """
    app = Flask(__name__)

    # ── Load configuration ─────────────────────────────────────────
    if config is None:
        env = os.environ.get("FLASK_ENV", "development")
        config = ProdConfig if env == "production" else DevConfig

    if isinstance(config, dict):
        app.config.from_mapping(config)
    else:
        app.config.from_object(config)

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

    # C2: Refuse to start without a SECRET_KEY (except during testing)
    if not app.config.get("TESTING") and not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY environment variable is required. "
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    # ── Initialise extensions ──────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # C8: Talisman — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
    Talisman(
        app,
        force_https=app.config.get("TALISMAN_FORCE_HTTPS", False),
        strict_transport_security=app.config.get("TALISMAN_HSTS", False),
        strict_transport_security_max_age=app.config.get(
            "TALISMAN_HSTS_MAX_AGE", 31_536_000
        ),
        session_cookie_secure=app.config.get("SESSION_COOKIE_SECURE", False),
        content_security_policy=_CSP,
        content_security_policy_nonce_in=[],  # no nonces — no inline code
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
    )

    # ── C9: Security logging ──────────────────────────────────────
    from .security.logging_setup import setup_logging
    setup_logging(app)

    # ── C7: Permanent sessions (applies idle timeout) ─────────────
    @app.before_request
    def _make_session_permanent():
        session.permanent = True

    # ── Prevent browser back-button caching of authenticated states ──
    @app.after_request
    def _add_cache_control(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # ── C1: Deny-by-default — every route requires login ──────────
    @app.before_request
    def _enforce_login():
        # Home page is exempt (public educational showcase)
        if request.endpoint == "index":
            return None
        # Auth blueprint (login / register) is exempt
        if request.blueprint == "auth":
            return None
        # Static files are exempt
        if request.endpoint and request.endpoint == "static":
            return None
        # Everything else requires authentication
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        return None

    # ── Register blueprints ────────────────────────────────────────
    from .blueprints.auth import auth_bp
    from .blueprints.notes import notes_bp
    from .blueprints.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(admin_bp)

    # Root route serves the public Home Page
    @app.route("/")
    def index():
        from flask import render_template
        return render_template("home.html")

    # ── Register error handlers (C3) ──────────────────────────────
    from .errors import register_error_handlers
    register_error_handlers(app)

    # ── Register CLI commands (C5) ────────────────────────────────
    from .cli import register_cli
    register_cli(app)

    # ── Create database tables ─────────────────────────────────────
    with app.app_context():
        from . import models  # noqa: F401 — registers user_loader
        db.create_all()

    return app
