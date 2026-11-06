"""Flask extension instances — initialised once, bound to app in the factory."""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login"  # C1: redirect unauthenticated users
login_manager.login_message_category = "warning"

csrf = CSRFProtect()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],  # no global limit; per-route limits set in blueprints
)
