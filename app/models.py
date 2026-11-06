"""Database models — User, Note.

Controls:
  C3  Validate all Input & Handle Exceptions — ORM-only, no raw SQL
  C7  Secure Digital Identities              — user_loader for Flask-Login
"""

from datetime import datetime, timezone
from typing import Any

from flask_login import UserMixin

from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """Application user with role-based access."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' | 'admin'
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    notes = db.relationship("Note", back_populates="owner", lazy="dynamic")

    def __init__(
        self,
        username: str | None = None,
        password_hash: str | None = None,
        role: str = "user",
        is_active: bool = True,
        **kwargs: Any,
    ):
        super().__init__()
        if username is not None:
            self.username = username
        if password_hash is not None:
            self.password_hash = password_hash
        self.role = role
        self.is_active = is_active
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return f"<User {self.username!r} role={self.role}>"


class Note(db.Model):
    """A note belonging to exactly one user."""

    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False, default="")
    url = db.Column(db.String(2048), nullable=True)       # optional link
    url_title = db.Column(db.String(500), nullable=True)   # cached preview title
    url_description = db.Column(db.String(1000), nullable=True)  # cached meta description
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    owner = db.relationship("User", back_populates="notes")

    def __init__(
        self,
        title: str | None = None,
        content: str = "",
        url: str | None = None,
        url_title: str | None = None,
        url_description: str | None = None,
        user_id: int | None = None,
        **kwargs: Any,
    ):
        super().__init__()
        if title is not None:
            self.title = title
        self.content = content
        self.url = url
        self.url_title = url_title
        self.url_description = url_description
        if user_id is not None:
            self.user_id = user_id
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return f"<Note {self.id} user={self.user_id}>"


# ── C7: Flask-Login user loader ───────────────────────────────────
@login_manager.user_loader
def _load_user(user_id):
    return db.session.get(User, int(user_id))
