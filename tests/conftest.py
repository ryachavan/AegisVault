"""Pytest fixtures for secure-notes test suite.

Controls:
  C1  Implement Access Control
  C2  Use Cryptography to Protect Data
  C3  Validate all Input & Handle Exceptions
  C7  Secure Digital Identities — limiter reset between tests
  C8  Leverage Browser Security Features
"""

import os
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db, limiter
from app.models import Note, User
from app.security.passwords import hash_password


@pytest.fixture(scope="session")
def app_instance():
    """Create test application instance."""
    app = create_app(TestConfig)
    return app


@pytest.fixture
def app(app_instance):
    """Provide app with fresh database tables per test."""
    with app_instance.app_context():
        db.create_all()
        yield app_instance
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client bound to the app context."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _reset_limiter(app):
    """Reset Flask-Limiter storage between every test (C7).

    Guarantees that rate-limiting tests do not affect other test cases.
    """
    with app.app_context():
        if limiter.enabled and getattr(limiter, "_storage", None):
            try:
                limiter.reset()
            except Exception:
                pass
    yield
    with app.app_context():
        if limiter.enabled and getattr(limiter, "_storage", None):
            try:
                limiter.reset()
            except Exception:
                pass


@pytest.fixture
def alice_user(app):
    """Regular user Alice."""
    with app.app_context():
        user = User(
            username="alice",
            password_hash=hash_password("AliceSecretPass123!"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        return user_id


@pytest.fixture
def bob_user(app):
    """Regular user Bob."""
    with app.app_context():
        user = User(
            username="bob",
            password_hash=hash_password("BobSecretPass123!"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        return user_id


@pytest.fixture
def admin_user(app):
    """Privileged admin user."""
    with app.app_context():
        user = User(
            username="secadmin",
            password_hash=hash_password("AdminSecretPass123!"),
            role="admin",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        return user_id


@pytest.fixture
def alice_note(app, alice_user):
    """Note owned by Alice."""
    with app.app_context():
        note = Note(
            title="Alice Confidential Research",
            content="Top secret project notes for Alice only.",
            user_id=alice_user,
        )
        db.session.add(note)
        db.session.commit()
        note_id = note.id
        return note_id
