"""Test Cryptography and Secrets Management — C2 (Use Cryptography to Protect Data).

Proves:
  - Password hashing uses Argon2id with verification and rehash support.
  - Application strictly refuses to boot if SECRET_KEY is omitted from environment.
"""

import os
import pytest

from app import create_app
from app.config import DevConfig
from app.security.passwords import hash_password, verify_and_rehash, verify_password


def test_c2_argon2_hashing_and_verification():
    """Proves password hashes use Argon2id format and verify correctly."""
    pw = "SuperSecurePassword123!"
    pwhash = hash_password(pw)

    assert pwhash.startswith("$argon2id$")
    assert verify_password(pwhash, pw) is True
    assert verify_password(pwhash, "IncorrectPass!") is False


def test_c2_verify_and_rehash_functionality():
    """Proves verify_and_rehash verifies valid passwords."""
    pw = "SuperSecurePassword123!"
    pwhash = hash_password(pw)

    is_valid, new_hash = verify_and_rehash(pwhash, pw)
    assert is_valid is True
    # With modern default parameters, immediately rehashed is None
    assert new_hash is None


def test_c2_refuses_to_start_without_secret_key(monkeypatch):
    """Proves factory refuses to instantiate without SECRET_KEY in production/development."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.load_dotenv", lambda *args, **kwargs: None)

    class MissingKeyConfig(DevConfig):
        SECRET_KEY = None

    with pytest.raises(RuntimeError, match="SECRET_KEY environment variable is required"):
        create_app(MissingKeyConfig)
