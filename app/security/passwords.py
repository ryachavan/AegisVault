"""Argon2 password hashing — C2 (Use Cryptography to Protect Data).

Provides hash, verify, and verify-with-rehash (upgrades hash parameters
transparently when the Argon2 defaults change).
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Return an Argon2id hash of *password*."""
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True if *password* matches *password_hash*, False otherwise.

    Handles malformed hashes gracefully (returns False).
    """
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_and_rehash(password_hash: str, password: str) -> tuple[bool, str | None]:
    """Verify password and rehash if the stored hash uses outdated parameters.

    Returns:
        (is_valid, new_hash_or_None)
        If valid *and* the hash needs upgrading, new_hash is the fresh hash.
    """
    if not verify_password(password_hash, password):
        return False, None
    if _ph.check_needs_rehash(password_hash):
        return True, _ph.hash(password)
    return True, None
