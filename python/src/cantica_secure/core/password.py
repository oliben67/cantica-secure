"""Password hashing and verification using Argon2."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_ph = PasswordHasher()


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    if not hashed:
        # Key-based / directory accounts have no password; never verifiable.
        return False
    try:
        _ph.verify(hashed, plaintext)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False
