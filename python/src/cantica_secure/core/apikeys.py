"""API token generation and hashing (opaque bearer tokens / X-API-Key)."""

from __future__ import annotations

import hashlib
import secrets


def generate_api_token() -> tuple[str, str]:
    """Return (raw_token, token_hash). Only raw_token is shown to the user."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_api_token(raw)


def hash_api_token(raw: str) -> str:
    """SHA-256 hex digest of *raw* for storage and lookup."""
    return hashlib.sha256(raw.encode()).hexdigest()
