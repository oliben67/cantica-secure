"""JWT creation and decoding — access tokens, invitations, confirmations."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt

ALGORITHM = "HS256"
ISSUER = "cantica-secure"


def create_access_token(
    *,
    user_id: str,
    email: str,
    roles: list[str],
    permissions: list[str],
    secret: str,
    expire_minutes: int,
    group_id: str | None = None,
) -> str:
    """Return a signed JWT with RBAC claims embedded (shared claim shape)."""
    now = datetime.now(timezone.utc)
    payload: dict = {
        "iss": ISSUER,
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
        "roles": roles,
        "permissions": permissions,
    }
    if group_id is not None:
        payload["group_id"] = group_id
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> dict:
    """Decode and verify a JWT. Raises jwt.InvalidTokenError on failure."""
    return jwt.decode(token, secret, algorithms=[ALGORITHM])


def create_invitation_token(
    *,
    user_id: str,
    email: str,
    roles: list[str],
    secret: str,
    expire_minutes: int,
) -> str:
    """Server-signed invitation JWT (spec REGISTRATION C.2) — single-use via jti."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "purpose": "invite",
        "sub": user_id,
        "email": email,
        "roles": roles,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_invitation_token(token: str, secret: str) -> dict:
    """Decode an invitation JWT; raises InvalidTokenError if not a valid invite."""
    payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
    if payload.get("purpose") != "invite" or not payload.get("jti"):
        raise jwt.InvalidTokenError("Not an invitation token")
    return payload


def create_enrolment_confirmation(*, user_id: str, cantica_user_id: str, secret: str) -> str:
    """Server-signed confirmation of a key enrolment (the server signs with ITS
    key; the client's key is only stored/verified)."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "purpose": "enrolment-confirmation",
        "sub": user_id,
        "cantica_user_id": cantica_user_id,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)
