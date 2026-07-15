"""Client-signed (RS256) assertion verification and jti replay protection.

Clients hold an RSA key pair. Assertions are JWTs signed with the PRIVATE key
client-side and verified here against the enrolled PUBLIC key — private-key
material must never reach the server. Claim shape: iss/sub = cantica_user_id,
iat/exp/jti (shared with @cantica/secure-ui's key machinery).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cantica_secure.orm.models import UsedJti

ASSERTION_ALGORITHM = "RS256"


class KeyAssertionError(Exception):
    """Verification failure — callers translate to a generic 401."""


def reject_private_key_material(pem: str) -> None:
    """Refuse anything that looks like a private key — public keys only."""
    if "PRIVATE KEY" in pem:
        raise KeyAssertionError("private key material submitted — only public keys are accepted")
    if "PUBLIC KEY" not in pem:
        raise KeyAssertionError("not a PEM public key")


def verify_assertion(assertion: str, public_key_pem: str, *, max_age_seconds: int) -> dict:
    """Verify an RS256 client assertion; return its payload.

    Enforces signature, exp (via PyJWT), iat freshness (max_age_seconds, with
    30s clock-skew leeway), and requires a jti claim. Raises KeyAssertionError.
    """
    try:
        payload = jwt.decode(
            assertion,
            public_key_pem,
            algorithms=[ASSERTION_ALGORITHM],
            options={"verify_aud": False},
            leeway=30,
        )
    except jwt.InvalidTokenError as exc:
        raise KeyAssertionError(f"assertion invalid: {exc}") from exc

    iat = payload.get("iat")
    if iat is None:
        raise KeyAssertionError("assertion missing iat")
    issued = datetime.fromtimestamp(float(iat), tz=timezone.utc)
    now = datetime.now(timezone.utc)
    if issued < now - timedelta(seconds=max_age_seconds) or issued > now + timedelta(seconds=30):
        raise KeyAssertionError("assertion outside freshness window")

    if not payload.get("jti"):
        raise KeyAssertionError("assertion missing jti")

    return payload


def burn_jti(session: Session, jti: str, purpose: str, expires_at: datetime) -> None:
    """Record *jti* as used; raises KeyAssertionError on replay.

    Opportunistically prunes expired rows so the table stays small.
    """
    now = datetime.now(timezone.utc)
    session.query(UsedJti).filter(UsedJti.expires_at < now).delete()
    session.add(UsedJti(jti=jti, purpose=purpose, expires_at=expires_at))
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise KeyAssertionError(f"jti replayed ({purpose})") from exc
