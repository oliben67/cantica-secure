"""OidcBackend — validate an OIDC ID token, extract identity + directory groups.

credential = the raw ID token obtained by the client from the IdP; secret is
ignored. Signature is verified against the issuer's JWKS (discovered via
/.well-known/openid-configuration and cached per backend instance).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx
import jwt

from cantica_secure.backends.base import AuthResult
from cantica_secure.backends.provision import provision_directory_user

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from cantica_secure.orm.models import User

log = logging.getLogger(__name__)


class OidcBackend:
    """
    Validate an OIDC ID token against the configured issuer JWKS.
    credential = id_token, secret = ignored.
    Reads the configured groups claim for directory-group resolution.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        group_claim: str,
        default_roles: list[str],
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._group_claim = group_claim
        self._default_roles = default_roles
        self._jwk_client: jwt.PyJWKClient | None = None

    @classmethod
    def from_config(cls, config) -> "OidcBackend":
        return cls(
            issuer=config.oidc_issuer,
            client_id=config.oidc_client_id,
            group_claim=config.oidc_group_claim,
            default_roles=config.default_roles,
        )

    # ── JWKS resolution (separate seam so tests can inject a key) ─────────────

    def _signing_key_for(self, id_token: str) -> Any:
        """Return the verification key for *id_token* from the issuer's JWKS."""
        if self._jwk_client is None:
            discovery = f"{self._issuer}/.well-known/openid-configuration"
            resp = httpx.get(discovery, timeout=10.0)
            resp.raise_for_status()
            jwks_uri = resp.json()["jwks_uri"]
            self._jwk_client = jwt.PyJWKClient(jwks_uri)
        return self._jwk_client.get_signing_key_from_jwt(id_token).key

    # ── AuthBackend protocol ──────────────────────────────────────────────────

    def authenticate(self, credential: str, secret: str) -> AuthResult | None:  # noqa: ARG002
        try:
            key = self._signing_key_for(credential)
            claims = jwt.decode(
                credential,
                key,
                algorithms=["RS256", "ES256"],
                audience=self._client_id,
                issuer=self._issuer,
            )
        except (jwt.InvalidTokenError, httpx.HTTPError, KeyError) as exc:
            log.warning("OIDC token rejected: %s", exc)
            return None

        raw_groups = claims.get(self._group_claim) or []
        groups = [g for g in raw_groups if isinstance(g, str)] if isinstance(raw_groups, list) else []

        return AuthResult(
            user_id="",  # resolved / created by sync_user
            email=str(claims.get("email", "")),
            e_user_id=str(claims.get("sub", "")) or None,
            first_name=str(claims.get("given_name", "")),
            last_name=str(claims.get("family_name", "")),
            directory_groups=groups,
        )

    def sync_user(self, session: "Session", result: AuthResult) -> "User":
        return provision_directory_user(session, result, default_roles=self._default_roles)
