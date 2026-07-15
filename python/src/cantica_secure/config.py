"""Cantica Secure configuration.

Loaded from environment variables (prefix ``SECURE_``) by default; hosts may
also construct :class:`SecureConfig` programmatically and hand it to
:class:`~cantica_secure.shim.SecurityShim`, mapping their own settings onto it.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class SecureConfig(BaseSettings):
    """All security behaviour is driven from this one object."""

    # ── Mode ───────────────────────────────────────────────────────────────────
    # Local mode: auth is disabled and every request resolves to a synthetic
    # admin principal — matches both hosts' single-user default behaviour.
    local_mode: bool = True
    # Identity returned in local mode (hosts may point this at a real DB row).
    local_user_id: str = "local"
    local_user_email: str = "local@cantica.local"

    # Anonymous access (cantica-api's auth.yaml semantics): when enabled,
    # requests without credentials resolve to an "anonymous" principal holding
    # these roles instead of failing with 401.
    allow_anonymous: bool = False
    anonymous_roles_raw: str = "[]"

    # ── Security database (owned by the package — hosts never touch it) ────────
    # SQLite path; alternatively db_url for e.g. Postgres deployments.
    db_path: Path = Path.home() / ".cantica" / "secure" / "secure.db"
    db_url: str = ""

    # ── JWT / sessions ─────────────────────────────────────────────────────────
    jwt_secret: str = ""
    jwt_expire_minutes: int = 60

    # ── Initial admin (seeded on startup when set, non-local mode) ─────────────
    admin_email: str = "admin@cantica.local"
    admin_password: str = ""

    # ── Auth backend: "local" | "ldap" | "oidc" ────────────────────────────────
    auth_backend: str = "local"

    ldap_host: str = ""
    ldap_port: int = 389
    ldap_base_dn: str = ""
    ldap_group_attr: str = "memberOf"
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_user_filter: str = "(mail={email})"

    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_group_claim: str = "groups"

    # ── Registration & key-based auth ──────────────────────────────────────────
    default_roles_raw: str = '["limbo"]'
    auto_activate_users: bool = False
    invite_expire_minutes: int = 1440
    invite_rate_limit_per_hour: int = 10
    assertion_max_age_seconds: int = 300

    model_config = SettingsConfigDict(env_prefix="SECURE_")

    @property
    def default_roles(self) -> list[str]:
        try:
            roles = json.loads(self.default_roles_raw)
        except json.JSONDecodeError:
            return ["limbo"]
        cleaned = [r for r in roles if isinstance(r, str) and r.strip()]
        return cleaned or ["limbo"]

    @property
    def anonymous_roles(self) -> list[str]:
        try:
            roles = json.loads(self.anonymous_roles_raw)
        except json.JSONDecodeError:
            return []
        return [r for r in roles if isinstance(r, str) and r.strip()]

    @property
    def resolved_db_url(self) -> str:
        if self.db_url:
            return self.db_url
        return f"sqlite:///{self.db_path}"
