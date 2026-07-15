"""Shim-bound FastAPI dependencies — CurrentUser, DB session, require_permission.

Everything resolves through the SecurityShim instance the host mounted
(``request.app.state.cantica_secure``): no globals, so two differently
configured hosts can mount the package in one process.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated

import jwt
from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from cantica_secure.core.apikeys import hash_api_token
from cantica_secure.core.flags import GENERIC_AUTH_FAILURE, gate_user
from cantica_secure.core.jwt import decode_access_token
from cantica_secure.orm.db import new_session
from cantica_secure.orm.models import ApiToken, Role, User

if TYPE_CHECKING:
    from cantica_secure.shim import SecurityShim

_bearer = HTTPBearer(auto_error=False)
_ALL = "*"

ANONYMOUS_USER_ID = "anonymous"


@dataclass
class CurrentUser:
    """The authenticated principal handed to hosts (via their PrincipalAdapter)."""

    user_id: str
    email: str
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    group_id: str | None = None
    e_user_id: str | None = None
    # warning:* flags carried by the account (spec AUTH F "authenticated with warning").
    warnings: list[str] = field(default_factory=list)

    def has(self, permission: str) -> bool:
        return _ALL in self.permissions or permission in self.permissions

    @property
    def is_anonymous(self) -> bool:
        return self.user_id == ANONYMOUS_USER_ID


def get_shim(request: Request) -> "SecurityShim":
    shim = getattr(request.app.state, "cantica_secure", None)
    if shim is None:  # pragma: no cover - mount error
        raise RuntimeError("SecurityShim is not mounted on this app")
    return shim


ShimDep = Annotated["SecurityShim", Depends(get_shim)]


def get_db_session(shim: ShimDep) -> Generator[Session, None, None]:
    with new_session(shim.engine) as session:
        yield session


DbSession = Annotated[Session, Depends(get_db_session)]


def _generic_401() -> HTTPException:
    # One indistinguishable failure for invalid / blocked / inactive / unknown —
    # the real reason lives in the cantica_secure.audit log (see core/flags.py).
    return HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)


def _anonymous_principal(shim: "SecurityShim", session: Session) -> CurrentUser:
    role_names = shim.config.anonymous_roles
    permissions: set[str] = set()
    if role_names:
        roles = session.scalars(
            select(Role).options(selectinload(Role.permissions)).where(Role.name.in_(role_names))
        ).all()
        for role in roles:
            permissions.update(p.name for p in role.permissions)
    return CurrentUser(
        user_id=ANONYMOUS_USER_ID,
        email="",
        roles=role_names,
        permissions=sorted(permissions),
    )


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> CurrentUser:
    """Resolve the current principal.

    Order: local mode → bearer JWT → opaque API token (bearer or X-API-Key)
    → anonymous (when enabled) → 401. The flag gate (spec AUTH F) runs on
    EVERY request for user-bound credentials, so a blocked:* flag or
    deactivation takes effect immediately, not at the next login.
    """
    shim = get_shim(request)
    config = shim.config

    if config.local_mode:
        return CurrentUser(
            user_id=config.local_user_id,
            email=config.local_user_email,
            roles=["admin"],
            permissions=[_ALL],
        )

    raw = credentials.credentials if credentials is not None else None

    # ── JWT path (three dot-separated segments) ───────────────────────────────
    if raw is not None and raw.count(".") == 2:
        try:
            payload = decode_access_token(raw, config.jwt_secret)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

        with new_session(shim.engine) as session:
            user = session.scalar(
                select(User).options(selectinload(User.flags)).where(User.id == payload["sub"])
            )
            result = gate_user(user, context="request:jwt")
            if not result.allowed:
                raise _generic_401()

        request.state.cantica_warnings = result.warnings
        return CurrentUser(
            user_id=payload["sub"],
            email=payload.get("email", ""),
            roles=payload.get("roles", []),
            permissions=payload.get("permissions", []),
            group_id=payload.get("group_id"),
            warnings=result.warnings,
        )

    # ── API token path (opaque; bearer or X-API-Key header) ──────────────────
    opaque = raw if raw is not None else x_api_key
    if opaque:
        token_hash = hash_api_token(opaque)
        with new_session(shim.engine) as session:
            api_token = session.scalar(
                select(ApiToken)
                .options(
                    selectinload(ApiToken.user).selectinload(User.roles),
                    selectinload(ApiToken.user).selectinload(User.flags),
                )
                .where(ApiToken.token_hash == token_hash)
            )
            if api_token is None:
                raise HTTPException(status_code=401, detail="Invalid token")

            now = datetime.now(timezone.utc)
            if api_token.expires_at is not None and api_token.expires_at < now:
                raise HTTPException(status_code=401, detail="Token expired")

            result = gate_user(api_token.user, context="request:api-token")
            if not result.allowed:
                raise _generic_401()

            api_token.last_used_at = now
            session.commit()

            request.state.cantica_warnings = result.warnings
            return CurrentUser(
                user_id=api_token.user.id,
                email=api_token.user.email,
                roles=[r.name for r in api_token.user.roles],
                permissions=list(api_token.scopes),
                warnings=result.warnings,
            )

    # ── Anonymous (cantica-api's auth.yaml semantics) ─────────────────────────
    if config.allow_anonymous:
        with new_session(shim.engine) as session:
            return _anonymous_principal(shim, session)

    raise HTTPException(status_code=401, detail="Unauthorized")


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def require_permission(*permissions: str):
    """Return a FastAPI Depends that raises 403 unless the user holds ANY
    of the listed permissions (OR semantics). No-op in local mode ('*')."""
    async def _check(user: CurrentUserDep) -> None:
        if any(user.has(p) for p in permissions):
            return
        raise HTTPException(
            status_code=403,
            detail=f"Requires one of: {', '.join(permissions)}",
        )
    return Depends(_check)
