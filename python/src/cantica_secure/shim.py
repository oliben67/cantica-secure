"""SecurityShim — the one import a host needs.

Usage::

    from cantica_secure import SecureConfig, SecurityShim

    shim = SecurityShim(
        SecureConfig(),                     # SECURE_* env, or host-mapped values
        app_name="Cantica Studio",
        permissions=[("runtime:start", "Start actors"), ...],
        builtin_roles={"operator": {"description": ..., "permissions": [...]}},
        principal_adapter=to_host_user,     # optional CurrentUser → host model
        mail_transport=SmtpMailTransport(...),   # optional invitation delivery
        on_user_event=callback,             # optional (event, user_id) hook
    )
    shim.mount(app, prefix="/v1")

    CurrentUserDep = shim.current_user_dep  # for host endpoints
    require = shim.require_permission       # permission guard factory
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, FastAPI

from cantica_secure.api import auth as auth_router_module
from cantica_secure.api import directory as directory_router_module
from cantica_secure.api import ui_config as ui_config_router_module
from cantica_secure.api import users as users_router_module
from cantica_secure.api.auth import InvitationResponse
from cantica_secure.api.deps import CurrentUser, get_current_user, require_permission
from cantica_secure.config import SecureConfig
from cantica_secure.core.flags import audit_log
from cantica_secure.core.password import hash_password
from cantica_secure.mail import MailTransport
from cantica_secure.orm.db import Base, make_engine, new_session
from cantica_secure.orm.migrate import migrate
from cantica_secure.orm.seed import ensure_admin, seed

# (event, user_id) — events: "created", "activated"
UserEventCallback = Callable[[str, str], None]
PrincipalAdapter = Callable[[CurrentUser], Any]


class SecurityShim:
    """Owns the security database and mounts the security API into a host app."""

    def __init__(
        self,
        config: SecureConfig | None = None,
        *,
        app_name: str = "Cantica",
        permissions: list[tuple[str, str]] | None = None,
        builtin_roles: dict[str, dict] | None = None,
        principal_adapter: PrincipalAdapter | None = None,
        mail_transport: MailTransport | None = None,
        on_user_event: UserEventCallback | None = None,
    ) -> None:
        self.config = config or SecureConfig()
        self.app_name = app_name
        self._permissions = permissions or []
        self._builtin_roles = builtin_roles or {}
        self._principal_adapter = principal_adapter
        self.mail_transport = mail_transport
        self._on_user_event = on_user_event

        self.engine = make_engine(self.config.resolved_db_url)
        Base.metadata.create_all(self.engine)
        migrate(self.engine)
        with new_session(self.engine) as session:
            seed(session, permissions=self._permissions, builtin_roles=self._builtin_roles)
            if not self.config.local_mode and self.config.admin_password:
                ensure_admin(
                    session,
                    self.config.admin_email,
                    hash_password(self.config.admin_password),
                )

        # Invitation rate limiting — per shim instance, per client IP.
        self._rate_lock = threading.Lock()
        self._rate_hits: dict[str, list[float]] = {}

    # ── Mounting ──────────────────────────────────────────────────────────────

    def mount(self, app: FastAPI, prefix: str = "/v1") -> None:
        """Wire the security surface into *app*.

        Routes: {prefix}/auth/*, {prefix}/users/*, {prefix}/roles,
        {prefix}/directory/*, {prefix}/security/ui-config. Also installs the
        X-Cantica-Warning response header middleware and registers this shim
        on ``app.state.cantica_secure``.
        """
        if getattr(app.state, "cantica_secure", None) is not None:
            raise RuntimeError("A SecurityShim is already mounted on this app")
        app.state.cantica_secure = self

        public = APIRouter()
        public.include_router(auth_router_module.router, prefix="/auth", tags=["secure-auth"])
        public.include_router(ui_config_router_module.router, prefix="/security", tags=["secure-ui"])

        protected = APIRouter(dependencies=[Depends(get_current_user)])
        protected.include_router(users_router_module.users_router, prefix="/users", tags=["secure-users"])
        protected.include_router(users_router_module.roles_router, prefix="/roles", tags=["secure-roles"])
        protected.include_router(directory_router_module.router, prefix="/directory", tags=["secure-directory"])

        app.include_router(public, prefix=prefix)
        app.include_router(protected, prefix=prefix)

        @app.middleware("http")
        async def _warning_header(request, call_next):  # noqa: ANN001, ANN202
            response = await call_next(request)
            warnings = getattr(request.state, "cantica_warnings", None)
            if warnings:
                response.headers["X-Cantica-Warning"] = ", ".join(warnings)
            return response

    # ── Host integration surface ──────────────────────────────────────────────

    @property
    def current_user_dep(self):  # noqa: ANN201 — FastAPI dependency
        """Dependency for host endpoints. Applies the principal adapter when set."""
        if self._principal_adapter is None:
            return Depends(get_current_user)

        adapter = self._principal_adapter

        async def _adapted(user: CurrentUser = Depends(get_current_user)):  # noqa: ANN202, B008
            return adapter(user)

        return Depends(_adapted)

    @staticmethod
    def require_permission(*permissions: str):  # noqa: ANN205
        return require_permission(*permissions)

    def notify_user_event(self, event: str, user_id: str) -> None:
        if self._on_user_event is None:
            return
        try:
            self._on_user_event(event, user_id)
        except Exception:  # noqa: BLE001 — host callbacks must not break auth flows
            audit_log.exception("user-event callback failed: %s %s", event, user_id)

    def deliver_invitation(self, email: str, token: str) -> InvitationResponse:
        """Email the invitation when a transport exists, else return it in-band."""
        if self.mail_transport is None:
            return InvitationResponse(invitation=token)
        try:
            self.mail_transport.send_invitation(email, token)
        except Exception:  # noqa: BLE001
            audit_log.exception("invitation mail delivery failed for %s", email)
        # Never return the token when mail delivery is configured — the
        # response stays shape-identical whether or not the address exists.
        return InvitationResponse()

    # ── Invitation rate limiting ──────────────────────────────────────────────

    def rate_limited(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self._rate_lock:
            hits = [t for t in self._rate_hits.get(client_ip, []) if now - t < 3600]
            if len(hits) >= self.config.invite_rate_limit_per_hour:
                self._rate_hits[client_ip] = hits
                return True
            hits.append(now)
            self._rate_hits[client_ip] = hits
            return False

    def reset_rate_limiter(self) -> None:
        """Test hook."""
        with self._rate_lock:
            self._rate_hits.clear()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def dispose(self) -> None:
        self.engine.dispose()
