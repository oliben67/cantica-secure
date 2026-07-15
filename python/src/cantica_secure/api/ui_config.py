"""Server-driven UI configuration — lets one @cantica/secure-ui bundle adapt
to whichever host it faces (feature discovery, no secrets)."""

from __future__ import annotations

from fastapi import APIRouter

from cantica_secure.api.deps import ShimDep

router = APIRouter()


@router.get("/ui-config")
def ui_config(shim: ShimDep) -> dict:
    config = shim.config
    return {
        "app_name": shim.app_name,
        "local_mode": config.local_mode,
        "auth_backend": config.auth_backend,
        "features": {
            "password_login": not config.local_mode and config.auth_backend == "local",
            "oidc_login": config.auth_backend == "oidc",
            "invitations": not config.local_mode,
            "key_enrolment": not config.local_mode,
            "anonymous_access": config.allow_anonymous,
            "auto_activate_users": config.auto_activate_users,
            "mail_delivery": shim.mail_transport is not None,
        },
    }
