"""Phase B conformance suite — one wheel, two differently-configured hosts.

Mounts the shim into two fake hosts carrying the REAL permission vocabularies
of both servers (presets.py): a studio-api-flavoured host and a
cantica-api-flavoured host (anonymous access enabled, coarse role model,
principal adapter mapping to a cantica-style principal). Both run in one
process against isolated in-memory databases.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cantica_secure import (
    CANTICA_PERMISSIONS,
    CANTICA_ROLES,
    STUDIO_PERMISSIONS,
    STUDIO_ROLES,
    CurrentUser,
    SecureConfig,
    SecurityShim,
)
from tests.conftest import ADMIN_EMAIL, ADMIN_PASS, assertion, enrol, keypair

STUDIO_SECRET = "studio-conformance-secret-xxxxxxxxxxxxxx"
CANTICA_SECRET = "cantica-conformance-secret-xxxxxxxxxxxxx"


# ── A cantica-api-style principal, produced by the PrincipalAdapter ───────────


@dataclass
class CanticaPrincipal:
    """Stand-in for cantica-api's pydantic User (id/username/roles model)."""

    id: str
    username: str
    roles: list[str]

    def is_admin(self) -> bool:
        return "admin" in self.roles


def to_cantica_principal(user: CurrentUser) -> CanticaPrincipal:
    return CanticaPrincipal(id=user.user_id, username=user.email or "anonymous", roles=user.roles)


# ── Two hosts in one process ──────────────────────────────────────────────────


@pytest.fixture
def hosts():  # noqa: ANN201
    events: list[tuple[str, str, str]] = []  # (host, event, user_id)

    studio_shim = SecurityShim(
        SecureConfig(
            db_url="sqlite:///:memory:",
            local_mode=False,
            jwt_secret=STUDIO_SECRET,
            admin_email=ADMIN_EMAIL,
            admin_password=ADMIN_PASS,
        ),
        app_name="Cantica Studio",
        permissions=STUDIO_PERMISSIONS,
        builtin_roles=STUDIO_ROLES,
        on_user_event=lambda e, uid: events.append(("studio", e, uid)),
    )
    studio_app = FastAPI()
    studio_shim.mount(studio_app)

    @studio_app.get("/v1/runtime/actors", dependencies=[studio_shim.require_permission("runtime:read")])
    def list_actors() -> list:
        return []

    @studio_app.post("/v1/runtime/actors", dependencies=[studio_shim.require_permission("runtime:start")])
    def start_actor() -> dict:
        return {"status": "running"}

    cantica_shim = SecurityShim(
        SecureConfig(
            db_url="sqlite:///:memory:",
            local_mode=False,
            jwt_secret=CANTICA_SECRET,
            admin_email=ADMIN_EMAIL,
            admin_password=ADMIN_PASS,
            allow_anonymous=True,
            anonymous_roles_raw='["readonly"]',
            default_roles_raw='["user"]',
            auto_activate_users=True,
        ),
        app_name="Cantica",
        permissions=CANTICA_PERMISSIONS,
        builtin_roles=CANTICA_ROLES,
        principal_adapter=to_cantica_principal,
        on_user_event=lambda e, uid: events.append(("cantica", e, uid)),
    )
    cantica_app = FastAPI()
    cantica_shim.mount(cantica_app)

    @cantica_app.get("/v1/prompts", dependencies=[cantica_shim.require_permission("prompts:read")])
    def list_prompts() -> list:
        return []

    @cantica_app.post("/v1/prompts", dependencies=[cantica_shim.require_permission("prompts:write")])
    def create_prompt() -> dict:
        return {"status": "created"}

    @cantica_app.get("/v1/whoami")
    def whoami(principal=cantica_shim.current_user_dep) -> dict:  # noqa: ANN001, B008
        assert isinstance(principal, CanticaPrincipal)
        return {"username": principal.username, "roles": principal.roles, "admin": principal.is_admin()}

    with TestClient(studio_app) as studio, TestClient(cantica_app) as cantica:
        yield studio, cantica, studio_shim, cantica_shim, events
    studio_shim.dispose()
    cantica_shim.dispose()


def _login(client: TestClient) -> dict:
    r = client.post("/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_user(client: TestClient, h: dict, email: str, role: str) -> str:
    u = client.post("/v1/users", json={"email": email, "password": "Pw123456!"}, headers=h).json()
    client.post(f"/v1/users/{u['id']}/roles/{role}", headers=h)
    return u["id"]


def _user_headers(client: TestClient, email: str) -> dict:
    r = client.post("/v1/auth/login", json={"email": email, "password": "Pw123456!"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── Studio-flavoured host ─────────────────────────────────────────────────────


def test_studio_vocabulary_seeded(hosts) -> None:  # noqa: ANN001
    studio, _, _, _, _ = hosts
    roles = {r["name"]: r for r in studio.get("/v1/roles", headers=_login(studio)).json()}
    assert set(roles) == {"admin", "operator", "viewer", "limbo"}
    assert "runtime:start" in roles["operator"]["permissions"]
    assert "users:write" not in roles["operator"]["permissions"]
    assert roles["limbo"]["permissions"] == []


def test_studio_permission_guards(hosts) -> None:  # noqa: ANN001
    studio, _, _, _, _ = hosts
    h = _login(studio)
    _make_user(studio, h, "op@studio.com", "operator")
    _make_user(studio, h, "view@studio.com", "viewer")

    op = _user_headers(studio, "op@studio.com")
    view = _user_headers(studio, "view@studio.com")

    assert studio.get("/v1/runtime/actors", headers=op).status_code == 200
    assert studio.post("/v1/runtime/actors", headers=op).status_code == 200
    assert studio.get("/v1/runtime/actors", headers=view).status_code == 200
    assert studio.post("/v1/runtime/actors", headers=view).status_code == 403
    # Unauthenticated requests fail — studio host has no anonymous access.
    assert studio.get("/v1/runtime/actors").status_code == 401


def test_studio_ui_config(hosts) -> None:  # noqa: ANN001
    studio, _, _, _, _ = hosts
    cfg = studio.get("/v1/security/ui-config").json()
    assert cfg["app_name"] == "Cantica Studio"
    assert cfg["features"]["password_login"] is True
    assert cfg["features"]["anonymous_access"] is False


# ── Cantica-flavoured host ────────────────────────────────────────────────────


def test_cantica_anonymous_read_write_split(hosts) -> None:  # noqa: ANN001
    _, cantica, _, _, _ = hosts
    # Anonymous readers are allowed (auth.yaml semantics)…
    assert cantica.get("/v1/prompts").status_code == 200
    # …but anonymous writes are rejected.
    assert cantica.post("/v1/prompts").status_code == 403


def test_cantica_principal_adapter(hosts) -> None:  # noqa: ANN001
    _, cantica, _, _, _ = hosts
    # Anonymous principal flows through the adapter.
    anon = cantica.get("/v1/whoami").json()
    assert anon == {"username": "anonymous", "roles": ["readonly"], "admin": False}
    # Authenticated admin maps too.
    who = cantica.get("/v1/whoami", headers=_login(cantica)).json()
    assert who["username"] == ADMIN_EMAIL
    assert who["admin"] is True


def test_cantica_user_role_can_write(hosts) -> None:  # noqa: ANN001
    _, cantica, _, _, _ = hosts
    h = _login(cantica)
    _make_user(cantica, h, "writer@cantica.com", "user")
    uh = _user_headers(cantica, "writer@cantica.com")
    assert cantica.post("/v1/prompts", headers=uh).status_code == 200
    # The coarse "user" role never gets host admin permissions.
    assert cantica.get("/v1/users", headers=uh).status_code == 403


def test_cantica_invitation_auto_activates_with_default_role(hosts) -> None:  # noqa: ANN001
    _, cantica, _, _, events = hosts
    r = cantica.post("/v1/auth/invitations",
                     json={"first_name": "N", "last_name": "U", "email": "auto@cantica.com"})
    assert r.status_code == 200
    users = cantica.get("/v1/users", headers=_login(cantica)).json()
    u = next(x for x in users if x["email"] == "auto@cantica.com")
    assert u["is_active"] is True          # auto_activate_users=True on this host
    assert u["roles"] == ["user"]          # default_roles=["user"], not limbo
    assert ("cantica", "created", u["id"]) in events


def test_cantica_ui_config(hosts) -> None:  # noqa: ANN001
    _, cantica, _, _, _ = hosts
    cfg = cantica.get("/v1/security/ui-config").json()
    assert cfg["app_name"] == "Cantica"
    assert cfg["features"]["anonymous_access"] is True
    assert cfg["features"]["auto_activate_users"] is True


# ── Cross-host isolation ──────────────────────────────────────────────────────


def test_hosts_are_isolated(hosts) -> None:  # noqa: ANN001
    studio, cantica, _, _, _ = hosts
    h = _login(studio)
    _make_user(studio, h, "only-studio@x.com", "viewer")

    # The user exists on studio, not on cantica.
    cantica_users = [u["email"] for u in cantica.get("/v1/users", headers=_login(cantica)).json()]
    assert "only-studio@x.com" not in cantica_users

    # A studio access token is rejected by the cantica host (different secret).
    studio_token = _user_headers(studio, "only-studio@x.com")
    assert cantica.get("/v1/users", headers=studio_token).status_code == 401

    # Vocabularies never bleed: cantica's role list has no studio roles.
    cantica_roles = {r["name"] for r in cantica.get("/v1/roles", headers=_login(cantica)).json()}
    assert cantica_roles == {"admin", "user", "readonly", "limbo"}


def test_key_enrolled_on_one_host_does_not_assert_on_the_other(hosts) -> None:  # noqa: ANN001
    studio, cantica, studio_shim, _, events = hosts
    studio_shim  # noqa: B018
    priv, cuid = enrol(studio, "keyed@studio.com")
    # Same claim format, wrong host: no enrolled key there → generic 401.
    r = cantica.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)})
    assert r.status_code == 401
    assert ("studio", "enrolled", _uid(studio, "keyed@studio.com")) in events


def test_lifecycle_events_fire_per_host(hosts) -> None:  # noqa: ANN001
    studio, _, _, _, events = hosts
    h = _login(studio)
    studio.post("/v1/auth/invitations",
                json={"first_name": "E", "last_name": "V", "email": "events@studio.com"})
    uid = _uid(studio, "events@studio.com")
    studio.post(f"/v1/users/{uid}/activate", headers=h)
    f = studio.post(f"/v1/users/{uid}/flags", json={"flag": "warning:none"}, headers=h).json()
    studio.delete(f"/v1/users/{uid}/flags/{f['id']}", headers=h)

    kinds = [e for host, e, u in events if host == "studio" and u == uid]
    assert kinds == ["created", "activated", "flagged", "unflagged"]


def _uid(client: TestClient, email: str) -> str:
    users = client.get("/v1/users", headers=_login(client)).json()
    return next(u["id"] for u in users if u["email"] == email)
