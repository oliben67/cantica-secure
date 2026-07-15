"""Host-integration behaviours — dual mounts, principal adapter, anonymous
mode, ui-config, and user-event callbacks."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cantica_secure import CurrentUser, SecureConfig, SecurityShim
from tests.conftest import ADMIN_EMAIL, admin_headers, invite, make_app, make_shim, user_id_by_email


def test_two_shims_in_two_apps_are_independent() -> None:
    """Two differently-configured mounts coexist in one process (Phase B goal)."""
    shim_a = make_shim()
    shim_b = SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True))
    app_a = make_app(shim_a)
    app_b = make_app(shim_b)
    with TestClient(app_a) as a, TestClient(app_b) as b:
        assert a.get("/v1/things").status_code == 401       # remote: auth required
        assert b.get("/v1/things").status_code == 200       # local: wildcard admin
        assert a.get("/v1/security/ui-config").json()["local_mode"] is False
        assert b.get("/v1/security/ui-config").json()["local_mode"] is True
    shim_a.dispose()
    shim_b.dispose()


def test_double_mount_rejected() -> None:
    shim = SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True))
    app = FastAPI()
    shim.mount(app)
    try:
        shim.mount(app)
        raise AssertionError("second mount must fail")
    except RuntimeError:
        pass
    finally:
        shim.dispose()


def test_principal_adapter_maps_current_user() -> None:
    """Hosts receive their own principal type from shim.current_user_dep."""

    @dataclass
    class HostUser:
        name: str
        is_admin: bool

    shim = SecurityShim(
        SecureConfig(db_url="sqlite:///:memory:", local_mode=True),
        principal_adapter=lambda u: HostUser(name=u.email, is_admin="admin" in u.roles),
    )
    app = FastAPI()
    shim.mount(app)

    @app.get("/v1/whoami")
    def whoami(user=shim.current_user_dep):  # noqa: ANN001, ANN202, B008
        return {"name": user.name, "is_admin": user.is_admin, "type": type(user).__name__}

    with TestClient(app) as c:
        data = c.get("/v1/whoami").json()
    assert data == {"name": "local@cantica.local", "is_admin": True, "type": "HostUser"}
    shim.dispose()


def test_anonymous_mode_grants_configured_roles() -> None:
    """cantica-api's auth.yaml semantics: credential-less requests get roles."""
    shim = make_shim(allow_anonymous=True, anonymous_roles_raw='["viewer"]')
    app = make_app(shim)
    with TestClient(app) as c:
        # viewer holds things:read → host endpoint opens up without credentials
        assert c.get("/v1/things").status_code == 200
        me = c.get("/v1/auth/me").json()
        assert me["anonymous"] is True
        assert me["roles"] == ["viewer"]
        # but write-side security endpoints stay closed
        assert c.get("/v1/users").status_code == 403
    shim.dispose()


def test_ui_config_reports_features(remote) -> None:  # noqa: ANN001
    client, _ = remote
    data = client.get("/v1/security/ui-config").json()
    assert data["app_name"] == "Test Host"
    f = data["features"]
    assert f["password_login"] is True
    assert f["invitations"] is True
    assert f["key_enrolment"] is True
    assert f["oidc_login"] is False
    assert f["anonymous_access"] is False
    assert f["mail_delivery"] is False


def test_user_event_callbacks_fire() -> None:
    from tests.conftest import HOST_PERMISSIONS, HOST_ROLES, JWT_SECRET

    events: list[tuple[str, str]] = []
    shim = SecurityShim(
        SecureConfig(
            db_url="sqlite:///:memory:", local_mode=False,
            jwt_secret=JWT_SECRET,
            admin_email=ADMIN_EMAIL, admin_password="Test1234!",
        ),
        permissions=HOST_PERMISSIONS, builtin_roles=HOST_ROLES,
        on_user_event=lambda event, uid: events.append((event, uid)),
    )
    app = make_app(shim)
    with TestClient(app) as c:
        invite(c, "hook@x.com")
        assert ("created" in [e for e, _ in events])
        # activation event
        h = admin_headers(c)
        uid = user_id_by_email(c, h, "hook@x.com")
        c.post(f"/v1/users/{uid}/activate", headers=h)
    assert ("activated", uid) in events
    shim.dispose()


def test_current_user_dep_without_adapter_returns_package_type() -> None:
    shim = SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True))
    app = FastAPI()
    shim.mount(app)

    @app.get("/v1/whoami")
    def whoami(user=shim.current_user_dep):  # noqa: ANN001, ANN202, B008
        return {"is_cu": isinstance(user, CurrentUser), "uid": user.user_id}

    with TestClient(app) as c:
        assert c.get("/v1/whoami").json() == {"is_cu": True, "uid": "local"}
    shim.dispose()
