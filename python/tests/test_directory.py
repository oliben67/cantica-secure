"""Enterprise directory — mapping CRUD, OIDC login, LDAP backend, provisioning."""

from __future__ import annotations

import sys
import time
import types
import uuid

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from cantica_secure.backends.base import AuthResult
from cantica_secure.backends.oidc import OidcBackend
from cantica_secure.backends.provision import provision_directory_user
from cantica_secure.orm.db import new_session
from cantica_secure.shim import SecurityShim
from tests.conftest import admin_headers, keypair, make_app, make_shim

OIDC_ISSUER = "https://idp.example.com"
OIDC_CLIENT_ID = "cantica-client"

_IDP_PRIVATE, _IDP_PUBLIC = keypair()


def _id_token(**overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": OIDC_ISSUER,
        "aud": OIDC_CLIENT_ID,
        "sub": "corp-uid-42",
        "email": "jdoe@corp.example.com",
        "given_name": "Jane",
        "family_name": "Doe",
        "groups": ["ops-group"],
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        **overrides,
    }
    return pyjwt.encode(claims, _IDP_PRIVATE, algorithm="RS256")


@pytest.fixture
def oidc(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, SecurityShim]:
    shim = make_shim(auth_backend="oidc", oidc_issuer=OIDC_ISSUER, oidc_client_id=OIDC_CLIENT_ID)
    monkeypatch.setattr(OidcBackend, "_signing_key_for", lambda self, token: _IDP_PUBLIC)
    app = make_app(shim)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, shim
    shim.dispose()


def _admin_jwt_headers(client: TestClient, shim: SecurityShim) -> dict:
    # Password login is unavailable under auth_backend=oidc — mint directly.
    from sqlalchemy import select

    from cantica_secure.core.jwt import create_access_token
    from cantica_secure.orm.models import User
    from tests.conftest import ADMIN_EMAIL, JWT_SECRET

    with new_session(shim.engine) as s:
        admin = s.scalar(select(User).where(User.email == ADMIN_EMAIL))
        assert admin is not None
    token = create_access_token(
        user_id=admin.id, email=admin.email, roles=["admin"], permissions=["*"],
        secret=JWT_SECRET, expire_minutes=5,
    )
    return {"Authorization": f"Bearer {token}"}


# ── Mapping CRUD ──────────────────────────────────────────────────────────────


def test_mapping_crud_round_trip(remote) -> None:  # noqa: ANN001
    client, _ = remote
    h = admin_headers(client)
    r = client.post("/v1/directory/mappings",
                    json={"external_group": "ops-group", "role_name": "viewer"}, headers=h)
    assert r.status_code == 201, r.text
    mid = r.json()["id"]

    assert any(m["id"] == mid for m in client.get("/v1/directory/mappings", headers=h).json())
    assert client.post("/v1/directory/mappings",
                       json={"external_group": "ops-group", "role_name": "viewer"},
                       headers=h).status_code == 409
    assert client.post("/v1/directory/mappings",
                       json={"external_group": "g", "role_name": "nope"}, headers=h).status_code == 404
    assert client.delete(f"/v1/directory/mappings/{mid}", headers=h).status_code == 204


# ── OIDC login + provisioning ─────────────────────────────────────────────────


def test_oidc_login_provisions_user_with_mapped_role(oidc) -> None:  # noqa: ANN001
    client, shim = oidc
    h = _admin_jwt_headers(client, shim)
    client.post("/v1/directory/mappings",
                json={"external_group": "ops-group", "role_name": "admin"}, headers=h)

    r = client.post("/v1/auth/oidc", json={"id_token": _id_token()})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    assert client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"}).status_code == 200

    users = client.get("/v1/users", headers=h).json()
    jane = next(u for u in users if u["email"] == "jdoe@corp.example.com")
    assert jane["e_user_id"] == "corp-uid-42"
    assert jane["roles"] == ["admin"]
    assert jane["is_active"] is True


def test_oidc_unmapped_groups_fall_back_to_limbo_newbie(oidc) -> None:  # noqa: ANN001
    client, shim = oidc
    r = client.post("/v1/auth/oidc", json={"id_token": _id_token(groups=["unmapped"])})
    assert r.status_code == 200
    tok = r.json()["access_token"]
    # limbo = zero permissions → host resources stay closed.
    assert client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"}).status_code == 403

    h = _admin_jwt_headers(client, shim)
    users = client.get("/v1/users", headers=h).json()
    jane = next(u for u in users if u["email"] == "jdoe@corp.example.com")
    assert jane["roles"] == ["limbo"]
    assert any(f["flag"] == "newbie" for f in jane["flags"])


def test_oidc_group_revocation_revokes_role_on_next_login(oidc) -> None:  # noqa: ANN001
    client, shim = oidc
    h = _admin_jwt_headers(client, shim)
    client.post("/v1/directory/mappings",
                json={"external_group": "ops-group", "role_name": "admin"}, headers=h)
    client.post("/v1/directory/mappings",
                json={"external_group": "view-group", "role_name": "viewer"}, headers=h)
    assert client.post("/v1/auth/oidc", json={"id_token": _id_token()}).status_code == 200

    client.post("/v1/auth/oidc", json={"id_token": _id_token(groups=["view-group"])})
    users = client.get("/v1/users", headers=h).json()
    jane = next(u for u in users if u["email"] == "jdoe@corp.example.com")
    assert jane["roles"] == ["viewer"]


def test_oidc_rejects_wrong_audience_and_expiry(oidc) -> None:  # noqa: ANN001
    client, _ = oidc
    assert client.post("/v1/auth/oidc",
                       json={"id_token": _id_token(aud="other")}).status_code == 401
    now = int(time.time())
    assert client.post("/v1/auth/oidc",
                       json={"id_token": _id_token(iat=now - 900, exp=now - 600)}).status_code == 401


def test_oidc_blocked_user_denied_generically(oidc) -> None:  # noqa: ANN001
    client, shim = oidc
    assert client.post("/v1/auth/oidc", json={"id_token": _id_token()}).status_code == 200
    h = _admin_jwt_headers(client, shim)
    users = client.get("/v1/users", headers=h).json()
    jane = next(u for u in users if u["email"] == "jdoe@corp.example.com")
    client.post(f"/v1/users/{jane['id']}/flags", json={"flag": "blocked:abuse"}, headers=h)

    r = client.post("/v1/auth/oidc", json={"id_token": _id_token()})
    assert r.status_code == 401
    assert "blocked" not in r.text.lower()


# ── Provisioning specifics ────────────────────────────────────────────────────


def test_provision_adopts_existing_email_account_and_matches_group(remote) -> None:  # noqa: ANN001
    _client, shim = remote
    from cantica_secure.orm.models import Group, User

    with new_session(shim.engine) as s:
        s.add(Group(name="ops", external_id="cn=ops,dc=corp"))
        s.add(User(email="adopt@corp.example.com", password_hash="", is_active=True))
        s.commit()

    with new_session(shim.engine) as s:
        user = provision_directory_user(
            s,
            AuthResult(user_id="", email="adopt@corp.example.com",
                       e_user_id="corp-77", first_name="Ada",
                       directory_groups=["cn=ops,dc=corp"]),
            default_roles=["limbo"],
        )
        assert user.e_user_id == "corp-77"
        assert user.first_name == "Ada"
        assert user.group_id is not None


# ── LDAP backend (ldap3 faked) ────────────────────────────────────────────────


class _FakeEntry:
    entry_dn = "cn=jdoe,ou=users,dc=corp"
    entry_attributes_as_dict = {
        "givenName": ["Jane"],
        "sn": ["Doe"],
        "mail": ["jdoe@corp.example.com"],
        "objectGUID": ["guid-1234"],
        "memberOf": ["cn=ops,dc=corp"],
    }


def _fake_ldap3(bind_results: dict[str, bool]) -> types.ModuleType:
    mod = types.ModuleType("ldap3")

    class Server:
        def __init__(self, *a, **k) -> None: ...

    class Connection:
        def __init__(self, _server, user=None, password=None, auto_bind=False) -> None:
            key = user or "<anonymous>"
            if auto_bind and not bind_results.get(key, False):
                raise RuntimeError(f"bind failed for {key}")
            self.entries: list[_FakeEntry] = []

        def search(self, *_a, **_k) -> None:
            self.entries = [_FakeEntry()]

        def unbind(self) -> None: ...

    mod.Server = Server
    mod.Connection = Connection
    return mod


def _ldap_backend():  # noqa: ANN202
    from cantica_secure.backends.ldap import LdapBackend

    return LdapBackend(host="ldap.corp", port=389, base_dn="dc=corp",
                       group_attr="memberOf", default_roles=["limbo"])


def test_ldap_backend_authenticates_and_extracts_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "ldap3", _fake_ldap3({
        "<anonymous>": True,
        "cn=jdoe,ou=users,dc=corp": True,
    }))
    result = _ldap_backend().authenticate("jdoe@corp.example.com", "hunter2")
    assert result is not None
    assert result.email == "jdoe@corp.example.com"
    assert result.e_user_id == "guid-1234"
    assert result.directory_groups == ["cn=ops,dc=corp"]


def test_ldap_backend_rejects_bad_or_empty_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "ldap3", _fake_ldap3({"<anonymous>": True}))
    backend = _ldap_backend()
    assert backend.authenticate("jdoe@corp.example.com", "wrong") is None
    assert backend.authenticate("jdoe@corp.example.com", "") is None
