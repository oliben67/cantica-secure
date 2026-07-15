"""Coverage-gap tests — error paths, small branches, and transports."""

from __future__ import annotations

import time
import types
import uuid

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from cantica_secure import SecureConfig, SecurityShim
from cantica_secure.backends.base import AuthResult, get_auth_backend
from cantica_secure.backends.local import LocalBackend
from cantica_secure.backends.provision import provision_directory_user
from cantica_secure.core import keyauth
from cantica_secure.core.flags import gate_user
from cantica_secure.core.jwt import create_access_token, decode_invitation_token
from cantica_secure.core.password import hash_password, verify_password
from cantica_secure.orm import migrate as migrate_mod
from cantica_secure.orm.db import make_engine, new_session
from cantica_secure.orm.models import Role, User
from cantica_secure.orm.seed import ensure_admin, seed
from cantica_secure.shim import SecurityShim as Shim
from tests.conftest import (
    JWT_SECRET,
    admin_headers,
    assertion,
    enrol,
    invite,
    keypair,
    user_id_by_email,
)

Fixture = tuple[TestClient, SecurityShim]


# ── auth.py error paths ───────────────────────────────────────────────────────


def test_login_unknown_email_and_blocked_user(remote: Fixture) -> None:
    client, _ = remote
    assert client.post("/v1/auth/login",
                       json={"email": "ghost@x.com", "password": "x"}).status_code == 401

    h = admin_headers(client)
    u = client.post("/v1/users", json={"email": "loginblock@x.com", "password": "Pw123456!"}, headers=h).json()
    client.post(f"/v1/users/{u['id']}/flags", json={"flag": "blocked:none"}, headers=h)
    r = client.post("/v1/auth/login", json={"email": "loginblock@x.com", "password": "Pw123456!"})
    assert r.status_code == 401
    assert "blocked" not in r.text.lower()


def test_oidc_unavailable_in_local_mode_and_wrong_backend(local: Fixture, remote: Fixture) -> None:
    local_client, _ = local
    assert local_client.post("/v1/auth/oidc", json={"id_token": "x"}).status_code == 400
    remote_client, _ = remote  # auth_backend = "local"
    assert remote_client.post("/v1/auth/oidc", json={"id_token": "x"}).status_code == 400


def test_invitation_invalid_email_422(remote: Fixture) -> None:
    client, _ = remote
    r = client.post("/v1/auth/invitations",
                    json={"first_name": "a", "last_name": "b", "email": "not-an-email"})
    assert r.status_code == 422


def test_invitation_reissued_for_unenrolled_existing_user(remote: Fixture) -> None:
    client, _ = remote
    first = invite(client, "reissue@x.com")
    second = invite(client, "reissue@x.com")  # exists, not enrolled → re-issue
    assert first != second
    payload = pyjwt.decode(second, JWT_SECRET, algorithms=["HS256"])
    assert payload["email"] == "reissue@x.com"


def test_register_missing_fields_422(remote: Fixture) -> None:
    client, _ = remote
    assert client.post("/v1/auth/register", json={"client_id": "x"}).status_code == 422


def test_register_assertion_without_invitation(remote: Fixture) -> None:
    client, _ = remote
    priv, pub = keypair()
    r = client.post("/v1/auth/register",
                    json={"assertion": assertion(priv, "no-invite"), "public_key_pem": pub})
    assert r.status_code == 401


def test_register_with_garbage_invitation(remote: Fixture) -> None:
    client, _ = remote
    priv, pub = keypair()
    a = assertion(priv, "bad-invite", extra={"invitation": "not.a.jwt"})
    assert client.post("/v1/auth/register",
                       json={"assertion": a, "public_key_pem": pub}).status_code == 401


def test_register_invitation_identity_mismatch(remote: Fixture) -> None:
    client, _ = remote
    # A validly signed invitation for a nonexistent user id.
    forged = pyjwt.encode(
        {"iss": "cantica-secure", "purpose": "invite", "sub": "ghost-id",
         "email": "ghost@x.com", "roles": [], "iat": int(time.time()),
         "exp": int(time.time()) + 600, "jti": str(uuid.uuid4())},
        JWT_SECRET, algorithm="HS256",
    )
    priv, pub = keypair()
    a = assertion(priv, "ghost", extra={"invitation": forged})
    assert client.post("/v1/auth/register",
                       json={"assertion": a, "public_key_pem": pub}).status_code == 401


def test_register_enrol_jti_replay_across_users(remote: Fixture) -> None:
    client, _ = remote
    shared_jti = str(uuid.uuid4())

    inv1 = invite(client, "jti1@x.com")
    priv1, pub1 = keypair()
    a1 = assertion(priv1, "jti1", extra={"invitation": inv1}, jti=shared_jti)
    assert client.post("/v1/auth/register",
                       json={"assertion": a1, "public_key_pem": pub1}).status_code == 200

    inv2 = invite(client, "jti2@x.com")
    priv2, pub2 = keypair()
    a2 = assertion(priv2, "jti2", extra={"invitation": inv2}, jti=shared_jti)
    assert client.post("/v1/auth/register",
                       json={"assertion": a2, "public_key_pem": pub2}).status_code == 401


def test_assert_with_garbage_assertion(remote: Fixture) -> None:
    client, _ = remote
    assert client.post("/v1/auth/assert", json={"assertion": "garbage"}).status_code == 401


def test_api_token_list_expiry_and_delete(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    created = client.post("/v1/auth/tokens",
                          json={"name": "t1", "scopes": ["users:read"], "expires_days": 7},
                          headers=h).json()
    assert created["expires_at"] is not None

    listed = client.get("/v1/auth/tokens", headers=h).json()
    assert any(t["id"] == created["id"] for t in listed)

    assert client.delete(f"/v1/auth/tokens/{created['id']}", headers=h).status_code == 204
    assert client.delete(f"/v1/auth/tokens/{created['id']}", headers=h).status_code == 404


# ── deps.py error paths ───────────────────────────────────────────────────────


def test_expired_and_invalid_jwt(remote: Fixture) -> None:
    client, _ = remote
    expired = create_access_token(
        user_id="u", email="e@x.com", roles=[], permissions=[],
        secret=JWT_SECRET, expire_minutes=-1,
    )
    r = client.get("/v1/things", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401 and "expired" in r.text.lower()

    r2 = client.get("/v1/things", headers={"Authorization": "Bearer a.b.c"})
    assert r2.status_code == 401 and "invalid" in r2.text.lower()


def test_expired_api_token_and_blocked_token_user(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    raw_expired = client.post("/v1/auth/tokens",
                              json={"name": "old", "scopes": ["things:read"], "expires_days": -1},
                              headers=h).json()["token"]
    assert client.get("/v1/things", headers={"X-API-Key": raw_expired}).status_code == 401

    u = client.post("/v1/users", json={"email": "tokblock@x.com", "password": "Pw123456!"}, headers=h).json()
    client.post(f"/v1/users/{u['id']}/roles/admin", headers=h)
    utok = client.post("/v1/auth/login",
                       json={"email": "tokblock@x.com", "password": "Pw123456!"}).json()["access_token"]
    raw = client.post("/v1/auth/tokens", json={"name": "mine", "scopes": ["things:read"]},
                      headers={"Authorization": f"Bearer {utok}"}).json()["token"]
    assert client.get("/v1/things", headers={"X-API-Key": raw}).status_code == 200

    client.post(f"/v1/users/{u['id']}/flags", json={"flag": "blocked:none"}, headers=h)
    r = client.get("/v1/things", headers={"X-API-Key": raw})
    assert r.status_code == 401
    assert "blocked" not in r.text.lower()


# ── users.py CRUD branches ────────────────────────────────────────────────────


def test_users_crud_error_paths(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)

    u = client.post("/v1/users", json={"email": "crud@x.com", "password": "Pw123456!"}, headers=h).json()
    assert client.post("/v1/users", json={"email": "crud@x.com", "password": "x"}, headers=h).status_code == 409

    assert client.get(f"/v1/users/{u['id']}", headers=h).json()["email"] == "crud@x.com"
    assert client.get("/v1/users/ghost", headers=h).status_code == 404

    updated = client.put(f"/v1/users/{u['id']}",
                         json={"first_name": "C", "last_name": "R", "password": "NewPw1234!"},
                         headers=h).json()
    assert (updated["first_name"], updated["last_name"]) == ("C", "R")
    assert client.put("/v1/users/ghost", json={"first_name": "x"}, headers=h).status_code == 404

    # roles
    assert client.post("/v1/users/ghost/roles/viewer", headers=h).status_code == 404
    assert client.post(f"/v1/users/{u['id']}/roles/nope", headers=h).status_code == 404
    client.post(f"/v1/users/{u['id']}/roles/viewer", headers=h)
    removed = client.delete(f"/v1/users/{u['id']}/roles/viewer", headers=h).json()
    assert removed["roles"] == []

    # flags
    assert client.get(f"/v1/users/{u['id']}/flags", headers=h).json() == []
    assert client.get("/v1/users/ghost/flags", headers=h).status_code == 404
    assert client.post("/v1/users/ghost/flags", json={"flag": "ok"}, headers=h).status_code == 404
    f = client.post(f"/v1/users/{u['id']}/flags", json={"flag": "ok"}, headers=h).json()
    assert client.delete(f"/v1/users/{u['id']}/flags/{f['id']}", headers=h).status_code == 204
    assert client.delete(f"/v1/users/{u['id']}/flags/ghost", headers=h).status_code == 404

    assert client.delete("/v1/users/ghost/roles/viewer", headers=h).status_code == 404

    # activation / keys
    assert client.post("/v1/users/ghost/activate", headers=h).status_code == 404
    assert client.delete(f"/v1/users/{u['id']}/keys/ghost", headers=h).status_code == 404

    # delete
    assert client.delete(f"/v1/users/{u['id']}", headers=h).status_code == 204
    assert client.delete(f"/v1/users/{u['id']}", headers=h).status_code == 404


def test_directory_mapping_validation(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    assert client.post("/v1/directory/mappings",
                       json={"external_group": "   ", "role_name": "viewer"},
                       headers=h).status_code == 422
    assert client.delete("/v1/directory/mappings/ghost", headers=h).status_code == 404


# ── backends ─────────────────────────────────────────────────────────────────


def test_backend_factory_branches() -> None:
    assert type(get_auth_backend(SecureConfig(auth_backend="ldap"))).__name__ == "LdapBackend"
    assert type(get_auth_backend(SecureConfig(auth_backend="oidc"))).__name__ == "OidcBackend"
    assert type(get_auth_backend(SecureConfig(auth_backend="local"), session=None)).__name__ == "LocalBackend"


def test_local_backend_edge_cases(remote: Fixture) -> None:
    _, shim = remote
    with pytest.raises(RuntimeError):
        LocalBackend(None).authenticate("a@x.com", "pw")
    with new_session(shim.engine) as s:
        backend = LocalBackend(s)
        assert backend.authenticate("nobody@x.com", "pw") is None
        with pytest.raises(ValueError, match="not found"):
            backend.sync_user(s, AuthResult(user_id="ghost", email="g@x.com"))


def test_ldap_backend_from_config_search_failure_and_no_entries(
    remote: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    from cantica_secure.backends.ldap import LdapBackend, _first

    assert _first("plain") == "plain"
    assert _first(None) == ""

    backend = LdapBackend.from_config(SecureConfig(ldap_host="h", ldap_bind_dn="svc", ldap_bind_password="pw"))

    # search bind fails → None
    mod = types.ModuleType("ldap3")
    mod.Server = type("Server", (), {"__init__": lambda self, *a, **k: None})

    class FailingConn:
        def __init__(self, *_a, **_k) -> None:
            raise RuntimeError("bind failed")

    mod.Connection = FailingConn
    monkeypatch.setitem(sys.modules, "ldap3", mod)
    assert backend.authenticate("a@x.com", "pw") is None

    # search succeeds, no entries → None
    class EmptyConn:
        def __init__(self, *_a, **_k) -> None:
            self.entries: list = []

        def search(self, *_a, **_k) -> None: ...
        def unbind(self) -> None: ...

    mod2 = types.ModuleType("ldap3")
    mod2.Server = mod.Server
    mod2.Connection = EmptyConn
    monkeypatch.setitem(sys.modules, "ldap3", mod2)
    assert backend.authenticate("a@x.com", "pw") is None

    # sync_user delegates to provisioning
    _, shim = remote
    with new_session(shim.engine) as s:
        user = backend.sync_user(s, AuthResult(user_id="", email="ldapsync@x.com", e_user_id="g-1"))
        assert user.e_user_id == "g-1"


def test_oidc_jwks_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    from cantica_secure.backends import oidc as oidc_mod

    calls: list[str] = []

    class FakeResp:
        def raise_for_status(self) -> None: ...
        def json(self) -> dict:
            return {"jwks_uri": "https://idp.example.com/jwks"}

    monkeypatch.setattr(oidc_mod.httpx, "get", lambda url, timeout: (calls.append(url), FakeResp())[1])

    class FakeSigningKey:
        key = "fake-key"

    class FakeJWKClient:
        def __init__(self, uri: str) -> None:
            calls.append(uri)

        def get_signing_key_from_jwt(self, _token: str) -> FakeSigningKey:
            return FakeSigningKey()

    monkeypatch.setattr(oidc_mod.jwt, "PyJWKClient", FakeJWKClient)

    backend = oidc_mod.OidcBackend.from_config(SecureConfig(
        oidc_issuer="https://idp.example.com/", oidc_client_id="c"))
    assert backend._signing_key_for("tok") == "fake-key"
    assert backend._signing_key_for("tok2") == "fake-key"  # client cached
    assert calls == ["https://idp.example.com/.well-known/openid-configuration",
                     "https://idp.example.com/jwks"]


def test_provision_new_user_joins_matched_group(remote: Fixture) -> None:
    _client, shim = remote
    from cantica_secure.orm.models import Group

    with new_session(shim.engine) as s:
        s.add(Group(name="fresh-ops", external_id="cn=fresh,dc=corp"))
        s.commit()
    with new_session(shim.engine) as s:
        user = provision_directory_user(
            s, AuthResult(user_id="", email="fresh@corp.example.com", e_user_id="e-fresh",
                          directory_groups=["cn=fresh,dc=corp"]),
            default_roles=["limbo"],
        )
        assert user.group_id is not None


def test_provision_existing_user_roles_replaced(remote: Fixture) -> None:
    client, shim = remote
    h = admin_headers(client)
    client.post("/v1/directory/mappings",
                json={"external_group": "g-admin", "role_name": "admin"}, headers=h)

    with new_session(shim.engine) as s:
        user = provision_directory_user(
            s, AuthResult(user_id="", email="repl@x.com", e_user_id="e-9"),
            default_roles=["limbo"],
        )
        assert [r.name for r in user.roles] == ["limbo"]
    with new_session(shim.engine) as s:
        user = provision_directory_user(
            s, AuthResult(user_id="", email="repl@x.com", e_user_id="e-9",
                          first_name="R", last_name="E", directory_groups=["g-admin"]),
            default_roles=["limbo"],
        )
        assert [r.name for r in user.roles] == ["admin"]
        assert (user.first_name, user.last_name) == ("R", "E")


# ── core units ────────────────────────────────────────────────────────────────


def test_gate_user_none_is_denied() -> None:
    result = gate_user(None, context="unit")
    assert not result.allowed and result.audit_reason == "not found"


def test_access_token_carries_group_id() -> None:
    tok = create_access_token(user_id="u", email="e", roles=[], permissions=[],
                              secret="s", expire_minutes=5, group_id="g-1")
    assert pyjwt.decode(tok, "s", algorithms=["HS256"])["group_id"] == "g-1"


def test_decode_invitation_rejects_access_tokens() -> None:
    tok = create_access_token(user_id="u", email="e", roles=[], permissions=[],
                              secret="s", expire_minutes=5)
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_invitation_token(tok, "s")


def test_keyauth_units() -> None:
    with pytest.raises(keyauth.KeyAssertionError, match="not a PEM public key"):
        keyauth.reject_private_key_material("garbage")

    priv, pub = keypair()
    now = int(time.time())
    no_iat = pyjwt.encode({"exp": now + 300, "jti": "j"}, priv, algorithm="RS256")
    with pytest.raises(keyauth.KeyAssertionError, match="missing iat"):
        keyauth.verify_assertion(no_iat, pub, max_age_seconds=300)

    no_jti = pyjwt.encode({"iat": now, "exp": now + 300}, priv, algorithm="RS256")
    with pytest.raises(keyauth.KeyAssertionError, match="missing jti"):
        keyauth.verify_assertion(no_jti, pub, max_age_seconds=300)

    # PyJWT itself rejects a far-future iat (ImmatureSignature); either way
    # the caller sees a KeyAssertionError.
    future = pyjwt.encode({"iat": now + 3600, "exp": now + 3900, "jti": "j"}, priv, algorithm="RS256")
    with pytest.raises(keyauth.KeyAssertionError, match="freshness|not yet valid|invalid"):
        keyauth.verify_assertion(future, pub, max_age_seconds=300)

    # Our own freshness window: iat slightly in the future but within PyJWT
    # leeway is still rejected past 30s.
    slightly_future = pyjwt.encode({"iat": now - 400, "exp": now + 300, "jti": "j"}, priv, algorithm="RS256")
    with pytest.raises(keyauth.KeyAssertionError, match="freshness"):
        keyauth.verify_assertion(slightly_future, pub, max_age_seconds=300)


def test_password_units() -> None:
    hashed = hash_password("secret")
    assert verify_password("secret", hashed)
    assert not verify_password("wrong", hashed)
    assert not verify_password("anything", "")           # key-based account
    assert not verify_password("anything", "not-a-hash")  # invalid hash format


def test_config_json_fallbacks() -> None:
    c = SecureConfig(default_roles_raw="not json", anonymous_roles_raw="not json")
    assert c.default_roles == ["limbo"]
    assert c.anonymous_roles == []
    assert SecureConfig(default_roles_raw='["", 3]').default_roles == ["limbo"]
    assert SecureConfig(db_url="postgresql://x").resolved_db_url == "postgresql://x"
    assert SecureConfig().resolved_db_url.startswith("sqlite:///")


# ── mail transport ────────────────────────────────────────────────────────────


def test_smtp_transport_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    from cantica_secure import mail as mail_mod

    actions: list = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            actions.append(("connect", host, port))

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *a) -> None: ...

        def starttls(self) -> None:
            actions.append(("tls",))

        def login(self, user: str, pw: str) -> None:
            actions.append(("login", user))

        def send_message(self, msg) -> None:  # noqa: ANN001
            actions.append(("send", msg["To"], msg.get_content()))

    monkeypatch.setattr(mail_mod.smtplib, "SMTP", FakeSMTP)
    t = mail_mod.SmtpMailTransport(host="smtp.x", username="u", password="p")
    t.send_invitation("dest@x.com", "TOKEN123")
    kinds = [a[0] for a in actions]
    assert kinds == ["connect", "tls", "login", "send"]
    assert "TOKEN123" in actions[-1][2]


# ── shim edges ────────────────────────────────────────────────────────────────


def test_shim_swallows_callback_and_mail_failures(remote: Fixture) -> None:
    client, shim = remote

    def boom(*_a) -> None:
        raise RuntimeError("host callback broke")

    shim._on_user_event = boom
    shim.notify_user_event("created", "u-1")  # must not raise

    class BoomMail:
        def send_invitation(self, *_a) -> None:
            raise RuntimeError("smtp down")

    shim.mail_transport = BoomMail()
    try:
        r = client.post("/v1/auth/invitations",
                        json={"first_name": "a", "last_name": "b", "email": "boom@x.com"})
        assert r.status_code == 200
        assert r.json()["invitation"] is None  # still never leaks the token
    finally:
        shim.mail_transport = None
        shim._on_user_event = None


# ── orm edges ─────────────────────────────────────────────────────────────────


def test_make_engine_file_path(tmp_path) -> None:  # noqa: ANN001
    url = f"sqlite:///{tmp_path}/sub/dir/secure.db"
    engine = make_engine(url)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (id INTEGER)"))
    engine.dispose()
    assert (tmp_path / "sub" / "dir" / "secure.db").exists()


def test_migrate_add_columns(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # noqa: ANN001
    engine = create_engine(f"sqlite:///{tmp_path}/m.db")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id VARCHAR PRIMARY KEY)"))
    monkeypatch.setattr(migrate_mod, "_ADD_COLUMNS", [
        ("users", "e_user_id", "VARCHAR(255)"),
        ("missing_table", "col", "VARCHAR"),
    ])
    migrate_mod.migrate(engine)
    cols = {c["name"] for c in inspect(engine).get_columns("users")}
    assert "e_user_id" in cols
    migrate_mod.migrate(engine)  # idempotent (column exists branch)
    engine.dispose()


def test_seed_idempotent_and_ensure_admin_branches(tmp_path) -> None:  # noqa: ANN001
    engine = make_engine(f"sqlite:///{tmp_path}/s.db")
    from cantica_secure.orm.db import Base

    Base.metadata.create_all(engine)
    with new_session(engine) as s:
        seed(s, permissions=[("x:read", "X")], builtin_roles={"r": {"description": "", "permissions": ["x:read"]}})
        seed(s, permissions=[("x:read", "X")], builtin_roles={"r": {"description": "", "permissions": ["x:read"]}})
        assert s.scalar(select_count()) == 1

        a1 = ensure_admin(s, "a@x.com", "hash", admin_role="does-not-exist")
        a2 = ensure_admin(s, "a@x.com", "hash")
        assert a1.id == a2.id
    engine.dispose()


def select_count():  # noqa: ANN201
    from sqlalchemy import func, select

    return select(func.count()).select_from(Role).where(Role.name == "r")


def test_shim_default_config_and_admin_seed(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SECURE_DB_PATH", str(tmp_path / "d" / "x.db"))
    monkeypatch.setenv("SECURE_LOCAL_MODE", "false")
    monkeypatch.setenv("SECURE_JWT_SECRET", "env-secret")
    monkeypatch.setenv("SECURE_ADMIN_PASSWORD", "EnvAdmin1!")
    shim = Shim()  # default SecureConfig() from env
    try:
        with new_session(shim.engine) as s:
            from sqlalchemy import select

            admin = s.scalar(select(User).where(User.email == "admin@cantica.local"))
            assert admin is not None
    finally:
        shim.dispose()
