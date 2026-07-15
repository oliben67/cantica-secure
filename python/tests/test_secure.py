"""Core flows — flag gate, invitations, key enrolment, assertions, tokens.

Merged from studio-api's test_remote_auth.py and cantica-api's
test_keyauth.py, run standalone against a shim-mounted FastAPI app.
"""

from __future__ import annotations

import jwt as pyjwt
from fastapi.testclient import TestClient

from cantica_secure.shim import SecurityShim
from tests.conftest import (
    JWT_SECRET,
    activate_by_email,
    admin_headers,
    assertion,
    enrol,
    invite,
    keypair,
    user_id_by_email,
)

Fixture = tuple[TestClient, SecurityShim]


# ── Local mode ────────────────────────────────────────────────────────────────


def test_local_mode_grants_wildcard_admin(local: Fixture) -> None:
    client, _ = local
    assert client.get("/v1/things").status_code == 200
    me = client.get("/v1/auth/me").json()
    assert me["permissions"] == ["*"]


def test_local_mode_register_is_noop(local: Fixture) -> None:
    client, _ = local
    r = client.post("/v1/auth/register",
                    json={"client_id": "abc", "public_key_pem": "-----BEGIN PUBLIC KEY-----..."})
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "mode": "local"}


def test_local_mode_blocks_login_invitations_assert(local: Fixture) -> None:
    client, _ = local
    assert client.post("/v1/auth/login", json={"email": "a", "password": "b"}).status_code == 400
    assert client.post("/v1/auth/invitations",
                       json={"first_name": "a", "last_name": "b", "email": "c@d.e"}).status_code == 400
    assert client.post("/v1/auth/assert", json={"assertion": "x.y.z"}).status_code == 400


# ── Login, permissions, host guard ────────────────────────────────────────────


def test_admin_login_and_host_permission_guard(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    assert client.get("/v1/things", headers=h).status_code == 200
    assert client.get("/v1/things").status_code == 401


def test_limbo_role_seeded_with_zero_permissions(remote: Fixture) -> None:
    client, _ = remote
    roles = client.get("/v1/roles", headers=admin_headers(client)).json()
    limbo = next(r for r in roles if r["name"] == "limbo")
    assert limbo["permissions"] == []


def _make_user(client: TestClient, h: dict, email: str, role: str = "viewer") -> str:
    u = client.post("/v1/users", json={"email": email, "password": "Pw123456!"}, headers=h).json()
    client.post(f"/v1/users/{u['id']}/roles/{role}", headers=h)
    return u["id"]


def _user_token(client: TestClient, email: str) -> str:
    r = client.post("/v1/auth/login", json={"email": email, "password": "Pw123456!"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# ── Flag gate (spec AUTH F) ───────────────────────────────────────────────────


def test_warning_flag_authenticates_with_header(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    uid = _make_user(client, h, "warned@x.com")
    client.post(f"/v1/users/{uid}/flags", json={"flag": "warning:abuse", "comment": "spam"}, headers=h)
    tok = _user_token(client, "warned@x.com")
    r = client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert "warning:abuse" in r.headers["X-Cantica-Warning"]


def test_blocked_flag_invalidates_live_token(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    uid = _make_user(client, h, "blocked@x.com")
    tok = _user_token(client, "blocked@x.com")
    assert client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"}).status_code == 200

    client.post(f"/v1/users/{uid}/flags", json={"flag": "blocked:abuse"}, headers=h)
    r = client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401
    assert "blocked" not in r.text.lower()


def test_blocked_inactive_invalid_indistinguishable(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    uid_b = _make_user(client, h, "b@x.com")
    tok_b = _user_token(client, "b@x.com")
    client.post(f"/v1/users/{uid_b}/flags", json={"flag": "blocked:none"}, headers=h)
    uid_i = _make_user(client, h, "i@x.com")
    tok_i = _user_token(client, "i@x.com")
    client.put(f"/v1/users/{uid_i}", json={"is_active": False}, headers=h)

    r_blocked = client.get("/v1/things", headers={"Authorization": f"Bearer {tok_b}"})
    r_inactive = client.get("/v1/things", headers={"Authorization": f"Bearer {tok_i}"})
    assert r_blocked.status_code == r_inactive.status_code == 401
    assert r_blocked.json() == r_inactive.json()


def test_unknown_flag_rejected_and_duplicate_conflicts(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    uid = _make_user(client, h, "f@x.com")
    assert client.post(f"/v1/users/{uid}/flags", json={"flag": "nonsense"}, headers=h).status_code == 422
    assert client.post(f"/v1/users/{uid}/flags", json={"flag": "warning:none"}, headers=h).status_code == 201
    assert client.post(f"/v1/users/{uid}/flags", json={"flag": "warning:none"}, headers=h).status_code == 409


# ── Invitations (spec REGISTRATION C) ─────────────────────────────────────────


def test_invitation_creates_newbie_limbo_user(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "newbie@x.com")
    payload = pyjwt.decode(invitation, JWT_SECRET, algorithms=["HS256"])
    assert payload["purpose"] == "invite"
    assert payload["roles"] == ["limbo"]

    h = admin_headers(client)
    users = client.get("/v1/users", params={"flag": "newbie"}, headers=h).json()
    match = [u for u in users if u["email"] == "newbie@x.com"]
    assert match and match[0]["is_active"] is False
    assert match[0]["roles"] == ["limbo"]


def test_activation_enables_and_clears_newbie(remote: Fixture) -> None:
    client, _ = remote
    invite(client, "toenable@x.com")
    h = admin_headers(client)
    uid = user_id_by_email(client, h, "toenable@x.com")
    u = client.post(f"/v1/users/{uid}/activate", headers=h).json()
    assert u["is_active"] is True
    assert all(f["flag"] != "newbie" for f in u["flags"])


def test_invitation_rate_limited(remote: Fixture) -> None:
    client, shim = remote
    shim.reset_rate_limiter()
    for i in range(shim.config.invite_rate_limit_per_hour):
        client.post("/v1/auth/invitations",
                    json={"first_name": "a", "last_name": "b", "email": f"rl{i}@x.com"})
    r = client.post("/v1/auth/invitations",
                    json={"first_name": "a", "last_name": "b", "email": "rl-final@x.com"})
    assert r.status_code == 429


def test_invitation_for_enrolled_user_returns_no_token(remote: Fixture) -> None:
    client, _ = remote
    enrol(client, "hijack@x.com")
    r = client.post("/v1/auth/invitations",
                    json={"first_name": "a", "last_name": "b", "email": "hijack@x.com"})
    assert r.status_code == 200
    assert r.json()["invitation"] is None


def test_invitation_email_delivery_hides_token(remote: Fixture) -> None:
    client, shim = remote
    sent: list[tuple[str, str]] = []

    class FakeMail:
        def send_invitation(self, email: str, token: str) -> None:
            sent.append((email, token))

    shim.mail_transport = FakeMail()
    try:
        r = client.post("/v1/auth/invitations",
                        json={"first_name": "a", "last_name": "b", "email": "mailed@x.com"})
        assert r.status_code == 200
        assert r.json()["invitation"] is None  # delivered out-of-band only
        assert sent and sent[0][0] == "mailed@x.com" and sent[0][1].count(".") == 2
    finally:
        shim.mail_transport = None


# ── Key enrolment (spec 3–8) ──────────────────────────────────────────────────


def test_enrolment_binds_email_as_cantica_user_id(remote: Fixture) -> None:
    client, _ = remote
    _priv, cuid = enrol(client, "enrolme@x.com")
    assert cuid == "enrolme@x.com"
    h = admin_headers(client)
    uid = user_id_by_email(client, h, "enrolme@x.com")
    keys = client.get(f"/v1/users/{uid}/keys", headers=h).json()
    assert len(keys) == 1 and keys[0]["cantica_user_id"] == "enrolme@x.com"


def test_enrolment_rejects_private_key_material(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "leaky@x.com")
    private_pem, _pub = keypair()
    a = assertion(private_pem, "leaky", extra={"invitation": invitation})
    r = client.post("/v1/auth/register", json={"assertion": a, "public_key_pem": private_pem})
    assert r.status_code == 401


def test_enrolment_rejects_wrong_key_signature(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "forged@x.com")
    signer_priv, _ = keypair()
    _, other_pub = keypair()
    a = assertion(signer_priv, "forged", extra={"invitation": invitation})
    assert client.post("/v1/auth/register",
                       json={"assertion": a, "public_key_pem": other_pub}).status_code == 401


def test_enrolment_rejects_replayed_invitation(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "replay@x.com")
    priv1, pub1 = keypair()
    a1 = assertion(priv1, "replay", extra={"invitation": invitation})
    assert client.post("/v1/auth/register",
                       json={"assertion": a1, "public_key_pem": pub1}).status_code == 200
    priv2, pub2 = keypair()
    a2 = assertion(priv2, "replay", extra={"invitation": invitation})
    assert client.post("/v1/auth/register",
                       json={"assertion": a2, "public_key_pem": pub2}).status_code == 401


def test_enrolment_rejects_stale_assertion(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "stale@x.com")
    priv, pub = keypair()
    a = assertion(priv, "stale", extra={"invitation": invitation}, iat_offset=-3600)
    assert client.post("/v1/auth/register",
                       json={"assertion": a, "public_key_pem": pub}).status_code == 401


# ── Key assertions (spec AUTH A–E) ────────────────────────────────────────────


def test_assert_exchanges_signature_for_access_token(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "keyuser@x.com")
    uid = activate_by_email(client, "keyuser@x.com")
    h = admin_headers(client)
    client.post(f"/v1/users/{uid}/roles/viewer", headers=h)

    r = client.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    assert client.get("/v1/things", headers={"Authorization": f"Bearer {tok}"}).status_code == 200


def test_assert_denied_for_inactive_newbie(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "inactivekey@x.com")  # never activated
    assert client.post("/v1/auth/assert",
                       json={"assertion": assertion(priv, cuid)}).status_code == 401


def test_assert_returns_warnings(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "warnkey@x.com")
    uid = activate_by_email(client, "warnkey@x.com")
    h = admin_headers(client)
    client.post(f"/v1/users/{uid}/flags", json={"flag": "warning:suspicious"}, headers=h)
    r = client.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)})
    assert r.status_code == 200
    assert r.json()["warnings"] == ["warning:suspicious"]


def test_assert_rejects_wrong_key_and_replay(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "victim@x.com")
    activate_by_email(client, "victim@x.com")
    attacker_priv, _ = keypair()
    assert client.post("/v1/auth/assert",
                       json={"assertion": assertion(attacker_priv, cuid)}).status_code == 401

    a = assertion(priv, cuid)
    assert client.post("/v1/auth/assert", json={"assertion": a}).status_code == 200
    assert client.post("/v1/auth/assert", json={"assertion": a}).status_code == 401


def test_revoked_key_stops_authenticating(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "revokeme@x.com")
    uid = activate_by_email(client, "revokeme@x.com")
    h = admin_headers(client)
    assert client.post("/v1/auth/assert",
                       json={"assertion": assertion(priv, cuid)}).status_code == 200
    key_id = client.get(f"/v1/users/{uid}/keys", headers=h).json()[0]["id"]
    assert client.delete(f"/v1/users/{uid}/keys/{key_id}", headers=h).status_code == 204
    assert client.post("/v1/auth/assert",
                       json={"assertion": assertion(priv, cuid)}).status_code == 401


# ── API tokens (bearer + X-API-Key) ───────────────────────────────────────────


def test_api_token_via_bearer_and_x_api_key(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    raw = client.post("/v1/auth/tokens", json={"name": "ci", "scopes": ["things:read"]}, headers=h).json()["token"]
    assert client.get("/v1/things", headers={"Authorization": f"Bearer {raw}"}).status_code == 200
    assert client.get("/v1/things", headers={"X-API-Key": raw}).status_code == 200
    assert client.get("/v1/things", headers={"X-API-Key": "wrong"}).status_code == 401


def test_api_token_scopes_enforced(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    raw = client.post("/v1/auth/tokens", json={"name": "narrow", "scopes": ["users:read"]}, headers=h).json()["token"]
    assert client.get("/v1/things", headers={"X-API-Key": raw}).status_code == 403
