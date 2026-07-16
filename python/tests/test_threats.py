"""Consolidated threat suite (extraction roadmap Phase F).

The security guarantees both hosts inherit from the package, named as one
coherent suite: replay protection, user enumeration resistance, revocation
latency, private-key rejection, and cross-user forgery. (Some cases overlap
the endpoint suites — kept here so the guarantees are legible in one place.)
"""

from __future__ import annotations

import time
import uuid

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from cantica_secure import SecurityShim
from tests.conftest import (
    JWT_SECRET,
    activate_by_email,
    admin_headers,
    assertion,
    enrol,
    invite,
    keypair,
)

Fixture = tuple[TestClient, SecurityShim]


# ── Replay protection ─────────────────────────────────────────────────────────


def test_invitation_is_single_use(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "replay-inv@x.com")
    priv1, pub1 = keypair()
    a1 = assertion(priv1, "e", extra={"invitation": invitation})
    assert client.post("/v1/auth/register", json={"assertion": a1, "public_key_pem": pub1}).status_code == 200
    # Same invitation, fresh key → burned jti rejects the second use.
    priv2, pub2 = keypair()
    a2 = assertion(priv2, "e", extra={"invitation": invitation})
    assert client.post("/v1/auth/register", json={"assertion": a2, "public_key_pem": pub2}).status_code == 401


def test_enrolment_assertion_jti_not_replayable_across_users(remote: Fixture) -> None:
    client, _ = remote
    shared = str(uuid.uuid4())
    inv1 = invite(client, "r1@x.com")
    p1, k1 = keypair()
    assert client.post("/v1/auth/register", json={
        "assertion": assertion(p1, "e", extra={"invitation": inv1}, jti=shared), "public_key_pem": k1,
    }).status_code == 200
    inv2 = invite(client, "r2@x.com")
    p2, k2 = keypair()
    assert client.post("/v1/auth/register", json={
        "assertion": assertion(p2, "e", extra={"invitation": inv2}, jti=shared), "public_key_pem": k2,
    }).status_code == 401


def test_auth_assertion_is_single_use(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "replay-auth@x.com")
    activate_by_email(client, "replay-auth@x.com")
    a = assertion(priv, cuid)
    assert client.post("/v1/auth/assert", json={"assertion": a}).status_code == 200
    assert client.post("/v1/auth/assert", json={"assertion": a}).status_code == 401


def test_stale_assertion_rejected(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "stale@x.com")
    activate_by_email(client, "stale@x.com")
    old = assertion(priv, cuid, iat_offset=-3600)
    assert client.post("/v1/auth/assert", json={"assertion": old}).status_code == 401


# ── Enumeration resistance ────────────────────────────────────────────────────


def test_blocked_inactive_and_unknown_are_indistinguishable(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)

    def _token(email: str) -> str:
        uid = client.post("/v1/users", json={"email": email, "password": "Pw123456!"}, headers=h).json()["id"]
        client.post(f"/v1/users/{uid}/roles/viewer", headers=h)
        tok = client.post("/v1/auth/login", json={"email": email, "password": "Pw123456!"}).json()["access_token"]
        return uid, tok

    b_uid, b_tok = _token("blk@x.com")
    client.post(f"/v1/users/{b_uid}/flags", json={"flag": "blocked:abuse"}, headers=h)
    i_uid, i_tok = _token("ina@x.com")
    client.put(f"/v1/users/{i_uid}", json={"is_active": False}, headers=h)

    rb = client.get("/v1/things", headers={"Authorization": f"Bearer {b_tok}"})
    ri = client.get("/v1/things", headers={"Authorization": f"Bearer {i_tok}"})
    assert rb.status_code == ri.status_code == 401
    assert rb.json() == ri.json()  # byte-identical body — no state disclosure
    assert "blocked" not in rb.text.lower() and "inactive" not in ri.text.lower()


def test_enrolled_email_yields_no_reissued_invitation(remote: Fixture) -> None:
    client, _ = remote
    enrol(client, "known@x.com")
    # Anyone probing an enrolled address gets the generic shape, no token.
    r = client.post("/v1/auth/invitations",
                    json={"first_name": "a", "last_name": "b", "email": "known@x.com"})
    assert r.status_code == 200 and r.json()["invitation"] is None


# ── Revocation latency ────────────────────────────────────────────────────────


def test_blocked_flag_invalidates_live_token_immediately(remote: Fixture) -> None:
    client, _ = remote
    h = admin_headers(client)
    uid = client.post("/v1/users", json={"email": "live@x.com", "password": "Pw123456!"}, headers=h).json()["id"]
    client.post(f"/v1/users/{uid}/roles/viewer", headers=h)
    tok = client.post("/v1/auth/login", json={"email": "live@x.com", "password": "Pw123456!"}).json()["access_token"]
    bh = {"Authorization": f"Bearer {tok}"}
    assert client.get("/v1/things", headers=bh).status_code == 200
    client.post(f"/v1/users/{uid}/flags", json={"flag": "blocked:none"}, headers=h)
    assert client.get("/v1/things", headers=bh).status_code == 401  # next request, no re-login


def test_revoked_key_stops_authenticating(remote: Fixture) -> None:
    client, _ = remote
    priv, cuid = enrol(client, "revoke@x.com")
    uid = activate_by_email(client, "revoke@x.com")
    h = admin_headers(client)
    assert client.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)}).status_code == 200
    key_id = client.get(f"/v1/users/{uid}/keys", headers=h).json()[0]["id"]
    assert client.delete(f"/v1/users/{uid}/keys/{key_id}", headers=h).status_code == 204
    assert client.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)}).status_code == 401


# ── Key material & forgery ─────────────────────────────────────────────────────


def test_private_key_upload_rejected(remote: Fixture) -> None:
    client, _ = remote
    invitation = invite(client, "leak@x.com")
    priv, _pub = keypair()
    r = client.post("/v1/auth/register",
                    json={"assertion": assertion(priv, "e", extra={"invitation": invitation}),
                          "public_key_pem": priv})  # sending the PRIVATE key
    assert r.status_code == 401


def test_wrong_key_cannot_impersonate(remote: Fixture) -> None:
    client, _ = remote
    _priv, cuid = enrol(client, "victim@x.com")
    activate_by_email(client, "victim@x.com")
    attacker_priv, _ = keypair()
    r = client.post("/v1/auth/assert", json={"assertion": assertion(attacker_priv, cuid)})
    assert r.status_code == 401


def test_forged_invitation_signature_rejected(remote: Fixture) -> None:
    client, _ = remote
    # A validly *shaped* invitation signed with the wrong secret.
    forged = pyjwt.encode(
        {"iss": "cantica-secure", "purpose": "invite", "sub": "x", "email": "x@x.com",
         "roles": [], "iat": int(time.time()), "exp": int(time.time()) + 600, "jti": str(uuid.uuid4())},
        "not-the-server-secret", algorithm="HS256",
    )
    priv, pub = keypair()
    r = client.post("/v1/auth/register",
                    json={"assertion": assertion(priv, "e", extra={"invitation": forged}),
                          "public_key_pem": pub})
    assert r.status_code == 401
    assert forged  # (JWT_SECRET is the real one; forged uses a different key)


@pytest.mark.parametrize("cuid", ["ghost@x.com", "", "does-not-exist"])
def test_assert_for_unknown_identity_rejected(remote: Fixture, cuid: str) -> None:
    client, _ = remote
    priv, _ = keypair()
    assert client.post("/v1/auth/assert", json={"assertion": assertion(priv, cuid)}).status_code == 401
