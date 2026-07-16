"""Cross-server contract: one key pair, both servers (extraction roadmap Phase F).

Two independently configured hosts (different jwt_secret, DB, vocabulary) mount
the shim. The same RSA key pair, once its public key is enrolled on each host,
authenticates on both — proving the RS256 assertion contract (iss/sub =
cantica_user_id, iat/exp/jti) is identical across deployments. This is the
"one identity, both servers" goal.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cantica_secure import (
    CANTICA_PERMISSIONS,
    CANTICA_ROLES,
    STUDIO_PERMISSIONS,
    STUDIO_ROLES,
    SecureConfig,
    SecurityShim,
)
from tests.conftest import ADMIN_EMAIL, ADMIN_PASS, assertion, invite, keypair

STUDIO_SECRET = "studio-x-secret-xxxxxxxxxxxxxxxxxxxxxxxx"
CANTICA_SECRET = "cantica-x-secret-xxxxxxxxxxxxxxxxxxxxxxx"


def _host(secret: str, permissions, roles, **extra) -> tuple[TestClient, SecurityShim]:
    shim = SecurityShim(
        SecureConfig(
            db_url="sqlite:///:memory:", local_mode=False, jwt_secret=secret,
            admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASS,
            auto_activate_users=True, **extra,
        ),
        permissions=permissions, builtin_roles=roles,
    )
    app = FastAPI()
    shim.mount(app)
    return TestClient(app, raise_server_exceptions=True), shim


@pytest.fixture
def two_hosts():  # noqa: ANN201
    studio, s_shim = _host(STUDIO_SECRET, STUDIO_PERMISSIONS, STUDIO_ROLES)
    cantica, c_shim = _host(CANTICA_SECRET, CANTICA_PERMISSIONS, CANTICA_ROLES)
    try:
        yield studio, cantica
    finally:
        s_shim.dispose()
        c_shim.dispose()


def _enrol_public_key(client: TestClient, email: str, private_pem: str, public_pem: str) -> str:
    """Invite + enrol a specific (already generated) key pair; returns cantica_user_id."""
    invitation = invite(client, email)
    a = assertion(private_pem, "enrolee", extra={"invitation": invitation})
    r = client.post("/v1/auth/register", json={"assertion": a, "public_key_pem": public_pem})
    assert r.status_code == 200, r.text
    return r.json()["cantica_user_id"]


def test_one_key_pair_authenticates_on_both_servers(two_hosts) -> None:  # noqa: ANN001
    studio, cantica = two_hosts
    private_pem, public_pem = keypair()

    # Enrol the SAME public key (same person) on both servers.
    studio_cuid = _enrol_public_key(studio, "dev@corp.com", private_pem, public_pem)
    cantica_cuid = _enrol_public_key(cantica, "dev@corp.com", private_pem, public_pem)
    assert studio_cuid == cantica_cuid == "dev@corp.com"

    # A single private key signs assertions that authenticate on both.
    for client in (studio, cantica):
        r = client.post("/v1/auth/assert", json={"assertion": assertion(private_pem, "dev@corp.com")})
        assert r.status_code == 200, r.text
        assert r.json()["access_token"]


def test_access_tokens_do_not_cross_servers(two_hosts) -> None:  # noqa: ANN001
    """Enrolment/assertion contract is shared, but issued session tokens are
    per-host (different jwt_secret) — a studio token is rejected by cantica."""
    studio, cantica = two_hosts
    private_pem, public_pem = keypair()
    _enrol_public_key(studio, "dev@corp.com", private_pem, public_pem)

    studio_token = studio.post(
        "/v1/auth/assert", json={"assertion": assertion(private_pem, "dev@corp.com")}
    ).json()["access_token"]

    # The studio-issued JWT is not a valid credential on the cantica host.
    r = cantica.get("/v1/users", headers={"Authorization": f"Bearer {studio_token}"})
    assert r.status_code == 401


def test_key_enrolled_on_one_server_cannot_assert_on_the_other(two_hosts) -> None:  # noqa: ANN001
    """Without enrolling on the second server, the key has no bound public key
    there, so assertion is rejected — enrolment is per-host by design."""
    studio, cantica = two_hosts
    private_pem, public_pem = keypair()
    _enrol_public_key(studio, "solo@corp.com", private_pem, public_pem)

    r = cantica.post("/v1/auth/assert", json={"assertion": assertion(private_pem, "solo@corp.com")})
    assert r.status_code == 401
