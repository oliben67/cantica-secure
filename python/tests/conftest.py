"""Shared fixtures — shim-mounted apps in local, remote, and OIDC configurations."""

from __future__ import annotations

import time
import uuid

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cantica_secure import SecureConfig, SecurityShim

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASS = "Test1234!"
JWT_SECRET = "secure-test-secret-xxxxxxxxxxxxxxxxxxxxxx"

# A small host-like permission vocabulary for tests.
HOST_PERMISSIONS = [
    ("things:read", "Read things"),
    ("things:write", "Write things"),
]
HOST_ROLES = {
    "admin": {
        "description": "Everything",
        "permissions": [
            "things:read", "things:write",
            "users:read", "users:write", "roles:read", "roles:write",
            "tokens:read", "tokens:write",
        ],
    },
    "viewer": {"description": "Read-only", "permissions": ["things:read"]},
}


def make_shim(**config_overrides) -> SecurityShim:
    config = SecureConfig(
        db_url="sqlite:///:memory:",
        local_mode=False,
        jwt_secret=JWT_SECRET,
        admin_email=ADMIN_EMAIL,
        admin_password=ADMIN_PASS,
        **config_overrides,
    )
    return SecurityShim(config, app_name="Test Host", permissions=HOST_PERMISSIONS, builtin_roles=HOST_ROLES)


def make_app(shim: SecurityShim) -> FastAPI:
    app = FastAPI()
    shim.mount(app)

    # A host endpoint guarded by a host permission, to prove the guard works.
    @app.get("/v1/things", dependencies=[shim.require_permission("things:read")])
    def list_things() -> list:
        return []

    return app


@pytest.fixture
def remote() -> tuple[TestClient, SecurityShim]:
    shim = make_shim()
    app = make_app(shim)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, shim
    shim.dispose()


@pytest.fixture
def local() -> tuple[TestClient, SecurityShim]:
    shim = SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True))
    app = make_app(shim)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, shim
    shim.dispose()


# ── Helpers ───────────────────────────────────────────────────────────────────


def admin_headers(client: TestClient) -> dict:
    r = client.post("/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )


def assertion(private_pem: str, subject: str, *, extra: dict | None = None,
              iat_offset: int = 0, jti: str | None = None) -> str:
    now = int(time.time()) + iat_offset
    payload = {
        "iss": subject, "sub": subject, "aud": "cantica-secure",
        "iat": now, "exp": now + 300, "jti": jti or str(uuid.uuid4()),
        **(extra or {}),
    }
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def invite(client: TestClient, email: str) -> str:
    r = client.post("/v1/auth/invitations",
                    json={"first_name": "T", "last_name": "U", "email": email})
    assert r.status_code == 200, r.text
    token = r.json()["invitation"]
    assert token
    return token


def enrol(client: TestClient, email: str) -> tuple[str, str]:
    """Invite + enrol a user; returns (private_pem, cantica_user_id)."""
    invitation = invite(client, email)
    private_pem, public_pem = keypair()
    a = assertion(private_pem, "enrolee", extra={"invitation": invitation})
    r = client.post("/v1/auth/register", json={"assertion": a, "public_key_pem": public_pem})
    assert r.status_code == 200, r.text
    return private_pem, r.json()["cantica_user_id"]


def user_id_by_email(client: TestClient, headers: dict, email: str) -> str:
    users = client.get("/v1/users", headers=headers).json()
    return next(u["id"] for u in users if u["email"] == email)


def activate_by_email(client: TestClient, email: str) -> str:
    h = admin_headers(client)
    uid = user_id_by_email(client, h, email)
    client.post(f"/v1/users/{uid}/activate", headers=h)
    return uid
