"""Auth endpoints — login, OIDC, invitations, key enrolment, assertions, API tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from cantica_secure.api.deps import CurrentUserDep, DbSession, ShimDep, require_permission
from cantica_secure.backends.base import get_auth_backend
from cantica_secure.core.apikeys import generate_api_token
from cantica_secure.core.flags import FLAG_NEWBIE, GENERIC_AUTH_FAILURE, audit_log, gate_user
from cantica_secure.core.jwt import (
    create_access_token,
    create_enrolment_confirmation,
    create_invitation_token,
    decode_invitation_token,
)
from cantica_secure.core.keyauth import (
    KeyAssertionError,
    burn_jti,
    reject_private_key_material,
    verify_assertion,
)
from cantica_secure.orm.models import ApiToken, JwtKey, Role, User, UserFlag

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    warnings: list[str] = []


class OidcLoginRequest(BaseModel):
    id_token: str


class InvitationRequest(BaseModel):
    first_name: str
    last_name: str
    email: str


class InvitationResponse(BaseModel):
    status: str = "invitation issued"
    # Present only when no mail transport is configured (in-band mode).
    invitation: str | None = None


class EnrolRequest(BaseModel):
    # RS256 JWS signed with the user's PRIVATE key; payload embeds the
    # invitation JWT under the "invitation" claim, plus iat/exp/jti.
    assertion: str | None = None
    public_key_pem: str | None = None
    # Legacy local-mode body ({client_id, public_key_pem}) — accepted as a
    # no-op when local_mode is on so pre-remote clients keep working.
    client_id: str | None = None


class AssertRequest(BaseModel):
    assertion: str


class CreateTokenRequest(BaseModel):
    name: str
    scopes: list[str] = []
    expires_days: int | None = None


def _token_dict(t: ApiToken) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "scopes": t.scopes,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "created_at": t.created_at.isoformat(),
    }


def _issue_access_token(shim, user: User, warnings: list[str]) -> LoginResponse:  # noqa: ANN001
    permissions = list({p.name for role in user.roles for p in role.permissions})
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        roles=[r.name for r in user.roles],
        permissions=permissions,
        group_id=user.group_id,
        secret=shim.config.jwt_secret,
        expire_minutes=shim.config.jwt_expire_minutes,
    )
    return LoginResponse(
        access_token=token,
        expires_in=shim.config.jwt_expire_minutes * 60,
        warnings=warnings,
    )


# ── Login (password / OIDC) ───────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, shim: ShimDep, db: DbSession) -> LoginResponse:
    config = shim.config
    if config.local_mode:
        raise HTTPException(status_code=400, detail="Login not available in local mode")

    backend = get_auth_backend(config, session=db)
    result = backend.authenticate(body.email, body.password)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = backend.sync_user(db, result)

    gate = gate_user(user, context="login")
    if not gate.allowed:
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
    return _issue_access_token(shim, user, gate.warnings)


@router.post("/oidc", response_model=LoginResponse)
def oidc_login(body: OidcLoginRequest, shim: ShimDep, db: DbSession) -> LoginResponse:
    """Exchange an OIDC ID token for an access token (spec REGISTRATION B)."""
    config = shim.config
    if config.local_mode:
        raise HTTPException(status_code=400, detail="OIDC login not available in local mode")
    if config.auth_backend != "oidc":
        raise HTTPException(status_code=400, detail="OIDC backend is not configured")

    backend = get_auth_backend(config)
    result = backend.authenticate(body.id_token, "")
    if result is None:
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
    user = backend.sync_user(db, result)

    gate = gate_user(user, context="oidc-login")
    if not gate.allowed:
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
    return _issue_access_token(shim, user, gate.warnings)


# ── Invitations (spec REGISTRATION C) ─────────────────────────────────────────


@router.post("/invitations", response_model=InvitationResponse)
def request_invitation(
    body: InvitationRequest, request: Request, shim: ShimDep, db: DbSession
) -> InvitationResponse:
    """Public invitation request (spec C.1–C.2).

    Creates the account (disabled + 'newbie' unless auto_activate_users) with
    the configured default roles, and issues a single-use invitation JWT.
    With a mail transport the token is delivered by email and the response
    carries no token; responses are shape-identical for new and existing
    emails to limit account enumeration.
    """
    config = shim.config
    if config.local_mode:
        raise HTTPException(status_code=400, detail="Invitations not available in local mode")

    client_ip = request.client.host if request.client else "unknown"
    if shim.rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too many invitation requests — try again later")

    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="A valid email is required")

    existing = db.scalar(
        select(User).options(selectinload(User.jwt_keys), selectinload(User.roles)).where(User.email == email)
    )

    if existing is not None:
        # Re-issue only for accounts that never completed enrolment; anything
        # else gets the same generic response (no enumeration, no key hijack).
        active_keys = [k for k in existing.jwt_keys if k.revoked_at is None]
        if active_keys:
            audit_log.warning("invitation refused: user=%s already enrolled", existing.id)
            return InvitationResponse()
        token = create_invitation_token(
            user_id=existing.id,
            email=existing.email,
            roles=[r.name for r in existing.roles],
            secret=config.jwt_secret,
            expire_minutes=config.invite_expire_minutes,
        )
        audit_log.info("invitation re-issued: user=%s", existing.id)
        return shim.deliver_invitation(existing.email, token)

    role_names = config.default_roles
    roles = list(db.scalars(select(Role).where(Role.name.in_(role_names))))
    user = User(
        email=email,
        password_hash="",  # key-based account; password login stays impossible
        first_name=body.first_name.strip(),
        last_name=body.last_name.strip(),
        is_active=config.auto_activate_users,
    )
    user.roles = roles
    db.add(user)
    db.flush()
    if not config.auto_activate_users:
        db.add(UserFlag(user_id=user.id, flag=FLAG_NEWBIE, comment="awaiting admin activation"))
    db.commit()
    shim.notify_user_event("created", user.id)

    token = create_invitation_token(
        user_id=user.id,
        email=user.email,
        roles=[r.name for r in roles],
        secret=config.jwt_secret,
        expire_minutes=config.invite_expire_minutes,
    )
    audit_log.info(
        "invitation issued: user=%s email=%s roles=%s active=%s",
        user.id, user.email, role_names, user.is_active,
    )
    return shim.deliver_invitation(user.email, token)


# ── Key enrolment (spec REGISTRATION B&C 3–8) ─────────────────────────────────


@router.post("/register")
def register_key(body: EnrolRequest, shim: ShimDep, db: DbSession) -> dict:
    """Enrol a client public key bound to cantica_user_id (spec steps 3–8)."""
    config = shim.config

    if config.local_mode:
        # Local mode has no auth; acknowledge so local clients stop erroring.
        return {"status": "ok", "mode": "local"}

    if not body.assertion or not body.public_key_pem:
        raise HTTPException(status_code=422, detail="assertion and public_key_pem are required")

    try:
        reject_private_key_material(body.public_key_pem)
        payload = verify_assertion(
            body.assertion, body.public_key_pem,
            max_age_seconds=config.assertion_max_age_seconds,
        )
    except KeyAssertionError as exc:
        audit_log.warning("enrolment denied: %s", exc)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    invitation = payload.get("invitation")
    if not invitation:
        audit_log.warning("enrolment denied: assertion carries no invitation")
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    try:
        invite = decode_invitation_token(invitation, config.jwt_secret)
    except pyjwt.InvalidTokenError as exc:
        audit_log.warning("enrolment denied: invitation invalid: %s", exc)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    user = db.scalar(
        select(User)
        .options(selectinload(User.jwt_keys), selectinload(User.flags))
        .where(User.id == invite["sub"])
    )
    # Spec step 7: extracted data must match what registration recorded (B.2/C.2).
    if user is None or user.email != invite.get("email"):
        audit_log.warning("enrolment denied: invitation identity mismatch (sub=%s)", invite.get("sub"))
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
    if any(k.revoked_at is None for k in user.jwt_keys):
        audit_log.warning("enrolment denied: user=%s already enrolled", user.id)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    # Spec step 8.a/8.b: enterprise id when present, account email otherwise.
    cantica_user_id = user.e_user_id or user.email

    try:
        burn_jti(
            db, invite["jti"], "invite",
            datetime.fromtimestamp(float(invite["exp"]), tz=timezone.utc),
        )
        burn_jti(
            db, payload["jti"], "enrol",
            datetime.now(timezone.utc) + timedelta(seconds=config.assertion_max_age_seconds),
        )
    except KeyAssertionError as exc:
        audit_log.warning("enrolment denied: %s", exc)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    db.add(JwtKey(
        cantica_user_id=cantica_user_id,
        user_id=user.id,
        public_key=body.public_key_pem,
    ))
    db.commit()
    audit_log.info("key enrolled: user=%s cantica_user_id=%s", user.id, cantica_user_id)

    return {
        "status": "enrolled",
        "cantica_user_id": cantica_user_id,
        "confirmation": create_enrolment_confirmation(
            user_id=user.id, cantica_user_id=cantica_user_id, secret=config.jwt_secret,
        ),
    }


# ── Key assertion → access token (spec AUTH A–F) ──────────────────────────────


@router.post("/assert", response_model=LoginResponse)
def assert_auth(body: AssertRequest, shim: ShimDep, db: DbSession) -> LoginResponse:
    """Exchange a key-signed assertion for a short-lived access token."""
    config = shim.config
    if config.local_mode:
        raise HTTPException(status_code=400, detail="Assertions not available in local mode")

    # cantica_user_id travels as iss/sub — read unverified to find the key.
    try:
        unverified = pyjwt.decode(body.assertion, options={"verify_signature": False})
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
    cantica_user_id = unverified.get("sub") or unverified.get("iss") or ""

    key = db.scalar(
        select(JwtKey).where(
            JwtKey.cantica_user_id == cantica_user_id, JwtKey.revoked_at.is_(None)
        )
    )
    if key is None:
        audit_log.warning("assert denied: no enrolled key for %r", cantica_user_id)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    try:
        payload = verify_assertion(
            body.assertion, key.public_key,
            max_age_seconds=config.assertion_max_age_seconds,
        )
        burn_jti(
            db, payload["jti"], "auth",
            datetime.now(timezone.utc) + timedelta(seconds=config.assertion_max_age_seconds),
        )
    except KeyAssertionError as exc:
        audit_log.warning("assert denied [%s]: %s", cantica_user_id, exc)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    user = db.scalar(
        select(User)
        .options(
            selectinload(User.roles).selectinload(Role.permissions),
            selectinload(User.flags),
        )
        .where(User.id == key.user_id)
    )
    result = gate_user(user, context="assert")
    if not result.allowed or user is None:
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    key.last_used_at = datetime.now(timezone.utc)
    db.commit()
    audit_log.info("assert ok: user=%s cantica_user_id=%s warnings=%s", user.id, cantica_user_id, result.warnings)
    return _issue_access_token(shim, user, result.warnings)


# ── Session info ──────────────────────────────────────────────────────────────


@router.get("/me")
def me(current_user: CurrentUserDep) -> dict:
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "roles": current_user.roles,
        "permissions": current_user.permissions,
        "group_id": current_user.group_id,
        "warnings": current_user.warnings,
        "anonymous": current_user.is_anonymous,
    }


# ── API token management ──────────────────────────────────────────────────────


@router.get("/tokens", dependencies=[require_permission("tokens:read")])
def list_tokens(current_user: CurrentUserDep, db: DbSession) -> list[dict]:
    tokens = db.scalars(
        select(ApiToken).where(ApiToken.user_id == current_user.user_id)
    ).all()
    return [_token_dict(t) for t in tokens]


@router.post("/tokens", status_code=201, dependencies=[require_permission("tokens:write")])
def create_token(body: CreateTokenRequest, current_user: CurrentUserDep, db: DbSession) -> dict:
    raw, token_hash = generate_api_token()
    expires_at: datetime | None = None
    if body.expires_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    api_token = ApiToken(
        user_id=current_user.user_id,
        token_hash=token_hash,
        name=body.name,
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(api_token)
    db.commit()
    return {**_token_dict(api_token), "token": raw}


@router.delete("/tokens/{token_id}", status_code=204, dependencies=[require_permission("tokens:write")])
def delete_token(token_id: str, current_user: CurrentUserDep, db: DbSession) -> None:
    token = db.scalar(
        select(ApiToken).where(
            ApiToken.id == token_id, ApiToken.user_id == current_user.user_id
        )
    )
    if token is None:
        raise HTTPException(status_code=404, detail="Token not found")
    db.delete(token)
    db.commit()
