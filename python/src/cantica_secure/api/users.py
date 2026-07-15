"""User and role management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from cantica_secure.api.deps import CurrentUserDep, DbSession, ShimDep, require_permission
from cantica_secure.core.flags import FLAG_NEWBIE, KNOWN_FLAGS, audit_log
from cantica_secure.core.password import hash_password
from cantica_secure.orm.models import JwtKey, Role, User, UserFlag

users_router = APIRouter()
roles_router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────


class CreateUserRequest(BaseModel):
    email: str
    password: str
    first_name: str = ""
    last_name: str = ""


class UpdateUserRequest(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    password: str | None = None
    is_active: bool | None = None


class AddFlagRequest(BaseModel):
    flag: str
    comment: str = ""


def _user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_active": user.is_active,
        "e_user_id": user.e_user_id,
        "roles": [r.name for r in user.roles],
        "flags": [_flag_dict(f) for f in user.flags],
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
    }


def _flag_dict(f: UserFlag) -> dict:
    return {
        "id": f.id,
        "flag": f.flag,
        "comment": f.comment,
        "created_by": f.created_by,
        "created_at": f.created_at.isoformat(),
    }


def _role_dict(role: Role) -> dict:
    return {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": [p.name for p in role.permissions],
        "created_at": role.created_at.isoformat(),
    }


# ── User CRUD ─────────────────────────────────────────────────────────────────


@users_router.get("", dependencies=[require_permission("users:read")])
def list_users(db: DbSession, flag: str | None = None) -> list[dict]:
    """List users, optionally filtered by flag (e.g. ?flag=newbie for the activation screen)."""
    stmt = select(User).options(selectinload(User.roles), selectinload(User.flags))
    if flag:
        stmt = stmt.join(UserFlag).where(UserFlag.flag == flag)
    users = db.scalars(stmt).all()
    return [_user_dict(u) for u in users]


@users_router.post("", status_code=201, dependencies=[require_permission("users:write")])
def create_user(body: CreateUserRequest, db: DbSession) -> dict:
    if db.scalar(select(User).where(User.email == body.email)) is not None:
        raise HTTPException(status_code=409, detail=f"User {body.email!r} already exists")
    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
    )
    db.add(user)
    db.commit()
    return _user_dict(user)


@users_router.get("/{user_id}", dependencies=[require_permission("users:read")])
def get_user(user_id: str, db: DbSession) -> dict:
    user = db.scalar(select(User).options(selectinload(User.roles), selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_dict(user)


@users_router.put("/{user_id}", dependencies=[require_permission("users:write")])
def update_user(user_id: str, body: UpdateUserRequest, db: DbSession) -> dict:
    user = db.scalar(select(User).options(selectinload(User.roles), selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.first_name is not None:
        user.first_name = body.first_name
    if body.last_name is not None:
        user.last_name = body.last_name
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    if body.is_active is not None:
        user.is_active = body.is_active
    db.commit()
    return _user_dict(user)


@users_router.delete("/{user_id}", status_code=204, dependencies=[require_permission("users:write")])
def delete_user(user_id: str, db: DbSession) -> None:
    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()


@users_router.post("/{user_id}/roles/{role_name}", dependencies=[require_permission("users:write")])
def assign_role(user_id: str, role_name: str, db: DbSession) -> dict:
    user = db.scalar(select(User).options(selectinload(User.roles), selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        raise HTTPException(status_code=404, detail=f"Role {role_name!r} not found")
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
    return _user_dict(user)


@users_router.delete("/{user_id}/roles/{role_name}", dependencies=[require_permission("users:write")])
def remove_role(user_id: str, role_name: str, db: DbSession) -> dict:
    user = db.scalar(select(User).options(selectinload(User.roles), selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.roles = [r for r in user.roles if r.name != role_name]
    db.commit()
    return _user_dict(user)


# ── Flags & activation (spec REGISTRATION A.4 / C.pre.2) ──────────────────────


@users_router.get("/{user_id}/flags", dependencies=[require_permission("users:read")])
def list_flags(user_id: str, db: DbSession) -> list[dict]:
    user = db.scalar(select(User).options(selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return [_flag_dict(f) for f in user.flags]


@users_router.post("/{user_id}/flags", status_code=201, dependencies=[require_permission("users:write")])
def add_flag(user_id: str, body: AddFlagRequest, current_user: CurrentUserDep, db: DbSession) -> dict:
    if body.flag not in KNOWN_FLAGS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown flag {body.flag!r}. Known flags: {', '.join(sorted(KNOWN_FLAGS))}",
        )
    user = db.scalar(select(User).options(selectinload(User.flags)).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if any(f.flag == body.flag for f in user.flags):
        raise HTTPException(status_code=409, detail=f"User already flagged {body.flag!r}")
    f = UserFlag(user_id=user_id, flag=body.flag, comment=body.comment, created_by=current_user.user_id)
    db.add(f)
    db.commit()
    audit_log.info("flag added: user=%s flag=%s by=%s", user_id, body.flag, current_user.user_id)
    return _flag_dict(f)


@users_router.delete("/{user_id}/flags/{flag_id}", status_code=204, dependencies=[require_permission("users:write")])
def remove_flag(user_id: str, flag_id: str, current_user: CurrentUserDep, db: DbSession) -> None:
    f = db.scalar(select(UserFlag).where(UserFlag.id == flag_id, UserFlag.user_id == user_id))
    if f is None:
        raise HTTPException(status_code=404, detail="Flag not found")
    db.delete(f)
    db.commit()
    audit_log.info("flag removed: user=%s flag=%s by=%s", user_id, f.flag, current_user.user_id)


@users_router.post("/{user_id}/activate", dependencies=[require_permission("users:write")])
def activate_user(user_id: str, current_user: CurrentUserDep, shim: ShimDep, db: DbSession) -> dict:
    """Enable a newly registered user and clear its 'newbie' flag (activation screen)."""
    user = db.scalar(
        select(User).options(selectinload(User.roles), selectinload(User.flags)).where(User.id == user_id)
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    for f in list(user.flags):
        if f.flag == FLAG_NEWBIE:
            db.delete(f)
    db.commit()
    db.refresh(user)
    audit_log.info("user activated: user=%s by=%s", user_id, current_user.user_id)
    shim.notify_user_event("activated", user_id)
    return _user_dict(user)


# ── Enrolled keys (spec REGISTRATION A.5) ─────────────────────────────────────


@users_router.get("/{user_id}/keys", dependencies=[require_permission("users:read")])
def list_keys(user_id: str, db: DbSession) -> list[dict]:
    keys = db.scalars(select(JwtKey).where(JwtKey.user_id == user_id)).all()
    return [
        {
            "id": k.id,
            "cantica_user_id": k.cantica_user_id,
            "created_at": k.created_at.isoformat(),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
        }
        for k in keys
    ]


@users_router.delete("/{user_id}/keys/{key_id}", status_code=204, dependencies=[require_permission("users:write")])
def revoke_key(user_id: str, key_id: str, current_user: CurrentUserDep, db: DbSession) -> None:
    """Revoke an enrolled key — assertions signed with it stop working immediately."""
    from datetime import datetime, timezone  # noqa: PLC0415

    key = db.scalar(select(JwtKey).where(JwtKey.id == key_id, JwtKey.user_id == user_id))
    if key is None:
        raise HTTPException(status_code=404, detail="Key not found")
    key.revoked_at = datetime.now(timezone.utc)
    db.commit()
    audit_log.info("key revoked: user=%s key=%s by=%s", user_id, key_id, current_user.user_id)


# ── Role listing ──────────────────────────────────────────────────────────────


@roles_router.get("", dependencies=[require_permission("roles:read")])
def list_roles(db: DbSession) -> list[dict]:
    roles = db.scalars(select(Role).options(selectinload(Role.permissions))).all()
    return [_role_dict(r) for r in roles]
