"""Security ORM — users, roles, permissions, flags, keys, tokens, mappings.

Extracted from studio-api's security models. Provider/API-provider entities
are deliberately absent: Cantica Secure owns identity and access only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Table, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cantica_secure.orm.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Association tables ─────────────────────────────────────────────────────────

user_roles_table = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions_table = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", String(36), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


# ── Core entities ─────────────────────────────────────────────────────────────

class Group(Base):
    """A named group of users. Cantica Secure owns group identity/membership;
    what a group *grants* in the host (e.g. shared provider keys in studio-api)
    is host business, keyed by this id."""

    __tablename__ = "groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="")
    # Opaque identifier used by an external directory (LDAP DN, OIDC groups claim).
    external_id: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    members: Mapped[list["User"]] = relationship("User", back_populates="group")


class User(Base):
    """Core user profile and credentials."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    first_name: Mapped[str] = mapped_column(String(100), default="")
    last_name: Mapped[str] = mapped_column(String(100), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # User id provided by the enterprise infrastructure (AD/OIDC); null outside
    # enterprise environments. Unique-when-set (partial index in migrate.py).
    e_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    group_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    group: Mapped["Group | None"] = relationship("Group", back_populates="members")
    roles: Mapped[list["Role"]] = relationship(
        "Role", secondary=user_roles_table, back_populates="users"
    )
    api_tokens: Mapped[list["ApiToken"]] = relationship(
        "ApiToken", back_populates="user", cascade="all, delete-orphan"
    )
    flags: Mapped[list["UserFlag"]] = relationship(
        "UserFlag", back_populates="user", cascade="all, delete-orphan"
    )
    jwt_keys: Mapped[list["JwtKey"]] = relationship(
        "JwtKey", back_populates="user", cascade="all, delete-orphan"
    )


class UserFlag(Base):
    """A moderation / lifecycle mark on a user. A user can hold several flags.

    Flag codes are an open vocabulary validated in core/flags.py. `newbie`
    marks a new user awaiting activation; `warning:*` and `blocked:*` drive
    the auth gate.
    """

    __tablename__ = "user_flags"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    flag: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    comment: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str] = mapped_column(String(36), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    user: Mapped[User] = relationship("User", back_populates="flags")


class JwtKey(Base):
    """A user's enrolled signing key for key-based authentication.

    Stores the PUBLIC key only — assertions are signed client-side with the
    matching private key and verified here. cantica_user_id is e_user_id for
    enterprise users, the account email otherwise.
    """

    __tablename__ = "jwt_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cantica_user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    public_key: Mapped[str] = mapped_column(String(4096), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="jwt_keys")


class UsedJti(Base):
    """Replay protection — every client-signed JWT's jti is burned on first use."""

    __tablename__ = "used_jtis"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)  # invite | enrol | auth
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Role(Base):
    """A named permission profile assignable to multiple users."""

    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    users: Mapped[list[User]] = relationship(
        "User", secondary=user_roles_table, back_populates="roles"
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission", secondary=role_permissions_table, back_populates="roles"
    )


class Permission(Base):
    """An atomic action on a resource, named resource:action.

    The vocabulary is host-defined: each host registers its permissions with
    the shim at mount time (see shim.PermissionModel).
    """

    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    roles: Mapped[list[Role]] = relationship(
        "Role", secondary=role_permissions_table, back_populates="permissions"
    )


class ApiToken(Base):
    """Long-lived credential for CLI / 3rd-party access. Only the hash is stored."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    user: Mapped[User] = relationship("User", back_populates="api_tokens")


class DirectoryGroupRole(Base):
    """Maps an external directory group (AD DN, OIDC groups value) to a Role."""

    __tablename__ = "directory_group_roles"
    __table_args__ = (UniqueConstraint("external_group", "role_id", name="uq_dir_group_role"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_group: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    role: Mapped["Role"] = relationship("Role")
