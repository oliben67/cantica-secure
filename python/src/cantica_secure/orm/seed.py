"""Idempotent seeding — host-registered permissions/roles, limbo, first admin."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from cantica_secure.orm.models import Permission, Role, User

log = logging.getLogger(__name__)

# Permissions Cantica Secure itself needs, regardless of host vocabulary.
BASE_PERMISSIONS: list[tuple[str, str]] = [
    ("users:read",  "View users, their flags, keys, and role assignments"),
    ("users:write", "Create, update, activate, flag, and delete users"),
    ("roles:read",  "View roles, permissions, and directory mappings"),
    ("roles:write", "Create, update, and delete roles and directory mappings"),
    ("tokens:read",  "View own API tokens"),
    ("tokens:write", "Create and revoke own API tokens"),
]

# Deny-by-default role for users with no assignment yet. Every endpoint
# requires an explicit permission, so zero permissions means zero access.
LIMBO_ROLE = "limbo"


def seed(
    session: Session,
    *,
    permissions: list[tuple[str, str]],
    builtin_roles: dict[str, dict],
) -> None:
    """Create the host-registered permissions and roles (idempotent).

    *permissions* is the merged host vocabulary (BASE_PERMISSIONS are always
    included); *builtin_roles* maps role name → {description, permissions}.
    The ``limbo`` role is always seeded with zero permissions.
    """
    merged = {name: desc for name, desc in BASE_PERMISSIONS}
    for name, desc in permissions:
        merged.setdefault(name, desc)

    perm_by_name: dict[str, Permission] = {}
    for name, description in merged.items():
        existing = session.scalar(select(Permission).where(Permission.name == name))
        if existing is None:
            p = Permission(name=name, description=description)
            session.add(p)
            perm_by_name[name] = p
            log.debug("Seeded permission: %s", name)
        else:
            perm_by_name[name] = existing

    all_roles = dict(builtin_roles)
    all_roles.setdefault(LIMBO_ROLE, {
        "description": "No access (default for unassigned users)",
        "permissions": [],
    })

    for role_name, role_def in all_roles.items():
        role = session.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            role = Role(name=role_name, description=role_def.get("description", ""))
            session.add(role)
            log.debug("Seeded role: %s", role_name)
        existing_perm_names = {p.name for p in role.permissions}
        for perm_name in role_def.get("permissions", []):
            if perm_name in perm_by_name and perm_name not in existing_perm_names:
                role.permissions.append(perm_by_name[perm_name])

    session.commit()


def ensure_admin(session: Session, email: str, password_hash: str, *, admin_role: str = "admin") -> User:
    """Seed the first admin user when none exists (idempotent)."""
    existing = session.scalar(select(User).where(User.email == email))
    if existing is not None:
        return existing
    user = User(email=email, password_hash=password_hash, first_name="Admin", is_active=True)
    role = session.scalar(select(Role).where(Role.name == admin_role))
    if role is not None:
        user.roles.append(role)
    session.add(user)
    session.commit()
    log.info("Seeded admin user %s", email)
    return user
