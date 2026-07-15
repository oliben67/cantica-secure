"""Directory user provisioning (spec REGISTRATION B.1–B.2).

Creates or updates a user from an enterprise identity (LDAP bind / OIDC token):
stores the enterprise id in users.e_user_id, refreshes profile fields, assigns
roles from the admin-maintained directory_group_roles mapping, and assigns
group membership by matching Group.external_id against the directory groups.
Users whose groups map to no roles fall back to *default_roles* and are
flagged 'newbie' for admin review.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from cantica_secure.backends.base import AuthResult
from cantica_secure.core.flags import FLAG_NEWBIE, audit_log
from cantica_secure.orm.models import DirectoryGroupRole, Group, Role, User, UserFlag


def _mapped_roles(session: Session, directory_groups: list[str]) -> list[Role]:
    if not directory_groups:
        return []
    mappings = session.scalars(
        select(DirectoryGroupRole)
        .options(selectinload(DirectoryGroupRole.role))
        .where(DirectoryGroupRole.external_group.in_(directory_groups))
    ).all()
    seen: dict[str, Role] = {}
    for m in mappings:
        seen[m.role.id] = m.role
    return list(seen.values())


def _matched_group(session: Session, directory_groups: list[str]) -> Group | None:
    if not directory_groups:
        return None
    return session.scalar(
        select(Group).where(Group.external_id.in_(directory_groups)).limit(1)
    )


def provision_directory_user(
    session: Session,
    result: AuthResult,
    *,
    default_roles: list[str],
) -> User:
    """Upsert a user from a directory identity; returns the provisioned User.

    Lookup order: e_user_id, then email (adopting the account by setting
    e_user_id). Directory-mapped roles REPLACE the user's roles on every login
    so revoking an AD group revokes access; when no group maps, existing roles
    are kept (or *default_roles* + 'newbie' for brand-new users).
    """
    user: User | None = None
    if result.e_user_id:
        user = session.scalar(
            select(User)
            .options(selectinload(User.roles), selectinload(User.flags))
            .where(User.e_user_id == result.e_user_id)
        )
    if user is None and result.email:
        user = session.scalar(
            select(User)
            .options(selectinload(User.roles), selectinload(User.flags))
            .where(User.email == result.email)
        )

    roles = _mapped_roles(session, result.directory_groups)
    group = _matched_group(session, result.directory_groups)

    if user is None:
        # Brand-new enterprise user (spec B.2).
        fallback = not roles
        if fallback:
            roles = list(session.scalars(select(Role).where(Role.name.in_(default_roles))))
        user = User(
            email=result.email,
            password_hash="",  # directory-authenticated; local password login disabled
            first_name=result.first_name,
            last_name=result.last_name,
            e_user_id=result.e_user_id,
            is_active=True,
        )
        user.roles = roles
        if group is not None:
            user.group_id = group.id
        session.add(user)
        session.flush()
        if fallback:
            session.add(UserFlag(
                user_id=user.id, flag=FLAG_NEWBIE,
                comment="directory user with no mapped groups — review roles",
            ))
        audit_log.info(
            "directory user provisioned: user=%s e_user_id=%s roles=%s%s",
            user.id, result.e_user_id, [r.name for r in roles],
            " (fallback + newbie)" if fallback else "",
        )
    else:
        user.e_user_id = user.e_user_id or result.e_user_id
        if result.first_name:
            user.first_name = result.first_name
        if result.last_name:
            user.last_name = result.last_name
        if result.email:
            user.email = result.email
        if roles:
            user.roles = roles
        if group is not None and user.group_id != group.id:
            user.group_id = group.id
        audit_log.info(
            "directory user refreshed: user=%s e_user_id=%s roles=%s",
            user.id, user.e_user_id, [r.name for r in user.roles],
        )

    session.commit()
    # Reload with permissions eager-loaded for token issuance.
    refreshed = session.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(Role.permissions), selectinload(User.flags))
        .where(User.id == user.id)
    )
    assert refreshed is not None
    return refreshed
