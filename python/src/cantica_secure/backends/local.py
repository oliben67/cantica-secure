"""LocalBackend — email + argon2 password, no external directory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from cantica_secure.backends.base import AuthResult
from cantica_secure.core.password import verify_password
from cantica_secure.orm.models import Role, User

if TYPE_CHECKING:
    pass


class LocalBackend:
    """Authenticate against the local users table using argon2-hashed passwords."""

    def __init__(self, session: Session | None) -> None:
        self._session = session

    def authenticate(self, credential: str, secret: str) -> AuthResult | None:
        if self._session is None:
            raise RuntimeError("LocalBackend requires a DB session")
        user = self._session.scalar(
            select(User).where(User.email == credential, User.is_active.is_(True))
        )
        if user is None or not verify_password(secret, user.password_hash):
            return None
        return AuthResult(user_id=user.id, email=user.email)

    def sync_user(self, session: Session, result: AuthResult) -> User:
        # No external directory — reload user with roles and permissions eagerly.
        user = session.scalar(
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == result.user_id)
        )
        if user is None:
            raise ValueError(f"User {result.user_id!r} not found")
        return user
