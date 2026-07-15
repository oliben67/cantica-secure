"""Minimal startup migrations for the security database.

``Base.metadata.create_all`` creates missing tables but never adds columns to
existing ones. This applies the additive changes create_all cannot express,
idempotently, at startup. Hosts never migrate the security DB themselves.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

log = logging.getLogger(__name__)

_ADD_COLUMNS: list[tuple[str, str, str]] = [
    # (table, column, DDL type) — applied only when the column is missing.
]

_INDEXES: list[str] = [
    # Partial unique index: e_user_id must be unique when set, NULLs unrestricted.
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_e_user_id "
    "ON users (e_user_id) WHERE e_user_id IS NOT NULL",
]


def migrate(engine: Engine) -> None:
    """Apply additive schema migrations. Safe to run on every startup."""
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl_type in _ADD_COLUMNS:
            if table not in inspector.get_table_names():
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))
                log.info("Migrated: added %s.%s", table, column)
        for ddl in _INDEXES:
            conn.execute(text(ddl))
