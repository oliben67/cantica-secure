"""Engine, session factory, and declarative Base for the security database."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


def make_engine(db_url: str) -> Engine:
    """Create the security-DB engine. SQLite gets WAL + enforced foreign keys.

    An in-memory SQLite URL gets a StaticPool so every session shares the one
    connection (otherwise each connection would see a fresh, empty database).
    """
    kwargs: dict = {"echo": False, "future": True}
    if db_url in ("sqlite://", "sqlite:///:memory:"):
        from sqlalchemy.pool import StaticPool  # noqa: PLC0415

        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}
    elif db_url.startswith("sqlite:///"):
        Path(db_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(db_url, **kwargs)

    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _configure(conn, _record):  # noqa: ANN001, ANN202
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def new_session(engine: Engine) -> Session:
    return Session(engine, expire_on_commit=False)
