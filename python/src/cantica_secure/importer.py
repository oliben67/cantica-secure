"""One-shot migration of host security data into the Cantica Secure database.

Extraction roadmap Phase C. The importer is host-agnostic: a host reads its own
tables (schemas and datetime conventions differ) and hands normalized records
to :func:`import_records`, which upserts them into the security DB **preserving
ids verbatim** so downstream references (e.g. ``Provider.user_id`` in
studio-api, prompt authorship in cantica-api) stay valid.

A convenience reader, :func:`read_studio_db`, is provided because studio-api's
security tables share the package's schema (the package was extracted from it),
so its DB can be reflected directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.engine import Engine

from cantica_secure.orm.db import new_session
from cantica_secure.orm.models import ApiToken, JwtKey, Role, User, UserFlag


@dataclass
class ImportUser:
    id: str
    email: str
    password_hash: str = ""
    first_name: str = ""
    last_name: str = ""
    is_active: bool = True
    e_user_id: str | None = None
    role_names: list[str] = field(default_factory=list)


@dataclass
class ImportFlag:
    user_id: str
    flag: str
    comment: str = ""
    created_by: str = ""


@dataclass
class ImportKey:
    id: str
    cantica_user_id: str
    user_id: str
    public_key: str
    revoked: bool = False


@dataclass
class ImportToken:
    id: str
    user_id: str
    token_hash: str
    name: str = ""
    scopes: list[str] = field(default_factory=list)


@dataclass
class ImportReport:
    users: int = 0
    flags: int = 0
    keys: int = 0
    tokens: int = 0
    skipped_roles: list[str] = field(default_factory=list)


def import_records(
    engine: Engine,
    *,
    users: list[ImportUser] | None = None,
    flags: list[ImportFlag] | None = None,
    keys: list[ImportKey] | None = None,
    tokens: list[ImportToken] | None = None,
) -> ImportReport:
    """Upsert host records into the security DB (idempotent, ids preserved).

    Roles are matched by name against the already-seeded host vocabulary;
    names with no seeded role are skipped and reported (never invented, so the
    permission model stays authoritative). Existing rows with the same id are
    left untouched — re-running the import is safe.
    """
    report = ImportReport()
    now = datetime.now(timezone.utc)

    with new_session(engine) as session:
        role_by_name = {r.name: r for r in session.scalars(select(Role)).all()}

        for u in users or []:
            if session.get(User, u.id) is not None:
                continue
            row = User(
                id=u.id, email=u.email, password_hash=u.password_hash,
                first_name=u.first_name, last_name=u.last_name,
                is_active=u.is_active, e_user_id=u.e_user_id,
            )
            for name in u.role_names:
                role = role_by_name.get(name)
                if role is None:
                    if name not in report.skipped_roles:
                        report.skipped_roles.append(name)
                    continue
                row.roles.append(role)
            session.add(row)
            report.users += 1
        session.commit()

        existing_users = {u.id for u in session.scalars(select(User)).all()}

        for f in flags or []:
            if f.user_id not in existing_users:
                continue
            dup = session.scalar(
                select(UserFlag).where(UserFlag.user_id == f.user_id, UserFlag.flag == f.flag)
            )
            if dup is not None:
                continue
            session.add(UserFlag(
                user_id=f.user_id, flag=f.flag, comment=f.comment, created_by=f.created_by,
            ))
            report.flags += 1

        for k in keys or []:
            if k.user_id not in existing_users or session.get(JwtKey, k.id) is not None:
                continue
            session.add(JwtKey(
                id=k.id, cantica_user_id=k.cantica_user_id, user_id=k.user_id,
                public_key=k.public_key, revoked_at=now if k.revoked else None,
            ))
            report.keys += 1

        for t in tokens or []:
            if t.user_id not in existing_users or session.get(ApiToken, t.id) is not None:
                continue
            session.add(ApiToken(
                id=t.id, user_id=t.user_id, token_hash=t.token_hash,
                name=t.name, scopes=list(t.scopes),
            ))
            report.tokens += 1

        session.commit()

    return report


# ── studio-api reader (same schema as the package) ────────────────────────────


def read_studio_db(studio_db_path: str) -> tuple[
    list[ImportUser], list[ImportFlag], list[ImportKey], list[ImportToken]
]:
    """Reflect a studio-api security DB into import records.

    studio-api's users/user_flags/jwt_keys/api_tokens/roles/user_roles tables
    share the package's schema, so we reflect and read them directly.
    """
    from sqlalchemy import MetaData, Table, create_engine  # noqa: PLC0415

    engine = create_engine(f"sqlite:///{studio_db_path}")
    md = MetaData()
    try:
        users_t = Table("users", md, autoload_with=engine)
        roles_t = Table("roles", md, autoload_with=engine)
        user_roles_t = Table("user_roles", md, autoload_with=engine)
        flags_t = Table("user_flags", md, autoload_with=engine)
        keys_t = Table("jwt_keys", md, autoload_with=engine)
        tokens_t = Table("api_tokens", md, autoload_with=engine)

        with engine.connect() as conn:
            role_name = {r.id: r.name for r in conn.execute(select(roles_t.c.id, roles_t.c.name))}
            roles_of: dict[str, list[str]] = {}
            for ur in conn.execute(select(user_roles_t.c.user_id, user_roles_t.c.role_id)):
                roles_of.setdefault(ur.user_id, []).append(role_name.get(ur.role_id, ""))

            users = [
                ImportUser(
                    id=r.id, email=r.email, password_hash=r.password_hash or "",
                    first_name=r.first_name or "", last_name=r.last_name or "",
                    is_active=bool(r.is_active), e_user_id=r.e_user_id,
                    role_names=[n for n in roles_of.get(r.id, []) if n],
                )
                for r in conn.execute(select(users_t))
            ]
            flags = [
                ImportFlag(user_id=r.user_id, flag=r.flag, comment=r.comment or "",
                           created_by=r.created_by or "")
                for r in conn.execute(select(flags_t))
            ]
            keys = [
                ImportKey(id=r.id, cantica_user_id=r.cantica_user_id, user_id=r.user_id,
                          public_key=r.public_key, revoked=r.revoked_at is not None)
                for r in conn.execute(select(keys_t))
            ]
            tokens = [
                ImportToken(id=r.id, user_id=r.user_id, token_hash=r.token_hash,
                            name=r.name or "", scopes=r.scopes or [])
                for r in conn.execute(select(tokens_t))
            ]
        return users, flags, keys, tokens
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m cantica_secure.importer studio <studio.db> <secure.db>``."""
    import argparse  # noqa: PLC0415

    from cantica_secure.config import SecureConfig  # noqa: PLC0415
    from cantica_secure.shim import SecurityShim  # noqa: PLC0415

    parser = argparse.ArgumentParser(prog="cantica-secure import-host-db")
    parser.add_argument("source", choices=["studio"], help="host schema to read")
    parser.add_argument("source_db", help="path to the host security database")
    parser.add_argument("secure_db", help="path to the target Cantica Secure database")
    args = parser.parse_args(argv)

    users, flags, keys, tokens = read_studio_db(args.source_db)
    # Build a shim purely to create/seed the target schema, then import.
    shim = SecurityShim(SecureConfig(local_mode=True, db_url=f"sqlite:///{args.secure_db}"))
    try:
        report = import_records(shim.engine, users=users, flags=flags, keys=keys, tokens=tokens)
    finally:
        shim.dispose()
    print(  # noqa: T201
        f"Imported: {report.users} users, {report.flags} flags, "
        f"{report.keys} keys, {report.tokens} tokens"
    )
    if report.skipped_roles:
        print(f"Skipped unknown roles: {', '.join(report.skipped_roles)}")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
