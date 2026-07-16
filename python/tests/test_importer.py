"""Import of host security data into the security DB (extraction Phase C)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from cantica_secure import SecureConfig, SecurityShim
from cantica_secure.importer import (
    ImportFlag,
    ImportKey,
    ImportToken,
    ImportUser,
    import_records,
    main,
    read_studio_db,
)
from cantica_secure.orm.db import new_session
from cantica_secure.orm.models import ApiToken, JwtKey, Role, User, UserFlag
from tests.conftest import HOST_PERMISSIONS, HOST_ROLES


@pytest.fixture
def target():  # noqa: ANN201
    shim = SecurityShim(
        SecureConfig(db_url="sqlite:///:memory:", local_mode=True),
        permissions=HOST_PERMISSIONS,
        builtin_roles=HOST_ROLES,
    )
    yield shim
    shim.dispose()


def test_import_records_preserves_ids_and_maps_roles(target: SecurityShim) -> None:
    report = import_records(
        target.engine,
        users=[
            ImportUser(id="user-1", email="a@x.com", first_name="A",
                       role_names=["admin", "unknown-role"]),
            ImportUser(id="user-2", email="b@x.com", is_active=False, e_user_id="e-2"),
        ],
        flags=[
            ImportFlag(user_id="user-2", flag="newbie", comment="review"),
            ImportFlag(user_id="ghost", flag="ok"),  # unknown user → skipped
        ],
        keys=[ImportKey(id="key-1", cantica_user_id="a@x.com", user_id="user-1",
                        public_key="PUB", revoked=True)],
        tokens=[ImportToken(id="tok-1", user_id="user-1", token_hash="h", name="ci",
                            scopes=["things:read"])],
    )
    assert (report.users, report.flags, report.keys, report.tokens) == (2, 1, 1, 1)
    assert report.skipped_roles == ["unknown-role"]

    with new_session(target.engine) as s:
        u1 = s.get(User, "user-1")
        assert u1 is not None and u1.email == "a@x.com"
        assert {r.name for r in u1.roles} == {"admin"}  # unknown role dropped
        u2 = s.get(User, "user-2")
        assert u2.is_active is False and u2.e_user_id == "e-2"
        assert s.scalar(select(UserFlag).where(UserFlag.user_id == "user-2")).flag == "newbie"
        key = s.get(JwtKey, "key-1")
        assert key.revoked_at is not None and key.cantica_user_id == "a@x.com"
        assert s.get(ApiToken, "tok-1").scopes == ["things:read"]


def test_import_is_idempotent(target: SecurityShim) -> None:
    users = [ImportUser(id="u1", email="a@x.com", role_names=["viewer"])]
    flags = [ImportFlag(user_id="u1", flag="ok")]
    keys = [ImportKey(id="k1", cantica_user_id="a@x.com", user_id="u1", public_key="P")]
    tokens = [ImportToken(id="t1", user_id="u1", token_hash="h")]

    first = import_records(target.engine, users=users, flags=flags, keys=keys, tokens=tokens)
    assert (first.users, first.flags, first.keys, first.tokens) == (1, 1, 1, 1)

    second = import_records(target.engine, users=users, flags=flags, keys=keys, tokens=tokens)
    assert (second.users, second.flags, second.keys, second.tokens) == (0, 0, 0, 0)

    with new_session(target.engine) as s:
        assert len(s.scalars(select(User)).all()) == 1
        assert len(s.scalars(select(UserFlag)).all()) == 1


# ── studio reader + CLI ───────────────────────────────────────────────────────


def _make_studio_db(path: str) -> None:
    """Build a studio-shaped security DB and seed a couple of rows."""
    from cantica_secure.orm.db import Base, make_engine
    from cantica_secure.orm.migrate import migrate

    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    migrate(engine)
    with new_session(engine) as s:
        s.add(Role(id="r-admin", name="admin", description="A"))
        s.add(Role(id="r-view", name="viewer", description="V"))
        s.commit()
        u = User(id="su-1", email="src@x.com", first_name="S", e_user_id="corp-1", is_active=True)
        u.roles = [s.get(Role, "r-admin"), s.get(Role, "r-view")]
        s.add(u)
        s.add(UserFlag(user_id="su-1", flag="warning:none", comment="c"))
        s.add(JwtKey(id="sk-1", cantica_user_id="corp-1", user_id="su-1", public_key="PUB"))
        s.add(ApiToken(id="st-1", user_id="su-1", token_hash="hh", name="cli", scopes=["x"]))
        s.commit()
    engine.dispose()


def test_read_studio_db(tmp_path) -> None:  # noqa: ANN001
    db = tmp_path / "studio.db"
    _make_studio_db(str(db))
    users, flags, keys, tokens = read_studio_db(str(db))
    assert len(users) == 1
    u = users[0]
    assert u.id == "su-1" and u.e_user_id == "corp-1"
    assert set(u.role_names) == {"admin", "viewer"}
    assert flags[0].flag == "warning:none"
    assert keys[0].cantica_user_id == "corp-1"
    assert tokens[0].scopes == ["x"]


def test_importer_cli_end_to_end(tmp_path, capsys) -> None:  # noqa: ANN001
    src = tmp_path / "studio.db"
    dst = tmp_path / "secure.db"
    _make_studio_db(str(src))

    rc = main(["studio", str(src), str(dst)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 users" in out

    # The target now holds the imported user with preserved id.
    from cantica_secure.orm.db import make_engine

    engine = make_engine(f"sqlite:///{dst}")
    with new_session(engine) as s:
        u = s.get(User, "su-1")
        assert u is not None and u.email == "src@x.com"
    engine.dispose()
