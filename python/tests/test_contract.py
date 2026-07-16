"""Contract-freeze regression (extraction roadmap Phase F).

Guards the security API surface: if a change adds/removes an operation or
alters its required request fields, params, or response codes, this fails with
a diff and a reminder to intentionally re-freeze via
``python -m cantica_secure.contract``.
"""

from __future__ import annotations

from cantica_secure.contract import (
    CONTRACT_VERSION,
    build_contract,
    load_frozen_contract,
)
from cantica_secure.contract import _fresh_app as fresh_app


def test_contract_matches_frozen_snapshot() -> None:
    live = build_contract(fresh_app())
    frozen = load_frozen_contract()

    assert live["version"] == frozen["version"] == CONTRACT_VERSION

    live_ops = set(live["operations"])
    frozen_ops = set(frozen["operations"])
    added = live_ops - frozen_ops
    removed = frozen_ops - live_ops
    assert not added and not removed, (
        f"security API surface drifted — added={sorted(added)} removed={sorted(removed)}. "
        "If intentional, re-freeze: python -m cantica_secure.contract"
    )

    drifted = {
        op: {"frozen": frozen["operations"][op], "live": live["operations"][op]}
        for op in frozen_ops
        if live["operations"][op] != frozen["operations"][op]
    }
    assert not drifted, (
        f"operation signatures drifted: {list(drifted)}. "
        "If intentional, re-freeze: python -m cantica_secure.contract"
    )


def test_contract_covers_the_core_flows() -> None:
    """Sanity: the frozen contract includes the endpoints the roadmap promises."""
    ops = set(load_frozen_contract()["operations"])
    for required in [
        "POST /v1/auth/login",
        "POST /v1/auth/oidc",
        "POST /v1/auth/invitations",
        "POST /v1/auth/register",
        "POST /v1/auth/assert",
        "GET /v1/security/ui-config",
        "POST /v1/users/{user_id}/activate",
        "POST /v1/users/{user_id}/flags",
        "GET /v1/directory/mappings",
    ]:
        assert required in ops, f"missing contract endpoint: {required}"


def test_build_contract_filters_non_security_and_non_http_routes(tmp_path) -> None:  # noqa: ANN001
    """build_contract skips host routes, non-standard methods; write round-trips."""
    from fastapi import FastAPI

    from cantica_secure import SecureConfig, SecurityShim
    from cantica_secure.contract import build_contract, write_frozen_contract, CONTRACT_PATH

    app = FastAPI()
    shim = SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True))
    shim.mount(app)

    # A host route outside the contract prefixes → excluded (covers the skip).
    @app.get("/v1/things")
    def things() -> list:
        return []

    # A HEAD route on a contract path → non-standard method skipped.
    @app.head("/v1/security/ui-config")
    def head_cfg() -> None:
        return None

    try:
        contract = build_contract(app)
        ops = set(contract["operations"])
        assert "GET /v1/things" not in ops
        assert "HEAD /v1/security/ui-config" not in ops
        assert "GET /v1/security/ui-config" in ops

        # write_frozen_contract round-trips (restore afterwards).
        original = CONTRACT_PATH.read_text(encoding="utf-8")
        try:
            write_frozen_contract(contract)
            assert CONTRACT_PATH.read_text(encoding="utf-8").endswith("\n")
        finally:
            CONTRACT_PATH.write_text(original, encoding="utf-8")
    finally:
        shim.dispose()
