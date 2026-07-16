"""Frozen API contract for Cantica Secure (extraction roadmap Phase F).

The security surface is a contract two servers depend on, so it is versioned
with the package. :func:`build_contract` produces a normalized, stable summary
of the mounted routes (method, path, required request fields, response codes);
``contract.json`` is the frozen snapshot; ``tests/test_contract.py`` fails if a
change drifts from it without an intentional re-freeze.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI

CONTRACT_VERSION = "1.0"
CONTRACT_PATH = Path(__file__).with_name("contract.json")

# Only these path prefixes form the shared contract (host routes are excluded).
_CONTRACT_PREFIXES = ("/v1/auth", "/v1/users", "/v1/roles", "/v1/directory", "/v1/security")


def _required_request_fields(operation: dict[str, Any], components: dict[str, Any]) -> list[str]:
    body = operation.get("requestBody")
    if not body:
        return []
    schema = body.get("content", {}).get("application/json", {}).get("schema", {})
    ref = schema.get("$ref")
    if ref:
        name = ref.rsplit("/", 1)[-1]
        schema = components.get("schemas", {}).get(name, {})
    return sorted(schema.get("required", []))


def build_contract(app: FastAPI) -> dict[str, Any]:
    """Return the normalized contract for the security routes mounted on *app*."""
    spec = app.openapi()
    components = spec.get("components", {})
    operations: dict[str, dict[str, Any]] = {}

    for path, methods in spec.get("paths", {}).items():
        if not path.startswith(_CONTRACT_PREFIXES):
            continue
        for method, operation in methods.items():
            if method.upper() not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                continue
            key = f"{method.upper()} {path}"
            params = sorted(
                f"{p['in']}:{p['name']}"
                for p in operation.get("parameters", [])
                if p.get("required")
            )
            operations[key] = {
                "required_request_fields": _required_request_fields(operation, components),
                "required_params": params,
                "responses": sorted(operation.get("responses", {}).keys()),
            }

    return {"version": CONTRACT_VERSION, "operations": dict(sorted(operations.items()))}


def load_frozen_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def write_frozen_contract(contract: dict[str, Any]) -> None:
    CONTRACT_PATH.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")


def _fresh_app() -> FastAPI:
    """A bare app with a default shim mounted — used to (re)generate the contract."""
    from cantica_secure import SecureConfig, SecurityShim  # noqa: PLC0415

    app = FastAPI()
    SecurityShim(SecureConfig(db_url="sqlite:///:memory:", local_mode=True)).mount(app)
    return app


if __name__ == "__main__":  # pragma: no cover - regen helper
    write_frozen_contract(build_contract(_fresh_app()))
    print(f"Wrote {CONTRACT_PATH}")
