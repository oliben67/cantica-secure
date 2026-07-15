"""User flag vocabulary and the flag-aware authentication gate (spec AUTH F).

Flags are an open vocabulary (the set will evolve) validated here rather than
as a closed DB enum. `newbie` must always exist. A user can hold several flags.

External failures are ONE generic 401 — the specific reason (blocked /
inactive / unknown, with flag comments) goes to the ``cantica_secure.audit``
logger and is visible to admins through the flags API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cantica_secure.orm.models import User

audit_log = logging.getLogger("cantica_secure.audit")

FLAG_NEWBIE = "newbie"
FLAG_OK = "ok"
FLAG_PENDING_ROLES = "pending:roles"

WARNING_FLAGS = frozenset({"warning:abuse", "warning:suspicious", "warning:none"})
BLOCKED_FLAGS = frozenset({"blocked:abuse", "blocked:suspicious", "blocked:none"})

KNOWN_FLAGS = frozenset(
    {FLAG_NEWBIE, FLAG_OK, FLAG_PENDING_ROLES} | WARNING_FLAGS | BLOCKED_FLAGS
)

# The one body every unauthenticated caller sees, regardless of the reason.
GENERIC_AUTH_FAILURE = "Not authenticated — contact your administrator"


@dataclass
class GateResult:
    """Outcome of the flag gate for one user."""

    allowed: bool
    warnings: list[str] = field(default_factory=list)
    # Internal reason for the audit log; never sent to the caller.
    audit_reason: str = ""


def gate_user(user: User | None, *, context: str) -> GateResult:
    """Evaluate spec AUTH F for *user*. Logs denials/warnings to the audit log.

    | state                          | outcome                             |
    | active, no negative flags      | allowed                             |
    | active + warning flags         | allowed, warnings surfaced          |
    | blocked flags (any activity)   | denied                              |
    | inactive                       | denied                              |
    | not found                      | denied                              |
    """
    if user is None:
        audit_log.warning("auth denied [%s]: user not found", context)
        return GateResult(allowed=False, audit_reason="not found")

    flags = {f.flag: f.comment for f in user.flags}
    blocked = sorted(set(flags) & BLOCKED_FLAGS)
    warnings = sorted(set(flags) & WARNING_FLAGS)

    if blocked:
        detail = "; ".join(f"{b} ({flags[b]})" if flags[b] else b for b in blocked)
        state = "active" if user.is_active else "inactive"
        audit_log.warning("auth denied [%s]: user=%s %s, blocked: %s", context, user.id, state, detail)
        return GateResult(allowed=False, audit_reason=f"blocked ({state}): {detail}")

    if not user.is_active:
        extra = f", warnings: {', '.join(warnings)}" if warnings else ""
        audit_log.warning("auth denied [%s]: user=%s inactive%s", context, user.id, extra)
        return GateResult(allowed=False, audit_reason=f"inactive{extra}")

    if warnings:
        audit_log.info("auth warning [%s]: user=%s carries %s", context, user.id, ", ".join(warnings))
        return GateResult(allowed=True, warnings=warnings)

    return GateResult(allowed=True)
