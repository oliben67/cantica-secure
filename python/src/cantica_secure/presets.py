"""Reference host vocabularies — the real permission models of both servers.

Hosts pass these to :class:`~cantica_secure.shim.SecurityShim` at mount time
(Phase C of the extraction roadmap); the conformance suite mounts both to
guarantee one wheel serves the two servers. Keeping them here means the
vocabularies are versioned with the package contract, not copy-pasted.
"""

from __future__ import annotations

# ── Cantica Studio server (studio-api) ─────────────────────────────────────────
# Mirrors studio_api/orm/seed.py verbatim.

STUDIO_PERMISSIONS: list[tuple[str, str]] = [
    # Actor runtime
    ("runtime:read",      "List and inspect running actors"),
    ("runtime:start",     "Start new actors"),
    ("runtime:stop",      "Stop and delete actors"),
    ("runtime:instruct",  "Send instructions and fire events to actors"),
    # Actor graph
    ("graph:read",        "Read the actor graph"),
    ("graph:write",       "Save changes to the actor graph"),
    # Prompts & providers
    ("prompts:read",      "Fetch prompts from Cantica servers"),
    ("providers:read",    "List available LLM provider models"),
    # Resources
    ("resources:read",    "Read actor resources"),
    ("resources:write",   "Add, delete, and share actor resources"),
    # Provider management
    ("providers:write",   "Create, update, and delete providers and their tokens"),
    # User management
    ("users:read",        "View users and their role assignments"),
    ("users:write",       "Create, update, and delete users"),
    # Role management
    ("roles:read",        "View roles and their permissions"),
    ("roles:write",       "Create, update, and delete roles"),
    # API token management
    ("tokens:read",       "List API tokens"),
    ("tokens:write",      "Create and revoke API tokens"),
    # Group management
    ("groups:read",       "View groups and their membership"),
    ("groups:write",      "Create, update, delete groups and manage membership"),
]

STUDIO_ROLES: dict[str, dict] = {
    "admin": {
        "description": "Full administrative access to all resources",
        "permissions": [p[0] for p in STUDIO_PERMISSIONS],
    },
    "operator": {
        "description": "Manage actors, graphs, and resources; read-only on users",
        "permissions": [
            "runtime:read", "runtime:start", "runtime:stop", "runtime:instruct",
            "graph:read", "graph:write",
            "prompts:read", "providers:read",
            "resources:read", "resources:write",
            "providers:write",
            "tokens:read", "tokens:write",
            "groups:read",
        ],
    },
    "viewer": {
        "description": "Read-only access to actors, graph, and prompts",
        "permissions": [
            "runtime:read",
            "graph:read",
            "prompts:read",
            "providers:read",
            "resources:read",
        ],
    },
}


# ── Cantica server (cantica-api) ───────────────────────────────────────────────
# cantica-api uses a coarse role enum (admin / user / readonly / anonymous)
# rather than named permissions; this maps that model onto explicit
# permissions so the shim's require_permission covers its endpoints.

CANTICA_PERMISSIONS: list[tuple[str, str]] = [
    ("prompts:read",     "Read prompts, versions, tags, and branches"),
    ("prompts:write",    "Create and update prompts, versions, tags, and branches"),
    ("community:read",   "Read stars, comments, forks, and collections"),
    ("community:write",  "Star, comment, fork, and manage collections"),
    ("namespaces:read",  "Read namespaces and certificates"),
    ("namespaces:write", "Manage namespaces and certificates"),
    ("federation:read",  "Read federation state and peers"),
    ("federation:write", "Manage federations, members, and peers"),
    ("hooks:write",      "Manage webhooks"),
    ("admin:all",        "Administrative operations (invites, user management)"),
]

_CANTICA_READ = ["prompts:read", "community:read", "namespaces:read", "federation:read"]
_CANTICA_WRITE = ["prompts:write", "community:write", "namespaces:write", "federation:write", "hooks:write"]

CANTICA_ROLES: dict[str, dict] = {
    # cantica-api Role.admin
    "admin": {
        "description": "Full administrative access",
        "permissions": [p[0] for p in CANTICA_PERMISSIONS] + [
            "users:read", "users:write", "roles:read", "roles:write",
            "tokens:read", "tokens:write",
        ],
    },
    # cantica-api Role.user
    "user": {
        "description": "Read and write prompts and community content",
        "permissions": _CANTICA_READ + _CANTICA_WRITE + ["tokens:read", "tokens:write"],
    },
    # cantica-api Role.readonly — also the natural anonymous role
    # (SECURE_ALLOW_ANONYMOUS=1 + SECURE_ANONYMOUS_ROLES='["readonly"]').
    "readonly": {
        "description": "Read-only access to public content",
        "permissions": _CANTICA_READ,
    },
}
