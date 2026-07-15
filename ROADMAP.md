# Roadmap — Cantica Secure: a shimmable security package for both servers

Repository: `git@github.com:oliben67/cantica-secure.git` — mounted as the
`cantica-secure/` submodule of this workspace, like the other subprojects.

Extract the entire security codebase into one independent, mountable FastAPI
package — plus a matching React form library — consumed by **cantica-api**
("cantica server") and **studio-api** ("cantica studio server").

Ground rules set for this effort:

1. **No code is removed from any project.** Extraction is additive: the package
   is built alongside the existing implementations, hosts adopt it behind a
   flag, and the in-repo security code keeps working (and keeps its tests)
   until a separate, later decision retires it.
2. **Shimmable.** One `SecurityShim.mount(app, ...)` call wires the whole
   surface into a host FastAPI app — same idiom as cantica-api's existing
   `CanticaShim.mount(app, prefix="/api/v1")`.
3. **Security-owned state.** Keys (client signing keys), the security
   **database** (users, roles, flags, invitations, sessions), and **tokens**
   (JWTs, API tokens) are managed by the package. **Provider API keys are
   explicitly out of scope** — `Provider` / `ProviderToken`,
   `/v1/providers`, and `syncProviderKeys` stay where they are (studio-api).
4. **Unified but themeable UI.** The package ships the React forms; each host
   styles them so they feel native to the app they run inside.

---

## What gets extracted (inventory)

The two servers deliberately converged during the remote-mode work
([roadmap-remote-mode-auth.md](roadmap-remote-mode-auth.md)) — same flag
vocabulary, same gate semantics, same RS256 assertion claims. That convergence
is the extraction seam.

### From studio-api (`cantica-studio/studio-api/src/studio_api/`)

| Area | Files | Notes |
|---|---|---|
| Auth core | `auth/deps.py` (CurrentUser, gate-on-every-request, require_permission), `auth/jwt.py`, `auth/flags.py`, `auth/keyauth.py`, `auth/password.py` | canonical: richest implementation |
| Backends | `auth/backends.py` (AuthResult protocol), `auth/local_backend.py`, `auth/ldap_backend.py`, `auth/oidc_backend.py`, `auth/provision.py` | directory provisioning + group→role mapping |
| Models | `orm/models.py`: `User` (incl. `e_user_id`), `Role`, `Permission`, `ApiToken`, `UserFlag`, `JwtKey`, `UsedJti`, `DirectoryGroupRole` | **not** `Provider`/`ProviderToken`; `Group` is split (see below) |
| Endpoints | `api/v1/auth.py` (login, oidc, invitations, register, assert, api tokens), `api/v1/users.py` (CRUD, flags, activate, keys, roles), `api/v1/directory.py` | |
| Seeds & migrations | `orm/seed.py` (permissions, admin/operator/viewer/limbo, admin user), `orm/migrate.py` | |
| Settings | `jwt_*`, `admin_*`, `auth_backend`, `ldap_*`, `oidc_*`, `default_roles`, `auto_activate_users`, `invite_expire_minutes`, `assertion_max_age_seconds` | |

### From cantica-api (`cantica-api/src/cantica/`)

| Area | Files | Notes |
|---|---|---|
| Auth core | `core/auth_gate.py`, `core/jwt_utils.py`, `core/security.py` (API-key hashing), `core/auth_provider.py`, `core/auth_config.py` (anonymous roles via auth.yaml) | anonymous-access model is a cantica-api feature the package must support |
| Invitations | `api/v1/endpoints/invites.py` + `core/mailer.py` (SMTP invite delivery, QR) | the mailer closes the enumeration gap studio-api still has |
| Endpoints | `api/v1/endpoints/sessions.py` (login/me/logout), `endpoints/auth.py` (API tokens), `endpoints/keyauth.py` | |
| Models | `orm/tables.py`: `UserOrm`, `UserFlagOrm`, `JwtKeyOrm`, `UsedJtiOrm`, invite table, `ApiKeyOrm` | ISO-string datetime convention differs from studio-api |
| Store methods | `services/version_store.py` user/flag/key/jti sections | become package repository methods |

### From the clients (`cantica-studio/clients/shared/`)

| Area | Files | Notes |
|---|---|---|
| Key machinery | `auth-core.ts` (key pair, `createAssertion`, `createEnrolmentAssertion`, `createAuthAssertion`) | becomes the JS SDK half of the package |
| Admin/setup UI | `webview-src/components/AdminUsersModal.tsx`, `DirectoryMappingsModal.tsx` (+ store slice, protocol) | seeds for the shared form library |
| API client | `studio-client.ts` auth/admin methods | becomes the typed fetch client |

### Deliberately NOT extracted

- `Provider`, `ProviderToken`, `api/v1/access.py`, `provider_models.py`,
  `syncProviderKeys` — provider API-key management stays in studio-api.
- `Group` ownership of providers: the security package owns group
  *membership/identity* (directory mapping, `groups` claim); studio-api keeps
  the group→provider ownership relation, referencing the security group id.
- cantica-api's vault/versioning ACLs (namespace visibility etc.) — domain
  authorization stays in the host; the package supplies the *principal* and
  *permissions*, hosts decide what they mean.

---

## Target shape

The `cantica-secure` repo (submodule at `cantica-secure/`) with two publishable
artefacts:

```
cantica-secure/
├── python/                       # package: cantica_secure (wheel, like actor-ai)
│   ├── src/cantica_secure/
│   │   ├── shim.py               # SecurityShim — the only import a host needs
│   │   ├── config.py             # SecurityConfig (pydantic-settings, prefix SECURITY_)
│   │   ├── orm/                  # models + engine + seeds + migrations (own DB)
│   │   ├── core/                 # jwt, flags/gate, keyauth, password, api-keys
│   │   ├── backends/             # local / ldap / oidc + provisioning
│   │   ├── api/                  # routers: auth, users, directory, tokens, ui-config
│   │   └── adapters.py           # host integration protocols (see below)
│   └── tests/
└── ui/                           # package: @cantica/secure-ui (npm)
    ├── src/
    │   ├── theme.ts              # ThemeProvider + CSS custom-property tokens
    │   ├── client.ts             # typed fetch client (+ transport adapter)
    │   ├── keys.ts               # browser/node key machinery (from auth-core.ts)
    │   └── forms/                # Login, InviteRequest, InviteAccept, KeyEnrolment,
    │                             # AdminUsers, Flags, DirectoryMappings, ApiTokens,
    │                             # SessionBadge (warnings)
    └── stories/                  # per-theme visual review (cantica vs studio skins)
```

### The shim contract

```python
from cantica_secure import SecurityShim, SecurityConfig

shim = SecurityShim(
    SecurityConfig(),                    # SECURITY_* env; falls back to host-mapped values
    principal_adapter=...,               # optional host hooks
    on_user_event=...,                   # user created/activated/flagged/blocked callbacks
)
shim.mount(app, prefix="/v1")            # mounts /auth, /users, /roles, /directory, /security/ui-config
CurrentUserDep = shim.current_user_dep   # FastAPI dependency for host endpoints
require = shim.require_permission       # permission guard factory for host endpoints
```

- **Own database.** The shim owns `security.db` (SQLite; engine/url
  configurable — Postgres for cantica deployments): users, roles, permissions,
  flags, jwt_keys, used_jtis, invitations, api_tokens, directory mappings.
  Hosts never touch these tables directly; they consume `CurrentUser` and the
  event callbacks (e.g. studio-api links `Provider.user_id` to the security
  user id it receives).
- **Adapters, not inheritance.**
  - `PrincipalAdapter`: maps the package's `CurrentUser` (id, email,
    e_user_id, roles, permissions, group ids, warnings) to whatever the host
    wants downstream (cantica-api's `User` pydantic model with its `Role`
    enum; studio-api uses it as-is).
  - `PermissionModel`: hosts register their permission vocabulary at mount
    (`runtime:start`, `graph:write`, … vs `prompts:write`, …); seeds and the
    role editor operate on the registered set. cantica-api's coarse role enum
    maps to three built-in roles; its anonymous-access mode is a config flag
    (`allow_anonymous` + anonymous role), preserving auth.yaml semantics.
  - `MailTransport`: optional; when present, invitations go out by email
    (cantica-api's mailer plugs in here), otherwise in-band like studio-api
    today.
- **Local mode** stays a first-class config (`SECURITY_DISABLED` /
  `local_mode`): the dependency returns the synthetic admin principal exactly
  as both servers do now, so single-user setups are untouched.
- **Token canon**: HS256 access tokens with the shared claim shape
  (`sub`, `email`, `roles`, `permissions`, `group_id`, warnings header) and
  RS256 client assertions (`iss`/`sub` = cantica_user_id, `iat`/`exp`/`jti`)
  — already identical across both servers, frozen as the package's contract.

### The UI contract

- **Theming**: every component reads design tokens from CSS custom properties
  (`--csec-bg`, `--csec-accent`, `--csec-radius`, `--csec-font`, …) with a
  `ThemeProvider` that accepts a token map + optional per-slot class
  overrides. Ship two reference themes: `canticaWeb` (matches cantica-web's
  Vite app) and `studio` (matches the webview's `cs-*` design language). The
  host sets tokens once; forms inherit the surrounding look.
- **Transport adapter**: components never fetch directly. They receive a
  `SecurityClient` built on either `fetch` (cantica-web, Electron renderer
  with direct access) or a **postMessage bridge** (VS Code webview — reusing
  the existing `requestAdminData`/`adminData`-style protocol so CSP-restricted
  webviews keep working).
- **Server-driven config**: `GET /security/ui-config` reports which features
  are enabled (invitations, oidc, ldap, key enrolment, anonymous mode,
  auto-activation) so the same form bundle renders correctly against either
  server.
- Components (all controlled, all headless-friendly): `LoginForm`,
  `OidcButton`, `InviteRequestForm`, `InviteAcceptForm`, `KeyEnrolment`,
  `AdminUsersPanel` (activation checkbox + flags — port of AdminUsersModal),
  `DirectoryMappingsPanel`, `ApiTokensPanel`, `SessionWarningBadge`.

---

## Phases

### Phase A — Package skeleton & canon (python)

Stand up `cantica-secure/python` with the **studio-api implementation as the
base** (it is the superset): copy — not move — `auth/*`, the security models,
seeds, migrations, and the auth/users/directory routers into the package
namespace; parameterize the hard studio-isms (settings prefix, permission
list, DB path). Port cantica-api's extras the base lacks: SMTP invite
delivery, anonymous-access mode, API-key header (`X-API-Key`) support.
Bring the merged test suites (studio-api's `test_remote_auth.py`,
`test_directory.py`, `test_auth.py`; cantica-api's `test_keyauth.py`) across
as the package's suite.
**Exit:** `SecurityShim.mount(FastAPI())` passes the merged suite standalone;
wheel builds like actor-ai's.

### Phase B — Shim & adapters

Implement `SecurityShim`, `SecurityConfig`, `PrincipalAdapter`,
`PermissionModel` registration, `MailTransport`, user-event callbacks, and the
`/security/ui-config` endpoint. Add conformance tests that mount the shim into
two fake hosts with the real permission vocabularies of both servers.
**Exit:** one wheel, two differently-configured mounts, both green.

### Phase C — Host adoption behind flags (no removals)

- **studio-api**: add `SECURITY_SHIM=1` path in `create_app()` that mounts the
  package routers instead of including the in-repo `auth`/`users`/`directory`
  routers, and aliases `CurrentUserDep`/`require_permission` to the shim's.
  The in-repo modules stay in the tree and keep their tests (run in the
  default, non-shim configuration). Provider endpoints keep working against
  the shim's user ids (event callback keeps `Provider.user_id` valid).
- **cantica-api**: same flag; `PrincipalAdapter` produces the existing `User`
  model so `VersionStore` authorization call sites are untouched. Existing
  `/v1/invites`, `/v1/auth/*` remain mounted when the flag is off.
- **Data**: one-shot import command (`cantica-secure import-host-db`) that
  copies users/flags/keys/tokens from a host DB into the security DB; both
  hosts' existing tables are left in place (rule 1).
- CI runs each host suite twice: flag off (today's code) and flag on (shim).
**Exit:** both host suites green in both configurations.

### Phase D — UI library

Build `@cantica/secure-ui` from the existing React: port AdminUsersModal /
DirectoryMappingsModal into themeable panels, add the login/invite/enrolment
forms (new — today enrolment is programmatic only), extract `auth-core.ts`
into `keys.ts`, and implement the two transports + two reference themes.
Visual review via stories rendered under both themes side by side.
**Exit:** the same `AdminUsersPanel` renders pixel-consistent with cantica-web
inside cantica-web, and native-feeling inside the studio webview, with no
component code differences — themes only.

### Phase E — UI adoption (no removals)

- **cantica-web**: add `/admin/security` routes using the panels + `fetch`
  transport + `canticaWeb` theme (net-new screens for cantica server — it has
  no security UI today).
- **studio clients**: mount the package panels behind the existing toolbar
  entries via the postMessage transport + `studio` theme; the current modals
  stay in the tree as the non-shim fallback.
**Exit:** flag-on builds of both UIs drive registration→activation→enrolment→
assert end-to-end against their servers through the package forms.

### Phase F — Contract hardening

- Freeze and publish the security API as an OpenAPI document versioned with
  the package; add a cross-server contract test (same key pair enrols on
  studio-api and authenticates on cantica-api's shim mount and vice versa —
  the "one identity, both servers" goal).
- Threat tests move into the package (replay, enumeration, revocation
  latency, private-key upload) so both hosts inherit them.
- Publishing: wheel to the repo root for Docker builds (actor-ai pattern) and
  npm package consumed via the workspace.
**Exit:** version-pinned package consumed by both servers in CI; deprecation
of the in-repo copies becomes a documented *future* decision, not part of
this roadmap.

---

## Risks & decisions to make early

1. **Two datetime conventions** (native tz-aware vs ISO strings) — the package
   picks native datetimes; the Phase C import command converts. Don't try to
   share tables with hosts.
2. **User-id continuity**: hosts key existing rows by their current user ids
   (`Provider.user_id`, version authorship). The import preserves ids
   verbatim; the shim never re-mints ids for imported users.
3. **Group split**: security owns group identity/membership; studio-api keeps
   provider-ownership rows pointing at those ids. Needs one FK-by-convention
   (no cross-DB constraint) — document it.
4. **Session strategy in webviews**: the postMessage transport means the token
   lives in the extension host / Electron main, never in the webview —
   matches the existing key-material rule; the fetch transport (cantica-web)
   needs a storage decision (memory + refresh vs cookie).
5. **Coverage gates differ** (cantica-api ≥99%, studio-api lighter): the
   package adopts the stricter gate from day one to be mountable in both.
6. **Atlas vs create_all+migrate**: the package owns its schema with its own
   migration story (Alembic or the lightweight runner); hosts never migrate
   security tables. cantica-api's Atlas config must exclude the security DB.
