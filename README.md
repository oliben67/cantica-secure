# Cantica Secure

A shimmable security package for the Cantica ecosystem: one FastAPI-mountable
authentication/authorization core plus a themeable React form library, shared
by the Cantica server (`cantica-api`) and the Cantica Studio server
(`cantica-studio/studio-api`).

- One `SecurityShim.mount(app)` wires the whole security surface into a host.
- Owns its own security database: users, roles, flags, invitations, client
  signing keys, JWTs, and API tokens. Provider API keys are out of scope.
- Ships `@cantica/secure-ui` React forms themeable to match the host app.

See [ROADMAP.md](ROADMAP.md) for the extraction plan, package layout, and
phase-by-phase exit criteria. This repo is consumed as the `cantica-secure/`
submodule of the [cantica](https://github.com/oliben67/cantica) workspace.
