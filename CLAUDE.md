# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A teaching example of MCP server security, with control flow written as `cano` workflows. Four
crates cooperate: **rmcp** (MCP server + client), **cano** (workflows), **casbin** +
**sqlx-adapter** (RBAC, policies in Postgres), and **sqlx**/PostgreSQL (the `documents` resource).
On top of RBAC it demonstrates several MCP security scenarios: token auth (audience/expiry/passthrough),
credential leakage, prompt injection, OS command injection, scope minimization, human-in-the-loop
consent, and SSRF. See `README.md` for the walkthrough.

**Casbin is embedded, not a service.** The `Enforcer` lives in-process; `enforce()` is a plain
call. The only container is PostgreSQL (stores `casbin_rule` + `documents`). Don't add a "casbin"
service to `compose.yaml`.

## Commands

- Build both binaries: `cargo build` (the driver spawns the server, so build before running)
- Run the demo: `docker compose up -d` then `cargo run --bin driver`
- Test (hermetic, no Docker): `cargo test`; single file e.g. `cargo test --test guards`
- Lint / format: `cargo clippy --all-targets` · `cargo fmt`

## Architecture (the big picture)

Two binaries from one library crate (`src/lib.rs`): `src/bin/server.rs` (MCP server over **stdio**)
and `src/main.rs` (`driver`, spawns the server via `TokioChildProcess`, acts as the MCP client).

**Cano runs at two levels:**
1. Top-level driver loop in `src/simulation.rs`: `Connect → Matrix → Auth → Secrets → Injection →
   Command → Scope → Consent → Ssrf → Done`. Scenarios live in `src/scenarios.rs` (added via the
   `scenario_stage!` macro).
2. Per-request security pipeline in `src/request_pipeline.rs`, run inside every tool:
   `Authenticate → Authorize → InspectInput → Execute → InspectOutput → Audit → Done`. Built fresh
   per call; shared deps (enforcer, pool, token store) are injected via cano `Resources` (each a
   small `impl Resource` newtype), and stages communicate via a `MemoryStore` (keys: `actor`,
   `scopes`, `outcome`, `message`, `untrusted`, `wc_flag`, `findings`). The `reject(...)` helper
   records a terminal outcome and routes to `Audit`.

**What each stage enforces** (guards live in `src/guards/`, run regardless of authz — defense in depth):
- `Authenticate` → `auth::introspect` (token→claims) + audience check (`domain::AUDIENCE`) +
  `auth::is_expired`. Bad token → `Outcome::AuthFailed`.
- `Authorize` → token **scope** (`domain::scope_for` ∩ token scopes) **and** casbin **role**
  (`authz::check`). Either failing → `Outcome::NotAuthorized`.
- `InspectInput` → `guards::command::validate_format` (render), consent (`Delete{confirm}`),
  `guards::ssrf::validate_url` (import_url). Any → `Outcome::Blocked`.
- `Execute` → `db` CRUD + `guards::command::render` (safe argv `wc`); `import_url` validates only
  (no real fetch). DB errors via `db_err` → `guards::secrets::sanitize_error`.
- `InspectOutput` → `guards::secrets::redact` + `guards::prompt_injection::neutralize` on returned
  document content.

`PipelineOutcome { outcome, message, findings }` maps to the MCP result: `Outcome::Allowed` →
success, everything else → `CallToolResult::error` (is_error = true).

## Conventions and gotchas

- **Server stdout is the JSON-RPC channel.** Never `println!` in the server / its request-path
  libraries; logs go to **stderr** (`tracing_subscriber` in `bin/server.rs`). The driver prints to
  stdout (it's the client). `Audit` never logs the token or raw secrets.
- **Identity is a `token`** tool parameter, introspected to claims. `auth::token_store()` builds
  the `token → TokenClaims` map (the server passes `Arc<HashMap<String, TokenClaims>>`). The
  `actor: &str` params in `db.rs`/`authz.rs` are the *resolved* identity — don't rename to token.
  AuthN (`auth.rs`) is separate from authZ (`authz.rs`).
- **Tokens, scopes, audience, roles, the demo cast** live in `src/domain.rs` (`SEED_USERS`,
  `ROLE_GRANTS`, `scope_for`, `AUDIENCE`, and the `TOKEN_*` demo-token consts). Token scopes are
  derived from the role in `auth::scopes_for_role` (least privilege). Change identity/authorization
  there; it flows to seeding, the token store, and the report.
- **The RBAC matrix** (`simulation.rs`) sends `confirm=true` on delete so it tests role/scope, not
  the consent guard (shown separately). Keep that, or the delete column goes all-❌.
- **Determinism:** the server seeds casbin (clear+add+save) and runs `TRUNCATE documents RESTART
  IDENTITY` on startup; the token store is rebuilt each run. The RBAC matrix output is stable.
- **Guards are illustrative** (regex/std-lib based) — keep that framing. `guards::ssrf` uses the
  std library for IP classification (not hand-rolled parsing); `import_url` validates but doesn't
  fetch — a real fetcher must also pin DNS (TOCTOU).
- **Versions/features:** edition 2024 (Rust 1.89+); `casbin`/`sqlx-adapter`/`sqlx` pinned to
  `runtime-tokio-rustls` (keep aligned or a second TLS backend leaks in); `schemars` must be 1.x.
  `tokio` needs `io-util` (stdin piping for `render`) and `process`. `render_document` needs `wc`
  on PATH (Linux/macOS). Deps added for the guards: `regex`, `url`.
