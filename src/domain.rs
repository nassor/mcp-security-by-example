//! Shared vocabulary used across the example: actions, the pipeline outcome, roles, and the
//! demo cast (with their bearer tokens).

use serde::{Deserialize, Serialize};

/// The CRUD actions a user may attempt on a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
}

impl Action {
    /// The casbin `act` string for this action.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }

    /// All four actions, in the order used by the report columns.
    pub const ALL: [Action; 4] = [Action::Create, Action::Read, Action::Update, Action::Delete];
}

/// The single object class protected by casbin. One resource type keeps the example focused.
pub const RESOURCE: &str = "document";

/// The terminal outcome of the per-request pipeline. Distinguishes the layers that can stop a
/// request so the report can explain *why* something was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Authenticated, authorized, and executed (possibly with guard findings on the output).
    Allowed,
    /// The presented token was unknown or invalid (authentication failed).
    AuthFailed,
    /// Authenticated, but casbin denied the action (authorization failed).
    NotAuthorized,
    /// A guard blocked the request (e.g. command-injection input validation).
    Blocked,
}

/// A row in the protected `documents` table.
#[derive(Debug, Clone)]
pub struct Document {
    pub id: i64,
    pub title: String,
    pub content: String,
    pub created_by: String,
}

/// A seed user: their name, the role label shown in the report, and their (demo) bearer token.
/// Users whose role is a real role (see [`ROLE_GRANTS`]) get a casbin role assignment; `dave` is
/// intentionally unassigned — he authenticates fine but is denied by authorization.
pub struct SeedUser {
    pub name: &'static str,
    pub role: &'static str,
    pub token: &'static str,
}

/// The demo cast. Tokens are demo secrets, in source like the casbin policies — a real
/// deployment would issue short-lived, scoped tokens from a vault (never hard-coded).
pub const SEED_USERS: [SeedUser; 4] = [
    SeedUser {
        name: "alice",
        role: "admin",
        token: "tok-alice-9f3a7c",
    },
    SeedUser {
        name: "bob",
        role: "editor",
        token: "tok-bob-2c71e0",
    },
    SeedUser {
        name: "carol",
        role: "viewer",
        token: "tok-carol-5d8841",
    },
    SeedUser {
        name: "dave",
        role: "(unassigned)",
        token: "tok-dave-0b14fa",
    },
];

/// Role → permitted actions. Seeded into casbin as `p, role, document, action` policy lines.
pub const ROLE_GRANTS: &[(&str, &[Action])] = &[
    (
        "admin",
        &[Action::Create, Action::Read, Action::Update, Action::Delete],
    ),
    ("editor", &[Action::Read, Action::Update]),
    ("viewer", &[Action::Read]),
];

/// Whether `role` is one of the real roles defined in [`ROLE_GRANTS`].
pub fn is_real_role(role: &str) -> bool {
    ROLE_GRANTS.iter().any(|(r, _)| *r == role)
}

/// The demo bearer token for a named seed user (used by the driver to act as them).
pub fn token_for(name: &str) -> &'static str {
    SEED_USERS
        .iter()
        .find(|u| u.name == name)
        .map(|u| u.token)
        .unwrap_or("")
}

/// The audience this server accepts: a token issued for any other audience is rejected
/// (the fix for the MCP "token passthrough" anti-pattern).
pub const AUDIENCE: &str = "doc-server";

/// A far-future token expiry (2100-01-01 UTC, unix seconds) used for valid demo tokens.
pub const EXP_VALID: u64 = 4_102_444_800;
/// An already-past expiry used for the expired demo token.
pub const EXP_EXPIRED: u64 = 0;

/// Deliberately-bad demo tokens used by the scenarios (all introspect to subject `alice`):
/// an expired token, one minted for a different audience, and a down-scoped read-only token.
pub const TOKEN_EXPIRED: &str = "tok-expired-aa0011";
pub const TOKEN_WRONG_AUDIENCE: &str = "tok-wrongaud-bb2233";
pub const TOKEN_READONLY_ALICE: &str = "tok-alice-readonly-cc4455";

/// The OAuth-style scope required to perform an action on the document resource. Per-action
/// scopes keep tokens least-privilege; a wildcard `documents:*` is the anti-pattern to avoid.
pub fn scope_for(action: Action) -> &'static str {
    match action {
        Action::Create => "documents:create",
        Action::Read => "documents:read",
        Action::Update => "documents:update",
        Action::Delete => "documents:delete",
    }
}
