//! Token authentication: introspect opaque bearer tokens into claims, and check them.
//!
//! This is the authentication layer (*who are you, and is this token even for us?*), distinct
//! from casbin authorization (*what may you do?* — see [`crate::authz`]) and from token scopes
//! (*what did this token grant?* — checked in the pipeline). Callers present a token, not a
//! claimed name, so they cannot impersonate another user.
//!
//! [`token_store`] simulates the set of tokens an identity provider has issued (as if from an
//! OAuth introspection endpoint or a verified JWT). The pipeline's `Authenticate` stage then
//! enforces the audience and expiry — a token minted for another service or an expired one is
//! rejected ("token passthrough" prevention).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    AUDIENCE, EXP_EXPIRED, EXP_VALID, ROLE_GRANTS, SEED_USERS, TOKEN_EXPIRED, TOKEN_READONLY_ALICE,
    TOKEN_WRONG_AUDIENCE, scope_for,
};

/// What the server learns when it introspects a token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    pub subject: String,
    pub audience: String,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

/// Scopes granted to a role, derived from its casbin permissions (least privilege by default).
fn scopes_for_role(role: &str) -> Vec<String> {
    ROLE_GRANTS
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, actions)| actions.iter().map(|a| scope_for(*a).to_string()).collect())
        .unwrap_or_default()
}

/// Build the `token → claims` store. Each seed user gets a valid token (correct audience,
/// far-future expiry, role-matching scopes), plus three deliberately-bad demo tokens used by the
/// scenarios: expired, wrong-audience, and a down-scoped read-only token.
pub fn token_store() -> HashMap<String, TokenClaims> {
    let mut store = HashMap::new();
    for u in SEED_USERS.iter() {
        store.insert(
            u.token.to_string(),
            TokenClaims {
                subject: u.name.to_string(),
                audience: AUDIENCE.to_string(),
                expires_at: EXP_VALID,
                scopes: scopes_for_role(u.role),
            },
        );
    }
    store.insert(
        TOKEN_EXPIRED.to_string(),
        TokenClaims {
            subject: "alice".into(),
            audience: AUDIENCE.into(),
            expires_at: EXP_EXPIRED,
            scopes: scopes_for_role("admin"),
        },
    );
    store.insert(
        TOKEN_WRONG_AUDIENCE.to_string(),
        TokenClaims {
            subject: "alice".into(),
            audience: "other-service".into(),
            expires_at: EXP_VALID,
            scopes: scopes_for_role("admin"),
        },
    );
    store.insert(
        TOKEN_READONLY_ALICE.to_string(),
        TokenClaims {
            subject: "alice".into(),
            audience: AUDIENCE.into(),
            expires_at: EXP_VALID,
            scopes: vec!["documents:read".into()],
        },
    );
    store
}

/// Look up a token's claims (introspection). `None` for unknown/forged tokens.
pub fn introspect<'a>(
    store: &'a HashMap<String, TokenClaims>,
    token: &str,
) -> Option<&'a TokenClaims> {
    store.get(token)
}

/// Whether `expires_at` (unix seconds) is in the past.
pub fn is_expired(expires_at: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now >= expires_at
}
