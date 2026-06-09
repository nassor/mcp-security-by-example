//! Hermetic RBAC tests — no Docker/Postgres required.
//!
//! These build an enforcer backed by an in-memory adapter, seed it with the same policies
//! `authz::seed_policies` writes to Postgres, and assert the full permission matrix. This
//! pins the *policy model* independently of MCP and the database.

use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter};
use mcp_security_by_example::authz;
use mcp_security_by_example::domain::Action;

const MODEL: &str = r#"
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"#;

async fn seeded_enforcer() -> Enforcer {
    let model = DefaultModel::from_str(MODEL).await.unwrap();
    let mut enforcer = Enforcer::new(model, MemoryAdapter::default())
        .await
        .unwrap();
    authz::seed_policies(&mut enforcer).await.unwrap();
    enforcer
}

/// Assert an actor's allow/deny across all four actions, in [`Action::ALL`] order.
async fn assert_matrix(actor: &str, expected: [bool; 4]) {
    let enforcer = seeded_enforcer().await;
    for (action, want) in Action::ALL.iter().zip(expected) {
        let got = authz::check(&enforcer, actor, *action).unwrap();
        assert_eq!(
            got,
            want,
            "actor={actor} action={} expected {want} got {got}",
            action.as_str()
        );
    }
}

#[tokio::test]
async fn admin_can_do_everything() {
    assert_matrix("alice", [true, true, true, true]).await;
}

#[tokio::test]
async fn editor_can_read_and_update_only() {
    assert_matrix("bob", [false, true, true, false]).await;
}

#[tokio::test]
async fn viewer_can_read_only() {
    assert_matrix("carol", [false, true, false, false]).await;
}

#[tokio::test]
async fn unassigned_user_is_denied_everything() {
    assert_matrix("dave", [false, false, false, false]).await;
}
