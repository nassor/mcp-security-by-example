//! In-process MCP test — no Docker/Postgres required.
//!
//! Requests rejected by the authentication, authorization, or input-guard stages never reach the
//! database, so we stand up the real [`DocServer`] over an in-memory duplex transport with a
//! lazily-connected pool (never opened) and verify those paths end to end. Allowed operations need
//! a real database and are covered by running the demo against Postgres.

use std::sync::Arc;

use anyhow::Result;
use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{Peer, RunningService};
use rmcp::{RoleClient, ServiceExt, object};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::RwLock;

use mcp_security_by_example::domain::{
    TOKEN_EXPIRED, TOKEN_READONLY_ALICE, TOKEN_WRONG_AUDIENCE, token_for,
};
use mcp_security_by_example::server::DocServer;
use mcp_security_by_example::{auth, authz};

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

async fn build_server() -> Result<DocServer> {
    let model = DefaultModel::from_str(MODEL).await?;
    let mut enforcer = Enforcer::new(model, MemoryAdapter::default()).await?;
    authz::seed_policies(&mut enforcer).await?;
    let enforcer = Arc::new(RwLock::new(enforcer));

    // Lazy pool: not connected until first use. The requests below all stop before Execute.
    let pool = PgPoolOptions::new().connect_lazy("postgres://unused:unused@127.0.0.1:1/none")?;
    let sessions = Arc::new(auth::token_store());
    Ok(DocServer::new(enforcer, pool, sessions))
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Map<String, serde_json::Value>,
) -> Result<CallToolResult> {
    let peer: &Peer<RoleClient> = client;
    Ok(peer
        .call_tool(CallToolRequestParams::new(name).with_arguments(args))
        .await?)
}

#[tokio::test]
async fn rejects_unauthenticated_unauthorized_and_unsafe_calls() -> Result<()> {
    let server = build_server().await?;

    let (server_io, client_io) = tokio::io::duplex(8192);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;

    // Tool discovery: all six tools are exposed.
    let tools = client.list_all_tools().await?;
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "create_document",
            "delete_document",
            "import_url",
            "read_document",
            "render_document",
            "update_document"
        ]
    );

    // Each call below must be rejected (is_error), and each stops before the database.
    let rejected: Vec<(&str, CallToolResult)> = vec![
        // Authentication: forged / wrong-audience / expired tokens.
        (
            "forged token",
            call(
                &client,
                "read_document",
                object!({"token": "tok-nope", "id": 1}),
            )
            .await?,
        ),
        (
            "wrong audience",
            call(
                &client,
                "read_document",
                object!({"token": TOKEN_WRONG_AUDIENCE, "id": 1}),
            )
            .await?,
        ),
        (
            "expired token",
            call(
                &client,
                "read_document",
                object!({"token": TOKEN_EXPIRED, "id": 1}),
            )
            .await?,
        ),
        // Authorization: role (dave) and token scope (read-only alice cannot update).
        (
            "dave delete (role)",
            call(
                &client,
                "delete_document",
                object!({"token": token_for("dave"), "id": 1, "confirm": true}),
            )
            .await?,
        ),
        (
            "read-only update (scope)",
            call(
                &client,
                "update_document",
                object!({"token": TOKEN_READONLY_ALICE, "id": 1, "content": "x"}),
            )
            .await?,
        ),
        // Guards: consent (delete w/o confirm), command injection, SSRF.
        (
            "delete w/o confirm",
            call(
                &client,
                "delete_document",
                object!({"token": token_for("alice"), "id": 1}),
            )
            .await?,
        ),
        (
            "command injection",
            call(
                &client,
                "render_document",
                object!({"token": token_for("alice"), "id": 1, "format": "words; rm -rf ~"}),
            )
            .await?,
        ),
        (
            "ssrf metadata",
            call(
                &client,
                "import_url",
                object!({"token": token_for("alice"), "url": "https://169.254.169.254/"}),
            )
            .await?,
        ),
    ];
    for (label, result) in &rejected {
        assert_eq!(result.is_error, Some(true), "{label} should be rejected");
    }

    client.cancel().await?;
    server_task.abort();
    Ok(())
}
