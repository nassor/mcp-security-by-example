//! MCP server binary. Builds the casbin enforcer (policies in Postgres) and the documents
//! pool, then serves the CRUD tools over stdio.
//!
//! IMPORTANT: stdout is the JSON-RPC channel — all logs go to stderr.

use std::sync::Arc;

use anyhow::Result;
use casbin::{CoreApi, DefaultModel, Enforcer};
use rmcp::{ServiceExt, transport::stdio};
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use mcp_security_by_example::{auth, authz, db, server::DocServer};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://app:app@localhost:5432/appdb".to_string());

    // Casbin: model + Postgres-backed adapter (auto-creates `casbin_rule`), then seed.
    let model = DefaultModel::from_file("rbac_model.conf").await?;
    let adapter = SqlxAdapter::new(database_url.clone(), 5).await?;
    let mut enforcer = Enforcer::new(model, adapter).await?;
    authz::seed_policies(&mut enforcer).await?;
    let enforcer = Arc::new(RwLock::new(enforcer));

    // The protected resource lives in its own pool; reset it for a deterministic demo.
    let pool = db::connect(&database_url).await?;
    db::init_schema(&pool).await?;

    // Token introspection store (authentication), built from the seed users.
    let sessions = Arc::new(auth::token_store());

    tracing::info!("doc-server ready; serving MCP over stdio");
    let service = DocServer::new(enforcer, pool, sessions)
        .serve(stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}
