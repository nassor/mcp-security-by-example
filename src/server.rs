//! The MCP server: CRUD + render tools over the `documents` resource.
//!
//! Each tool takes an opaque `token` (the bearer credential — the server resolves it to an
//! identity; callers can't just claim a name). The tool body is tiny: it hands the operation to
//! the per-request pipeline ([`crate::request_pipeline`]), which authenticates, authorizes, runs
//! the guards, executes, and audits, then maps the outcome onto an MCP result.

use std::collections::HashMap;
use std::sync::Arc;

use casbin::Enforcer;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::auth::TokenClaims;
use crate::request_pipeline::{self, Operation};

/// The MCP server. Holds the shared enforcer, documents pool, and token sessions.
#[derive(Clone)]
pub struct DocServer {
    enforcer: Arc<RwLock<Enforcer>>,
    pool: PgPool,
    sessions: Arc<HashMap<String, TokenClaims>>,
}

impl DocServer {
    pub fn new(
        enforcer: Arc<RwLock<Enforcer>>,
        pool: PgPool,
        sessions: Arc<HashMap<String, TokenClaims>>,
    ) -> Self {
        Self {
            enforcer,
            pool,
            sessions,
        }
    }

    /// Run one operation through the per-request pipeline.
    async fn run_op(&self, token: String, op: Operation) -> Result<CallToolResult, ErrorData> {
        let outcome = request_pipeline::run(
            self.enforcer.clone(),
            self.pool.clone(),
            self.sessions.clone(),
            token,
            op,
        )
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(outcome.into_tool_result())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateArgs {
    /// The caller's bearer token.
    pub token: String,
    pub title: String,
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadArgs {
    /// The caller's bearer token.
    pub token: String,
    pub id: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateArgs {
    /// The caller's bearer token.
    pub token: String,
    pub id: i64,
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteArgs {
    /// The caller's bearer token.
    pub token: String,
    pub id: i64,
    /// Explicit confirmation for this destructive action (human-in-the-loop).
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenderArgs {
    /// The caller's bearer token.
    pub token: String,
    pub id: i64,
    /// One of: words, lines, chars.
    pub format: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImportUrlArgs {
    /// The caller's bearer token.
    pub token: String,
    /// The URL to import (must be an external HTTPS URL).
    pub url: String,
}

#[tool_router]
impl DocServer {
    #[tool(description = "Create a new document")]
    async fn create_document(
        &self,
        Parameters(args): Parameters<CreateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(
            args.token,
            Operation::Create {
                title: args.title,
                content: args.content,
            },
        )
        .await
    }

    #[tool(description = "Read a document by id")]
    async fn read_document(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(args.token, Operation::Read { id: args.id })
            .await
    }

    #[tool(description = "Update a document's content by id")]
    async fn update_document(
        &self,
        Parameters(args): Parameters<UpdateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(
            args.token,
            Operation::Update {
                id: args.id,
                content: args.content,
            },
        )
        .await
    }

    #[tool(description = "Delete a document by id")]
    async fn delete_document(
        &self,
        Parameters(args): Parameters<DeleteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(
            args.token,
            Operation::Delete {
                id: args.id,
                confirm: args.confirm,
            },
        )
        .await
    }

    #[tool(description = "Render a document by counting its words, lines, or chars")]
    async fn render_document(
        &self,
        Parameters(args): Parameters<RenderArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(
            args.token,
            Operation::Render {
                id: args.id,
                format: args.format,
            },
        )
        .await
    }

    #[tool(description = "Import a document from an external HTTPS URL (SSRF-guarded)")]
    async fn import_url(
        &self,
        Parameters(args): Parameters<ImportUrlArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_op(args.token, Operation::ImportUrl { url: args.url })
            .await
    }
}

#[tool_handler]
impl ServerHandler for DocServer {}
