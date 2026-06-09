//! The per-request security pipeline, expressed as a cano workflow.
//!
//! Every MCP tool call runs this FSM, layering authentication, authorization, and guards:
//!
//! ```text
//! Authenticate → Authorize → InspectInput → Execute → InspectOutput → Audit → Done
//!      │ fail        │ deny        │ block                                  ▲
//!      └─────────────┴─────────────┴──────────────────────────────────────-┘  (skip to Audit)
//! ```
//!
//! - **Authenticate** — introspect the bearer token; reject unknown, wrong-audience, or expired
//!   tokens (token-passthrough prevention).
//! - **Authorize** — require BOTH the token's scope and the casbin role (least privilege).
//! - **InspectInput** — command-injection (render), human-in-the-loop consent (delete), and SSRF
//!   (import_url) guards.
//! - **Execute** — run the operation (DB errors are sanitized).
//! - **InspectOutput** — redact secrets and neutralize prompt injection in returned content.
//! - **Audit** — log the redacted result (never the token or raw secrets).
//!
//! Shared dependencies and the request flow through cano `Resources`; stages communicate via a
//! `MemoryStore`, which the caller reads once the workflow finishes.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use cano::prelude::*;
use casbin::Enforcer;
use rmcp::model::{CallToolResult, Content};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::auth::{self, TokenClaims};
use crate::domain::{Action, Outcome, RESOURCE, scope_for};
use crate::guards::{self, Finding};
use crate::{authz, db};

/// The operation a tool wants to perform, carrying its action-specific data.
#[derive(Clone)]
pub enum Operation {
    Create { title: String, content: String },
    Read { id: i64 },
    Update { id: i64, content: String },
    Delete { id: i64, confirm: bool },
    Render { id: i64, format: String },
    ImportUrl { url: String },
}

impl Operation {
    /// The casbin action this operation requires. `Render` and `ImportUrl` read, so they need
    /// `read` (a teaching simplification — `import_url` is gated as a read-level capability).
    pub fn action(&self) -> Action {
        match self {
            Operation::Create { .. } => Action::Create,
            Operation::Read { .. } => Action::Read,
            Operation::Update { .. } => Action::Update,
            Operation::Delete { .. } => Action::Delete,
            Operation::Render { .. } => Action::Read,
            Operation::ImportUrl { .. } => Action::Read,
        }
    }
}

/// What the pipeline produces: the terminal outcome, a human-readable message, and any guard
/// findings (for auditing / the report).
pub struct PipelineOutcome {
    pub outcome: Outcome,
    pub message: String,
    pub findings: Vec<Finding>,
}

impl PipelineOutcome {
    /// Map the outcome onto an MCP tool result. Only `Allowed` is a success; everything else
    /// (auth failure, authorization denial, guard block) is a tool-level error.
    pub fn into_tool_result(self) -> CallToolResult {
        let content = vec![Content::text(self.message)];
        match self.outcome {
            Outcome::Allowed => CallToolResult::success(content),
            _ => CallToolResult::error(content),
        }
    }
}

// --- Resources injected into the per-request workflow -----------------------------------

/// Shared enforcer (created once at startup, cloned into each request).
struct Authz(Arc<RwLock<Enforcer>>);
impl Resource for Authz {}

/// Shared documents pool.
struct Db(PgPool);
impl Resource for Db {}

/// Shared token → claims store (introspection).
struct Sessions(Arc<HashMap<String, TokenClaims>>);
impl Resource for Sessions {}

/// The request being processed (the presented token + the operation).
struct ReqInput {
    token: String,
    op: Operation,
}
impl Resource for ReqInput {}

// --- Workflow states -------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ReqStage {
    Authenticate,
    Authorize,
    InspectInput,
    Execute,
    InspectOutput,
    Audit,
    Done,
}

fn task_err(e: impl std::fmt::Display) -> CanoError {
    CanoError::task_execution(e.to_string())
}

/// Turn a database error into a cano error with secrets (e.g. the connection string) stripped.
fn db_err(e: impl std::fmt::Display) -> CanoError {
    CanoError::task_execution(guards::secrets::sanitize_error(&e.to_string()))
}

/// Record a terminal rejection (auth/authz/guard) in the store and route to Audit.
async fn reject(
    store: &MemoryStore,
    outcome: Outcome,
    message: String,
) -> Result<TaskResult<ReqStage>, CanoError> {
    store.put("outcome", outcome).map_err(task_err)?;
    store.put("message", message).map_err(task_err)?;
    Ok(TaskResult::Single(ReqStage::Audit))
}

// --- Stage: Authenticate (token introspection + audience + expiry) ---------------------

#[derive(Clone)]
struct Authenticate;

#[task(state = ReqStage)]
impl Authenticate {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let sessions = res.get::<Sessions, _>("sessions")?;
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;

        let claims = match auth::introspect(&sessions.0, &input.token) {
            Some(c) => c,
            None => {
                return reject(
                    &store,
                    Outcome::AuthFailed,
                    "authentication failed: unknown or invalid token".to_string(),
                )
                .await;
            }
        };
        if claims.audience != crate::domain::AUDIENCE {
            return reject(
                &store,
                Outcome::AuthFailed,
                format!(
                    "authentication failed: token audience {:?} is not accepted (expected {:?})",
                    claims.audience,
                    crate::domain::AUDIENCE
                ),
            )
            .await;
        }
        if auth::is_expired(claims.expires_at) {
            return reject(
                &store,
                Outcome::AuthFailed,
                "authentication failed: token expired".to_string(),
            )
            .await;
        }

        store
            .put("actor", claims.subject.clone())
            .map_err(task_err)?;
        store
            .put("scopes", claims.scopes.clone())
            .map_err(task_err)?;
        Ok(TaskResult::Single(ReqStage::Authorize))
    }
}

// --- Stage: Authorize (token scope AND casbin role) ------------------------------------

#[derive(Clone)]
struct Authorize;

#[task(state = ReqStage)]
impl Authorize {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let authz = res.get::<Authz, _>("authz")?;
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;
        let actor: String = store.get("actor").map_err(task_err)?;
        let scopes: Vec<String> = store.get("scopes").map_err(task_err)?;
        let action = input.op.action();

        // 1) Token scope (least privilege): the token must carry the required scope.
        let required = scope_for(action);
        let scope_ok = scopes.iter().any(|s| s == required || s == "documents:*");
        if !scope_ok {
            return reject(
                &store,
                Outcome::NotAuthorized,
                format!("denied: token scope is missing {required:?}"),
            )
            .await;
        }

        // 2) Casbin role: the actor's role must permit the action.
        let role_ok = {
            let enforcer = authz.0.read().await;
            authz::check(&enforcer, &actor, action).map_err(task_err)?
        };
        if !role_ok {
            return reject(
                &store,
                Outcome::NotAuthorized,
                format!(
                    "permission denied: {} may not {} a {}",
                    actor,
                    action.as_str(),
                    RESOURCE
                ),
            )
            .await;
        }

        Ok(TaskResult::Single(ReqStage::InspectInput))
    }
}

// --- Stage: InspectInput (command-injection, consent, SSRF) ----------------------------

#[derive(Clone)]
struct InspectInput;

#[task(state = ReqStage)]
impl InspectInput {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;

        match &input.op {
            // Command injection: only an allowlisted format reaches the (argv) executor.
            Operation::Render { format, .. } => match guards::command::validate_format(format) {
                Ok(flag) => {
                    store.put("wc_flag", flag.to_string()).map_err(task_err)?;
                }
                Err(reason) => {
                    store
                        .put(
                            "findings",
                            vec![Finding::new("command_injection", reason.clone())],
                        )
                        .map_err(task_err)?;
                    return reject(
                        &store,
                        Outcome::Blocked,
                        format!("blocked by command-injection guard: {reason}"),
                    )
                    .await;
                }
            },
            // Human-in-the-loop: a destructive delete needs explicit confirmation, so untrusted
            // content cannot silently trigger it.
            Operation::Delete { confirm, .. } if !confirm => {
                return reject(
                    &store,
                    Outcome::Blocked,
                    "blocked: delete requires explicit confirmation (confirm=true)".to_string(),
                )
                .await;
            }
            // SSRF: a fetch target must be an external HTTPS URL, never an internal address.
            Operation::ImportUrl { url } => {
                if let Err(reason) = guards::ssrf::validate_url(url) {
                    store
                        .put("findings", vec![Finding::new("ssrf", reason.clone())])
                        .map_err(task_err)?;
                    return reject(
                        &store,
                        Outcome::Blocked,
                        format!("blocked by SSRF guard: {reason}"),
                    )
                    .await;
                }
            }
            _ => {}
        }
        Ok(TaskResult::Single(ReqStage::Execute))
    }
}

// --- Stage: Execute --------------------------------------------------------------------

#[derive(Clone)]
struct Execute;

#[task(state = ReqStage)]
impl Execute {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let db = res.get::<Db, _>("db")?;
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;
        let actor: String = store.get("actor").map_err(task_err)?;
        let pool = &db.0;

        let message = match &input.op {
            Operation::Create { title, content } => {
                let id = db::create(pool, &actor, title, content)
                    .await
                    .map_err(db_err)?;
                format!("created document id={id}")
            }
            Operation::Read { id } => match db::read(pool, *id).await.map_err(db_err)? {
                Some(doc) => {
                    store.put("untrusted", doc.content).map_err(task_err)?;
                    format!(
                        "read document id={} (created_by {})",
                        doc.id, doc.created_by
                    )
                }
                None => format!("document id={id} not found"),
            },
            Operation::Update { id, content } => {
                let n = db::update(pool, *id, content).await.map_err(db_err)?;
                format!("updated {n} row(s) for document id={id}")
            }
            Operation::Delete { id, .. } => {
                let n = db::delete(pool, *id).await.map_err(db_err)?;
                format!("deleted {n} row(s) for document id={id}")
            }
            Operation::Render { id, format } => {
                let flag: String = store.get("wc_flag").map_err(task_err)?;
                match db::read(pool, *id).await.map_err(db_err)? {
                    Some(doc) => {
                        let counted = guards::command::render(&doc.content, &flag)
                            .await
                            .map_err(task_err)?;
                        format!("rendered document id={} ({format}): {counted}", doc.id)
                    }
                    None => format!("document id={id} not found"),
                }
            }
            // The SSRF guard already validated this URL; we don't actually fetch (a real fetcher
            // must also pin DNS to defeat rebinding — see guards::ssrf).
            Operation::ImportUrl { url } => {
                format!(
                    "SSRF check passed: {url} is an allowed destination (fetch elided in this example)"
                )
            }
        };

        store.put("message", message).map_err(task_err)?;
        Ok(TaskResult::Single(ReqStage::InspectOutput))
    }
}

// --- Stage: InspectOutput (secret redaction + prompt-injection neutralization) ---------

#[derive(Clone)]
struct InspectOutput;

#[task(state = ReqStage)]
impl InspectOutput {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;
        store.put("outcome", Outcome::Allowed).map_err(task_err)?;

        let status: String = store.get("message").unwrap_or_default();
        let mut findings: Vec<Finding> = Vec::new();

        let final_message = if let Ok(untrusted) = store.get::<String>("untrusted") {
            // Returned document content is untrusted: redact secrets, then delimit + flag injection.
            let (redacted, secret_findings) = guards::secrets::redact(&untrusted);
            findings.extend(secret_findings);

            let source = match &input.op {
                Operation::Read { id } => format!("document:{id}"),
                _ => "document".to_string(),
            };
            let (wrapped, injection_findings) =
                guards::prompt_injection::neutralize(&source, &redacted);
            findings.extend(injection_findings);

            let summary = if findings.is_empty() {
                "no threats detected".to_string()
            } else {
                let detail = findings
                    .iter()
                    .map(|f| format!("{}:{}", f.kind, f.detail))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{} finding(s) [{detail}]", findings.len())
            };
            format!("{status}\n{wrapped}\n[guard] {summary}")
        } else {
            status
        };

        store.put("message", final_message).map_err(task_err)?;
        store.put("findings", findings).map_err(task_err)?;
        Ok(TaskResult::Single(ReqStage::Audit))
    }
}

// --- Stage: Audit ----------------------------------------------------------------------

#[derive(Clone)]
struct Audit;

#[task(state = ReqStage)]
impl Audit {
    async fn run(&self, res: &Resources) -> Result<TaskResult<ReqStage>, CanoError> {
        let input = res.get::<ReqInput, _>("input")?;
        let store = res.get::<MemoryStore, _>("store")?;
        // The token is NEVER logged; the actor is the resolved identity (if any).
        let actor: String = store
            .get("actor")
            .unwrap_or_else(|_| "<unauthenticated>".to_string());
        let outcome: Outcome = store.get("outcome").unwrap_or(Outcome::AuthFailed);
        let message: String = store.get("message").unwrap_or_default();

        tracing::info!(
            actor = %actor,
            action = input.op.action().as_str(),
            outcome = ?outcome,
            "{message}"
        );
        Ok(TaskResult::Single(ReqStage::Done))
    }
}

// --- Entry point -----------------------------------------------------------------------

/// Build and run the per-request pipeline, returning its outcome.
pub async fn run(
    enforcer: Arc<RwLock<Enforcer>>,
    pool: PgPool,
    sessions: Arc<HashMap<String, TokenClaims>>,
    token: String,
    op: Operation,
) -> Result<PipelineOutcome> {
    let store = MemoryStore::new();
    let resources = Resources::new()
        .insert("authz", Authz(enforcer))
        .insert("db", Db(pool))
        .insert("sessions", Sessions(sessions))
        .insert("input", ReqInput { token, op })
        .insert("store", store.clone());

    let workflow = Workflow::new(resources)
        .register(ReqStage::Authenticate, Authenticate)
        .register(ReqStage::Authorize, Authorize)
        .register(ReqStage::InspectInput, InspectInput)
        .register(ReqStage::Execute, Execute)
        .register(ReqStage::InspectOutput, InspectOutput)
        .register(ReqStage::Audit, Audit)
        .add_exit_state(ReqStage::Done);

    workflow.orchestrate(ReqStage::Authenticate).await?;

    let outcome = store
        .get::<Outcome>("outcome")
        .unwrap_or(Outcome::AuthFailed);
    let message = store
        .get::<String>("message")
        .unwrap_or_else(|_| "no message".to_string());
    let findings = store.get::<Vec<Finding>>("findings").unwrap_or_default();
    Ok(PipelineOutcome {
        outcome,
        message,
        findings,
    })
}
