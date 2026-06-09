//! The top-level driver loop, expressed as a cano workflow:
//!
//! ```text
//! Connect → Matrix → Auth → Secrets → Injection → Command → Scope → Consent → Ssrf → Done
//! ```
//!
//! `Connect` proves the MCP handshake by listing tools. `Matrix` runs the RBAC permission matrix
//! (each user acting via their bearer token). The remaining phases run the security scenarios from
//! [`crate::scenarios`], each printing how an attack was handled.

use anyhow::Result;
use cano::prelude::*;
use rmcp::service::Peer;
use rmcp::{RoleClient, object};

use crate::domain::{Action, RESOURCE, SEED_USERS, token_for};
use crate::scenarios::{self, call};

/// The MCP client peer, wrapped so it can live in cano `Resources`.
struct Client(Peer<RoleClient>);
impl Resource for Client {}

/// One user's allow/deny across the four CRUD actions (indexed like [`Action::ALL`]).
#[derive(Clone)]
struct Row {
    actor: String,
    role: String,
    allowed: [bool; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Phase {
    Connect,
    Matrix,
    Auth,
    Secrets,
    Injection,
    Command,
    Scope,
    Consent,
    Ssrf,
    Done,
}

fn task_err(e: impl std::fmt::Display) -> CanoError {
    CanoError::task_execution(e.to_string())
}

/// The MCP tool name for a given action.
fn tool_name(action: Action) -> &'static str {
    match action {
        Action::Create => "create_document",
        Action::Read => "read_document",
        Action::Update => "update_document",
        Action::Delete => "delete_document",
    }
}

// --- Stage: Connect --------------------------------------------------------------------

#[derive(Clone)]
struct ConnectTask;

#[task(state = Phase)]
impl ConnectTask {
    async fn run(&self, res: &Resources) -> Result<TaskResult<Phase>, CanoError> {
        let client = res.get::<Client, _>("client")?;
        let tools = client.0.list_all_tools().await.map_err(task_err)?;
        println!("Connected to MCP server. It exposes {} tools:", tools.len());
        for t in &tools {
            println!("  - {}", t.name);
        }
        Ok(TaskResult::Single(Phase::Matrix))
    }
}

// --- Stage: Matrix (RBAC permission matrix, via tokens) --------------------------------

#[derive(Clone)]
struct MatrixTask;

#[task(state = Phase)]
impl MatrixTask {
    async fn run(&self, res: &Resources) -> Result<TaskResult<Phase>, CanoError> {
        let client = res.get::<Client, _>("client")?;
        let peer = &client.0;

        // The admin seeds one document so read/update/delete have a target.
        // The Matrix runs first after Connect, so after the server's TRUNCATE this is id = 1.
        call(
            peer,
            "create_document",
            object!({ "token": token_for("alice"), "title": "Seed", "content": "seed" }),
        )
        .await?;
        let doc_id = 1i64;

        let mut rows: Vec<Row> = Vec::new();
        for user in SEED_USERS.iter() {
            let mut allowed = [false; 4];
            for (i, action) in Action::ALL.iter().enumerate() {
                // Delete carries confirm=true here so the matrix tests authorization (role/scope),
                // not the human-in-the-loop consent guard (shown in its own scenario).
                let args = match action {
                    Action::Create => {
                        object!({ "token": user.token, "title": "T", "content": "C" })
                    }
                    Action::Read => object!({ "token": user.token, "id": doc_id }),
                    Action::Update => {
                        object!({ "token": user.token, "id": doc_id, "content": "edited" })
                    }
                    Action::Delete => {
                        object!({ "token": user.token, "id": doc_id, "confirm": true })
                    }
                };
                let result = call(peer, tool_name(*action), args).await?;
                // A rejected call is a tool-level error (is_error = true); anything else is allowed.
                allowed[i] = result.is_error != Some(true);
            }
            rows.push(Row {
                actor: user.name.to_string(),
                role: user.role.to_string(),
                allowed,
            });
        }

        print_matrix(&rows);
        Ok(TaskResult::Single(Phase::Auth))
    }
}

// --- Stages: the security scenarios ----------------------------------------------------

macro_rules! scenario_stage {
    ($task:ident, $next:ident, $run:path) => {
        #[derive(Clone)]
        struct $task;

        #[task(state = Phase)]
        impl $task {
            async fn run(&self, res: &Resources) -> Result<TaskResult<Phase>, CanoError> {
                let client = res.get::<Client, _>("client")?;
                $run(&client.0).await?;
                Ok(TaskResult::Single(Phase::$next))
            }
        }
    };
}

scenario_stage!(AuthTask, Secrets, scenarios::auth);
scenario_stage!(SecretsTask, Injection, scenarios::secrets);
scenario_stage!(InjectionTask, Command, scenarios::injection);
scenario_stage!(CommandTask, Scope, scenarios::command);
scenario_stage!(ScopeTask, Consent, scenarios::scope);
scenario_stage!(ConsentTask, Ssrf, scenarios::consent);
scenario_stage!(SsrfTask, Done, scenarios::ssrf);

fn print_matrix(rows: &[Row]) {
    let cell = |b: bool| if b { "  ✅  " } else { "  ❌  " };
    println!();
    println!("Permission matrix (resource: {RESOURCE})");
    println!(
        "{:<8} {:<14} {:^6} {:^6} {:^6} {:^6}",
        "actor", "role", "create", "read", "update", "delete"
    );
    println!("{}", "-".repeat(8 + 1 + 14 + 1 + 6 * 4 + 3));
    for r in rows {
        println!(
            "{:<8} {:<14} {} {} {} {}",
            r.actor,
            r.role,
            cell(r.allowed[0]),
            cell(r.allowed[1]),
            cell(r.allowed[2]),
            cell(r.allowed[3]),
        );
    }
}

// --- Entry point -----------------------------------------------------------------------

/// Run the full demo (RBAC matrix + the security scenarios) against a connected client.
pub async fn run(peer: Peer<RoleClient>) -> Result<()> {
    let resources = Resources::new().insert("client", Client(peer));

    let workflow = Workflow::new(resources)
        .register(Phase::Connect, ConnectTask)
        .register(Phase::Matrix, MatrixTask)
        .register(Phase::Auth, AuthTask)
        .register(Phase::Secrets, SecretsTask)
        .register(Phase::Injection, InjectionTask)
        .register(Phase::Command, CommandTask)
        .register(Phase::Scope, ScopeTask)
        .register(Phase::Consent, ConsentTask)
        .register(Phase::Ssrf, SsrfTask)
        .add_exit_state(Phase::Done);

    workflow.orchestrate(Phase::Connect).await?;
    Ok(())
}
