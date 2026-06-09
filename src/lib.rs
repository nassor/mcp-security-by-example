//! A small, readable example wiring four pieces together:
//!
//! - **rmcp** — an MCP server exposing CRUD + render tools, driven by an MCP client.
//! - **cano** — workflows at two levels: the top-level driver loop and a per-request
//!   security pipeline (authenticate → authorize → guards → execute → audit).
//! - **casbin** — RBAC enforcement (embedded library), with policies stored in Postgres.
//! - **PostgreSQL** — holds both the `casbin_rule` policy table and the `documents` resource.
//!
//! On top of RBAC, three security scenarios are demonstrated as pipeline guards: token-based
//! authentication (token theft / leakage), prompt-injection neutralization, and OS
//! command-injection protection. See `README.md` for the walkthrough.

pub mod auth;
pub mod authz;
pub mod db;
pub mod domain;
pub mod guards;
pub mod request_pipeline;
pub mod scenarios;
pub mod server;
pub mod simulation;
