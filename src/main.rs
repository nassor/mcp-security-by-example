//! Driver binary. Spawns the MCP server as a child process, connects as an MCP client, and
//! runs the simulation (itself a cano workflow). Run this with `cargo run --bin driver`.

use anyhow::Result;
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use tokio::process::Command;

use mcp_security_by_example::simulation;

#[tokio::main]
async fn main() -> Result<()> {
    // Spawn the server and speak JSON-RPC over its stdio. `--quiet` keeps cargo's build
    // output from cluttering the demo (the server itself logs to stderr).
    let transport = TokioChildProcess::new(Command::new("cargo").configure(|cmd| {
        cmd.args(["run", "--quiet", "--bin", "server"]);
    }))?;
    let service: RunningService<RoleClient, ()> = ().serve(transport).await?;

    // The simulation only needs a `Peer` to make calls; keep the owning handle here so we
    // can shut the server down cleanly afterwards.
    let peer = service.peer().clone();
    simulation::run(peer).await?;

    service.cancel().await?;
    Ok(())
}
