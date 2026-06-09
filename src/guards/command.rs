//! OS command-injection protection (CWE-78).
//!
//! The `render_document` tool shells out to `wc` to count words/lines/chars. The safety comes
//! from two layers:
//!
//! 1. [`validate_format`] — the only user-controlled value (`format`) is checked against an
//!    allowlist and rejected if it contains any shell metacharacter.
//! 2. [`render`] — execution uses `tokio::process::Command` with **argv** (no `sh -c`), and the
//!    document content is piped over **stdin**, never interpolated into a command string. Even an
//!    attacker-controlled value cannot break out into a second command.

use std::process::Stdio;

use anyhow::{Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Characters with special meaning to a shell. The allowlist below already constrains valid
/// input; rejecting these too is defense in depth and a clear teaching signal.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '\\', '(', ')', '<', '>', '\n', '\r', '*', '?', '{', '}', '!', '"',
    '\'',
];

/// Validate the requested render format. Returns the `wc` flag for an allowlisted format, or an
/// error explaining the rejection. The returned flag is a fixed `&'static str`, never user input.
pub fn validate_format(format: &str) -> Result<&'static str, String> {
    if let Some(c) = format.chars().find(|c| SHELL_METACHARACTERS.contains(c)) {
        return Err(format!(
            "format contains forbidden shell metacharacter {c:?}"
        ));
    }
    match format {
        "words" => Ok("-w"),
        "lines" => Ok("-l"),
        "chars" => Ok("-c"),
        other => Err(format!(
            "unknown format {other:?} (allowed: words, lines, chars)"
        )),
    }
}

/// Run `wc <flag>` on `content` via argv (no shell); content is piped to stdin.
pub async fn render(content: &str, flag: &str) -> Result<String> {
    let mut child = Command::new("wc")
        .arg(flag)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    // Write the content, then drop stdin to signal EOF (content is small, so no deadlock).
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        bail!("wc exited with status {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
