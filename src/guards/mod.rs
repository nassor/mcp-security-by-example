//! Security guards: input validation and output sanitization used as pipeline stages.
//!
//! Each guard is a small, independently testable function. They run *regardless* of casbin
//! authorization — authorization decides "may you", the guards decide "is this safe".
//!
//! - [`command`] — OS command-injection protection (CWE-78): allowlist + safe argv exec.
//! - [`secrets`] — credential/secret redaction and error sanitization.
//! - [`prompt_injection`] — neutralize indirect prompt injection in untrusted output.

pub mod command;
pub mod prompt_injection;
pub mod secrets;
pub mod ssrf;

/// One thing a guard noticed: a redacted secret, a flagged injection signature, or a blocked
/// command argument. Carried in the pipeline outcome for auditing and the report.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: &'static str,
    pub detail: String,
}

impl Finding {
    pub fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}
