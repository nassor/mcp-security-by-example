//! Credential/secret detection and redaction (OWASP MCP01: secret exposure).
//!
//! `redact` scans text for common secret shapes and replaces each with `[REDACTED:<kind>]`, so
//! secrets never leak through tool outputs. `sanitize_error` reuses it to strip credentials
//! (e.g. a Postgres connection string) out of error messages before they reach the client.
//!
//! Regex detection is illustrative, not exhaustive — it has false negatives and positives.

use std::sync::LazyLock;

use regex::Regex;

use super::Finding;

struct SecretPattern {
    kind: &'static str,
    re: Regex,
}

static PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    let p = |kind, pat: &str| SecretPattern {
        kind,
        re: Regex::new(pat).expect("valid secret regex"),
    };
    vec![
        // DB connection string with embedded credentials: postgres://user:pass@host/db
        p(
            "connection_string",
            r"(?i)(?:postgres|postgresql|mysql|mongodb)(?:\+srv)?://[^:\s/@]+:[^@\s]+@\S+",
        ),
        // AWS long-term access key id.
        p("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        // JSON Web Token (three base64url segments).
        p("jwt", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        // Bearer token in an Authorization-style string.
        p("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._~+/-]{8,}=*"),
        // PEM private key header.
        p("private_key", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ]
});

/// Replace any secret-looking substrings with `[REDACTED:<kind>]`, returning the redacted text
/// and one [`Finding`] per redaction.
pub fn redact(text: &str) -> (String, Vec<Finding>) {
    let mut out = text.to_string();
    let mut findings = Vec::new();
    for pattern in PATTERNS.iter() {
        let count = pattern.re.find_iter(&out).count();
        if count == 0 {
            continue;
        }
        for _ in 0..count {
            findings.push(Finding::new("secret", format!("redacted {}", pattern.kind)));
        }
        let replacement = format!("[REDACTED:{}]", pattern.kind);
        out = pattern
            .re
            .replace_all(&out, replacement.as_str())
            .into_owned();
    }
    (out, findings)
}

/// Sanitize an error message so secrets (notably DB connection strings) never reach the client.
pub fn sanitize_error(message: &str) -> String {
    redact(message).0
}
