//! Indirect prompt-injection neutralization for untrusted tool output (OWASP LLM01).
//!
//! A document's content is *data*, but an attacker can stuff instructions into it ("ignore
//! previous instructions…") hoping a downstream LLM will obey. `neutralize` always wraps the
//! content in clear `<untrusted_content>` delimiters (spotlighting) so a model treats it as data,
//! and flags known injection signatures so the caller is warned.
//!
//! Signature detection is illustrative, not exhaustive.

use std::sync::LazyLock;

use regex::Regex;

use super::Finding;

static SIGNATURES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let r = |kind, pat: &str| (kind, Regex::new(pat).expect("valid injection regex"));
    vec![
        r(
            "ignore-previous-instructions",
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        ),
        r(
            "disregard-above",
            r"(?i)disregard\s+(?:all\s+|everything\s+)?(?:above|previous|prior)",
        ),
        r("role-override", r"(?i)you\s+are\s+now\b"),
        r(
            "fake-system-role",
            r"(?im)\[(?:system|admin|root)\]|^\s*system\s*:",
        ),
        r("new-instructions", r"(?i)new\s+instructions\s*:"),
        r(
            "data-exfiltration",
            r"(?i)(?:reveal|exfiltrate|leak|send|email)\b[^\n]{0,40}\b(?:password|secret|api[\s_-]?key|token|database|credential)",
        ),
    ]
});

/// Wrap untrusted `content` in delimiters tagged with its `source`, and return a [`Finding`] per
/// detected injection signature. The content is preserved as data, never executed.
pub fn neutralize(source: &str, content: &str) -> (String, Vec<Finding>) {
    let mut findings = Vec::new();
    for (kind, re) in SIGNATURES.iter() {
        if re.is_match(content) {
            findings.push(Finding::new("prompt_injection", *kind));
        }
    }
    let wrapped = format!("<untrusted_content source={source:?}>\n{content}\n</untrusted_content>");
    (wrapped, findings)
}
