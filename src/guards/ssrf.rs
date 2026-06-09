//! Server-Side Request Forgery (SSRF) protection for URL-fetching tools.
//!
//! `validate_url` requires HTTPS and rejects URLs whose host is a private, loopback, link-local
//! (including the cloud-metadata endpoint `169.254.169.254`), or otherwise internal address.
//!
//! Per the MCP guidance, IP classification uses the standard library rather than hand-rolled
//! parsing (which misses octal/hex/IPv4-mapped tricks). NOTE: a real fetcher must *also* pin DNS
//! between this check and the request to defeat rebinding (TOCTOU); hostnames are allowed here
//! with that caveat, since resolving them would require network access.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

/// Validate that a URL is safe to fetch. Returns `Err(reason)` if it should be blocked.
pub fn validate_url(raw: &str) -> Result<(), String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid url: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!(
            "scheme {:?} not allowed (https required)",
            url.scheme()
        ));
    }
    match url.host() {
        Some(Host::Ipv4(ip)) if is_blocked_v4(ip) => {
            Err(format!("blocked internal/reserved address {ip}"))
        }
        Some(Host::Ipv6(ip)) => {
            if let Some(v4) = ip.to_ipv4_mapped()
                && is_blocked_v4(v4)
            {
                return Err(format!("blocked internal/reserved address {ip}"));
            }
            if is_blocked_v6(ip) {
                Err(format!("blocked internal/reserved address {ip}"))
            } else {
                Ok(())
            }
        }
        Some(Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            Err("blocked host localhost".into())
        }
        Some(_) => Ok(()),
        None => Err("url has no host".into()),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254.0.0/16, includes the 169.254.169.254 metadata endpoint
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.octets()[0] == 0
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40) // CGNAT 100.64.0.0/10
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
}
