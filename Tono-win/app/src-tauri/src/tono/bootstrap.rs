//! Pinned bootstrap addresses for the Tono control plane (F1).
//!
//! Source: `Tono/Info.plist` key `TonoAPIBootstrapAddresses` in the macOS
//! client (build 26+). The macOS incident that motivated them: with the
//! kill switch fully blocking, the API hostname could no longer be
//! resolved through system DNS, so the client could never arm or reconnect
//! — a control-plane self-lockout. Both the app's API client (DNS pinning
//! at the HTTP layer) and the Service's WFP bootstrap permit
//! (`bootstrap_api_hosts`) therefore carry literal IPs and depend on no
//! resolver while blocked.
//!
//! The addresses are Cloudflare anycast ranges for `api.afk.ccwu.cc`;
//! TLS/SNI still validates the *hostname*, so pinning changes only where
//! the TCP connection lands — a compromised resolver can no longer reroute
//! the control plane, and an attacker cannot forge Cloudflare's
//! certificate for the domain. They must be re-verified against the
//! macOS plist whenever it changes (check on every macOS release bump).

use std::net::Ipv4Addr;

/// Pinned bootstrap IPs for `api.afk.ccwu.cc` (see module docs; keep in
/// sync with `Tono/Info.plist` `TonoAPIBootstrapAddresses`).
pub const API_BOOTSTRAP_IPS: [&str; 2] = ["104.20.26.170", "172.66.162.98"];

/// The API hostname these pins stand in for.
pub const API_HOST: &str = "api.afk.ccwu.cc";

/// Hard cap for `bootstrap_api_hosts` on the wire (F1).
pub const MAX_BOOTSTRAP_HOSTS: usize = 8;

/// The pinned addresses, parsed once and validated as public IPv4
/// literals with the same admission predicate the catalog uses (§4).
pub fn pinned_bootstrap_ips() -> Vec<Ipv4Addr> {
    API_BOOTSTRAP_IPS
        .iter()
        .filter_map(|text| text.parse::<Ipv4Addr>().ok())
        .filter(|addr| tono_core::node::is_public_ipv4(*addr))
        .collect()
}

/// Merge the pinned IPs with dynamically resolved ones for
/// `StartClashRequest.bootstrap_api_hosts`: public-literal only, first
/// occurrence wins, capped at [`MAX_BOOTSTRAP_HOSTS`]. The pinned IPs come
/// first — they are the recovery path that must survive a poisoned DNS.
pub fn merge_bootstrap_hosts(dynamic: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut push = |host: String| {
        if hosts.len() < MAX_BOOTSTRAP_HOSTS && !hosts.contains(&host) {
            hosts.push(host);
        }
    };
    for addr in pinned_bootstrap_ips() {
        push(addr.to_string());
    }
    for host in dynamic {
        if let Ok(addr) = host.parse::<Ipv4Addr>()
            && tono_core::node::is_public_ipv4(addr)
        {
            push(addr.to_string());
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::{API_BOOTSTRAP_IPS, MAX_BOOTSTRAP_HOSTS, merge_bootstrap_hosts, pinned_bootstrap_ips};

    #[test]
    fn pinned_ips_are_public_ipv4_literals() {
        let ips = pinned_bootstrap_ips();
        assert_eq!(
            ips.len(),
            API_BOOTSTRAP_IPS.len(),
            "every pinned entry must parse as public IPv4"
        );
        assert_eq!(ips[0].to_string(), "104.20.26.170");
        assert_eq!(ips[1].to_string(), "172.66.162.98");
    }

    #[test]
    fn merge_dedupes_and_keeps_pins_first() {
        let dynamic = vec![
            "172.66.162.98".to_string(), // duplicate of a pin
            "1.1.1.1".to_string(),
            "104.20.26.170".to_string(), // duplicate of a pin
        ];
        let merged = merge_bootstrap_hosts(&dynamic);
        assert_eq!(merged, vec!["104.20.26.170", "172.66.162.98", "1.1.1.1"]);
    }

    #[test]
    fn merge_drops_non_public_and_malformed_entries() {
        let dynamic = vec![
            "10.0.0.8".to_string(),   // private
            "198.18.0.1".to_string(), // fake-ip range, reserved
            "not-an-ip".to_string(),  // garbage
            "8.8.8.8".to_string(),
        ];
        let merged = merge_bootstrap_hosts(&dynamic);
        assert_eq!(merged, vec!["104.20.26.170", "172.66.162.98", "8.8.8.8"]);
    }

    #[test]
    fn merge_caps_at_eight_hosts() {
        let dynamic: Vec<String> = (1..=16).map(|last| format!("9.0.0.{last}")).collect();
        let merged = merge_bootstrap_hosts(&dynamic);
        assert_eq!(merged.len(), MAX_BOOTSTRAP_HOSTS);
        assert_eq!(merged[0], "104.20.26.170");
        assert_eq!(merged[1], "172.66.162.98");
    }
}
