//! Cloud traffic policy (WeChat DIRECT) — wire models, validation, revision
//! tracking, and the verified on-disk cache (product-contract.md §3 parity,
//! Mac `ManagedTrafficPolicyProcessor` parity).
//!
//! Trust model: the policy is server-managed but untrusted input. Everything
//! is validated before install — digest, shape, size, domain suffix
//! whitelist (strict label boundaries), public-IP admission, and port
//! allowlists — and a failing download never replaces the last verified
//! copy. Revision monotonicity matches the exit catalog's: strictly newer
//! installs, same-revision same-digest is idempotent, same-revision
//! different-digest is invalid, older is a benign no-op.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::catalog::{CacheSafetyCheck, catalog_digest};
use crate::node::is_public_ipv4;

/// Maximum accepted policy JSON size (Mac parity: 64 KiB).
pub const MAX_POLICY_JSON_BYTES: usize = 64 * 1024;
/// Maximum accepted on-disk cache size.
pub const MAX_POLICY_CACHE_BYTES: u64 = 256 * 1024;
/// Cache file name inside the Tono data dir.
pub const POLICY_CACHE_FILE_NAME: &str = "managed-traffic-policy.json";
pub const POLICY_VERSION_V1: u32 = 1;
pub const POLICY_VERSION_V2: u32 = 2;
/// Limits shared with the Mac validator.
pub const MAX_POLICY_DOMAINS: usize = 32;
pub const MAX_POLICY_MEDIA: usize = 64;
pub const MAX_POLICY_WEB_DOMAINS: usize = 16;

pub const ALLOWED_WEB_DOMAIN_SUFFIXES: [&str; 13] = [
    "bilibili.com",
    "biliapi.net",
    "bilivideo.com",
    "hdslb.com",
    "qq.com",
    "gtimg.cn",
    "gtimg.com",
    "iqiyi.com",
    "qiyi.com",
    "qiyipic.com",
    "iqiyipic.com",
    "youku.com",
    "ykimg.com",
];

/// Domain suffixes allowed for DIRECT routing (Mac
/// `validatedManagedDirectDomain` parity). A host must equal a suffix or be
/// a subdomain of it — strict DNS label boundaries, so `evil-qq.com` and
/// `qq.com.evil.com` never qualify.
pub const ALLOWED_DOMAIN_SUFFIXES: [&str; 10] = [
    "qq.com",
    "qq.com.cn",
    "qpic.cn",
    "qlogo.cn",
    "gtimg.cn",
    "gtimg.com",
    "wechat.com",
    "weixin.com",
    "weixinbridge.com",
    "wxs.qq.com",
];

/// Addresses that may never receive a DIRECT permit (the pinned DoH
/// resolvers ride the tunnel by contract).
pub fn is_permanently_protected(address: Ipv4Addr) -> bool {
    address == Ipv4Addr::new(1, 1, 1, 1) || address == Ipv4Addr::new(8, 8, 8, 8)
}

/// Wire shape of `GET traffic-policy` (digest semantics identical to the
/// exit catalog: SHA-256 of the JSON's UTF-8 bytes, base64url, no padding).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TonoTrafficPolicyResponse {
    pub revision: i64,
    pub json: String,
    pub sha256: String,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

/// The validated policy document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TonoTrafficPolicy {
    pub version: u32,
    #[serde(default)]
    pub domains: Vec<PolicyDomain>,
    #[serde(rename = "mediaEndpoints", default)]
    pub media_endpoints: Vec<PolicyMedia>,
    #[serde(rename = "webDomains", default)]
    pub web_domains: Vec<PolicyDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDomain {
    pub host: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMedia {
    pub address: String,
    pub ports: Vec<u16>,
}

/// Why a policy document (or its cache) was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Any contract violation that maps to the API client's
    /// `invalidResponse` (digest, size, shape, version, limits).
    #[error("traffic policy response is invalid")]
    InvalidResponse,
    /// Revision lower than the installed one: benign out-of-order delivery,
    /// never an error and never counted toward retries (catalog L5 parity).
    #[error("traffic policy revision regressed")]
    StaleRevision,
    /// A domain failed the suffix whitelist.
    #[error("managed direct domain rejected: {0}")]
    Domain(String),
    /// An endpoint address failed admission (not public IPv4, or protected).
    #[error("managed endpoint address rejected: {0}")]
    Address(String),
    #[error("policy cache I/O failed: {0}")]
    Io(String),
}

/// Strict label-boundary suffix test (`host == suffix || host` ends with
/// `.suffix`), after light normalization (trim, lowercase, strip one
/// trailing dot).
pub fn is_allowed_direct_domain(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.is_empty()
        || host.len() > 253
        || host.bytes().any(|byte| !(0x21..=0x7E).contains(&byte))
    {
        return false;
    }
    ALLOWED_DOMAIN_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// Exact-web hosts use a separate, deliberately narrow suffix allowlist.
pub fn is_allowed_web_domain(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host != host.trim()
        || host.ends_with('.')
        || host.split('.').count() < 2
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return false;
    }
    if matches!(
        host,
        "anthropic.com" | "claude.ai" | "tono.app" | "tono.com"
    ) || ["anthropic.com", "claude.ai", "tono.app", "tono.com"]
        .iter()
        .any(|s| host.ends_with(&format!(".{s}")))
    {
        return false;
    }
    host == "ykimg.alicdn.com"
        || ALLOWED_WEB_DOMAIN_SUFFIXES
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn sorted_unique_ports(ports: &[u16], allowed: [u16; 2]) -> Option<Vec<u16>> {
    if ports.is_empty() {
        return None;
    }
    let mut unique: Vec<u16> = ports.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != ports.len() || !unique.iter().all(|port| allowed.contains(port)) {
        return None;
    }
    Some(unique)
}

/// Full document validation (Mac `validate` parity): envelope checks, then
/// per-entry admission. `protected` carries the currently protected
/// addresses (the selected node's IP at sync time); media endpoints must
/// also avoid the permanently protected resolvers.
pub fn validate_policy(
    response: &TonoTrafficPolicyResponse,
    protected: &BTreeSet<Ipv4Addr>,
) -> Result<TonoTrafficPolicy, PolicyError> {
    if response.revision < 0 || response.json.len() > MAX_POLICY_JSON_BYTES {
        return Err(PolicyError::InvalidResponse);
    }
    if response.sha256 != catalog_digest(&response.json) {
        return Err(PolicyError::InvalidResponse);
    }
    let shape: serde_json::Value =
        serde_json::from_str(&response.json).map_err(|_| PolicyError::InvalidResponse)?;
    let object = shape.as_object().ok_or(PolicyError::InvalidResponse)?;
    let version = object
        .get("version")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(PolicyError::InvalidResponse)?;
    let expected: BTreeSet<&str> = if version == POLICY_VERSION_V1 {
        ["version", "domains", "mediaEndpoints"]
            .into_iter()
            .collect()
    } else if version == POLICY_VERSION_V2 {
        ["version", "domains", "mediaEndpoints", "webDomains"]
            .into_iter()
            .collect()
    } else {
        return Err(PolicyError::InvalidResponse);
    };
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(PolicyError::InvalidResponse);
    }
    let document: TonoTrafficPolicy =
        serde_json::from_str(&response.json).map_err(|_| PolicyError::InvalidResponse)?;
    if document.domains.len() > MAX_POLICY_DOMAINS
        || document.media_endpoints.len() > MAX_POLICY_MEDIA
        || document.web_domains.len() > MAX_POLICY_WEB_DOMAINS
    {
        return Err(PolicyError::InvalidResponse);
    }

    let mut domains: Vec<PolicyDomain> = Vec::with_capacity(document.domains.len());
    for entry in &document.domains {
        // Mac parity: the entry must already be in canonical form
        // (lowercase, no trailing dot) — normalization is not repair.
        let normalized = entry.host.trim().to_lowercase();
        let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
        if normalized != entry.host {
            return Err(PolicyError::InvalidResponse);
        }
        if !is_allowed_direct_domain(&entry.host) {
            return Err(PolicyError::Domain(entry.host.clone()));
        }
        let ports =
            sorted_unique_ports(&entry.ports, [80, 443]).ok_or(PolicyError::InvalidResponse)?;
        domains.push(PolicyDomain {
            host: normalized.to_string(),
            ports,
        });
    }
    domains.sort_by(|left, right| left.host.cmp(&right.host));
    let before = domains.len();
    domains.dedup_by(|left, right| left.host == right.host);
    if domains.len() != before {
        return Err(PolicyError::InvalidResponse);
    }

    let mut web_domains = Vec::with_capacity(document.web_domains.len());
    for entry in &document.web_domains {
        if !is_allowed_web_domain(&entry.host) || entry.ports != [443] {
            return Err(PolicyError::InvalidResponse);
        }
        if domains.iter().any(|domain| domain.host == entry.host) {
            return Err(PolicyError::InvalidResponse);
        }
        web_domains.push(entry.clone());
    }
    web_domains.sort_by(|a, b| a.host.cmp(&b.host));
    let before = web_domains.len();
    web_domains.dedup_by(|a, b| a.host == b.host);
    if web_domains.len() != before {
        return Err(PolicyError::InvalidResponse);
    }

    let mut media: Vec<PolicyMedia> = Vec::with_capacity(document.media_endpoints.len());
    for entry in &document.media_endpoints {
        let address: Ipv4Addr = entry
            .address
            .parse()
            .map_err(|_| PolicyError::Address(entry.address.clone()))?;
        if !is_public_ipv4(address)
            || is_permanently_protected(address)
            || protected.contains(&address)
        {
            return Err(PolicyError::Address(entry.address.clone()));
        }
        let ports =
            sorted_unique_ports(&entry.ports, [443, 8000]).ok_or(PolicyError::InvalidResponse)?;
        media.push(PolicyMedia {
            address: address.to_string(),
            ports,
        });
    }
    media.sort_by(|left, right| left.address.cmp(&right.address));
    let before = media.len();
    media.dedup_by(|left, right| left.address == right.address);
    if media.len() != before {
        return Err(PolicyError::InvalidResponse);
    }

    Ok(TonoTrafficPolicy {
        version,
        domains,
        media_endpoints: media,
        web_domains,
    })
}

/// Result of a [`PolicyTracker::install`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyInstallOutcome {
    /// Newer revision: validated policy, ready to swap in.
    Installed(TonoTrafficPolicy),
    /// Same revision and digest: idempotent accept.
    Unchanged,
}

/// Revision monotonicity for the traffic policy (catalog tracker parity).
/// The monotonicity check runs after full validation, inside `install`, so
/// concurrently reordered downloads cannot regress the committed revision.
#[derive(Debug, Clone)]
pub struct PolicyTracker {
    current_revision: i64,
    current_digest: Option<String>,
}

impl Default for PolicyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyTracker {
    /// Nothing installed yet: any non-negative revision is newer.
    pub fn new() -> Self {
        Self {
            current_revision: -1,
            current_digest: None,
        }
    }

    /// Seed from a previously verified cache so a download can never roll
    /// back across restarts.
    pub fn from_installed(revision: i64, digest: String) -> Self {
        Self {
            current_revision: revision,
            current_digest: Some(digest),
        }
    }

    pub fn current_revision(&self) -> i64 {
        self.current_revision
    }

    pub fn current_digest(&self) -> Option<&str> {
        self.current_digest.as_deref()
    }

    /// Validate `response` and commit it if its revision is strictly newer.
    /// Equal revision with a different digest is invalid; equal revision
    /// with the same digest is an idempotent no-op; older is benign.
    pub fn install(
        &mut self,
        response: &TonoTrafficPolicyResponse,
        protected: &BTreeSet<Ipv4Addr>,
    ) -> Result<PolicyInstallOutcome, PolicyError> {
        let policy = validate_policy(response, protected)?;
        if response.revision < self.current_revision {
            return Err(PolicyError::StaleRevision);
        }
        if response.revision == self.current_revision {
            return if self.current_digest.as_deref() == Some(response.sha256.as_str()) {
                Ok(PolicyInstallOutcome::Unchanged)
            } else {
                Err(PolicyError::InvalidResponse)
            };
        }
        self.current_revision = response.revision;
        self.current_digest = Some(response.sha256.clone());
        Ok(PolicyInstallOutcome::Installed(policy))
    }
}

/// A cache entry that survived safety checks and full re-validation.
#[derive(Debug, Clone)]
pub struct CachedPolicy {
    pub response: TonoTrafficPolicyResponse,
    pub policy: TonoTrafficPolicy,
}

/// On-disk policy cache (`managed-traffic-policy.json`). Only fully
/// verified documents are ever written; writes are atomic (temp file +
/// rename), and every read re-runs safety checks and re-validation.
pub struct PolicyCache {
    path: PathBuf,
    safety: Box<dyn CacheSafetyCheck>,
}

impl PolicyCache {
    pub fn new(dir: &Path, safety: Box<dyn CacheSafetyCheck>) -> Self {
        Self {
            path: dir.join(POLICY_CACHE_FILE_NAME),
            safety,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load and re-validate the cached policy. Any safety or validation
    /// failure yields `None` — a corrupt cache is treated as absent.
    pub fn load(&self, protected: &BTreeSet<Ipv4Addr>) -> Option<CachedPolicy> {
        self.safety.check_path(&self.path).ok()?;
        let mut file = fs::File::open(&self.path).ok()?;
        self.safety.check_open(&file).ok()?;
        let mut body = String::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_POLICY_CACHE_BYTES + 1)
            .read_to_string(&mut body)
            .ok()?;
        let response: TonoTrafficPolicyResponse = serde_json::from_str(&body).ok()?;
        let policy = validate_policy(&response, protected).ok()?;
        Some(CachedPolicy { response, policy })
    }

    /// Atomically persist a policy. Re-validates before writing so the
    /// "only verified copies reach disk" invariant holds by construction.
    pub fn store(
        &self,
        response: &TonoTrafficPolicyResponse,
        protected: &BTreeSet<Ipv4Addr>,
    ) -> Result<(), PolicyError> {
        validate_policy(response, protected)?;
        let body =
            serde_json::to_string(response).map_err(|err| PolicyError::Io(err.to_string()))?;
        if body.len() as u64 > MAX_POLICY_CACHE_BYTES {
            return Err(PolicyError::Io(
                "serialized policy exceeds the cache limit".to_string(),
            ));
        }
        let dir = self
            .path
            .parent()
            .ok_or_else(|| PolicyError::Io("cache path has no parent".to_string()))?;
        fs::create_dir_all(dir).map_err(|err| PolicyError::Io(err.to_string()))?;
        let temp = dir.join(format!(
            ".{POLICY_CACHE_FILE_NAME}.tmp-{}",
            std::process::id()
        ));
        let write_result = (|| -> Result<(), PolicyError> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|err| PolicyError::Io(err.to_string()))?;
            file.write_all(body.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|err| PolicyError::Io(err.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
                    .map_err(|err| PolicyError::Io(err.to_string()))?;
            }
            // Give the platform policy the chance to tighten the temp file
            // (Windows DACL), symmetric with the read-side checks.
            self.safety
                .secure_written_file(&temp)
                .map_err(|err| PolicyError::Io(err.to_string()))?;
            fs::rename(&temp, &self.path).map_err(|err| PolicyError::Io(err.to_string()))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        write_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::catalog_digest;

    fn policy_json(domains: &str, media: &str) -> String {
        format!(r#"{{"version":1,"domains":[{domains}],"mediaEndpoints":[{media}]}}"#)
    }

    fn response(revision: i64, json: &str) -> TonoTrafficPolicyResponse {
        TonoTrafficPolicyResponse {
            revision,
            json: json.to_string(),
            sha256: catalog_digest(json),
            updated_at: None,
        }
    }

    fn no_protected() -> BTreeSet<Ipv4Addr> {
        BTreeSet::new()
    }

    fn good_document() -> String {
        policy_json(
            r#"{"host":"wxs.qq.com","ports":[80,443]},{"host":"qpic.cn","ports":[443]}"#,
            r#"{"address":"9.0.0.9","ports":[443,8000]}"#,
        )
    }

    #[test]
    fn digest_shape_matches_catalog_algorithm() {
        let digest = catalog_digest("");
        assert_eq!(digest.len(), 43);
        assert!(!digest.contains(['=', '+', '/']));
    }

    #[test]
    fn domain_suffix_boundaries_are_strict() {
        for good in [
            "qq.com",
            "wxs.qq.com",
            "a.qpic.cn",
            "cdn.a.gtimg.com",
            "Qpic.CN.",
            "a.b.wxs.qq.com",
        ] {
            assert!(is_allowed_direct_domain(good), "{good}");
        }
        for bad in [
            "evil-qq.com",
            "qq.com.evil.com",
            "qq.com.cn.evil.com",
            "notqq.com",
            "qq.co",
            "",
            "qq .com",
            "q q.com",
        ] {
            assert!(!is_allowed_direct_domain(bad), "{bad}");
        }
    }

    #[test]
    fn document_hosts_must_be_canonical() {
        // The predicate normalizes ("Qpic.CN." is an allowed *domain*), but
        // a document entry must already be canonical (Mac `host == entry.host`).
        assert!(is_allowed_direct_domain("Qpic.CN."));
        for host in ["Qpic.CN", "qpic.cn.", " qpic.cn"] {
            let doc = policy_json(&format!(r#"{{"host":"{host}","ports":[443]}}"#), "");
            assert_eq!(
                validate_policy(&response(0, &doc), &no_protected()),
                Err(PolicyError::InvalidResponse),
                "{host}"
            );
        }
    }

    #[test]
    fn accepts_valid_document_and_normalizes() {
        let policy = validate_policy(&response(3, &good_document()), &no_protected()).unwrap();
        assert_eq!(policy.version, 1);
        // Sorted by host; ports sorted.
        assert_eq!(policy.domains[0].host, "qpic.cn");
        assert_eq!(policy.domains[0].ports, vec![443]);
        assert_eq!(policy.domains[1].host, "wxs.qq.com");
        assert_eq!(policy.domains[1].ports, vec![80, 443]);
        assert_eq!(policy.media_endpoints[0].address, "9.0.0.9");
        assert_eq!(policy.media_endpoints[0].ports, vec![443, 8000]);
        assert!(
            policy.web_domains.is_empty(),
            "old v1 decodes with no web list"
        );
    }

    #[test]
    fn accepts_v2_exact_web_and_rejects_v1_web() {
        let v2 = r#"{"version":2,"domains":[],"mediaEndpoints":[],"webDomains":[{"host":"video.bilibili.com","ports":[443]},{"host":"ykimg.alicdn.com","ports":[443]}]}"#;
        let policy = validate_policy(&response(1, v2), &no_protected()).unwrap();
        assert_eq!(policy.version, 2);
        assert_eq!(policy.web_domains.len(), 2);
        let v1_web = v2.replace("\"version\":2", "\"version\":1");
        assert_eq!(
            validate_policy(&response(1, &v1_web), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
    }

    #[test]
    fn web_boundaries_fail_closed() {
        for host in [
            "Claude.ai",
            "claude.ai",
            "x.claude.ai",
            "anthropic.com",
            "tono.app",
            "evilbilibili.com",
        ] {
            let doc = format!(
                r#"{{"version":2,"domains":[],"mediaEndpoints":[],"webDomains":[{{"host":"{host}","ports":[443]}}]}}"#
            );
            assert_eq!(
                validate_policy(&response(1, &doc), &no_protected()),
                Err(PolicyError::InvalidResponse),
                "{host}"
            );
        }
        for ports in ["[]", "[80]", "[443,443]"] {
            let doc = format!(
                r#"{{"version":2,"domains":[],"mediaEndpoints":[],"webDomains":[{{"host":"bilibili.com","ports":{ports}}}]}}"#
            );
            assert_eq!(
                validate_policy(&response(1, &doc), &no_protected()),
                Err(PolicyError::InvalidResponse)
            );
        }
        let duplicate = r#"{"version":2,"domains":[{"host":"qq.com","ports":[443]}],"mediaEndpoints":[],"webDomains":[{"host":"qq.com","ports":[443]}]}"#;
        assert_eq!(
            validate_policy(&response(1, duplicate), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_domain_port_violations() {
        for ports in ["[80,80]", "[8080]", "[]", "[443,8000]"] {
            let doc = policy_json(&format!(r#"{{"host":"qq.com","ports":{ports}}}"#), "");
            assert_eq!(
                validate_policy(&response(0, &doc), &no_protected()),
                Err(PolicyError::InvalidResponse),
                "{ports}"
            );
        }
    }

    #[test]
    fn rejects_media_port_and_duplicate_violations() {
        for ports in ["[443,443]", "[80]", "[]"] {
            let doc = policy_json("", &format!(r#"{{"address":"9.0.0.9","ports":{ports}}}"#));
            assert_eq!(
                validate_policy(&response(0, &doc), &no_protected()),
                Err(PolicyError::InvalidResponse),
                "{ports}"
            );
        }
        let dup_domain = policy_json(
            r#"{"host":"qq.com","ports":[80]},{"host":"QQ.com","ports":[80]}"#,
            "",
        );
        assert_eq!(
            validate_policy(&response(0, &dup_domain), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_disallowed_and_protected_addresses() {
        for address in ["10.0.0.1", "198.18.0.1", "1.1.1.1", "8.8.8.8", "not-an-ip"] {
            let doc = policy_json("", &format!(r#"{{"address":"{address}","ports":[443]}}"#));
            assert!(
                matches!(
                    validate_policy(&response(0, &doc), &no_protected()),
                    Err(PolicyError::Address(_)) | Err(PolicyError::InvalidResponse),
                ),
                "{address}"
            );
        }
        // The selected node's IP is protected at sync time.
        let mut protected = BTreeSet::new();
        protected.insert(Ipv4Addr::new(9, 0, 0, 7));
        let doc = policy_json("", r#"{"address":"9.0.0.7","ports":[443]}"#);
        assert_eq!(
            validate_policy(&response(0, &doc), &protected),
            Err(PolicyError::Address("9.0.0.7".to_string()))
        );
    }

    #[test]
    fn rejects_envelope_violations() {
        // Negative revision.
        assert_eq!(
            validate_policy(&response(-1, &good_document()), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
        // Tampered digest.
        let mut tampered = response(1, &good_document());
        tampered.sha256 = catalog_digest("forged");
        assert_eq!(
            validate_policy(&tampered, &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
        // Wrong version.
        let wrong_version = policy_json("", "").replace(r#""version":1"#, r#""version":2"#);
        assert_eq!(
            validate_policy(&response(1, &wrong_version), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
        // Oversize JSON.
        let big = format!("{}//{}", good_document(), "x".repeat(MAX_POLICY_JSON_BYTES));
        assert_eq!(
            validate_policy(&response(1, &big), &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
    }

    #[test]
    fn tracker_enforces_revision_monotonicity() {
        let mut tracker = PolicyTracker::new();
        let outcome = tracker
            .install(&response(5, &good_document()), &no_protected())
            .unwrap();
        assert!(matches!(outcome, PolicyInstallOutcome::Installed(_)));
        assert_eq!(tracker.current_revision(), 5);
        // Same revision + digest: idempotent.
        assert_eq!(
            tracker
                .install(&response(5, &good_document()), &no_protected())
                .unwrap(),
            PolicyInstallOutcome::Unchanged
        );
        // Older: benign stale.
        assert_eq!(
            tracker.install(&response(4, &good_document()), &no_protected()),
            Err(PolicyError::StaleRevision)
        );
        // Same revision, different digest: invalid.
        let conflicting = response(5, &policy_json(r#"{"host":"qpic.cn","ports":[443]}"#, ""));
        assert_eq!(
            tracker.install(&conflicting, &no_protected()),
            Err(PolicyError::InvalidResponse)
        );
        assert_eq!(tracker.current_revision(), 5);
        // Newer installs.
        let newer = policy_json(
            r#"{"host":"qq.com","ports":[80,443]},{"host":"qpic.cn","ports":[443]}"#,
            "",
        );
        assert!(matches!(
            tracker
                .install(&response(6, &newer), &no_protected())
                .unwrap(),
            PolicyInstallOutcome::Installed(_)
        ));
        assert_eq!(tracker.current_revision(), 6);
        // Seeded tracker keeps monotonicity across restarts.
        let mut seeded = PolicyTracker::from_installed(6, response(6, &newer).sha256);
        assert_eq!(
            seeded.install(&response(5, &good_document()), &no_protected()),
            Err(PolicyError::StaleRevision)
        );
    }
}
