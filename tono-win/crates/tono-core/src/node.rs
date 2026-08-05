//! Catalog node admission contract (product-contract.md §4).
//!
//! A catalog node is usable only if every rule holds: VLESS over TLS with
//! Reality, a valid UUID, `xtls-rprx-vision` flow (when present), TCP
//! carrier (when present), no skip-cert-verify, and a public IPv4 literal
//! server. Only whitelisted fields survive into [`ValidatedNode`]; every
//! other byte of server YAML is discarded.

use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use thiserror::Error;

/// Name of the single select group in the owned runtime (§5).
pub const EXIT_GROUP_NAME: &str = "Tono-Exit";
/// Hard cap on catalog nodes (§3).
pub const MAX_CATALOG_NODES: usize = 200;
/// Only accepted `flow` value.
pub const REQUIRED_FLOW: &str = "xtls-rprx-vision";
/// Only accepted `network` value.
pub const REQUIRED_NETWORK: &str = "tcp";

/// Node names that may never come from a catalog: every group name the owned
/// runtime emits, plus Mihomo built-in policy names, so a crafted node cannot
/// hijack a rule target such as DIRECT. (Contract reserves `Tono-Exit`; the
/// built-ins are defense in depth on top of the macOS parity set.)
///
/// The two DIRECT outbound names matter as much as `Tono-Exit`: with a cloud
/// policy in force they are emitted as physical-interface-bound `proxies`
/// entries and as rule targets. Mihomo has a single proxy namespace, so a
/// catalog node sharing one of those names could steer DIRECT rules at the
/// crafted node instead of the owned outbound.
const RESERVED_NODE_NAMES: [&str; 7] = [
    "Tono-Exit",
    crate::config::DIRECT_GROUP_NAME,
    crate::config::WEB_DIRECT_GROUP_NAME,
    "DIRECT",
    "GLOBAL",
    "REJECT",
    "REJECT-DROP",
];

/// Reason a catalog node (or node set) was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeRejection {
    #[error("node entry is malformed: {0}")]
    Malformed(String),
    #[error("name is empty, over 128 bytes, or contains control characters")]
    BadName,
    #[error("type must be vless")]
    NotVless,
    #[error("tls must be enabled")]
    TlsDisabled,
    #[error("uuid is missing or not a valid UUID")]
    BadUuid,
    #[error("reality-public-key must be exactly 43 base64url characters")]
    BadRealityPublicKey,
    #[error("sni/servername is missing or not a valid host")]
    SniInvalid,
    #[error("reality-short-id must be non-empty hex with even length <= 16")]
    BadRealityShortId,
    #[error("flow must be xtls-rprx-vision")]
    UnsupportedFlow,
    #[error("network must be tcp")]
    UnsupportedNetwork,
    #[error("skip-cert-verify is not allowed")]
    SkipCertVerify,
    #[error("port must be in 1..=65535")]
    BadPort,
    #[error("server must be a public IPv4 literal")]
    ServerNotPublicIpv4,
    #[error("catalog holds more than {MAX_CATALOG_NODES} nodes")]
    TooManyNodes,
    #[error("node name is duplicated or reserved: {0}")]
    DuplicateOrReservedName(String),
}

/// A catalog node that passed admission. Whitelisted fields only (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedNode {
    pub name: String,
    /// Guaranteed public IPv4 literal.
    pub server: Ipv4Addr,
    pub port: u16,
    /// UUID as supplied (validated to parse).
    pub uuid: String,
    /// Emitted as Mihomo's `servername` key (never `sni`, which Reality
    /// silently ignores).
    pub servername: String,
    /// `xtls-rprx-vision` when supplied by the catalog; omitted otherwise
    /// (macOS parity: the contract constrains the value, not its presence).
    pub flow: Option<String>,
    pub client_fingerprint: Option<String>,
    pub reality_public_key: String,
    pub reality_short_id: String,
}

impl ValidatedNode {
    /// Re-serialize as a Mihomo `proxies:` entry (§5). `tls` and `network`
    /// are emitted as contract constants.
    pub fn to_runtime_mapping(&self) -> serde_yaml_ng::Mapping {
        use serde_yaml_ng::Value;
        let mut map = serde_yaml_ng::Mapping::new();
        let mut put = |key: &str, value: Value| {
            map.insert(Value::String(key.to_string()), value);
        };
        put("name", Value::String(self.name.clone()));
        put("type", Value::String("vless".to_string()));
        put("server", Value::String(self.server.to_string()));
        put(
            "port",
            Value::Number(serde_yaml_ng::Number::from(self.port)),
        );
        put("uuid", Value::String(self.uuid.clone()));
        put("tls", Value::Bool(true));
        put("servername", Value::String(self.servername.clone()));
        if let Some(flow) = &self.flow {
            put("flow", Value::String(flow.clone()));
        }
        if let Some(fingerprint) = &self.client_fingerprint {
            put("client-fingerprint", Value::String(fingerprint.clone()));
        }
        put("network", Value::String(REQUIRED_NETWORK.to_string()));
        let mut reality = serde_yaml_ng::Mapping::new();
        reality.insert(
            Value::String("public-key".to_string()),
            Value::String(self.reality_public_key.clone()),
        );
        reality.insert(
            Value::String("short-id".to_string()),
            Value::String(self.reality_short_id.clone()),
        );
        put("reality-opts", Value::Mapping(reality));
        map
    }
}

/// Raw shape of one catalog proxy entry. Unknown fields are tolerated here
/// and dropped by admission. `servername` is accepted as an alias of `sni`
/// because catalogs carry the Mihomo schema spelling.
#[derive(Debug, Deserialize)]
struct RawProxy {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    servername: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default, rename = "skip-cert-verify")]
    skip_cert_verify: Option<bool>,
    #[serde(default, rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    #[serde(default, rename = "reality-opts")]
    reality_opts: Option<RawRealityOpts>,
}

#[derive(Debug, Deserialize)]
struct RawRealityOpts {
    #[serde(default, rename = "public-key")]
    public_key: Option<String>,
    #[serde(default, rename = "short-id")]
    short_id: Option<String>,
}

/// Admit one YAML proxy map (product-contract.md §4). Every rejection branch
/// returns a dedicated [`NodeRejection`].
pub fn admit_node(value: &serde_yaml_ng::Value) -> Result<ValidatedNode, NodeRejection> {
    let raw: RawProxy = serde_yaml_ng::from_value(value.clone())
        .map_err(|err| NodeRejection::Malformed(err.to_string()))?;

    let name = raw.name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(is_forbidden_scalar_char) {
        return Err(NodeRejection::BadName);
    }
    if raw.kind != "vless" {
        return Err(NodeRejection::NotVless);
    }
    if raw.tls != Some(true) {
        return Err(NodeRejection::TlsDisabled);
    }
    let uuid = raw
        .uuid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(NodeRejection::BadUuid)?;
    // macOS parity: only the 36-character hyphenated form is accepted
    // (`Uuid::parse_str` alone would also allow simple/braced/urn forms).
    // The canonical lowercase form is what reaches the runtime (L6).
    let uuid = if uuid.len() == 36 {
        uuid::Uuid::parse_str(uuid)
            .map(|parsed| parsed.to_string())
            .map_err(|_| NodeRejection::BadUuid)?
    } else {
        return Err(NodeRejection::BadUuid);
    };

    let reality = raw.reality_opts.ok_or(NodeRejection::BadRealityPublicKey)?;
    let public_key = reality
        .public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(NodeRejection::BadRealityPublicKey)?;
    if public_key.len() != 43
        || !public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(NodeRejection::BadRealityPublicKey);
    }

    let servername = raw
        .servername
        .as_deref()
        .or(raw.sni.as_deref())
        .ok_or(NodeRejection::SniInvalid)?;
    let servername = normalize_sni_host(servername).ok_or(NodeRejection::SniInvalid)?;

    let short_id = reality
        .short_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(NodeRejection::BadRealityShortId)?;
    if short_id.len() > 16
        || short_id.len() % 2 != 0
        || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(NodeRejection::BadRealityShortId);
    }

    let flow = match raw.flow.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(REQUIRED_FLOW) => Some(REQUIRED_FLOW.to_string()),
        Some(_) => return Err(NodeRejection::UnsupportedFlow),
    };
    match raw.network.as_deref().map(str::trim) {
        None | Some("") => {}
        Some(network) if network.eq_ignore_ascii_case(REQUIRED_NETWORK) => {}
        Some(_) => return Err(NodeRejection::UnsupportedNetwork),
    }
    if raw.skip_cert_verify == Some(true) {
        return Err(NodeRejection::SkipCertVerify);
    }
    if raw.port == 0 {
        return Err(NodeRejection::BadPort);
    }

    let server_text = raw.server.trim();
    let server: Ipv4Addr = server_text
        .parse()
        .map_err(|_| NodeRejection::ServerNotPublicIpv4)?;
    if !is_public_ipv4(server) {
        return Err(NodeRejection::ServerNotPublicIpv4);
    }

    let client_fingerprint = match raw.client_fingerprint.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) if value.len() <= 64 && !value.chars().any(is_forbidden_scalar_char) => {
            Some(value.to_string())
        }
        Some(_) => return Err(NodeRejection::Malformed("client-fingerprint".to_string())),
    };

    Ok(ValidatedNode {
        name: name.to_string(),
        server,
        port: raw.port,
        uuid,
        servername,
        flow,
        client_fingerprint,
        reality_public_key: public_key.to_string(),
        reality_short_id: short_id.to_string(),
    })
}

/// Admit a whole catalog `proxies:` sequence and enforce the set-level rules:
/// node count cap, duplicate names, reserved names (§3/§4).
pub fn admit_nodes(values: &[serde_yaml_ng::Value]) -> Result<Vec<ValidatedNode>, NodeRejection> {
    let nodes: Vec<ValidatedNode> = values.iter().map(admit_node).collect::<Result<_, _>>()?;
    validate_node_set(&nodes)?;
    Ok(nodes)
}

/// Set-level rules shared by catalog validation and runtime generation.
pub fn validate_node_set(nodes: &[ValidatedNode]) -> Result<(), NodeRejection> {
    if nodes.len() > MAX_CATALOG_NODES {
        return Err(NodeRejection::TooManyNodes);
    }
    let mut names: HashSet<&str> = RESERVED_NODE_NAMES.iter().copied().collect();
    for node in nodes {
        if !names.insert(node.name.as_str()) {
            return Err(NodeRejection::DuplicateOrReservedName(node.name.clone()));
        }
    }
    Ok(())
}

/// SNI/servername validation mirroring the macOS `normalizedHost` exactly
/// (L7): trim, lowercase, strip surrounding dots; non-empty, <= 253 bytes,
/// no `%`, printable ASCII; IP literals accepted as-is; otherwise >= 2
/// labels of 1..=63 chars, each [a-z0-9-] and not hyphen-led/trailing.
fn normalize_sni_host(raw: &str) -> Option<String> {
    let host = raw.trim().to_lowercase();
    let host = host.trim_matches('.');
    if host.is_empty() || host.len() > 253 || host.contains('%') {
        return None;
    }
    if !host.bytes().all(|byte| (0x21..0x7F).contains(&byte)) {
        return None;
    }
    if host.parse::<Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(host.to_string());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    Some(host.to_string())
}

/// Control characters that must never reach a re-serialized scalar.
fn is_forbidden_scalar_char(ch: char) -> bool {
    (ch as u32) < 0x20 || (ch as u32) == 0x7F
}

/// Public IPv4 test (§4): rejects every private/reserved range — 0/8,
/// 10/8, 127/8, 100.64/10, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24,
/// 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, and 224/4 upwards
/// (multicast + reserved) — matching the macOS `isPublicIPv4` table, plus
/// four IETF special-registry /24s macOS misses (L8 hardening): AS112-v4
/// 192.31.196/24, AMT 192.52.193/24, 6to4 relay anycast 192.88.99/24,
/// AS112 192.175.48/24.
pub fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let b = address.octets();
    b[0] != 0
        && b[0] != 10
        && b[0] != 127
        && !(b[0] == 100 && (64..=127).contains(&b[1]))
        && !(b[0] == 169 && b[1] == 254)
        && !(b[0] == 172 && (16..=31).contains(&b[1]))
        && !(b[0] == 192 && b[1] == 0 && b[2] == 0)
        && !(b[0] == 192 && b[1] == 0 && b[2] == 2)
        && !(b[0] == 192 && b[1] == 168)
        && !(b[0] == 198 && (18..=19).contains(&b[1]))
        && !(b[0] == 198 && b[1] == 51 && b[2] == 100)
        && !(b[0] == 203 && b[1] == 0 && b[2] == 113)
        // Stricter than macOS (L8): special-registry /24s.
        && !(b[0] == 192 && b[1] == 31 && b[2] == 196)
        && !(b[0] == 192 && b[1] == 52 && b[2] == 193)
        && !(b[0] == 192 && b[1] == 88 && b[2] == 99)
        && !(b[0] == 192 && b[1] == 175 && b[2] == 48)
        && b[0] < 224
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_node_yaml() -> &'static str {
        // A fully populated, contract-compliant VLESS Reality node.
        r#"
name: "🇺🇸 US Reality 01"
type: vless
server: 203.0.113.9
port: 443
uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"
tls: true
sni: "www.microsoft.com"
flow: xtls-rprx-vision
network: tcp
client-fingerprint: chrome
reality-opts:
  public-key: "0123456789abcdef0123456789abcdef0123456789a"
  short-id: "0123456789abcdef"
"#
        // Note: the literal IP above is a documentation range; tests that
        // need a passing node use `passing_node()` below.
    }

    fn passing_node() -> serde_yaml_ng::Value {
        serde_yaml_ng::from_str(
            r#"
name: "🇺🇸 US Reality 01"
type: vless
server: 8.8.8.8
port: 443
uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"
tls: true
sni: "www.microsoft.com"
flow: xtls-rprx-vision
network: tcp
client-fingerprint: chrome
reality-opts:
  public-key: "0123456789abcdef0123456789abcdef0123456789a"
  short-id: "0123456789abcdef"
udp: true
ws-opts: { path: /ignored }
"#,
        )
        .unwrap()
    }

    fn admit_yaml(yaml: &str) -> Result<ValidatedNode, NodeRejection> {
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).unwrap();
        admit_node(&value)
    }

    fn passing_yaml() -> String {
        serde_yaml_ng::to_string(&passing_node()).unwrap()
    }

    fn passing_yaml_with(replaced: &str, replacement: &str) -> String {
        passing_yaml().replace(replaced, replacement)
    }

    #[test]
    fn accepts_fully_populated_node() {
        let node = admit_node(&passing_node()).unwrap();
        assert_eq!(node.name, "🇺🇸 US Reality 01");
        assert_eq!(node.server, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d");
        assert_eq!(node.servername, "www.microsoft.com");
        assert_eq!(node.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(node.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            node.reality_public_key,
            "0123456789abcdef0123456789abcdef0123456789a"
        );
        assert_eq!(node.reality_short_id, "0123456789abcdef");
    }

    #[test]
    fn drops_non_whitelisted_fields() {
        let node = admit_node(&passing_node()).unwrap();
        let yaml = serde_yaml_ng::to_string(&node.to_runtime_mapping()).unwrap();
        assert!(!yaml.contains("udp"));
        assert!(!yaml.contains("ws-opts"));
        let keys: Vec<String> = node
            .to_runtime_mapping()
            .keys()
            .filter_map(|key| key.as_str().map(str::to_string))
            .collect();
        for key in [
            "name",
            "type",
            "server",
            "port",
            "uuid",
            "tls",
            "servername",
            "flow",
            "client-fingerprint",
            "network",
            "reality-opts",
        ] {
            assert!(keys.contains(&key.to_string()), "missing key {key}");
        }
        assert_eq!(keys.len(), 11);
    }

    #[test]
    fn rejects_non_vless_type() {
        let err = admit_yaml(&passing_yaml_with("type: vless", "type: trojan")).unwrap_err();
        assert_eq!(err, NodeRejection::NotVless);
    }

    #[test]
    fn rejects_missing_or_disabled_tls() {
        let without_tls = passing_yaml()
            .lines()
            .filter(|line| !line.starts_with("tls:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            admit_yaml(&without_tls).unwrap_err(),
            NodeRejection::TlsDisabled
        );
        assert_eq!(
            admit_yaml(&passing_yaml_with("tls: true", "tls: false")).unwrap_err(),
            NodeRejection::TlsDisabled
        );
    }

    #[test]
    fn rejects_invalid_uuid() {
        assert_eq!(
            admit_yaml(&passing_yaml_with(
                "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d",
                "not-a-uuid"
            ))
            .unwrap_err(),
            NodeRejection::BadUuid
        );
    }

    #[test]
    fn rejects_missing_uuid() {
        let without_uuid = passing_yaml()
            .lines()
            .filter(|line| !line.starts_with("uuid:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            admit_yaml(&without_uuid).unwrap_err(),
            NodeRejection::BadUuid
        );
    }

    #[test]
    fn accepts_uppercase_uuid_and_stores_canonical_lowercase() {
        let node = admit_yaml(&passing_yaml_with(
            "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d",
            "9E107D9D-372B-4C81-8D2B-3F2D0A1B2C3D",
        ))
        .unwrap();
        assert_eq!(node.uuid, "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d");
    }

    #[test]
    fn rejects_wrong_reality_key_length() {
        for key in [
            "0123456789abcdef0123456789abcdef0123456789",   // 42
            "0123456789abcdef0123456789abcdef0123456789ab", // 44
        ] {
            assert_eq!(
                admit_yaml(&passing_yaml_with(
                    "0123456789abcdef0123456789abcdef0123456789a",
                    key
                ))
                .unwrap_err(),
                NodeRejection::BadRealityPublicKey
            );
        }
    }

    #[test]
    fn rejects_reality_key_outside_base64url_alphabet() {
        let valid = "0123456789abcdef0123456789abcdef0123456789a";
        for bad in ['+', '/', '=', ' '] {
            let mut key = valid.to_string();
            key.replace_range(10..11, &bad.to_string());
            assert_eq!(key.len(), 43);
            assert_eq!(
                admit_yaml(&passing_yaml_with(valid, &key)).unwrap_err(),
                NodeRejection::BadRealityPublicKey
            );
        }
    }

    #[test]
    fn rejects_missing_reality_opts() {
        let without_opts = passing_yaml()
            .lines()
            .filter(|line| {
                !line.starts_with("reality-opts:")
                    && !line.starts_with("  public-key:")
                    && !line.starts_with("  short-id:")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            admit_yaml(&without_opts).unwrap_err(),
            NodeRejection::BadRealityPublicKey
        );
    }

    #[test]
    fn rejects_missing_sni() {
        let without_sni = passing_yaml()
            .lines()
            .filter(|line| !line.starts_with("sni:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            admit_yaml(&without_sni).unwrap_err(),
            NodeRejection::SniInvalid
        );
    }

    #[test]
    fn accepts_servername_alias_for_sni() {
        let aliased = passing_yaml_with("sni:", "servername:");
        let node = admit_yaml(&aliased).unwrap();
        assert_eq!(node.servername, "www.microsoft.com");
    }

    /// Rebuild the passing node with a different reality-short-id.
    fn with_short_id(id: &str) -> serde_yaml_ng::Value {
        let mut mapping = passing_node().as_mapping().unwrap().clone();
        let mut reality = serde_yaml_ng::Mapping::new();
        reality.insert(
            serde_yaml_ng::Value::String("public-key".to_string()),
            serde_yaml_ng::Value::String("0123456789abcdef0123456789abcdef0123456789a".to_string()),
        );
        reality.insert(
            serde_yaml_ng::Value::String("short-id".to_string()),
            serde_yaml_ng::Value::String(id.to_string()),
        );
        mapping.insert(
            serde_yaml_ng::Value::String("reality-opts".to_string()),
            serde_yaml_ng::Value::Mapping(reality),
        );
        serde_yaml_ng::Value::Mapping(mapping)
    }

    /// Rebuild the passing node with a different display name.
    fn with_name(name: &str) -> serde_yaml_ng::Value {
        let mut mapping = passing_node().as_mapping().unwrap().clone();
        mapping.insert(
            serde_yaml_ng::Value::String("name".to_string()),
            serde_yaml_ng::Value::String(name.to_string()),
        );
        serde_yaml_ng::Value::Mapping(mapping)
    }

    #[test]
    fn rejects_bad_short_id() {
        for (label, value) in [
            ("odd length", "abc"),
            ("too long", "0123456789abcdef00"),
            ("non hex", "0123456789abcdeg"),
            ("empty", ""),
        ] {
            assert_eq!(
                admit_node(&with_short_id(value)).unwrap_err(),
                NodeRejection::BadRealityShortId,
                "{label}"
            );
        }
    }

    #[test]
    fn accepts_short_id_boundaries() {
        // Two hex chars is the shortest legal value; 16 the longest.
        for value in ["ab", "0123456789ABCDEF"] {
            assert!(admit_node(&with_short_id(value)).is_ok(), "{value}");
        }
    }

    #[test]
    fn rejects_wrong_flow() {
        assert_eq!(
            admit_yaml(&passing_yaml_with(
                "flow: xtls-rprx-vision",
                "flow: xtls-rprx-splice"
            ))
            .unwrap_err(),
            NodeRejection::UnsupportedFlow
        );
    }

    #[test]
    fn accepts_absent_flow() {
        let without_flow = passing_yaml()
            .lines()
            .filter(|line| !line.starts_with("flow:"))
            .collect::<Vec<_>>()
            .join("\n");
        let node = admit_yaml(&without_flow).unwrap();
        assert_eq!(node.flow, None);
    }

    #[test]
    fn rejects_non_tcp_network() {
        for network in ["ws", "grpc", "h2", "httpupgrade"] {
            assert_eq!(
                admit_yaml(&passing_yaml_with(
                    "network: tcp",
                    &format!("network: {network}")
                ))
                .unwrap_err(),
                NodeRejection::UnsupportedNetwork,
                "{network}"
            );
        }
    }

    #[test]
    fn normalizes_network_case_and_absence() {
        assert!(admit_yaml(&passing_yaml_with("network: tcp", "network: TCP")).is_ok());
        let without_network = passing_yaml()
            .lines()
            .filter(|line| !line.starts_with("network:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(admit_yaml(&without_network).is_ok());
    }

    #[test]
    fn rejects_skip_cert_verify_true() {
        let yaml = passing_yaml() + "skip-cert-verify: true\n";
        assert_eq!(
            admit_yaml(&yaml).unwrap_err(),
            NodeRejection::SkipCertVerify
        );
    }

    #[test]
    fn accepts_skip_cert_verify_false() {
        let yaml = passing_yaml() + "skip-cert-verify: false\n";
        assert!(admit_yaml(&yaml).is_ok());
    }

    #[test]
    fn rejects_bad_ports() {
        assert_eq!(
            admit_yaml(&passing_yaml_with("port: 443", "port: 0")).unwrap_err(),
            NodeRejection::BadPort
        );
        // 65536 does not fit u16 and surfaces as a malformed entry.
        assert!(matches!(
            admit_yaml(&passing_yaml_with("port: 443", "port: 65536")).unwrap_err(),
            NodeRejection::Malformed(_)
        ));
    }

    #[test]
    fn accepts_port_boundaries() {
        for port in [1, 65535] {
            assert!(
                admit_yaml(&passing_yaml_with("port: 443", &format!("port: {port}"))).is_ok(),
                "{port}"
            );
        }
    }

    #[test]
    fn rejects_hostname_server() {
        assert_eq!(
            admit_yaml(&passing_yaml_with(
                "server: 8.8.8.8",
                "server: exit.example.com"
            ))
            .unwrap_err(),
            NodeRejection::ServerNotPublicIpv4
        );
    }

    #[test]
    fn rejects_ipv6_server() {
        assert_eq!(
            admit_yaml(&passing_yaml_with(
                "server: 8.8.8.8",
                "server: \"2606:4700:4700::1111\""
            ))
            .unwrap_err(),
            NodeRejection::ServerNotPublicIpv4
        );
    }

    #[test]
    fn rejects_every_private_and_reserved_range() {
        let cases = [
            "0.1.2.3",         // 0/8
            "10.255.255.255",  // 10/8
            "100.64.0.1",      // 100.64/10 lower edge
            "100.127.255.254", // 100.64/10 upper edge
            "127.0.0.1",       // loopback
            "169.254.1.1",     // link-local
            "172.16.0.1",      // 172.16/12 lower edge
            "172.31.255.254",  // 172.16/12 upper edge
            "192.0.0.9",       // 192.0.0/24
            "192.0.2.1",       // documentation TEST-NET-1
            "192.168.1.1",     // 192.168/16
            "198.18.0.1",      // benchmark lower edge (also fake-ip range)
            "198.19.255.1",    // benchmark upper edge
            "198.51.100.7",    // documentation TEST-NET-2
            "203.0.113.55",    // documentation TEST-NET-3
            "224.0.0.1",       // multicast lower edge
            "239.255.255.255",
            "240.0.0.1", // 240/4 reserved
            "255.255.255.255",
        ];
        for ip in cases {
            assert_eq!(
                admit_yaml(&passing_yaml_with(
                    "server: 8.8.8.8",
                    &format!("server: {ip}")
                ))
                .unwrap_err(),
                NodeRejection::ServerNotPublicIpv4,
                "{ip}"
            );
        }
    }

    #[test]
    fn accepts_public_ips_at_range_edges() {
        for ip in [
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
        ] {
            assert!(
                admit_yaml(&passing_yaml_with(
                    "server: 8.8.8.8",
                    &format!("server: {ip}")
                ))
                .is_ok(),
                "{ip}"
            );
        }
    }

    #[test]
    fn rejects_bad_names() {
        let long_name = "x".repeat(129);
        for (label, name) in [
            ("empty", String::new()),
            ("control char", "bad\u{0007}name".to_string()),
            ("delete char", "bad\u{007F}name".to_string()),
            ("too long", long_name),
        ] {
            assert_eq!(
                admit_node(&with_name(&name)).unwrap_err(),
                NodeRejection::BadName,
                "{label}"
            );
        }
    }

    #[test]
    fn rejects_non_mapping_entry() {
        let value = serde_yaml_ng::Value::String("not a map".to_string());
        assert!(matches!(
            admit_node(&value).unwrap_err(),
            NodeRejection::Malformed(_)
        ));
    }

    #[test]
    fn set_rejects_duplicate_names() {
        let node = admit_node(&passing_node()).unwrap();
        assert_eq!(
            validate_node_set(&[node.clone(), node]).unwrap_err(),
            NodeRejection::DuplicateOrReservedName("🇺🇸 US Reality 01".to_string())
        );
    }

    #[test]
    fn set_rejects_reserved_names() {
        // Every group name the owned runtime emits must be here, not just the exit group:
        // the DIRECT groups share Mihomo's single proxy namespace whenever a cloud policy
        // is in force.
        for name in [
            "Tono-Exit",
            crate::config::DIRECT_GROUP_NAME,
            crate::config::WEB_DIRECT_GROUP_NAME,
            "DIRECT",
            "GLOBAL",
            "REJECT",
            "REJECT-DROP",
        ] {
            let mut node = admit_node(&passing_node()).unwrap();
            node.name = name.to_string();
            assert_eq!(
                validate_node_set(&[node]).unwrap_err(),
                NodeRejection::DuplicateOrReservedName(name.to_string())
            );
        }
    }

    #[test]
    fn set_rejects_more_than_200_nodes() {
        let base = admit_node(&passing_node()).unwrap();
        let nodes: Vec<ValidatedNode> = (0..=MAX_CATALOG_NODES)
            .map(|index| ValidatedNode {
                name: format!("node-{index}"),
                ..base.clone()
            })
            .collect();
        assert_eq!(
            validate_node_set(&nodes).unwrap_err(),
            NodeRejection::TooManyNodes
        );
        assert!(validate_node_set(&nodes[..MAX_CATALOG_NODES]).is_ok());
    }

    #[test]
    fn documentation_range_fixture_is_rejected_as_expected() {
        // Guards the fixture comment in valid_node_yaml(): 203.0.113/24 must
        // never pass admission.
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(valid_node_yaml()).unwrap();
        assert_eq!(
            admit_node(&value).unwrap_err(),
            NodeRejection::ServerNotPublicIpv4
        );
    }

    type YValue = serde_yaml_ng::Value;

    /// Rebuild the passing node with one top-level field replaced.
    fn with_field(key: &str, value: YValue) -> YValue {
        let mut mapping = passing_node().as_mapping().unwrap().clone();
        mapping.insert(YValue::String(key.to_string()), value);
        YValue::Mapping(mapping)
    }

    fn with_public_key(public_key: &str) -> YValue {
        let mut reality = serde_yaml_ng::Mapping::new();
        reality.insert(
            YValue::String("public-key".to_string()),
            YValue::String(public_key.to_string()),
        );
        reality.insert(
            YValue::String("short-id".to_string()),
            YValue::String("0123456789abcdef".to_string()),
        );
        with_field("reality-opts", YValue::Mapping(reality))
    }

    #[test]
    fn rejects_non_hyphenated_uuid_forms() {
        // macOS accepts only the 36-character hyphenated form (L6).
        for (label, value) in [
            ("simple 32-hex", "9e107d9d372b4c818d2b3f2d0a1b2c3d"),
            ("braced", "{9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d}"),
            ("urn", "urn:uuid:9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"),
        ] {
            assert_eq!(
                admit_node(&with_field("uuid", YValue::String(value.to_string()))).unwrap_err(),
                NodeRejection::BadUuid,
                "{label}"
            );
        }
    }

    #[test]
    fn rejects_non_string_server_scalars() {
        for value in [YValue::Number(123.into()), YValue::Bool(true)] {
            let message = format!("{value:?}");
            assert!(
                matches!(
                    admit_node(&with_field("server", value)).unwrap_err(),
                    NodeRejection::Malformed(_)
                ),
                "{message}"
            );
        }
    }

    #[test]
    fn rejects_non_standard_ip_literals() {
        for ip in [
            "08.8.8.8",       // leading-zero octet
            "8.8.8",          // three-octet form
            "134744072",      // single-integer form
            "0x8080808",      // hex form
            "::ffff:8.8.8.8", // v4-mapped IPv6
            "8.8.8.8.",       // trailing dot
        ] {
            assert_eq!(
                admit_node(&with_field("server", YValue::String(ip.to_string()))).unwrap_err(),
                NodeRejection::ServerNotPublicIpv4,
                "{ip}"
            );
        }
    }

    #[test]
    fn sni_rejects_invalid_hosts() {
        let cases: Vec<String> = vec![
            "!!!".to_string(),
            "localhost".to_string(),
            "-bad.com".to_string(),
            "bad-.com".to_string(),
            "a_b.com".to_string(),
            "a..com".to_string(),
            "a%b.com".to_string(),
            "a b.com".to_string(),
            format!("{}.com", "a".repeat(64)), // label over 63 bytes
            format!("{}.com", "a".repeat(250)), // total over 253 bytes
        ];
        for sni in cases {
            assert_eq!(
                admit_node(&with_field("sni", YValue::String(sni.clone()))).unwrap_err(),
                NodeRejection::SniInvalid,
                "{sni}"
            );
        }
    }

    #[test]
    fn sni_accepts_and_normalizes_valid_hosts() {
        // Lowercased (macOS parity).
        let node = admit_node(&with_field(
            "sni",
            YValue::String("WWW.Example.COM".to_string()),
        ))
        .unwrap();
        assert_eq!(node.servername, "www.example.com");
        // Surrounding dots are stripped.
        let node = admit_node(&with_field(
            "sni",
            YValue::String("..example.com.".to_string()),
        ))
        .unwrap();
        assert_eq!(node.servername, "example.com");
        // IP literals pass as-is: macOS normalizedHost returns early for them.
        let node = admit_node(&with_field("sni", YValue::String("1.2.3.4".to_string()))).unwrap();
        assert_eq!(node.servername, "1.2.3.4");
        // Hyphens inside labels and 63-byte labels are fine.
        let node = admit_node(&with_field(
            "sni",
            YValue::String("a-b-c.example.com".to_string()),
        ))
        .unwrap();
        assert_eq!(node.servername, "a-b-c.example.com");
        assert!(
            admit_node(&with_field(
                "sni",
                YValue::String(format!("{}.com", "a".repeat(63)))
            ))
            .is_ok()
        );
    }

    #[test]
    fn accepts_name_of_exactly_128_bytes() {
        assert!(admit_node(&with_name(&"x".repeat(128))).is_ok());
    }

    #[test]
    fn rejects_multibyte_reality_public_key() {
        // 43 chars but 86 bytes: length is measured in bytes and only
        // base64url ASCII survives anyway.
        assert_eq!(
            admit_node(&with_public_key(&"é".repeat(43))).unwrap_err(),
            NodeRejection::BadRealityPublicKey
        );
        // 42 ASCII chars plus one multibyte char.
        let key = format!("{}é", "a".repeat(42));
        assert_eq!(
            admit_node(&with_public_key(&key)).unwrap_err(),
            NodeRejection::BadRealityPublicKey
        );
    }

    #[test]
    fn rejects_special_registry_blocks_beyond_macos() {
        // L8 hardening blocks.
        for ip in [
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.175.48.1",
        ] {
            assert_eq!(
                admit_node(&with_field("server", YValue::String(ip.to_string()))).unwrap_err(),
                NodeRejection::ServerNotPublicIpv4,
                "{ip}"
            );
        }
        // Neighbours just outside the added blocks stay admissible.
        for ip in [
            "192.31.195.255",
            "192.31.197.1",
            "192.52.192.255",
            "192.52.194.1",
            "192.88.98.255",
            "192.88.100.1",
            "192.175.47.255",
            "192.175.49.1",
        ] {
            assert!(
                admit_node(&with_field("server", YValue::String(ip.to_string()))).is_ok(),
                "{ip}"
            );
        }
    }
}
