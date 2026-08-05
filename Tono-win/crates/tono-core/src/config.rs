//! Owned runtime configuration (product-contract.md §5).
//!
//! The runtime is generated locally per connect from validated catalog
//! nodes only — imported YAML is never copied. Every control value is
//! forced; there is no user-facing override. The controller secret is
//! 32 random bytes (base64) per start and exists only in the in-memory
//! runtime copy; [`redact_secret`] produces the disk-safe variant.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_yaml_ng::{Mapping, Value};
use thiserror::Error;

use crate::node::{EXIT_GROUP_NAME, NodeRejection, ValidatedNode, validate_node_set};

pub const MIXED_PORT: u16 = 7890;
pub const EXTERNAL_CONTROLLER: &str = "127.0.0.1:9090";
pub const TUN_DEVICE_NAME: &str = "Tono";
pub const FAKE_IP_RANGE: &str = "198.18.0.1/16";
pub const DNS_LISTEN: &str = "127.0.0.1:53";
/// Names of the physical-interface-bound DIRECT outbounds (present only when
/// the corresponding DirectPlan rules exist).
pub const DIRECT_GROUP_NAME: &str = "Tono-China-Direct";
pub const WEB_DIRECT_GROUP_NAME: &str = "Tono-China-Web-Direct";
/// DoH resolvers pinned through the exit group; the `#Tono-Exit` fragment
/// routes the lookups through the tunnel.
pub const DOH_NAMESERVERS: [&str; 2] = [
    "https://1.1.1.1/dns-query#Tono-Exit",
    "https://8.8.8.8/dns-query#Tono-Exit",
];
/// The only rules the runtime ever carries (§5).
pub const RULES: [&str; 3] = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "MATCH,Tono-Exit",
];

/// Why runtime generation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("selected node is not in the catalog: {0}")]
    MissingSelection(String),
    #[error("node set rejected: {0}")]
    Node(#[from] NodeRejection),
    #[error("direct plan rejected: {0}")]
    DirectPlan(String),
    #[error("runtime listener plan rejected: {0}")]
    RuntimePorts(String),
}

/// Per-connection loopback listeners. The App gives the mixed listener an ephemeral port used
/// only for a post-failure cross-check: a request through that listener bypasses WinTUN while
/// still exercising the selected node. It therefore distinguishes node/Core egress failure from
/// a broken Windows TUN data plane without weakening the real TUN connection verdict. The
/// controller must be non-zero because the App needs its exact authenticated endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimePorts {
    pub mixed_port: u16,
    pub controller_port: u16,
}

impl Default for RuntimePorts {
    fn default() -> Self {
        Self {
            mixed_port: MIXED_PORT,
            controller_port: 9090,
        }
    }
}

/// The exact China-DIRECT overlay for one connect. All
/// fields are already policy-validated by the caller; `build_owned_runtime`
/// re-checks the invariants that guard the tunnel (interface shape, no
/// rule targeting the selected node's IP).
///
/// - `hosts`: (domain, pinned IP) pairs rendered into the top-level
///   `hosts:` section (grouped per domain, sorted).
/// - `tcp_wechat_rules`: exact (host, IP, port) tuples for WeChat TCP rules.
/// - `tcp_web_rules`: exact (host, IP, TCP/443) tuples for reviewed web rules.
/// - `udp_wechat_rules`: exact (IP, port) tuples for the WeChat media UDP
///   rules (ports ⊆ {443, 8000}).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPlan {
    pub physical_interface: String,
    pub hosts: Vec<(String, String)>,
    pub tcp_wechat_rules: Vec<(String, std::net::Ipv4Addr, u16)>,
    pub tcp_web_rules: Vec<(String, std::net::Ipv4Addr, u16)>,
    pub udp_wechat_rules: Vec<(std::net::Ipv4Addr, u16)>,
}

impl DirectPlan {
    /// Accept a Windows interface alias exactly as returned by `MIB_IF_ROW2::Alias`. Aliases are
    /// user-visible Unicode and commonly contain localized text, dots, parentheses, or trademark
    /// characters. The runtime is serialized through `serde_yaml`, so validation needs to reject
    /// control characters and ambiguous surrounding whitespace rather than imposing an ASCII
    /// grammar. The Windows API reserves 257 UTF-16 code units including the terminator.
    pub fn validate_physical_interface(interface: &str) -> Result<(), ConfigError> {
        let reject =
            || ConfigError::DirectPlan(format!("invalid physical interface: {interface:?}"));
        if interface.is_empty()
            || interface.trim() != interface
            || interface.encode_utf16().count() > 256
            || interface.chars().any(char::is_control)
        {
            return Err(reject());
        }
        let lowered = interface.to_lowercase();
        if lowered == "tono" || matches!(lowered.as_str(), "lo" | "lo0" | "loopback") {
            return Err(reject());
        }
        Ok(())
    }
}

/// 32 random bytes, base64-encoded — the per-start controller secret (§5).
pub fn generate_controller_secret() -> String {
    STANDARD.encode(rand::random::<[u8; 32]>())
}

/// Build the owned Mihomo runtime (§5). `nodes` must come from catalog
/// admission; `selected` must name one of them and is placed first in the
/// single `Tono-Exit` group. `direct` is the optional WeChat-DIRECT
/// overlay — `None` produces byte-identical output to a plan-less build.
pub fn build_owned_runtime(
    nodes: &[ValidatedNode],
    selected: &str,
    secret: &str,
    direct: Option<&DirectPlan>,
) -> Result<OwnedRuntime, ConfigError> {
    build_owned_runtime_with_ports(nodes, selected, secret, direct, RuntimePorts::default())
}

/// Build the owned runtime with listeners chosen for this connection generation. This removes
/// the fixed 7890/9090 collision without allowing cloud/user configuration to choose a bind.
pub fn build_owned_runtime_with_ports(
    nodes: &[ValidatedNode],
    selected: &str,
    secret: &str,
    direct: Option<&DirectPlan>,
    ports: RuntimePorts,
) -> Result<OwnedRuntime, ConfigError> {
    if ports.controller_port == 0 {
        return Err(ConfigError::RuntimePorts(
            "controller port must be non-zero".to_string(),
        ));
    }
    if ports.mixed_port != 0 && ports.mixed_port == ports.controller_port {
        return Err(ConfigError::RuntimePorts(
            "mixed and controller listeners must use different ports".to_string(),
        ));
    }
    validate_node_set(nodes)?;
    let selected = selected.trim();
    let selected_node = nodes
        .iter()
        .find(|node| node.name == selected)
        .ok_or_else(|| ConfigError::MissingSelection(selected.to_string()))?;
    let route_exclusion = format!("{}/32", selected_node.server);

    if let Some(plan) = direct {
        DirectPlan::validate_physical_interface(&plan.physical_interface)?;
        // A DIRECT rule that targets the selected node's own IP would pull
        // the tunnel's control socket out of the tunnel.
        let hits_node = plan
            .tcp_wechat_rules
            .iter()
            .chain(plan.tcp_web_rules.iter())
            .any(|(_, ip, _)| *ip == selected_node.server)
            || plan
                .udp_wechat_rules
                .iter()
                .any(|(ip, _)| *ip == selected_node.server);
        if hits_node {
            return Err(ConfigError::DirectPlan(format!(
                "direct rule targets the selected node: {}",
                selected_node.server
            )));
        }
    }

    let yaml = serde_yaml_ng::to_string(&runtime_value(
        nodes,
        selected,
        secret,
        &route_exclusion,
        direct,
        ports,
    ))
    .map_err(|err| ConfigError::Node(NodeRejection::Malformed(err.to_string())))?;
    Ok(OwnedRuntime { yaml })
}

/// A freshly built owned runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRuntime {
    yaml: String,
}

impl OwnedRuntime {
    /// Full runtime YAML including the controller secret. In-memory only.
    pub fn yaml(&self) -> &str {
        &self.yaml
    }

    /// Disk-safe copy with the controller secret blanked (§5: the secret
    /// exists only in the service-held runtime copy).
    pub fn redacted_yaml(&self) -> String {
        redact_secret(&self.yaml)
    }
}

/// Blank the top-level `secret` key. Returns the input unchanged if it is
/// not a YAML mapping (never the case for [`build_owned_runtime`] output).
pub fn redact_secret(runtime_yaml: &str) -> String {
    let Ok(mut value) = serde_yaml_ng::from_str::<Value>(runtime_yaml) else {
        return runtime_yaml.to_string();
    };
    if let Some(mapping) = value.as_mapping_mut() {
        let key = Value::String("secret".to_string());
        if mapping.contains_key(&key) {
            mapping.insert(key, Value::String(String::new()));
        }
    }
    serde_yaml_ng::to_string(&value).unwrap_or_else(|_| runtime_yaml.to_string())
}

fn string(value: &str) -> Value {
    Value::String(value.to_string())
}

fn strings(values: &[&str]) -> Value {
    Value::Sequence(values.iter().map(|value| string(value)).collect())
}

fn put(mapping: &mut Mapping, key: &str, value: Value) {
    mapping.insert(string(key), value);
}

fn direct_outbound(name: &str, physical_interface: &str) -> Value {
    let mut outbound = Mapping::new();
    put(&mut outbound, "name", string(name));
    put(&mut outbound, "type", string("direct"));
    put(&mut outbound, "udp", Value::Bool(true));
    // Current Mihomo releases remove proxy groups carrying interface-name.
    // The supported form binds the concrete DIRECT outbound instead.
    put(&mut outbound, "interface-name", string(physical_interface));
    Value::Mapping(outbound)
}

fn runtime_value(
    nodes: &[ValidatedNode],
    selected: &str,
    secret: &str,
    route_exclusion: &str,
    direct: Option<&DirectPlan>,
    ports: RuntimePorts,
) -> Value {
    let mut root = Mapping::new();
    // Extra listeners stay disabled (macOS owned-runtime parity); the only
    // ingress is the mixed port below, bound locally.
    put(&mut root, "port", Value::Number(0.into()));
    put(&mut root, "socks-port", Value::Number(0.into()));
    put(&mut root, "redir-port", Value::Number(0.into()));
    put(
        &mut root,
        "mixed-port",
        Value::Number(ports.mixed_port.into()),
    );
    // `allow-lan: false` already limits Mihomo's normal listener scope. Keep the concrete bind as
    // a second, explicit boundary because the diagnostic port is not part of the product API and
    // must never become reachable from another machine after a future Mihomo default changes.
    put(&mut root, "bind-address", string("127.0.0.1"));
    put(&mut root, "allow-lan", Value::Bool(false));
    put(&mut root, "ipv6", Value::Bool(false));
    put(&mut root, "mode", string("rule"));
    put(&mut root, "log-level", string("info"));
    put(&mut root, "unified-delay", Value::Bool(true));
    put(&mut root, "find-process-mode", string("strict"));
    let mut profile = Mapping::new();
    // Never let a stale cache.db choice resurrect an old selection.
    put(&mut profile, "store-selected", Value::Bool(false));
    put(&mut root, "profile", Value::Mapping(profile));
    put(
        &mut root,
        "external-controller",
        string(&format!("127.0.0.1:{}", ports.controller_port)),
    );
    put(&mut root, "secret", string(secret));

    // WeChat-DIRECT: pin resolved domain addresses into `hosts:` so the
    // runtime never depends on a resolver for them (F/Mac Build 28).
    if let Some(plan) = direct
        && !plan.hosts.is_empty()
    {
        let mut grouped: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for (domain, address) in &plan.hosts {
            grouped
                .entry(domain.as_str())
                .or_default()
                .push(address.as_str());
        }
        let mut hosts = Mapping::new();
        for (domain, addresses) in grouped {
            hosts.insert(
                Value::String(domain.to_string()),
                Value::Sequence(addresses.iter().map(|address| string(address)).collect()),
            );
        }
        put(&mut root, "hosts", Value::Mapping(hosts));
    }

    let mut dns = Mapping::new();
    put(&mut dns, "enable", Value::Bool(true));
    put(&mut dns, "listen", string(DNS_LISTEN));
    put(&mut dns, "enhanced-mode", string("fake-ip"));
    put(&mut dns, "fake-ip-range", string(FAKE_IP_RANGE));
    put(&mut dns, "respect-rules", Value::Bool(true));
    put(&mut dns, "nameserver", strings(&DOH_NAMESERVERS));
    put(
        &mut dns,
        "proxy-server-nameserver",
        strings(&DOH_NAMESERVERS),
    );
    put(&mut root, "dns", Value::Mapping(dns));

    let mut tun = Mapping::new();
    put(&mut tun, "enable", Value::Bool(true));
    put(&mut tun, "stack", string("gvisor"));
    put(&mut tun, "device", string(TUN_DEVICE_NAME));
    put(&mut tun, "auto-route", Value::Bool(true));
    put(&mut tun, "auto-detect-interface", Value::Bool(true));
    put(&mut tun, "strict-route", Value::Bool(true));
    // gVisor ICMP would otherwise attempt a host-direct socket (macOS
    // parity; honored where the core build supports it).
    put(&mut tun, "disable-icmp-forwarding", Value::Bool(true));
    put(&mut tun, "dns-hijack", strings(&["any:53", "tcp://any:53"]));
    // Keeps Mihomo's own Reality socket out of the tunnel.
    put(
        &mut tun,
        "route-exclude-address",
        strings(&[route_exclusion]),
    );
    put(&mut root, "tun", Value::Mapping(tun));

    let mut proxies: Vec<Value> = nodes
        .iter()
        .map(|node| Value::Mapping(node.to_runtime_mapping()))
        .collect();
    if let Some(plan) = direct {
        let has_wechat = !plan.tcp_wechat_rules.is_empty() || !plan.udp_wechat_rules.is_empty();
        let has_web = !plan.tcp_web_rules.is_empty();
        if has_wechat {
            proxies.push(direct_outbound(DIRECT_GROUP_NAME, &plan.physical_interface));
        }
        if has_web {
            proxies.push(direct_outbound(
                WEB_DIRECT_GROUP_NAME,
                &plan.physical_interface,
            ));
        }
    }
    put(&mut root, "proxies", Value::Sequence(proxies));

    let mut groups: Vec<Value> = Vec::new();
    let mut ordered: Vec<&str> = Vec::with_capacity(nodes.len());
    ordered.push(selected);
    ordered.extend(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .filter(|name| *name != selected),
    );
    let mut group = Mapping::new();
    put(&mut group, "name", string(EXIT_GROUP_NAME));
    put(&mut group, "type", string("select"));
    put(
        &mut group,
        "proxies",
        Value::Sequence(ordered.iter().map(|name| string(name)).collect()),
    );
    groups.push(Value::Mapping(group));
    put(&mut root, "proxy-groups", Value::Sequence(groups));

    // Loopback, protected Claude processes, exact DIRECT pins, then MATCH.
    let mut rules: Vec<String> = RULES[..RULES.len() - 1]
        .iter()
        .map(|rule| rule.to_string())
        .collect();
    if let Some(plan) = direct {
        if !plan.tcp_wechat_rules.is_empty()
            || !plan.tcp_web_rules.is_empty()
            || !plan.udp_wechat_rules.is_empty()
        {
            rules.push("PROCESS-NAME,Claude.exe,Tono-Exit".to_string());
            rules.push("PROCESS-NAME,claude.exe,Tono-Exit".to_string());
        }
        for (host, address, port) in &plan.tcp_wechat_rules {
            rules.push(format!(
                "AND,((NETWORK,TCP),(DST-PORT,{port}),(DOMAIN,{host}),(IP-CIDR,{address}/32,no-resolve),(PROCESS-NAME,WeChat.exe)),{DIRECT_GROUP_NAME}"
            ));
        }
        for (address, port) in &plan.udp_wechat_rules {
            rules.push(format!(
                "AND,((NETWORK,UDP),(DST-PORT,{port}),(IP-CIDR,{address}/32),(PROCESS-NAME,WeChat.exe)),{DIRECT_GROUP_NAME}"
            ));
        }
        for (host, address, port) in &plan.tcp_web_rules {
            rules.push(format!(
                "AND,((NETWORK,TCP),(DST-PORT,{port}),(DOMAIN,{host}),(IP-CIDR,{address}/32,no-resolve)),{WEB_DIRECT_GROUP_NAME}"
            ));
        }
    }
    rules.push(RULES[RULES.len() - 1].to_string());
    put(
        &mut root,
        "rules",
        Value::Sequence(rules.iter().map(|rule| string(rule)).collect()),
    );
    Value::Mapping(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::admit_node;

    fn node(name: &str, server: &str) -> ValidatedNode {
        let yaml = format!(
            r#"
name: "{name}"
type: vless
server: {server}
port: 443
uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"
tls: true
sni: "www.microsoft.com"
flow: xtls-rprx-vision
reality-opts:
  public-key: "0123456789abcdef0123456789abcdef0123456789a"
  short-id: "0123456789abcdef"
"#
        );
        admit_node(&serde_yaml_ng::from_str(&yaml).unwrap()).unwrap()
    }

    fn three_nodes() -> Vec<ValidatedNode> {
        vec![
            node("US Reality 01", "8.8.8.8"),
            node("JP Reality 02", "1.1.1.1"),
            node("SG Reality 03", "9.9.9.9"),
        ]
    }

    fn build() -> OwnedRuntime {
        build_owned_runtime(&three_nodes(), "JP Reality 02", "test-secret", None).unwrap()
    }

    fn parsed(runtime: &OwnedRuntime) -> Value {
        serde_yaml_ng::from_str(runtime.yaml()).expect("generated YAML must parse")
    }

    fn get<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
        let mut current = value;
        for key in path {
            current = &current.as_mapping().unwrap()[string(key)];
        }
        current
    }

    #[test]
    fn generated_yaml_parses_back_to_a_map() {
        assert!(parsed(&build()).as_mapping().is_some());
    }

    #[test]
    fn forces_top_level_control_values() {
        let value = parsed(&build());
        assert_eq!(get(&value, &["mixed-port"]).as_i64(), Some(7890));
        assert_eq!(get(&value, &["bind-address"]).as_str(), Some("127.0.0.1"));
        assert_eq!(get(&value, &["allow-lan"]).as_bool(), Some(false));
        assert_eq!(get(&value, &["ipv6"]).as_bool(), Some(false));
        assert_eq!(get(&value, &["mode"]).as_str(), Some("rule"));
        assert_eq!(get(&value, &["log-level"]).as_str(), Some("info"));
        assert_eq!(get(&value, &["unified-delay"]).as_bool(), Some(true));
        assert_eq!(get(&value, &["find-process-mode"]).as_str(), Some("strict"));
        assert_eq!(
            get(&value, &["profile", "store-selected"]).as_bool(),
            Some(false)
        );
        assert_eq!(
            get(&value, &["external-controller"]).as_str(),
            Some("127.0.0.1:9090")
        );
        assert_eq!(get(&value, &["secret"]).as_str(), Some("test-secret"));
        // No leftover listeners.
        for key in ["port", "socks-port", "redir-port"] {
            assert_eq!(get(&value, &[key]).as_i64(), Some(0), "{key}");
        }
    }

    #[test]
    fn per_connection_ports_disable_mixed_listener_and_move_controller() {
        let runtime = build_owned_runtime_with_ports(
            &three_nodes(),
            "JP Reality 02",
            "test-secret",
            None,
            RuntimePorts {
                mixed_port: 0,
                controller_port: 41_237,
            },
        )
        .unwrap();
        let value = parsed(&runtime);
        assert_eq!(get(&value, &["mixed-port"]).as_i64(), Some(0));
        assert_eq!(
            get(&value, &["external-controller"]).as_str(),
            Some("127.0.0.1:41237")
        );
    }

    #[test]
    fn rejects_invalid_runtime_listener_plan() {
        for ports in [
            RuntimePorts {
                mixed_port: 0,
                controller_port: 0,
            },
            RuntimePorts {
                mixed_port: 9_090,
                controller_port: 9_090,
            },
        ] {
            assert!(matches!(
                build_owned_runtime_with_ports(
                    &three_nodes(),
                    "JP Reality 02",
                    "test-secret",
                    None,
                    ports,
                ),
                Err(ConfigError::RuntimePorts(_))
            ));
        }
    }

    #[test]
    fn forces_dns_contract() {
        let value = parsed(&build());
        assert_eq!(get(&value, &["dns", "enable"]).as_bool(), Some(true));
        assert_eq!(
            get(&value, &["dns", "listen"]).as_str(),
            Some("127.0.0.1:53")
        );
        assert_eq!(
            get(&value, &["dns", "enhanced-mode"]).as_str(),
            Some("fake-ip")
        );
        assert_eq!(
            get(&value, &["dns", "fake-ip-range"]).as_str(),
            Some("198.18.0.1/16")
        );
        assert_eq!(get(&value, &["dns", "respect-rules"]).as_bool(), Some(true));
        let expected: Vec<Value> = DOH_NAMESERVERS
            .iter()
            .map(|server| string(server))
            .collect();
        assert_eq!(
            get(&value, &["dns", "nameserver"]).as_sequence().unwrap(),
            &expected
        );
        assert_eq!(
            get(&value, &["dns", "proxy-server-nameserver"])
                .as_sequence()
                .unwrap(),
            &expected
        );
    }

    #[test]
    fn forces_tun_contract_and_route_exclusion() {
        let value = parsed(&build());
        assert_eq!(get(&value, &["tun", "enable"]).as_bool(), Some(true));
        assert_eq!(get(&value, &["tun", "stack"]).as_str(), Some("gvisor"));
        assert_eq!(get(&value, &["tun", "device"]).as_str(), Some("Tono"));
        assert_eq!(get(&value, &["tun", "auto-route"]).as_bool(), Some(true));
        assert_eq!(
            get(&value, &["tun", "auto-detect-interface"]).as_bool(),
            Some(true)
        );
        assert_eq!(get(&value, &["tun", "strict-route"]).as_bool(), Some(true));
        assert_eq!(
            get(&value, &["tun", "dns-hijack"]).as_sequence().unwrap(),
            &vec![string("any:53"), string("tcp://any:53")]
        );
        // Selected node is JP Reality 02 at 1.1.1.1.
        assert_eq!(
            get(&value, &["tun", "route-exclude-address"])
                .as_sequence()
                .unwrap(),
            &vec![string("1.1.1.1/32")]
        );
    }

    #[test]
    fn emits_exactly_one_select_group_with_selected_first() {
        let value = parsed(&build());
        let groups = get(&value, &["proxy-groups"]).as_sequence().unwrap();
        assert_eq!(groups.len(), 1, "no DIRECT/fallback group may exist");
        assert_eq!(groups[0][string("name")].as_str(), Some("Tono-Exit"));
        assert_eq!(groups[0][string("type")].as_str(), Some("select"));
        let choices: Vec<&str> = groups[0][string("proxies")]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .collect();
        assert_eq!(choices, ["JP Reality 02", "US Reality 01", "SG Reality 03"]);
    }

    #[test]
    fn emits_exactly_the_contract_rules() {
        let value = parsed(&build());
        let rules: Vec<&str> = get(&value, &["rules"])
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(
            rules,
            [
                "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR6,::1/128,DIRECT,no-resolve",
                "MATCH,Tono-Exit"
            ]
        );
        let raw = build().yaml().to_string();
        assert!(!raw.contains("GEOIP"), "no GEOIP rules may leak in");
    }

    #[test]
    fn serializes_vless_with_servername_and_reality_opts() {
        let value = parsed(&build());
        let proxies = get(&value, &["proxies"]).as_sequence().unwrap();
        assert_eq!(proxies.len(), 3);
        let first = &proxies[0];
        assert_eq!(first[string("type")].as_str(), Some("vless"));
        assert_eq!(
            first[string("servername")].as_str(),
            Some("www.microsoft.com")
        );
        assert!(
            first.get(string("sni")).is_none(),
            "sni alias must not be emitted"
        );
        assert_eq!(first[string("tls")].as_bool(), Some(true));
        assert_eq!(first[string("network")].as_str(), Some("tcp"));
        assert_eq!(first[string("flow")].as_str(), Some("xtls-rprx-vision"));
        assert_eq!(first[string("server")].as_str(), Some("8.8.8.8"));
        assert_eq!(
            first[string("reality-opts")][string("public-key")].as_str(),
            Some("0123456789abcdef0123456789abcdef0123456789a")
        );
        assert_eq!(
            first[string("reality-opts")][string("short-id")].as_str(),
            Some("0123456789abcdef")
        );
    }

    #[test]
    fn rejects_duplicate_and_reserved_names() {
        let mut nodes = three_nodes();
        nodes.push(node("US Reality 01", "1.0.0.1"));
        assert!(matches!(
            build_owned_runtime(&nodes, "US Reality 01", "s", None).unwrap_err(),
            ConfigError::Node(NodeRejection::DuplicateOrReservedName(_))
        ));
        let reserved = vec![node("Tono-Exit", "1.1.1.1")];
        assert_eq!(
            build_owned_runtime(&reserved, "Tono-Exit", "s", None).unwrap_err(),
            ConfigError::Node(NodeRejection::DuplicateOrReservedName(
                "Tono-Exit".to_string()
            ))
        );
    }

    #[test]
    fn rejects_missing_selection() {
        assert_eq!(
            build_owned_runtime(&three_nodes(), "No Such Node", "s", None).unwrap_err(),
            ConfigError::MissingSelection("No Such Node".to_string())
        );
        assert!(matches!(
            build_owned_runtime(&[], "anything", "s", None).unwrap_err(),
            ConfigError::MissingSelection(_)
        ));
    }

    #[test]
    fn secret_lives_only_in_the_memory_copy() {
        let runtime =
            build_owned_runtime(&three_nodes(), "US Reality 01", "super-secret-value", None)
                .unwrap();
        assert!(runtime.yaml().contains("super-secret-value"));
        let redacted = runtime.redacted_yaml();
        assert!(!redacted.contains("super-secret-value"));
        // The redacted copy is still valid YAML with a blanked secret.
        let value: Value = serde_yaml_ng::from_str(&redacted).unwrap();
        assert_eq!(get(&value, &["secret"]).as_str(), Some(""));
        // Everything else survives redaction.
        assert_eq!(get(&value, &["mixed-port"]).as_i64(), Some(7890));
    }

    #[test]
    fn redact_secret_handles_garbage_input() {
        assert_eq!(redact_secret("not: [valid"), "not: [valid");
        // A bare scalar parses fine and round-trips unchanged in content.
        assert_eq!(redact_secret("plain scalar").trim(), "plain scalar");
    }

    #[test]
    fn controller_secret_is_32_random_bytes_base64() {
        let first = generate_controller_secret();
        let second = generate_controller_secret();
        assert_ne!(first, second, "secret must be per-start random");
        let decoded = STANDARD.decode(&first).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(first.len(), 44);
    }

    #[test]
    fn redact_secret_preserves_everything_but_the_secret() {
        let runtime = build();
        let redacted: Value = serde_yaml_ng::from_str(&runtime.redacted_yaml()).unwrap();
        assert_eq!(get(&redacted, &["secret"]).as_str(), Some(""));
        assert_eq!(
            get(&redacted, &["external-controller"]).as_str(),
            Some("127.0.0.1:9090")
        );
        let rules: Vec<&str> = get(&redacted, &["rules"])
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules, RULES);
        assert_eq!(get(&redacted, &["proxies"]).as_sequence().unwrap().len(), 3);
        let groups = get(&redacted, &["proxy-groups"]).as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][string("name")].as_str(), Some("Tono-Exit"));
        let choices: Vec<&str> = groups[0][string("proxies")]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .collect();
        assert_eq!(choices, ["JP Reality 02", "US Reality 01", "SG Reality 03"]);
    }

    // ---- WeChat-DIRECT overlay ----

    fn direct_plan() -> DirectPlan {
        DirectPlan {
            physical_interface: "Ethernet 2".to_string(),
            hosts: vec![
                ("wxs.qq.com".to_string(), "9.0.0.10".to_string()),
                ("wxs.qq.com".to_string(), "9.0.0.11".to_string()),
                ("qpic.cn".to_string(), "9.0.0.12".to_string()),
            ],
            tcp_wechat_rules: vec![
                (
                    "wxs.qq.com".to_string(),
                    std::net::Ipv4Addr::new(9, 0, 0, 10),
                    443,
                ),
                (
                    "wxs.qq.com".to_string(),
                    std::net::Ipv4Addr::new(9, 0, 0, 10),
                    80,
                ),
                (
                    "qpic.cn".to_string(),
                    std::net::Ipv4Addr::new(9, 0, 0, 12),
                    443,
                ),
            ],
            tcp_web_rules: vec![(
                "www.bilibili.com".to_string(),
                std::net::Ipv4Addr::new(9, 0, 0, 30),
                443,
            )],
            udp_wechat_rules: vec![(std::net::Ipv4Addr::new(9, 0, 0, 20), 443)],
        }
    }

    #[test]
    fn no_direct_build_is_byte_identical_to_before() {
        let without =
            build_owned_runtime(&three_nodes(), "JP Reality 02", "test-secret", None).unwrap();
        let value = parsed(&without);
        // No direct artifacts at all.
        assert!(value.as_mapping().unwrap().get(string("hosts")).is_none());
        let groups = get(&value, &["proxy-groups"]).as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        let rules: Vec<&str> = get(&value, &["rules"])
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules, RULES);
    }

    #[test]
    fn direct_build_renders_hosts_outbounds_and_rules_in_order() {
        let runtime = build_owned_runtime(
            &three_nodes(),
            "JP Reality 02",
            "test-secret",
            Some(&direct_plan()),
        )
        .unwrap();
        let value = parsed(&runtime);

        // hosts: grouped per domain, pinned addresses only.
        let hosts = get(&value, &["hosts"]);
        let wxs = hosts
            .as_mapping()
            .unwrap()
            .get(string("wxs.qq.com"))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(wxs.len(), 2);
        let qpic = hosts
            .as_mapping()
            .unwrap()
            .get(string("qpic.cn"))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(qpic.len(), 1);

        // Current Mihomo accepts interface binding on concrete proxies, not
        // on proxy groups. Both DIRECT rule targets are concrete outbounds.
        let proxies = get(&value, &["proxies"]).as_sequence().unwrap();
        assert_eq!(proxies.len(), 5);
        let direct = &proxies[3];
        assert_eq!(direct[string("name")].as_str(), Some("Tono-China-Direct"));
        assert_eq!(direct[string("type")].as_str(), Some("direct"));
        assert_eq!(direct[string("udp")].as_bool(), Some(true));
        assert_eq!(
            direct[string("interface-name")].as_str(),
            Some("Ethernet 2")
        );
        let web_direct = &proxies[4];
        assert_eq!(
            web_direct[string("name")].as_str(),
            Some("Tono-China-Web-Direct")
        );
        assert_eq!(web_direct[string("type")].as_str(), Some("direct"));
        assert_eq!(
            web_direct[string("interface-name")].as_str(),
            Some("Ethernet 2")
        );

        // Tono-Exit remains the only group and still carries the selected
        // Reality node first; no deprecated group interface-name is emitted.
        let groups = get(&value, &["proxy-groups"]).as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][string("name")].as_str(), Some("Tono-Exit"));
        assert!(groups[0].get(string("interface-name")).is_none());

        // Rules: loopback, then TCP pins, then UDP WeChat pins, then MATCH.
        let rules: Vec<&str> = get(&value, &["rules"])
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(
            rules,
            [
                "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR6,::1/128,DIRECT,no-resolve",
                "PROCESS-NAME,Claude.exe,Tono-Exit",
                "PROCESS-NAME,claude.exe,Tono-Exit",
                "AND,((NETWORK,TCP),(DST-PORT,443),(DOMAIN,wxs.qq.com),(IP-CIDR,9.0.0.10/32,no-resolve),(PROCESS-NAME,WeChat.exe)),Tono-China-Direct",
                "AND,((NETWORK,TCP),(DST-PORT,80),(DOMAIN,wxs.qq.com),(IP-CIDR,9.0.0.10/32,no-resolve),(PROCESS-NAME,WeChat.exe)),Tono-China-Direct",
                "AND,((NETWORK,TCP),(DST-PORT,443),(DOMAIN,qpic.cn),(IP-CIDR,9.0.0.12/32,no-resolve),(PROCESS-NAME,WeChat.exe)),Tono-China-Direct",
                "AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,9.0.0.20/32),(PROCESS-NAME,WeChat.exe)),Tono-China-Direct",
                "AND,((NETWORK,TCP),(DST-PORT,443),(DOMAIN,www.bilibili.com),(IP-CIDR,9.0.0.30/32,no-resolve)),Tono-China-Web-Direct",
                "MATCH,Tono-Exit",
            ]
        );
        // MATCH remains the only fallback.
        assert_eq!(rules.last(), Some(&"MATCH,Tono-Exit"));
    }

    #[test]
    fn direct_rules_never_target_the_selected_node() {
        let mut plan = direct_plan();
        // JP Reality 02 is 1.1.1.1 in the fixture set; adding it must fail.
        plan.tcp_wechat_rules.push((
            "wxs.qq.com".to_string(),
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            443,
        ));
        assert!(matches!(
            build_owned_runtime(&three_nodes(), "JP Reality 02", "s", Some(&plan)),
            Err(ConfigError::DirectPlan(_))
        ));
        // The same address is fine when it is not the selected node.
        assert!(
            build_owned_runtime(&three_nodes(), "US Reality 01", "s", Some(&plan)).is_ok(),
            "a pin matching an unselected node stays legal"
        );
    }

    #[test]
    fn physical_interface_validation() {
        for good in [
            "Ethernet 2",
            "Wi-Fi",
            "en0",
            "以太网",
            "イーサネット",
            "vEthernet (Default Switch)",
            "Ethernet.Intel®",
            "LAN_1",
            "a",
        ] {
            DirectPlan::validate_physical_interface(good)
                .unwrap_or_else(|err| panic!("{good}: {err}"));
        }
        for bad in [
            "",
            &"x".repeat(257),
            "Tono",
            "tono",
            "lo0",
            "Loopback",
            " Ethernet",
            "Ethernet ",
            "Ethernet\nInjected",
            "Ethernet\0Hidden",
        ] {
            assert!(
                DirectPlan::validate_physical_interface(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn direct_plan_with_empty_collections_keeps_outbounds_groups_and_rules_stable() {
        let plan = DirectPlan {
            physical_interface: "Ethernet".to_string(),
            hosts: Vec::new(),
            tcp_wechat_rules: Vec::new(),
            tcp_web_rules: Vec::new(),
            udp_wechat_rules: Vec::new(),
        };
        let runtime =
            build_owned_runtime(&three_nodes(), "JP Reality 02", "s", Some(&plan)).unwrap();
        let value = parsed(&runtime);
        assert!(value.as_mapping().unwrap().get(string("hosts")).is_none());
        let groups = get(&value, &["proxy-groups"]).as_sequence().unwrap();
        assert_eq!(groups.len(), 1, "an empty plan declares no DIRECT group");
        let proxies = get(&value, &["proxies"]).as_sequence().unwrap();
        assert_eq!(
            proxies.len(),
            3,
            "an empty plan declares no DIRECT outbound"
        );
        let rules: Vec<&str> = get(&value, &["rules"])
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules, RULES);
    }
}
