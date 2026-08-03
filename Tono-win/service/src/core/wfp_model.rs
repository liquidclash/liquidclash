//! Platform-independent WFP rule model for the Tono kill switch.
//!
//! Everything here is a pure function of the desired protection state: [`expected_filters`]
//! renders the exact filter set the Windows engine (`wfp.rs`) must install, and [`diff`] turns
//! the live set into an ordered change plan. Keeping this module free of `windows-sys` is what
//! makes the rule tables from `docs/wfp-kill-switch.md` unit-testable on any host.
//!
//! Arbitration note: WFP arbitrates **sublayer-by-sublayer, highest sublayer weight first**;
//! within a sublayer, filters are ordered by descending filter weight and the first match with
//! a terminating action (permit/block) ends arbitration
//! (<https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration>). That is why every
//! rule lives in a *single* sublayer (Mullvad-style): "weighted permits over a low block-all"
//! only holds when filter weight is the sole ordering axis. A second, higher-weight sublayer
//! carrying a match-all block would decide every packet before any permit here is consulted.
//! Persistence is still reserved for the condition-free block-all pair, which is what survives
//! a reboot; everything else is rebuilt on service start.

use crate::core::structure::{KillSwitchStatusMode, ProxyEndpoint, ProxyProtocol};
use std::net::IpAddr;

/// A WFP object key. `wfp.rs` converts this into `windows_sys::core::GUID`; having our own
/// type is what lets this module compile off-Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid(u128);

impl Guid {
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Used by the Windows engine (`wfp.rs`) to render `windows_sys::core::GUID`s.
    #[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
    pub const fn into_u128(self) -> u128 {
        self.0
    }
}

// Fixed object GUIDs, generated once for Tono and never reused by anything else. Every WFP
// object the service creates carries `TONO_WFP_PROVIDER_KEY` as its provider key, so
// enumeration, verification, and emergency deletion are all scoped by it.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub const TONO_WFP_PROVIDER_KEY: Guid = Guid::from_u128(0x2f7c9d41_8b3e_4a6c_9d52_1e7f0a4b6c8d);
/// The single `tono-kill-switch` sublayer every rule lives in (see the arbitration note in the
/// module docs). Persistent, so the fail-closed block-all pair it contains survives reboot.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub const TONO_WFP_SUBLAYER_KEY: Guid = Guid::from_u128(0x2f7c9d42_8b3e_4a6c_9d52_1e7f0a4b6c8d);

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub const TONO_WFP_SUBLAYER_WEIGHT: u16 = 1000;

/// Hard permits: floor loopback, mihomo endpoint, tunnel interface.
pub const WEIGHT_HARD_PERMIT: u64 = 8;
/// Infrastructure permits: floor DHCP/NDP, bootstrap API channel.
pub const WEIGHT_INFRA_PERMIT: u64 = 7;
/// Session hard DNS block (non-loopback port 53).
pub const WEIGHT_DNS_BLOCK: u64 = 6;
/// Both block-alls: the intent floor's persistent pair and the session's redundant pair.
pub const WEIGHT_BLOCK_ALL: u64 = 1;

/// Resolved API host IPs are a bounded, public-only set before they ever reach WFP.
pub const MAX_API_HOST_IPS: usize = 8;

/// Filter keys are deterministic so verify-by-key works across restarts: a fixed 64-bit Tono
/// namespace over a 64-bit FNV-1a hash of the rule's identity tag.
///
/// **Bump this namespace on every rule-table change.** A rule whose conditions changed keeps
/// its tag — and therefore its key — so without a bump, the key-only diff would adopt an
/// older build's stale filter instead of replacing it. Bumping remaps every key, so the
/// upgrade path cleanly removes the entire old set and installs the new one.
/// (v1: `…9e00…` dual-sublayer; v2: `…9e01…` single-sublayer; v3: `…9e02…`
/// port-scoped DHCP with no global NTP bypass.)
const FILTER_NAMESPACE: u128 = 0x2f7c_9e02_0000_4a6c_0000_0000_0000_0000;

const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

fn key_for(tag: &str) -> Guid {
    Guid::from_u128(FILTER_NAMESPACE | fnv1a64(tag.as_bytes()) as u128)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    AleAuthConnectV4,
    AleAuthConnectV6,
    AleAuthRecvAcceptV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Permit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    IcmpV6,
}

impl IpProtocol {
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::IcmpV6 => 58,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    RemoteAddressV4 {
        addr: [u8; 4],
        prefix: u8,
    },
    RemoteAddressV6 {
        addr: [u8; 16],
        prefix: u8,
    },
    Protocol(IpProtocol),
    LocalPort(u16),
    RemotePort(u16),
    /// NDP types 133–137 as one inclusive range.
    IcmpV6TypeRange {
        min: u16,
        max: u16,
    },
    /// `FwpmGetAppIdFromFileName` blob of the staged core binary; resolved by the engine.
    AleAppId,
    /// WinTUN adapter LUID.
    LocalInterface(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub key: Guid,
    pub name: String,
    pub layer: LayerKind,
    pub weight: u64,
    pub action: FilterAction,
    pub conditions: Vec<Condition>,
    /// Only the intent floor's condition-free block-all pair is persistent — Proton's rule
    /// that persistence is reserved for condition-free blocking.
    pub persistent: bool,
}

/// The protection state the rule set is a function of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConfig {
    pub mode: KillSwitchStatusMode,
    /// Selected node endpoints the staged core may reach directly (usually exactly one).
    pub endpoints: Vec<ProxyEndpoint>,
    /// Resolved, validated, public-only API host IPs for the bootstrap channel.
    pub api_host_ips: Vec<IpAddr>,
    /// WinTUN LUID; only consulted in `Locked` mode.
    pub tun_luid: Option<u64>,
    /// Staged core path, folded into the endpoint permit's key: an installer that moves the
    /// binary must rekey the permit (Proton's upgrade lesson — app-path filters silently die
    /// when the exe moves), which the add-before-remove plan then swaps atomically.
    pub app_path: String,
    /// Cloud-approved DIRECT endpoints (WeChat acceleration): exact `IP:port` tuples any
    /// process may reach on the physical NIC. Rendered **only in `Locked`** (see rule G);
    /// never persisted, never restored, never inherited by the next arm — omission = clear.
    pub direct_endpoints: Vec<ProxyEndpoint>,
}

/// One row of the rule tables: every field of a `FilterSpec` except the derived key/name.
fn spec(
    tag: String,
    name: &str,
    layer: LayerKind,
    weight: u64,
    action: FilterAction,
    conditions: Vec<Condition>,
    persistent: bool,
) -> FilterSpec {
    FilterSpec {
        key: key_for(&tag),
        name: format!("Tono {name}"),
        layer,
        weight,
        action,
        conditions,
        persistent,
    }
}

/// The persistent fail-closed floor: loopback, DHCP, and NDP permits over a persistent
/// block-all pair. No volatile conditions, so the set never changes while armed.
pub fn intent_floor() -> Vec<FilterSpec> {
    use Condition as C;
    use FilterAction as A;
    use LayerKind as L;
    vec![
        spec(
            "intent/permit-loopback-v4".into(),
            "intent permit loopback v4",
            L::AleAuthConnectV4,
            WEIGHT_HARD_PERMIT,
            A::Permit,
            vec![C::RemoteAddressV4 {
                addr: [127, 0, 0, 0],
                prefix: 8,
            }],
            false,
        ),
        spec(
            "intent/permit-loopback-v6".into(),
            "intent permit loopback v6",
            L::AleAuthConnectV6,
            WEIGHT_HARD_PERMIT,
            A::Permit,
            vec![C::RemoteAddressV6 {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix: 128,
            }],
            false,
        ),
        spec(
            "intent/permit-dhcp-v4".into(),
            "intent permit DHCP v4",
            L::AleAuthConnectV4,
            WEIGHT_INFRA_PERMIT,
            A::Permit,
            vec![
                C::Protocol(IpProtocol::Udp),
                C::LocalPort(68),
                C::RemotePort(67),
            ],
            false,
        ),
        spec(
            "intent/permit-dhcp-v6".into(),
            "intent permit DHCPv6 client to server",
            L::AleAuthConnectV6,
            WEIGHT_INFRA_PERMIT,
            A::Permit,
            vec![
                C::Protocol(IpProtocol::Udp),
                C::LocalPort(546),
                C::RemotePort(547),
            ],
            false,
        ),
        spec(
            "intent/permit-ndp-out".into(),
            "intent permit NDP outbound",
            L::AleAuthConnectV6,
            WEIGHT_INFRA_PERMIT,
            A::Permit,
            vec![
                C::Protocol(IpProtocol::IcmpV6),
                C::IcmpV6TypeRange { min: 133, max: 137 },
            ],
            false,
        ),
        spec(
            "intent/permit-ndp-in".into(),
            "intent permit NDP inbound",
            L::AleAuthRecvAcceptV6,
            WEIGHT_INFRA_PERMIT,
            A::Permit,
            vec![
                C::Protocol(IpProtocol::IcmpV6),
                C::IcmpV6TypeRange { min: 133, max: 137 },
            ],
            false,
        ),
        spec(
            "intent/block-all-v4".into(),
            "intent block all v4",
            L::AleAuthConnectV4,
            WEIGHT_BLOCK_ALL,
            A::Block,
            vec![],
            true,
        ),
        spec(
            "intent/block-all-v6".into(),
            "intent block all v6",
            L::AleAuthConnectV6,
            WEIGHT_BLOCK_ALL,
            A::Block,
            vec![],
            true,
        ),
    ]
}

/// Parse and classify an endpoint for rule rendering. Invalid *or non-public* IPs render no
/// permit — the facade validates before arming, and a skipped permit fails closed, never open.
/// The public-IP table is shared with the API-host check (`is_public_api_ip`) so an endpoint
/// can never quietly point at loopback/LAN/link-local space either.
pub fn parse_endpoint(endpoint: &ProxyEndpoint) -> Option<(IpAddr, u16, IpProtocol)> {
    let ip: IpAddr = endpoint.ip.trim().parse().ok()?;
    if endpoint.port == 0 || !is_public_unreserved(&ip) {
        return None;
    }
    let protocol = match endpoint.protocol {
        ProxyProtocol::Tcp => IpProtocol::Tcp,
        ProxyProtocol::Udp => IpProtocol::Udp,
    };
    Some((ip, endpoint.port, protocol))
}

fn remote_address_condition(ip: IpAddr) -> Condition {
    match ip {
        IpAddr::V4(addr) => Condition::RemoteAddressV4 {
            addr: addr.octets(),
            prefix: 32,
        },
        IpAddr::V6(addr) => Condition::RemoteAddressV6 {
            addr: addr.octets(),
            prefix: 128,
        },
    }
}

fn layer_for(ip: IpAddr) -> LayerKind {
    match ip {
        IpAddr::V4(_) => LayerKind::AleAuthConnectV4,
        IpAddr::V6(_) => LayerKind::AleAuthConnectV6,
    }
}

/// The volatile session set, rebuilt per connect and per service start.
pub fn session_rules(config: &RuleConfig) -> Vec<FilterSpec> {
    use Condition as C;
    use FilterAction as A;
    use LayerKind as L;

    let mut filters = Vec::new();

    // A: the Tono-specific narrowing — the staged core may reach exactly the selected
    // endpoint, nothing else on the Internet.
    for endpoint in &config.endpoints {
        let Some((ip, port, protocol)) = parse_endpoint(endpoint) else {
            continue;
        };
        filters.push(spec(
            format!(
                "session/permit-endpoint/{}/{ip}/{port}/{}",
                config.app_path,
                protocol.number()
            ),
            "session permit core endpoint",
            layer_for(ip),
            WEIGHT_HARD_PERMIT,
            A::Permit,
            vec![
                C::AleAppId,
                remote_address_condition(ip),
                C::Protocol(protocol),
                C::RemotePort(port),
            ],
            false,
        ));
    }

    // B: tunnel interface, locked phase only. Until the adapter exists and lock runs, tunnel
    // traffic is blocked too — fail-closed.
    if config.mode == KillSwitchStatusMode::Locked
        && let Some(luid) = config.tun_luid
    {
        for layer in [L::AleAuthConnectV4, L::AleAuthConnectV6] {
            filters.push(spec(
                format!("session/permit-tunnel/{layer:?}/{luid}"),
                "session permit tunnel interface",
                layer,
                WEIGHT_HARD_PERMIT,
                A::Permit,
                vec![C::LocalInterface(luid)],
                false,
            ));
        }
    }

    // C: the bounded bootstrap API channel. Open in bootstrap, retracted at lock, and open
    // again in blocked mode as the recovery channel.
    if config.mode != KillSwitchStatusMode::Locked {
        for ip in &config.api_host_ips {
            filters.push(spec(
                format!("session/permit-api/{ip}"),
                "session permit bootstrap API",
                layer_for(*ip),
                WEIGHT_INFRA_PERMIT,
                A::Permit,
                vec![
                    remote_address_condition(*ip),
                    C::Protocol(IpProtocol::Tcp),
                    C::RemotePort(443),
                ],
                false,
            ));
        }
    }

    // G: cloud-approved DIRECT endpoints (WeChat acceleration). One exact `IP:port` permit
    // per tuple, hard-permit weight, and deliberately NOT app-scoped — the WeChat client
    // process needs the direct path just as much as the browser beside it.
    //
    // Locked only. A DIRECT plan exists to let specific traffic bypass the tunnel *while
    // connected*; in Bootstrap and in Blocked ("Protected Offline") there is no tunnel to
    // bypass and the user is told nothing gets out. Because these permits carry no app-id
    // condition, leaving them up in those modes would hand up to 256 (IP, port) tuples on
    // shared multi-tenant CDN addresses to every process on the machine, for a bypass whose
    // whole purpose is absent. The facade keeps the approved set in the armed session's memory
    // across a mode change, so re-locking re-renders it; the omission=clear contract still
    // decides when the set is empty. Retracting them is a mode change like any other: the
    // key-only diff removes exactly these keys, so nothing stale is left installed.
    if config.mode == KillSwitchStatusMode::Locked {
        for endpoint in &config.direct_endpoints {
            let Some((ip, port, protocol)) = parse_endpoint(endpoint) else {
                continue;
            };
            filters.push(spec(
                format!("session/permit-direct/{ip}/{port}/{}", protocol.number()),
                "session permit approved DIRECT",
                layer_for(ip),
                WEIGHT_HARD_PERMIT,
                A::Permit,
                vec![
                    remote_address_condition(ip),
                    C::Protocol(protocol),
                    C::RemotePort(port),
                ],
                false,
            ));
        }
    }

    // D: defense-in-depth hard DNS block. The floor's weight-8 loopback permit still wins for
    // 127.0.0.1/::1, so this blocks exactly non-loopback DNS.
    for layer in [L::AleAuthConnectV4, L::AleAuthConnectV6] {
        for protocol in [IpProtocol::Udp, IpProtocol::Tcp] {
            filters.push(spec(
                format!("session/block-dns/{layer:?}/{}", protocol.number()),
                "session block DNS",
                layer,
                WEIGHT_DNS_BLOCK,
                A::Block,
                vec![C::Protocol(protocol), C::RemotePort(53)],
                false,
            ));
        }
    }

    // E: redundant block-all, always present while armed. Never persistent — persistence is
    // reserved for the condition-free floor pair. Note non-persistent filters still outlive
    // the process in BFE's runtime store (until BFE restarts); only the PERSISTENT floor
    // survives a BFE restart or reboot, and service start reconciles the rest by key.
    for layer in [L::AleAuthConnectV4, L::AleAuthConnectV6] {
        filters.push(spec(
            format!("session/block-all/{layer:?}"),
            "session block all",
            layer,
            WEIGHT_BLOCK_ALL,
            A::Block,
            vec![],
            false,
        ));
    }

    filters
}

/// The complete expected filter set: the persistent intent floor plus the session set.
pub fn expected_filters(config: &RuleConfig) -> Vec<FilterSpec> {
    let mut filters = intent_floor();
    filters.extend(session_rules(config));
    filters
}

/// The shared reserved-range table: whether an IP is public unicast, usable for either a
/// bootstrap API host or a proxy endpoint. Documentation ranges (192.0.2.0/24 etc.) are
/// accepted — they are not local; the point is to keep these channels off
/// loopback/LAN/link-local/CGNAT space.
pub fn is_public_unreserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            !addr.is_private()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_multicast()
                && !addr.is_unspecified()
                && !addr.is_broadcast()
                // 100.64.0.0/10 carrier-grade NAT
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                // 198.18.0.0/15 benchmarking (RFC 2544)
                && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
                // 192.88.99.0/24 6to4 relay anycast (RFC 7526, deprecated)
                && !(octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                // 240.0.0.0/4 class E / reserved (broadcast already excluded above)
                && octets[0] < 240
        }
        IpAddr::V6(addr) => {
            !addr.is_loopback()
                && !addr.is_unspecified()
                && !addr.is_unique_local()
                && !addr.is_unicast_link_local()
                && !addr.is_multicast()
                // Reject v4-mapped forms; the contract is a native literal.
                && addr.to_ipv4_mapped().is_none()
        }
    }
}

/// Whether an IP may serve as a bootstrap API channel endpoint. Same table as endpoints.
pub fn is_public_api_ip(ip: &IpAddr) -> bool {
    is_public_unreserved(ip)
}

/// Bounded, deduplicated, public-only API host IP set, ready to be written into WFP.
pub fn sanitize_api_host_ips(ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut accepted: Vec<IpAddr> = Vec::new();
    for ip in ips {
        if !is_public_api_ip(&ip) || accepted.contains(&ip) {
            continue;
        }
        accepted.push(ip);
        if accepted.len() >= MAX_API_HOST_IPS {
            break;
        }
    }
    accepted
}

/// What must change to move the live set (`current`, by key) to `desired`.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan {
    pub install: Vec<FilterSpec>,
    pub remove: Vec<Guid>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
    Install(FilterSpec),
    Remove(Guid),
}

impl ChangePlan {
    /// Installs strictly before removes. When the endpoint changes, the new permit must be
    /// live before the old one is deleted — the core's selector moves only after the new WFP
    /// permit exists, so a switch never opens a direct window (Proton's ordering lesson).
    /// Teardown is the mirror: permits leave before any floor rule would be touched.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ordered_steps(&self) -> Vec<PlanStep> {
        self.install
            .iter()
            .cloned()
            .map(PlanStep::Install)
            .chain(self.remove.iter().copied().map(PlanStep::Remove))
            .collect()
    }
}

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub fn diff(current_keys: &[Guid], desired: &[FilterSpec]) -> ChangePlan {
    let install = desired
        .iter()
        .filter(|filter| !current_keys.contains(&filter.key))
        .cloned()
        .collect::<Vec<_>>();
    let desired_keys = desired.iter().map(|filter| filter.key).collect::<Vec<_>>();
    let remove = current_keys
        .iter()
        .filter(|key| !desired_keys.contains(key))
        .copied()
        .collect();
    ChangePlan { install, remove }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::structure::ProxyEndpoint;

    fn endpoint(ip: &str, port: u16) -> ProxyEndpoint {
        ProxyEndpoint {
            ip: ip.to_owned(),
            port,
            protocol: ProxyProtocol::Tcp,
        }
    }

    fn config(mode: KillSwitchStatusMode) -> RuleConfig {
        RuleConfig {
            mode,
            endpoints: vec![endpoint("8.8.8.8", 443)],
            api_host_ips: vec!["1.1.1.1".parse().unwrap()],
            tun_luid: Some(0x1234_5678),
            app_path: r"C:\ProgramData\Tono\bin\mihomo.exe".to_owned(),
            direct_endpoints: Vec::new(),
        }
    }

    fn has_condition(filters: &[FilterSpec], probe: &Condition) -> bool {
        filters
            .iter()
            .any(|filter| filter.conditions.contains(probe))
    }

    #[test]
    fn block_all_is_always_present_for_both_families() {
        for mode in [
            KillSwitchStatusMode::Bootstrap,
            KillSwitchStatusMode::Locked,
            KillSwitchStatusMode::Blocked,
        ] {
            let filters = expected_filters(&config(mode));
            // The persistent floor pair and the redundant session pair both exist, so every
            // connect layer ends in a condition-free block in every mode.
            for layer in [LayerKind::AleAuthConnectV4, LayerKind::AleAuthConnectV6] {
                let block_alls = filters
                    .iter()
                    .filter(|filter| {
                        filter.layer == layer
                            && filter.action == FilterAction::Block
                            && filter.conditions.is_empty()
                            && filter.weight == WEIGHT_BLOCK_ALL
                    })
                    .count();
                assert_eq!(
                    block_alls, 2,
                    "{mode:?}: missing block-all pair in {layer:?}"
                );
            }
        }
    }

    #[test]
    fn only_floor_blocks_are_persistent() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Locked));
        let persistent = filters
            .iter()
            .filter(|filter| filter.persistent)
            .collect::<Vec<_>>();
        assert_eq!(persistent.len(), 2);
        assert!(
            persistent.iter().all(|filter| {
                filter.action == FilterAction::Block && filter.conditions.is_empty()
            }),
            "persistence is reserved for the condition-free floor block"
        );
    }

    #[test]
    fn bootstrap_has_api_permit_but_no_tunnel_permit() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Bootstrap));
        assert!(has_condition(
            &filters,
            &Condition::RemoteAddressV4 {
                addr: [1, 1, 1, 1],
                prefix: 32
            }
        ));
        assert!(filters.iter().any(|filter| {
            filter.action == FilterAction::Permit
                && filter.weight == WEIGHT_INFRA_PERMIT
                && filter.conditions.contains(&Condition::RemotePort(443))
        }));
        assert!(
            !filters
                .iter()
                .flat_map(|filter| filter.conditions.iter())
                .any(|condition| matches!(condition, Condition::LocalInterface(_))),
            "bootstrap must not permit the tunnel"
        );
    }

    #[test]
    fn locked_has_tunnel_permit_but_no_api_permit() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Locked));
        let tun_permits = filters
            .iter()
            .filter(|filter| {
                filter
                    .conditions
                    .contains(&Condition::LocalInterface(0x1234_5678))
            })
            .count();
        assert_eq!(tun_permits, 2, "tunnel permit on v4 and v6 connect layers");
        assert!(
            !filters.iter().any(|filter| {
                filter.action == FilterAction::Permit
                    && filter.conditions.contains(&Condition::RemotePort(443))
                    && !filter.conditions.contains(&Condition::AleAppId)
            }),
            "locked must retract the bootstrap API channel"
        );
    }

    #[test]
    fn blocked_keeps_api_recovery_channel_without_tunnel() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Blocked));
        assert!(filters.iter().any(|filter| {
            filter.action == FilterAction::Permit
                && filter.weight == WEIGHT_INFRA_PERMIT
                && filter.conditions.contains(&Condition::RemotePort(443))
        }));
        assert!(
            !filters
                .iter()
                .flat_map(|filter| filter.conditions.iter())
                .any(|condition| matches!(condition, Condition::LocalInterface(_)))
        );
        // The endpoint permit (A) and DNS block (D) stay up while blocked.
        assert!(has_condition(&filters, &Condition::AleAppId));
        assert_eq!(
            filters
                .iter()
                .filter(|filter| filter.weight == WEIGHT_DNS_BLOCK)
                .count(),
            4
        );
    }

    #[test]
    fn endpoint_permit_is_app_scoped_and_exact() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Bootstrap));
        let permits = filters
            .iter()
            .filter(|filter| filter.conditions.contains(&Condition::AleAppId))
            .collect::<Vec<_>>();
        assert_eq!(permits.len(), 1, "only the selected endpoint is permitted");
        let conditions = &permits[0].conditions;
        assert!(conditions.contains(&Condition::RemoteAddressV4 {
            addr: [8, 8, 8, 8],
            prefix: 32
        }));
        assert!(conditions.contains(&Condition::RemotePort(443)));
        assert!(conditions.contains(&Condition::Protocol(IpProtocol::Tcp)));
        assert_eq!(permits[0].weight, WEIGHT_HARD_PERMIT);
        assert!(!permits[0].persistent);
    }

    #[test]
    fn rule_keys_are_deterministic() {
        let first = expected_filters(&config(KillSwitchStatusMode::Bootstrap));
        let second = expected_filters(&config(KillSwitchStatusMode::Bootstrap));
        assert_eq!(
            first.iter().map(|filter| filter.key).collect::<Vec<_>>(),
            second.iter().map(|filter| filter.key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn filter_namespace_marks_the_current_rule_table_version() {
        // Upgrade safety: the key-only diff adopts anything with a matching key, so the
        // namespace must change whenever the rule tables do. Pin the current marker (see the
        // constant's doc comment); any rule-table change must bump it and this pin.
        assert_eq!(FILTER_NAMESPACE >> 64, 0x2f7c_9e02_0000_4a6c);
    }

    #[test]
    fn moving_the_core_binary_rekeys_the_endpoint_permit() {
        let mut moved = config(KillSwitchStatusMode::Locked);
        moved.app_path = r"C:\ProgramData\Tono\bin\gen-2\mihomo.exe".to_owned();
        let before = expected_filters(&config(KillSwitchStatusMode::Locked));
        let after = expected_filters(&moved);
        let key_of = |filters: &[FilterSpec]| {
            filters
                .iter()
                .find(|filter| filter.conditions.contains(&Condition::AleAppId))
                .unwrap()
                .key
        };
        assert_ne!(
            key_of(&before),
            key_of(&after),
            "an installer moving the exe must rekey the app-id permit"
        );
        let plan = diff(
            &before.iter().map(|filter| filter.key).collect::<Vec<_>>(),
            &after,
        );
        assert_eq!(plan.install.len(), 1);
        assert_eq!(plan.remove.len(), 1);
    }

    #[test]
    fn a_new_tunnel_luid_rekeys_the_tunnel_permit() {
        let mut relanded = config(KillSwitchStatusMode::Locked);
        relanded.tun_luid = Some(0x9999);
        let before = expected_filters(&config(KillSwitchStatusMode::Locked));
        let after = expected_filters(&relanded);
        let tun_keys = |filters: &[FilterSpec]| {
            filters
                .iter()
                .filter(|filter| {
                    filter
                        .conditions
                        .iter()
                        .any(|condition| matches!(condition, Condition::LocalInterface(_)))
                })
                .map(|filter| filter.key)
                .collect::<Vec<_>>()
        };
        assert_ne!(tun_keys(&before), tun_keys(&after));
    }

    #[test]
    fn endpoint_switch_installs_new_permit_before_removing_old() {
        let old = expected_filters(&config(KillSwitchStatusMode::Locked));
        let mut switched = config(KillSwitchStatusMode::Locked);
        switched.endpoints = vec![endpoint("9.9.9.9", 8443)];
        let new = expected_filters(&switched);

        let old_permit = old
            .iter()
            .find(|filter| {
                filter.conditions.contains(&Condition::RemotePort(443))
                    && filter.conditions.contains(&Condition::AleAppId)
            })
            .unwrap()
            .key;
        let plan = diff(
            &old.iter().map(|filter| filter.key).collect::<Vec<_>>(),
            &new,
        );

        let new_permit = new
            .iter()
            .find(|filter| filter.conditions.contains(&Condition::RemotePort(8443)))
            .unwrap()
            .clone();
        assert!(plan.install.contains(&new_permit));
        assert!(plan.remove.contains(&old_permit));

        let steps = plan.ordered_steps();
        let install_at = steps
            .iter()
            .position(|step| *step == PlanStep::Install(new_permit.clone()))
            .unwrap();
        let remove_at = steps
            .iter()
            .position(|step| *step == PlanStep::Remove(old_permit))
            .unwrap();
        assert!(
            install_at < remove_at,
            "the new endpoint permit must be live before the old one is removed"
        );
        assert!(
            plan.remove
                .iter()
                .all(|key| !new.iter().any(|filter| filter.key == *key)),
            "nothing in the desired set may be removed"
        );
    }

    #[test]
    fn api_host_ips_are_public_bounded_and_deduplicated() {
        let rejected = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.88.99.1",
            "224.0.0.1",
            "240.0.0.1",
            "250.1.2.3",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:8.8.8.8",
        ];
        for ip in rejected {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_public_api_ip(&parsed), "accepted {ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "203.0.113.7"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_public_api_ip(&parsed), "rejected {ip}");
        }

        let many =
            (0..32).map(|index| IpAddr::from([8, 8, (index / 256) as u8, (index % 256) as u8 + 1]));
        let sanitized = sanitize_api_host_ips(
            ["1.1.1.1".parse().unwrap(), "1.1.1.1".parse().unwrap()]
                .into_iter()
                .chain(many),
        );
        assert!(sanitized.len() <= MAX_API_HOST_IPS);
        assert_eq!(
            sanitized
                .iter()
                .filter(|ip| **ip == "1.1.1.1".parse::<IpAddr>().unwrap())
                .count(),
            1,
            "duplicates collapse"
        );
    }

    #[test]
    fn session_rules_are_never_persistent() {
        let config = config(KillSwitchStatusMode::Bootstrap);
        for filter in session_rules(&config) {
            assert!(
                !filter.persistent,
                "volatile session rules must not be persistent: {}",
                filter.name
            );
        }
    }

    #[test]
    fn locked_without_a_luid_renders_no_tunnel_permit() {
        let mut config = config(KillSwitchStatusMode::Locked);
        config.tun_luid = None;
        let filters = expected_filters(&config);
        assert!(
            !filters
                .iter()
                .flat_map(|filter| filter.conditions.iter())
                .any(|condition| matches!(condition, Condition::LocalInterface(_))),
            "lock without a resolved LUID must not guess a tunnel permit"
        );
        // And the rest of the locked policy still stands (fail-closed).
        assert!(has_condition(&filters, &Condition::AleAppId));
    }

    #[test]
    fn multiple_endpoints_each_get_an_exact_permit() {
        let mut config = config(KillSwitchStatusMode::Bootstrap);
        config.endpoints = vec![
            endpoint("8.8.8.8", 443),
            endpoint("9.9.9.9", 8443),
            ProxyEndpoint {
                ip: "2606:4700:4700::1111".to_owned(),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            },
        ];
        let filters = session_rules(&config);
        let permits = filters
            .iter()
            .filter(|filter| filter.conditions.contains(&Condition::AleAppId))
            .collect::<Vec<_>>();
        assert_eq!(permits.len(), 3);
        assert!(has_condition(
            &filters,
            &Condition::RemoteAddressV4 {
                addr: [9, 9, 9, 9],
                prefix: 32
            }
        ));
        assert!(has_condition(&filters, &Condition::RemotePort(8443)));
        assert!(
            permits
                .iter()
                .any(|filter| filter.layer == LayerKind::AleAuthConnectV6),
            "v6 endpoint lands on the v6 connect layer"
        );
        assert_ne!(
            permits[0].key, permits[1].key,
            "each endpoint permit has its own deterministic key"
        );
    }

    #[test]
    fn invalid_endpoints_render_no_permit_and_stay_fail_closed() {
        for bad in [
            endpoint("not-an-ip", 443),
            endpoint("0.0.0.0", 443),
            endpoint("::", 443),
            endpoint("8.8.8.8", 0),
            endpoint("127.0.0.1", 443),   // loopback
            endpoint("10.0.0.8", 443),    // private
            endpoint("192.168.1.8", 443), // private
            endpoint("169.254.1.8", 443), // link-local
            endpoint("100.64.0.8", 443),  // CGNAT
            endpoint("fe80::8", 443),     // v6 link-local
            endpoint("fc00::8", 443),     // ULA
        ] {
            assert!(
                parse_endpoint(&bad).is_none(),
                "accepted invalid endpoint {}:{}",
                bad.ip,
                bad.port
            );
        }
        let mut config = config(KillSwitchStatusMode::Bootstrap);
        config.endpoints = vec![endpoint("10.0.0.8", 443)];
        let filters = expected_filters(&config);
        assert!(
            !has_condition(&filters, &Condition::AleAppId),
            "a rejected endpoint must produce no app-id permit"
        );
        // Fail closed: with no endpoint permit, the endpoint IP itself is blocked.
        let packet = packet(
            LayerKind::AleAuthConnectV4,
            IpProtocol::Tcp,
            "10.0.0.8",
            443,
        );
        assert_eq!(arbitrate(&filters, &packet), FilterAction::Block);
    }

    // --- C1 arbitration simulator -----------------------------------------------------
    //
    // MSDN filter arbitration (https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration):
    // sublayers are traversed highest-weight first; within a sublayer, filters are ordered by
    // descending weight; the first matching filter with a terminating action (permit/block)
    // ends arbitration. This simulator pins those semantics so the rule tables can never
    // again rely on the inverse (wrong) "filter weight first" ordering.

    #[derive(Debug, Clone)]
    struct Packet {
        layer: LayerKind,
        protocol: IpProtocol,
        remote_ip: IpAddr,
        local_port: Option<u16>,
        remote_port: u16,
        icmp_type: Option<u16>,
        app_id_matches: bool,
        local_interface: Option<u64>,
    }

    fn packet(layer: LayerKind, protocol: IpProtocol, ip: &str, port: u16) -> Packet {
        Packet {
            layer,
            protocol,
            remote_ip: ip.parse().unwrap(),
            local_port: None,
            remote_port: port,
            icmp_type: None,
            app_id_matches: false,
            local_interface: None,
        }
    }

    fn v4_prefix_matches(addr: [u8; 4], network: [u8; 4], prefix: u8) -> bool {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        u32::from_be_bytes(addr) & mask == u32::from_be_bytes(network) & mask
    }

    fn v6_prefix_matches(addr: [u8; 16], network: [u8; 16], prefix: u8) -> bool {
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        u128::from_be_bytes(addr) & mask == u128::from_be_bytes(network) & mask
    }

    fn condition_matches(condition: &Condition, packet: &Packet) -> bool {
        match condition {
            Condition::RemoteAddressV4 { addr, prefix } => match packet.remote_ip {
                IpAddr::V4(ip) => v4_prefix_matches(ip.octets(), *addr, *prefix),
                IpAddr::V6(_) => false,
            },
            Condition::RemoteAddressV6 { addr, prefix } => match packet.remote_ip {
                IpAddr::V6(ip) => v6_prefix_matches(ip.octets(), *addr, *prefix),
                IpAddr::V4(_) => false,
            },
            Condition::Protocol(protocol) => *protocol == packet.protocol,
            Condition::LocalPort(port) => packet.local_port == Some(*port),
            Condition::RemotePort(port) => *port == packet.remote_port,
            Condition::IcmpV6TypeRange { min, max } => packet
                .icmp_type
                .is_some_and(|ty| (*min..=*max).contains(&ty)),
            Condition::AleAppId => packet.app_id_matches,
            Condition::LocalInterface(luid) => packet.local_interface == Some(*luid),
        }
    }

    fn filter_matches(filter: &FilterSpec, packet: &Packet) -> bool {
        filter.layer == packet.layer
            && filter
                .conditions
                .iter()
                .all(|condition| condition_matches(condition, packet))
    }

    fn arbitrate(filters: &[FilterSpec], packet: &Packet) -> FilterAction {
        let mut matched = filters
            .iter()
            .filter(|filter| filter_matches(filter, packet))
            .collect::<Vec<_>>();
        // One sublayer for everything, so MSDN arbitration reduces to filter weight only:
        // highest weight first, first terminating match wins.
        matched.sort_by_key(|filter| filter.weight);
        matched
            .last()
            .map(|filter| filter.action)
            .expect("every layer must end in a block-all")
    }

    #[test]
    fn arbitration_keeps_infrastructure_open_in_every_mode() {
        for mode in [
            KillSwitchStatusMode::Bootstrap,
            KillSwitchStatusMode::Locked,
            KillSwitchStatusMode::Blocked,
        ] {
            let filters = expected_filters(&config(mode));
            let cases: &[(Packet, FilterAction, &str)] = &[
                (
                    packet(
                        LayerKind::AleAuthConnectV4,
                        IpProtocol::Tcp,
                        "127.0.0.1",
                        53,
                    ),
                    FilterAction::Permit,
                    "loopback tcp/53",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV4,
                        IpProtocol::Udp,
                        "127.0.0.1",
                        53,
                    ),
                    FilterAction::Permit,
                    "loopback udp/53",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV4,
                        IpProtocol::Udp,
                        "127.0.0.53",
                        5353,
                    ),
                    FilterAction::Permit,
                    "loopback /8 udp/5353",
                ),
                (
                    packet(LayerKind::AleAuthConnectV6, IpProtocol::Udp, "::1", 53),
                    FilterAction::Permit,
                    "loopback v6 udp/53",
                ),
                (
                    {
                        let mut packet = packet(
                            LayerKind::AleAuthConnectV4,
                            IpProtocol::Udp,
                            "192.168.1.2",
                            67,
                        );
                        packet.local_port = Some(68);
                        packet
                    },
                    FilterAction::Permit,
                    "DHCPv4 client",
                ),
                (
                    {
                        let mut packet = packet(
                            LayerKind::AleAuthConnectV4,
                            IpProtocol::Udp,
                            "203.0.113.8",
                            67,
                        );
                        packet.local_port = Some(49_152);
                        packet
                    },
                    FilterAction::Block,
                    "non-DHCP source to udp/67",
                ),
                (
                    {
                        let mut packet =
                            packet(LayerKind::AleAuthConnectV6, IpProtocol::Udp, "fe80::1", 547);
                        packet.local_port = Some(546);
                        packet
                    },
                    FilterAction::Permit,
                    "DHCPv6 client to server",
                ),
                (
                    {
                        let mut packet = packet(
                            LayerKind::AleAuthConnectV6,
                            IpProtocol::Udp,
                            "2001:db8::1",
                            547,
                        );
                        packet.local_port = Some(49_152);
                        packet
                    },
                    FilterAction::Block,
                    "non-DHCPv6 source to udp/547",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV4,
                        IpProtocol::Udp,
                        "162.159.200.123",
                        123,
                    ),
                    FilterAction::Block,
                    "NTP v4 has no physical-network bypass",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV6,
                        IpProtocol::Udp,
                        "2606:4700:4700::1234",
                        123,
                    ),
                    FilterAction::Block,
                    "NTP v6 has no physical-network bypass",
                ),
                (
                    packet(LayerKind::AleAuthConnectV4, IpProtocol::Udp, "9.9.9.9", 53),
                    FilterAction::Block,
                    "direct udp/53",
                ),
                (
                    packet(LayerKind::AleAuthConnectV4, IpProtocol::Tcp, "9.9.9.9", 53),
                    FilterAction::Block,
                    "direct tcp/53",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV6,
                        IpProtocol::Udp,
                        "2606:4700:4700::1111",
                        53,
                    ),
                    FilterAction::Block,
                    "direct v6 udp/53",
                ),
                (
                    packet(LayerKind::AleAuthConnectV4, IpProtocol::Tcp, "9.9.9.9", 443),
                    FilterAction::Block,
                    "arbitrary tcp",
                ),
                (
                    packet(
                        LayerKind::AleAuthConnectV6,
                        IpProtocol::Tcp,
                        "2606:4700:4700::1111",
                        443,
                    ),
                    FilterAction::Block,
                    "arbitrary v6 tcp",
                ),
            ];
            for (packet, expected, label) in cases {
                assert_eq!(arbitrate(&filters, packet), *expected, "{mode:?}: {label}");
            }
            for ty in 133..=137_u16 {
                let mut outbound = packet(
                    LayerKind::AleAuthConnectV6,
                    IpProtocol::IcmpV6,
                    "fe80::1",
                    0,
                );
                outbound.icmp_type = Some(ty);
                assert_eq!(
                    arbitrate(&filters, &outbound),
                    FilterAction::Permit,
                    "{mode:?}: NDP outbound type {ty}"
                );
                let mut inbound = packet(
                    LayerKind::AleAuthRecvAcceptV6,
                    IpProtocol::IcmpV6,
                    "fe80::1",
                    0,
                );
                inbound.icmp_type = Some(ty);
                assert_eq!(
                    arbitrate(&filters, &inbound),
                    FilterAction::Permit,
                    "{mode:?}: NDP inbound type {ty}"
                );
            }
        }
    }

    #[test]
    fn arbitration_endpoint_permit_requires_the_staged_app_id() {
        let filters = expected_filters(&config(KillSwitchStatusMode::Bootstrap));
        let mut packet = packet(LayerKind::AleAuthConnectV4, IpProtocol::Tcp, "8.8.8.8", 443);
        packet.app_id_matches = true;
        assert_eq!(arbitrate(&filters, &packet), FilterAction::Permit);
        packet.app_id_matches = false;
        assert_eq!(
            arbitrate(&filters, &packet),
            FilterAction::Block,
            "another binary must not inherit the endpoint permit"
        );
    }

    #[test]
    fn arbitration_api_channel_open_in_bootstrap_and_blocked_retracted_in_locked() {
        let packet = packet(LayerKind::AleAuthConnectV4, IpProtocol::Tcp, "1.1.1.1", 443);
        assert_eq!(
            arbitrate(
                &expected_filters(&config(KillSwitchStatusMode::Bootstrap)),
                &packet
            ),
            FilterAction::Permit
        );
        assert_eq!(
            arbitrate(
                &expected_filters(&config(KillSwitchStatusMode::Blocked)),
                &packet
            ),
            FilterAction::Permit
        );
        assert_eq!(
            arbitrate(
                &expected_filters(&config(KillSwitchStatusMode::Locked)),
                &packet
            ),
            FilterAction::Block,
            "locked must retract the bootstrap API channel"
        );
    }

    #[test]
    fn arbitration_tunnel_permitted_only_when_locked() {
        let mut packet = packet(LayerKind::AleAuthConnectV4, IpProtocol::Tcp, "9.9.9.9", 443);
        packet.local_interface = Some(0x1234_5678);
        assert_eq!(
            arbitrate(
                &expected_filters(&config(KillSwitchStatusMode::Locked)),
                &packet
            ),
            FilterAction::Permit
        );
        for mode in [
            KillSwitchStatusMode::Bootstrap,
            KillSwitchStatusMode::Blocked,
        ] {
            assert_eq!(
                arbitrate(&expected_filters(&config(mode)), &packet),
                FilterAction::Block,
                "{mode:?}: tunnel traffic must stay blocked until lock"
            );
        }
    }

    fn config_with_direct_endpoints(mode: KillSwitchStatusMode) -> RuleConfig {
        let mut config = config(mode);
        config.direct_endpoints = vec![
            endpoint("203.0.113.9", 443),
            ProxyEndpoint {
                ip: "203.0.113.10".to_owned(),
                port: 8000,
                protocol: ProxyProtocol::Udp,
            },
        ];
        config
    }

    #[test]
    fn direct_endpoints_are_permitted_exactly_for_any_process_while_locked() {
        let filters = expected_filters(&config_with_direct_endpoints(KillSwitchStatusMode::Locked));

        // Exact tuples permitted — with app_id_matches = false, proving the permits are
        // not app-scoped (the WeChat client itself must use them).
        let tcp = packet(
            LayerKind::AleAuthConnectV4,
            IpProtocol::Tcp,
            "203.0.113.9",
            443,
        );
        assert_eq!(arbitrate(&filters, &tcp), FilterAction::Permit);
        let udp = packet(
            LayerKind::AleAuthConnectV4,
            IpProtocol::Udp,
            "203.0.113.10",
            8000,
        );
        assert_eq!(arbitrate(&filters, &udp), FilterAction::Permit);

        // Same IP, wrong port: blocked. Wrong IP: blocked.
        let wrong_port = packet(
            LayerKind::AleAuthConnectV4,
            IpProtocol::Tcp,
            "203.0.113.9",
            8443,
        );
        assert_eq!(arbitrate(&filters, &wrong_port), FilterAction::Block);
        let wrong_ip = packet(
            LayerKind::AleAuthConnectV4,
            IpProtocol::Tcp,
            "203.0.113.11",
            443,
        );
        assert_eq!(arbitrate(&filters, &wrong_ip), FilterAction::Block);

        // And the DIRECT permit is hard-permit weight without an app-id condition.
        let permit = filters
            .iter()
            .find(|filter| {
                filter.conditions.contains(&Condition::RemoteAddressV4 {
                    addr: [203, 0, 113, 9],
                    prefix: 32,
                })
            })
            .expect("direct permit must exist");
        assert_eq!(permit.weight, WEIGHT_HARD_PERMIT);
        assert!(!permit.conditions.contains(&Condition::AleAppId));

        // Omission renders nothing.
        let without = expected_filters(&config(KillSwitchStatusMode::Locked));
        assert!(
            !without.iter().any(|filter| filter.name.contains("DIRECT")),
            "no direct endpoints configured, no DIRECT permits"
        );
    }

    /// The contract this replaces was "present in every mode while armed". A DIRECT permit is
    /// a hole in the tunnel, and it carries no app-id condition, so in the two modes where no
    /// tunnel exists it is a hole for every process on the machine into nothing. Bootstrap and
    /// Blocked must therefore arbitrate the exact approved tuples to Block, and the rendered
    /// set must not merely down-weight them — the permits must be absent, so the key-only diff
    /// removes them when the mode changes instead of leaving them installed.
    #[test]
    fn direct_permits_are_absent_and_blocked_outside_locked() {
        for mode in [
            KillSwitchStatusMode::Bootstrap,
            KillSwitchStatusMode::Blocked,
        ] {
            let filters = expected_filters(&config_with_direct_endpoints(mode));
            assert!(
                !filters.iter().any(|filter| filter.name.contains("DIRECT")),
                "{mode:?}: no tunnel exists, so no DIRECT permit may be installed"
            );
            for (protocol, ip, port) in [
                (IpProtocol::Tcp, "203.0.113.9", 443_u16),
                (IpProtocol::Udp, "203.0.113.10", 8000),
            ] {
                let approved = packet(LayerKind::AleAuthConnectV4, protocol, ip, port);
                assert_eq!(
                    arbitrate(&filters, &approved),
                    FilterAction::Block,
                    "{mode:?}: {ip}:{port} must not escape while disconnected"
                );
            }
        }

        // The mode change is what retracts them: every DIRECT key rendered while locked is in
        // the removal set once the switch drops back to Blocked, and nothing survives it.
        let locked = expected_filters(&config_with_direct_endpoints(KillSwitchStatusMode::Locked));
        let blocked =
            expected_filters(&config_with_direct_endpoints(KillSwitchStatusMode::Blocked));
        let direct_keys = locked
            .iter()
            .filter(|filter| filter.name.contains("DIRECT"))
            .map(|filter| filter.key)
            .collect::<Vec<_>>();
        assert_eq!(direct_keys.len(), 2);
        let plan = diff(
            &locked.iter().map(|filter| filter.key).collect::<Vec<_>>(),
            &blocked,
        );
        assert!(
            direct_keys.iter().all(|key| plan.remove.contains(key)),
            "a mode change must never leave a stale DIRECT permit installed"
        );
    }
}
