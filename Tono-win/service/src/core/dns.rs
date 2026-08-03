//! Per-adapter DNS protection for the Windows kill switch.
//!
//! Snapshot every adapter's IPv4/IPv6 `NameServer`/`ProfileNameServer` → point IPv4 at the
//! loopback resolver (`127.0.0.1`) and leave IPv6 with **no servers at all** → verify by
//! read-back → restore from the snapshot on disconnect. The snapshot (`protected-dns.json`) is
//! written atomically to the service state directory *before* any value is changed — the same
//! discipline as the kill-switch intent record.
//!
//! **Why IPv6 gets an empty server list and not `::1`.** The core listens on
//! `tono_core::config::DNS_LISTEN` = `127.0.0.1:53` — IPv4 only. Nothing has ever listened on
//! `[::1]:53`. A build that pointed the IPv6 family at `::1` therefore configured a resolver
//! that never answers, and every system lookup that Windows tried over IPv6 first waited out
//! its full timeout: the fake-ip readiness probe failed three attempts at 2 s each and connect
//! died in `securingDNS` on a machine whose DNS was otherwise fine. Nothing was bought for it —
//! IPv6 DNS to a physical resolver is already *blocked* by WFP (the weight-6 `block-dns` filter
//! on `CONNECT_V6` plus the condition-free v6 block-all), so `::1` prevented no leak. The
//! protected IPv6 state is an empty **static** list ([`NO_NAME_SERVERS`]) — deliberately not
//! DHCP, which would hand the ISP's resolvers straight back and *would* be a leak — so Windows
//! falls through to the IPv4 loopback resolver, which answers. `::1` is still *recognised* as a
//! protected/loopback value everywhere on the proof path, because adapters left that way by an
//! older build must not read as restored.
//!
//! **DNS-before-disarm invariant (identical to the macOS helper):** the kill switch may only
//! disarm after DNS restore is *proven*; if restore cannot be proven, the disarm is refused
//! and the block stays armed. See `windows_kill_switch::disarm_unlocked`.
//!
//! **Proof is read off the machine as it is now, never off history:** a restore is proven when
//! the registry read-back matches the snapshot exactly *and* a live read says that nothing on
//! the machine still resolves through the loopback core. Per-adapter live-apply results are
//! still recorded (in memory and in the snapshot file) and a failed live-apply is still retried
//! once during restore, but a `live_apply_failed` bit from an earlier round is a reason to
//! *demand* that live evidence — never a veto over evidence that is already in. It used to be
//! a veto, and that is exactly how a machine whose resolvers were provably the user's own again
//! (`registry_match=true`) was refused release on a single stale failure while the degraded
//! exit below needs a streak of three that one click on Disconnect can never reach. Evidence
//! that cannot be obtained is *unproven*, never proven — fail-closed for the normal disarm,
//! while the emergency path stays the documented escape hatch (it logs and proceeds).
//!
//! **The live apply is per address family.** IPv4 goes through CIM
//! (`SetDNSServerSearchOrder`, an IPv4-only method), IPv6 through `netsh interface ipv6 set
//! dnsservers`, and each family is proven by its own live read-back. Merging both families into
//! one CIM call either fails on every adapter or silently drops the IPv6 address, which leaves
//! an IPv6 resolver leaking while the registry still reads "protected".
//!
//! **Degraded exit (`docs/wfp-kill-switch.md`):** a registry-only match is not accepted as a
//! normal restore — but it *is* accepted, once, after the live apply has failed
//! `DEGRADED_RESTORE_STREAK` rounds in a row and the registry read-back matches the snapshot
//! exactly. On a machine where PowerShell/CIM is structurally unavailable (constrained-language
//! mode, AppLocker, a broken WMI repository, an EDR blocking
//! `Win32_NetworkAdapterConfiguration`) the live proof can never succeed, and without this exit
//! Disconnect, Sign Out and Quit are refused forever — the Protected-Offline deadlock this
//! design explicitly prevents. The acceptance is never silent: it carries
//! `DNS_RESTORE_DEGRADED_PREFIX` in `last_error` and in the status payload. Everything short
//! of that stays fail-closed, because automatically opening WFP while the live resolver may
//! still point at a dead loopback server strands the machine in an ambiguous and often
//! unrecoverable network state.
//!
//! **Nothing here may hang, and nothing here may become permanently unsatisfiable.** Every
//! engine call is bounded and holds a single-writer claim (`bounded_dns_call`), so an
//! unreturning Dnscache/registry/loader call fails the operation instead of parking the DNS
//! operation lock for the lifetime of the service. And a `protected-dns.json` this build cannot
//! read is recovered from live evidence (`recover_unreadable_snapshot`) rather than turning
//! the disarm gate into a permanent lockout — but only when nothing on the machine still
//! resolves through the loopback core.
//!
//! The pure snapshot/merge/restore-decision logic in this file is platform-independent and
//! unit-tested on any host; the registry/CIM/netsh engine is compiled only on Windows.

use crate::core::structure::DnsProtectionStatus;
use anyhow::{Context as _, Result, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const ENGINE_LIVE: bool = cfg!(all(windows, not(feature = "test")));

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub(crate) const LOOPBACK_V4: &str = "127.0.0.1";
/// The IPv6 loopback address. **Recognised, never written.** Nothing listens on `[::1]:53`, so
/// the protect path uses [`NO_NAME_SERVERS`] instead (see the module docs); this constant stays
/// because an adapter left on `::1` by an older build must still be recognised as protected on
/// the restore-proof path, or an upgrade would mis-prove a restore that never happened.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub(crate) const LOOPBACK_V6: &str = "::1";
/// The protected IPv6 state: a *static* server list with nothing in it, which the registry
/// stores as an empty `NameServer`. Distinct from deleting the value, which means DHCP and
/// would put the ISP's resolvers back.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub(crate) const NO_NAME_SERVERS: &str = "";
const SNAPSHOT_VERSION: u32 = 1;

/// One adapter's original DNS values. `None` means the registry value was absent — the
/// typical DHCP state — and restore must delete rather than rewrite it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub(crate) struct AdapterDnsSnapshot {
    pub interface_guid: String,
    pub ipv4_name_server: Option<String>,
    pub ipv4_profile_name_server: Option<String>,
    pub ipv6_name_server: Option<String>,
    pub ipv6_profile_name_server: Option<String>,
    /// The last CIM live-apply for this adapter failed, so the running resolver cannot be
    /// trusted to match the registry until a retry succeeds. Recorded in memory and in the
    /// snapshot file. It forces the loopback write to be replayed on the next enable
    /// ([`needs_loopback_replay`]) and it is why the restore proof insists on live evidence —
    /// but it does **not** by itself refuse a restore whose live state is verifiably correct
    /// (see [`restore_is_proven`] and the module docs).
    #[serde(default)]
    pub live_apply_failed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DnsSnapshot {
    pub version: u32,
    pub taken_at: u64,
    pub adapters: Vec<AdapterDnsSnapshot>,
}

fn snapshot_path() -> PathBuf {
    crate::service_paths()
        .persistent_state_dir()
        .join("protected-dns.json")
}

static DNS_OPERATION: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));
static DNS_LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// --- Pure logic (platform-independent, unit-tested below) ---

/// Registry `NameServer` values are comma-separated; tolerate spaces and empty segments.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn parse_name_server_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|server| !server.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// DNS servers the live apply should restore for **one address family**. `ProfileNameServer`
/// overrides `NameServer` when populated. `None` means "no saved value": restore DHCP for that
/// family.
///
/// The two families are deliberately never merged into one list. `SetDNSServerSearchOrder` on
/// `Win32_NetworkAdapterConfiguration` is documented for IPv4 addresses only, so a mixed
/// `["127.0.0.1", "::1"]` array is either rejected outright (every adapter fails forever) or —
/// worse — silently truncated to its IPv4 element, leaving the IPv6 resolver pointing at the
/// previous ISP/DHCP server while the registry read-back still reports "protected". Each
/// family now travels through its own mechanism and is proven separately (`engine`).
///
/// A saved value that is present but *empty* still maps to `None` (restore DHCP), even though
/// an empty static list is what the protect path now writes for IPv6. Windows leaves an empty
/// `NameServer` behind on perfectly ordinary DHCP adapters, so the registry cannot tell "the
/// user chose static-with-no-servers" from "this family is on DHCP"; guessing static there
/// would strand a DHCP machine with no resolvers at all. This never affects the protected
/// state, which is read from the *snapshot* — the values as they were before Tono touched
/// them — and the four exact registry values are written back verbatim regardless
/// (`engine::apply_snapshot`), which is what the restore proof compares.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn restored_family_servers(profile: Option<&str>, base: Option<&str>) -> Option<Vec<String>> {
    let profile = profile.map(parse_name_server_list).unwrap_or_default();
    let effective = if profile.is_empty() {
        base.map(parse_name_server_list).unwrap_or_default()
    } else {
        profile
    };
    let mut restored: Vec<String> = Vec::new();
    for server in effective {
        if !restored.contains(&server) {
            restored.push(server);
        }
    }
    (!restored.is_empty()).then_some(restored)
}

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn restored_live_servers_v4(adapter: &AdapterDnsSnapshot) -> Option<Vec<String>> {
    restored_family_servers(
        adapter.ipv4_profile_name_server.as_deref(),
        adapter.ipv4_name_server.as_deref(),
    )
}

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn restored_live_servers_v6(adapter: &AdapterDnsSnapshot) -> Option<Vec<String>> {
    restored_family_servers(
        adapter.ipv6_profile_name_server.as_deref(),
        adapter.ipv6_name_server.as_deref(),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn format_name_server_list(servers: &[String]) -> String {
    servers.join(",")
}

/// Whether a read-back value points at the loopback core: loopback only, nothing else.
///
/// This is the *recognition* predicate — "is the machine still resolving through a core that
/// may no longer be running?" — and it is what the restore-proof path asks. Its meaning must
/// not drift with the protect path: `::1` still counts, because an adapter left there by an
/// older build is still pointed at a resolver that never answers.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn is_loopback_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let servers = parse_name_server_list(value);
    !servers.is_empty()
        && servers
            .iter()
            .all(|server| server == LOOPBACK_V4 || server == LOOPBACK_V6)
}

/// Whether a read-back **IPv6** value is the protected state — the question "is this adapter
/// still protected?", which for IPv6 is not the same question as [`is_loopback_value`].
///
/// The protect path writes an empty static list, so an empty value is the protected state and
/// must *not* read as drift: otherwise the watchdog would see every adapter as unprotected on
/// every tick and rewrite the registry forever. A value absent altogether is DHCP — the ISP's
/// resolvers — and is genuinely unprotected. `::1` is accepted so that an upgrade over a build
/// that wrote it does not trigger a pointless machine-wide replay.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn is_protected_v6_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    parse_name_server_list(value).is_empty() || is_loopback_value(Some(value))
}

/// Idempotent enable: preserve every original already recorded, but append adapters that appeared
/// after protection started. Replacing an existing record would snapshot our loopback values and
/// destroy the way back; ignoring fresh GUIDs would leave a hot-plugged adapter unprotected.
fn merge_snapshot(existing: Option<DnsSnapshot>, fresh: DnsSnapshot) -> DnsSnapshot {
    let Some(mut existing) = existing else {
        return fresh;
    };
    for adapter in fresh.adapters {
        if !existing
            .adapters
            .iter()
            .any(|saved| saved.interface_guid == adapter.interface_guid)
        {
            existing.adapters.push(adapter);
        }
    }
    existing
}

/// Short-circuiting `enable` is only safe when a snapshot exists, the adapters are actually on
/// loopback, AND no live-apply failure is recorded (memory or snapshot). With no snapshot this is
/// the initial enable, so it must capture the originals and apply loopback. Anything else replays
/// the write — which also retries the live-apply — against the *original* snapshot.
fn needs_loopback_replay(
    snapshot_present: bool,
    all_loopback: bool,
    live_apply_failed: bool,
) -> bool {
    !snapshot_present || !all_loopback || live_apply_failed
}

/// Registry-only comparison of one adapter: the four saved values against the read-back
/// (deliberately excluding the `live_apply_failed` bookkeeping flag).
fn registry_values_match(saved: &AdapterDnsSnapshot, current: &AdapterDnsSnapshot) -> bool {
    saved.interface_guid == current.interface_guid
        && saved.ipv4_name_server == current.ipv4_name_server
        && saved.ipv4_profile_name_server == current.ipv4_profile_name_server
        && saved.ipv6_name_server == current.ipv6_name_server
        && saved.ipv6_profile_name_server == current.ipv6_profile_name_server
}

/// Whether the registry alone looks restored: the *degraded* leg of the proof, accepted only
/// under the rules in [`accepts_degraded_restore`].
fn registry_restore_matches(snapshot: &DnsSnapshot, current: &[AdapterDnsSnapshot]) -> bool {
    snapshot.adapters.iter().all(|saved| {
        current
            .iter()
            .find(|adapter| adapter.interface_guid == saved.interface_guid)
            .is_none_or(|adapter| registry_values_match(saved, adapter))
    })
}

/// Restore is proven from the machine's **current** state, on two pieces of evidence together:
/// every snapshotted adapter that is still present in the live read reads back exactly its
/// saved values, *and* the live read says nothing on this machine still resolves through the
/// loopback core. A registry match alone does not prove the second half, which is why
/// `live_loopback` is a parameter and not an afterthought.
///
/// `live_loopback` carries that second half: `Some(false)` = nothing is on loopback (the only
/// answer that can prove a restore), `Some(true)` = something provably still is (refused,
/// unconditionally — this is the ordering invariant the disarm gate exists for), `None` = the
/// engine could not be asked. Unobtainable evidence is *unproven*, never proven: it falls
/// through to [`accepts_degraded_restore`], which still demands an exact registry match and a
/// sustained failure streak.
///
/// What is deliberately **not** consulted: `live_apply_failed`. It records what happened in an
/// earlier round, and using it as a veto is the defect this signature exists to fix — on a real
/// machine the registry held the user's own resolvers again and nothing was on loopback, yet
/// the release was refused because one adapter still carried the flag, and the degraded exit
/// that is supposed to prevent exactly that deadlock needs three consecutive failures, which a
/// user clicking Disconnect once never reaches. A historical failure is a reason to *demand*
/// live evidence (the caller always gathers it), never a reason to overrule it.
///
/// An adapter that has vanished from the live read (disabled, unplugged, or no longer holding a
/// bound IP stack) counts as proven: it has no running resolver left to leak through, and no
/// amount of retrying can configure hardware that is not there. Demanding proof from an absent
/// adapter would be an unrecoverable deadlock with no fail-closed benefit — the registry values
/// it left behind are restored regardless, and if it comes back it comes back restored.
fn restore_is_proven(
    snapshot: &DnsSnapshot,
    current: &[AdapterDnsSnapshot],
    live_loopback: Option<bool>,
) -> bool {
    if live_loopback != Some(false) {
        return false;
    }
    snapshot.adapters.iter().all(|saved| {
        current
            .iter()
            .find(|adapter| adapter.interface_guid == saved.interface_guid)
            .is_none_or(|adapter| registry_values_match(saved, adapter))
    })
}

/// Whether the values saved for this adapter were *themselves* a loopback resolver.
fn saved_dns_was_loopback(saved: &AdapterDnsSnapshot) -> bool {
    is_loopback_value(saved.ipv4_name_server.as_deref())
        || is_loopback_value(saved.ipv4_profile_name_server.as_deref())
        || is_loopback_value(saved.ipv6_name_server.as_deref())
        || is_loopback_value(saved.ipv6_profile_name_server.as_deref())
}

/// The adapters the live loopback read has to cover: everything present now, minus the ones
/// whose *originals* were already a loopback resolver.
///
/// A machine that ran its own local resolver before Tono started (Acrylic, dnscrypt-proxy, a
/// local Pi-hole) had `127.0.0.1` in the registry all along, and a correct restore puts it
/// straight back. Asking the blunt "is anything on loopback?" question over that adapter would
/// answer "yes" after every successful restore and refuse every disconnect for ever — the same
/// class of deadlock this module keeps having to design out. The evidence the disarm gate
/// actually needs is narrower: is anything on loopback that the snapshot says should not be?
fn adapters_owing_live_proof(
    snapshot: &DnsSnapshot,
    current: &[AdapterDnsSnapshot],
) -> Vec<AdapterDnsSnapshot> {
    current
        .iter()
        .filter(|adapter| {
            !snapshot.adapters.iter().any(|saved| {
                saved.interface_guid == adapter.interface_guid && saved_dns_was_loopback(saved)
            })
        })
        .cloned()
        .collect()
}

/// How the live loopback evidence reads in an operator-facing message. `unknown` is its own
/// state on purpose: "we could not look" must never be reported as "nothing was found".
fn live_loopback_label(live_loopback: Option<bool>) -> &'static str {
    match live_loopback {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// Consecutive failing live-apply rounds after which a registry-matching restore is accepted as
/// *degraded*. Three, as specified in `docs/wfp-kill-switch.md`: one failure is noise, two is
/// bad luck, three in a row on the machine's own retry cadence means the live mechanism is
/// structurally unavailable (constrained-language mode, AppLocker, a broken WMI repository, an
/// EDR blocking `Win32_NetworkAdapterConfiguration`) and will not recover by being asked again.
const DEGRADED_RESTORE_STREAK: u32 = 3;

/// The documented degraded exit: accept a restore that the live mechanism could not confirm,
/// **only** when the registry read-back matches the snapshot exactly *and* the live apply has
/// failed `DEGRADED_RESTORE_STREAK` rounds in a row.
///
/// Why this is the right trade, and why it is not a hole in the DNS-before-disarm invariant:
/// the registry is what the DNS Client reads for the next lookup, so an exact registry match is
/// positive evidence that the machine's configured resolvers are the user's own again — what
/// the live apply adds is confirmation that the *currently running* resolver picked the change
/// up without waiting for an interface event. Without this exit, a machine whose CIM/PowerShell
/// path is permanently unavailable can never satisfy `restore_is_proven`, so Disconnect, Sign
/// Out and Quit are refused forever and the user is deadlocked in Protected Offline with no way
/// back to their network. A single failure never takes this path, a registry mismatch never
/// takes it, and every degraded acceptance is recorded in `last_error` and in the status
/// payload with its own marker — it is never silent.
fn accepts_degraded_restore(consecutive_live_failures: u32, registry_matches: bool) -> bool {
    registry_matches && consecutive_live_failures >= DEGRADED_RESTORE_STREAK
}

/// Why `enable_unlocked` is running. The distinction is a safety boundary, not bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnableTrigger {
    /// An explicit request (connect, network change, IPC). May capture originals and start
    /// protection from nothing.
    Request,
    /// The watchdog repairing observed drift. May only re-apply a snapshot that already exists.
    Reconcile,
}

/// Whether DNS protection is still *wanted* in this process.
///
/// Set by an explicit enable, cleared the moment any restore is requested — including the
/// emergency path, which proceeds even when the restore cannot be proven. Without this gate the
/// watchdog is a second writer with no notion of intent: after an emergency disarm that leaves
/// the snapshot behind (a partially failed restore keeps it *by design*, while WFP is removed
/// anyway), the watchdog sees `snapshot_present && !enabled` forever and forces every adapter
/// back to `127.0.0.1` every two seconds with no core listening. No race is needed for that —
/// only a disarm that could not prove its restore.
///
/// It is process-local and starts `false`; `initialize_status_cache` seeds it from the snapshot
/// on disk, so a service restart that finds protection in force keeps repairing drift, while a
/// snapshot that survives a disarm does not resurrect the loopback redirect.
static PROTECTION_WANTED: AtomicBool = AtomicBool::new(false);

static CONSECUTIVE_LIVE_FAILURES: AtomicU32 = AtomicU32::new(0);

/// One enable/restore round's live-apply outcome; returns the current streak of failing rounds.
fn note_apply_round(any_live_failed: bool) -> u32 {
    if any_live_failed {
        CONSECUTIVE_LIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        CONSECUTIVE_LIVE_FAILURES.swap(0, Ordering::Relaxed)
    }
}

/// Fold in-memory live-apply failures into a snapshot (the file may predate this process).
fn with_live_failures(
    snapshot: &DnsSnapshot,
    failures: &std::collections::BTreeSet<String>,
) -> DnsSnapshot {
    let mut merged = snapshot.clone();
    for adapter in &mut merged.adapters {
        adapter.live_apply_failed |= failures.contains(&adapter.interface_guid);
    }
    merged
}

/// Parse and version-check `protected-dns.json`, returning the reason it is unusable rather
/// than an opaque error.
///
/// `version` exists so that a schema change is a *migration*, not a brick: a file written by a
/// newer build cannot be reinterpreted by this one — its `None`/`Some` distinction is what
/// decides between deleting a value and rewriting it — so it is reported unreadable and goes
/// through the same recovery path as a corrupt file. Older versions stay readable: every field
/// added since carries `#[serde(default)]`.
fn parse_snapshot(bytes: &[u8]) -> std::result::Result<DnsSnapshot, String> {
    let snapshot: DnsSnapshot =
        serde_json::from_slice(bytes).map_err(|error| format!("the file is corrupt ({error})"))?;
    if snapshot.version > SNAPSHOT_VERSION {
        return Err(format!(
            "the file was written by a newer build (version {}, this build understands up to \
             {SNAPSHOT_VERSION})",
            snapshot.version
        ));
    }
    Ok(snapshot)
}

/// Whether restoration can be established **without** the snapshot.
///
/// A snapshot we cannot read is not evidence that DNS is still redirected — it only means we
/// cannot say what the servers *were*. If nothing on the machine still points at the loopback
/// core, and no live-apply failure is on record, then "DNS is no longer redirected to a dead
/// resolver" is demonstrably true regardless of what the file said, which is exactly what the
/// disarm gate needs to know. Anything else stays fail-closed: the kill switch remains armed
/// and the unreadable file is kept.
fn restore_established_without_snapshot(any_loopback: bool, live_apply_failed: bool) -> bool {
    !any_loopback && !live_apply_failed
}

/// Reconciliation delay after `failures` consecutive failed repairs, or `None` once repair is
/// suspended.
///
/// The watchdog used to call `enable()` every `DNS_WATCHDOG_INTERVAL` for as long as the
/// protection looked drifted, with no backoff and no cap — one permanently unconfigurable
/// adapter was enough to spawn PowerShell processes and rewrite the snapshot file forever.
/// Suspending relaxes nothing: the snapshot, the status error, and the armed kill switch all
/// stay exactly as they are, and an explicit connect still calls `enable()` directly.
fn reconcile_backoff(failures: u32) -> Option<std::time::Duration> {
    if failures == 0 {
        return Some(std::time::Duration::ZERO);
    }
    if failures >= DNS_RECONCILE_MAX_FAILURES {
        return None;
    }
    let doubling = 1_u32 << (failures - 1).min(5);
    Some(std::cmp::min(
        DNS_WATCHDOG_INTERVAL * doubling,
        DNS_RECONCILE_MAX_BACKOFF,
    ))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    crate::core::paths::ensure_persistent_state_layout()?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    let temporary = path.with_extension("tmp");
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    tokio::fs::write(&temporary, bytes).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(&temporary)?;
    crate::core::atomic_file::replace(&temporary, path).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    Ok(())
}

// --- Engine boundary (registry + CIM on Windows; stubs elsewhere) ---

/// Stable, App-mappable marker for "the DNS engine stopped answering". Same contract as
/// `windows_kill_switch::WFP_ENGINE_WEDGED_PREFIX`: the App matches by substring and every
/// handler wraps this message in its own context, so the marker must survive anywhere inside
/// the string. Separate from the WFP markers because the cause and the user action differ —
/// a wedged Dnscache/registry filter, not the Base Filtering Engine.
#[cfg_attr(not(any(all(windows, not(feature = "test")), test)), allow(dead_code))]
pub(crate) const DNS_ENGINE_WEDGED_PREFIX: &str = "TONO_DNS_ENGINE_WEDGED";

/// Stable, App-mappable marker for "`protected-dns.json` cannot be read *and* the machine is
/// still resolving through the loopback core". Same substring contract as the wedge markers.
/// Separate from them because the user action differs: this one is resolved by putting the
/// affected adapters back on automatic (DHCP) DNS, or by the elevated emergency disarm.
pub(crate) const DNS_SNAPSHOT_UNREADABLE_PREFIX: &str = "TONO_DNS_SNAPSHOT_UNREADABLE";

/// Stable, App-mappable marker for "the restore was accepted on registry evidence alone after a
/// sustained live-apply failure" (see [`accepts_degraded_restore`]). It rides in `last_error` on
/// an otherwise *successful* restore, so the App must treat it as a warning to surface, not as a
/// failed operation.
pub(crate) const DNS_RESTORE_DEGRADED_PREFIX: &str = "TONO_DNS_RESTORE_DEGRADED";

/// Budget for one *reading* DNS engine call (registry sweep + `GetAdaptersAddresses`). A
/// healthy enumeration is milliseconds; 25 s is the same clock `WFP_CALL_TIMEOUT` uses, so the
/// two modules give up on a wedged kernel/service at the same point, and it leaves the
/// surrounding `IPC_HANDLER_TIMEOUT` = 60 s more than half its budget to answer the client.
#[cfg(all(windows, not(feature = "test")))]
const DNS_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
/// Budget for a *mutating* call (loopback apply / snapshot restore). Longer than the reading
/// budget on purpose: this path already contains two internally bounded PowerShell batches
/// (2 × `engine::POWERSHELL_TIMEOUT` = 20 s) plus the registry sweep, and an outer bound below
/// its own inner bound would report a merely slow machine as wedged and refuse a restore that
/// was still making progress. It stays below `windows_kill_switch::DNS_RESTORE_TIMEOUT` = 40 s
/// so that a wedged DNS engine is named by *this* module's marker instead of being swallowed by
/// the cross-module bound, and because the first expiry latches the in-flight claim, one handler
/// can stall for at most one budget no matter how many engine calls its path makes (`enable`
/// makes up to six).
#[cfg(all(windows, not(feature = "test")))]
const DNS_APPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Budget for the best-effort cache flush: `LoadLibraryW("dnsapi.dll")` + a `DnsFlushResolver
/// Cache` RPC to the Dnscache service (no timeout parameter of its own) and, failing that, a
/// 5 s `ipconfig /flushdns`. Short, because a flush that never returns must not eat the
/// mutating budget — its failure is only logged, but the claim it leaves behind is what keeps
/// the next operation from piling a second thread onto a wedged Dnscache.
#[cfg(all(windows, not(feature = "test")))]
const DNS_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Anything slower than this is already pathological. Set above a PowerShell cold start
/// (~1 s), which the mutating path legitimately pays, so the warning means "degrading", not
/// "busy".
#[cfg(any(all(windows, not(feature = "test")), test))]
const DNS_SLOW_CALL: std::time::Duration = std::time::Duration::from_secs(5);

/// A DNS engine call that was handed to a blocking thread and has not come back yet.
///
/// Registered *before* the thread is spawned and released *only* by that thread — never by the
/// caller. Same asymmetry as `windows_kill_switch::EngineCallInFlight`: a caller that hits its
/// deadline gives up on the *answer*, not on the *ownership*.
#[cfg(any(all(windows, not(feature = "test")), test))]
#[derive(Debug, Clone, Copy)]
struct DnsCallInFlight {
    operation: &'static str,
    started_at: std::time::Instant,
    /// Epoch of this call. The releasing guard only clears its own epoch, so a call that
    /// returns very late can never erase the claim of a call that started after it.
    epoch: u64,
    /// Its caller already timed out and reported failure; the result is discarded on arrival.
    abandoned: bool,
}

#[cfg(any(all(windows, not(feature = "test")), test))]
static DNS_CALL_IN_FLIGHT: Lazy<Mutex<Option<DnsCallInFlight>>> = Lazy::new(|| Mutex::new(None));
#[cfg(any(all(windows, not(feature = "test")), test))]
static DNS_CALL_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(any(all(windows, not(feature = "test")), test))]
fn dns_call_slot() -> std::sync::MutexGuard<'static, Option<DnsCallInFlight>> {
    DNS_CALL_IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
fn dns_call_in_flight() -> Option<DnsCallInFlight> {
    *dns_call_slot()
}

/// Refusal for a caller that wants to start an engine call while an earlier one is still
/// inside the loader/registry/Dnscache. Fail-closed: nothing is applied, nothing is restored,
/// nothing is deleted, and the machine keeps whatever the last completed call left behind —
/// which for the restore path means the snapshot survives and the kill switch stays armed.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn wedged_dns_error(operation: &str, wedged: DnsCallInFlight) -> anyhow::Error {
    anyhow::anyhow!(
        "{DNS_ENGINE_WEDGED_PREFIX}: the DNS engine has been inside {} for {:?} without \
         returning, so {operation} is refused rather than started as a second concurrent \
         writer. The DNS Client service (Dnscache), a registry filter driver or third-party \
         security software is likely wedged; protected DNS stays in its last known state — \
         including its snapshot — until that call returns or the machine is restarted.",
        wedged.operation,
        wedged.started_at.elapsed(),
    )
}

/// Dropped on the blocking thread the instant the engine call returns — on time, or hours
/// late. This is the *only* place an in-flight claim is released, and it releases only its own
/// epoch.
#[cfg(any(all(windows, not(feature = "test")), test))]
struct DnsCallClaim(u64);

#[cfg(any(all(windows, not(feature = "test")), test))]
impl Drop for DnsCallClaim {
    fn drop(&mut self) {
        let mut slot = dns_call_slot();
        let Some(current) = *slot else { return };
        if current.epoch != self.0 {
            return;
        }
        *slot = None;
        if current.abandoned {
            // The caller reported failure long ago; this is the log line that says the engine
            // is alive again. The call's own result was dropped with its `JoinHandle`, so it
            // cannot contradict what was already reported.
            tracing::error!(
                "dns: {} finally returned after {:?}; its caller had already given up, the \
                 result is discarded, and DNS operations are accepted again",
                current.operation,
                current.started_at.elapsed(),
            );
        }
    }
}

/// The status watchdog reads every `DNS_WATCHDOG_INTERVAL`: only the rare, mutating operations
/// may announce themselves at info, or the service log would carry two lines every two seconds
/// forever.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn dns_call_is_periodic(operation: &str) -> bool {
    operation == "collect" || operation == "verify loopback"
}

/// Run one DNS engine operation on a blocking thread under a hard deadline, holding the
/// single-writer claim described on [`DnsCallInFlight`].
///
/// These calls are synchronous registry/IP-helper/CIM/Dnscache work, so they run off the IPC
/// runtime. They are also bounded, because on a real machine `DnsFlushResolverCache` (an RPC
/// to a wedged Dnscache), `LoadLibraryW` behind an AV image-load callback, or a registry sweep
/// behind a filter driver can block forever — and `spawn_blocking` cannot be cancelled: the
/// thread keeps running whatever the caller does.
///
/// Single-writer argument for the timeout path:
/// * the claim is registered *before* the thread is spawned and released only by that thread,
///   in `DnsCallClaim::drop`, when the blocking call actually returns;
/// * a caller that hits its deadline returns an error and leaves the claim standing, so every
///   later DNS engine call — this operation's, the next handler's, the watchdog's — fails fast
///   here instead of stacking a second writer on the same registry keys and adapters;
/// * the abandoned task can publish nothing: it only touches `engine::*`, its return value dies
///   with the `JoinHandle` the deadline dropped, and its claim release is keyed to its own
///   epoch, so it cannot clear a claim taken by a later call.
///
/// The facade's `DNS_OPERATION` lock alone cannot provide this: it is released as soon as the
/// timing-out caller returns, which is exactly when the abandoned thread is still working.
///
/// The machinery is compiled off Windows too, so those ownership rules stay unit-testable;
/// only the closures handed to it are Windows-only.
#[cfg(any(all(windows, not(feature = "test")), test))]
async fn bounded_dns_call<T: Send + 'static>(
    budget: std::time::Duration,
    operation: &'static str,
    call: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let epoch = {
        let mut slot = dns_call_slot();
        if let Some(wedged) = *slot {
            return Err(wedged_dns_error(operation, wedged));
        }
        let epoch = DNS_CALL_EPOCH.fetch_add(1, Ordering::AcqRel);
        *slot = Some(DnsCallInFlight {
            operation,
            started_at: std::time::Instant::now(),
            epoch,
            abandoned: false,
        });
        epoch
    };
    let announce = !dns_call_is_periodic(operation);
    if announce {
        tracing::info!("dns: {operation} starting");
    } else {
        tracing::debug!("dns: {operation} starting");
    }
    let started_at = std::time::Instant::now();
    let task = tokio::task::spawn_blocking(move || {
        // Local, so it drops (releasing the claim) after `call` returns and before the result
        // reaches the awaiting caller.
        let _claim = DnsCallClaim(epoch);
        call()
    });
    match tokio::time::timeout(budget, task).await {
        Ok(joined) => {
            let elapsed = started_at.elapsed();
            if elapsed >= DNS_SLOW_CALL {
                tracing::warn!(
                    "dns: {operation} finished in {}ms — the engine is answering, but far slower \
                     than a healthy call",
                    elapsed.as_millis()
                );
            } else if announce {
                tracing::info!("dns: {operation} finished in {}ms", elapsed.as_millis());
            } else {
                tracing::debug!("dns: {operation} finished in {}ms", elapsed.as_millis());
            }
            joined.context("DNS engine task failed")?
        }
        Err(_) => {
            // Claim the abandonment by epoch instead of writing the slot: the call may have
            // returned in the instant between the deadline and this line, in which case its
            // guard already cleared the slot and nothing is wedged.
            let still_running = {
                let mut slot = dns_call_slot();
                match slot.as_mut() {
                    Some(current) if current.epoch == epoch => {
                        current.abandoned = true;
                        true
                    }
                    _ => false,
                }
            };
            if still_running {
                tracing::error!(
                    "dns: {operation} did not return within {budget:?} and is still running; \
                     every further DNS operation fails fast until it returns"
                );
            } else {
                tracing::error!(
                    "dns: {operation} returned just after its {budget:?} deadline; its result was \
                     discarded and the caller was told it failed"
                );
            }
            bail!(
                "{DNS_ENGINE_WEDGED_PREFIX}: the DNS engine did not answer within {budget:?} \
                 during {operation}; the DNS Client service (Dnscache), a registry filter driver \
                 or third-party security software may be wedged. Protected DNS was left in its \
                 last known state, its snapshot was kept, and no further DNS operation starts \
                 until the pending call returns."
            )
        }
    }
}

async fn engine_collect() -> Result<Vec<AdapterDnsSnapshot>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        bounded_dns_call(DNS_CALL_TIMEOUT, "collect", engine::collect_adapters).await
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(Vec::new())
    }
}

async fn engine_apply_loopback(adapters: &[AdapterDnsSnapshot]) -> Result<Vec<(String, bool)>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let guids = adapters
            .iter()
            .map(|adapter| adapter.interface_guid.clone())
            .collect::<Vec<_>>();
        return bounded_dns_call(DNS_APPLY_TIMEOUT, "apply loopback", move || {
            engine::apply_loopback_set(&guids)
        })
        .await;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(adapters
            .iter()
            .map(|adapter| (adapter.interface_guid.clone(), true))
            .collect())
    }
}

async fn engine_apply_snapshot(snapshot: &DnsSnapshot) -> Result<Vec<(String, bool)>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let snapshot = snapshot.clone();
        return bounded_dns_call(DNS_APPLY_TIMEOUT, "restore snapshot", move || {
            engine::apply_snapshot(&snapshot)
        })
        .await;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        // The stub reports success unless a test asks for the machine condition that produced
        // the real-machine deadlock: a live apply that fails while the registry restore behind
        // it succeeds (`engine::apply_snapshot` writes the four registry values whatever the
        // PowerShell batch reported).
        let ok = !test_hooks::live_apply_fails();
        Ok(snapshot
            .adapters
            .iter()
            .map(|adapter| (adapter.interface_guid.clone(), ok))
            .collect())
    }
}

async fn engine_all_loopback(adapters: &[AdapterDnsSnapshot]) -> Result<bool> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let guids = adapters
            .iter()
            .map(|adapter| adapter.interface_guid.clone())
            .collect::<Vec<_>>();
        return bounded_dns_call(DNS_CALL_TIMEOUT, "verify loopback", move || {
            engine::all_loopback(&guids)
        })
        .await;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = adapters;
        Ok(false)
    }
}

/// Whether any adapter still resolves through the loopback core — "is any of it left?", the
/// mirror of `engine_all_loopback`'s "is protection complete?".
///
/// Two callers: the snapshot-less recovery, and the restore proof itself, which needs positive
/// live evidence that the machine is not being left pointed at a core that is about to stop
/// answering (see [`restore_is_proven`]). The restore proof narrows the adapter list first
/// ([`adapters_owing_live_proof`]).
async fn engine_any_loopback(adapters: &[AdapterDnsSnapshot]) -> Result<bool> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let guids = adapters
            .iter()
            .map(|adapter| adapter.interface_guid.clone())
            .collect::<Vec<_>>();
        return bounded_dns_call(DNS_CALL_TIMEOUT, "detect loopback", move || {
            engine::any_loopback(&guids)
        })
        .await;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = adapters;
        // Without this hook the stub would always answer "not on loopback", which makes the
        // unproven-restore branch — the fail-closed half of the corrupt-snapshot contract —
        // unreachable in every test build. A test that cannot fail is worse than none.
        Ok(test_hooks::live_dns_is_on_loopback())
    }
}

/// Test-only control over the engine answers that are unobservable off Windows.
#[cfg(any(not(all(windows, not(feature = "test"))), test))]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    static LIVE_DNS_ON_LOOPBACK: AtomicBool = AtomicBool::new(false);

    pub(crate) fn live_dns_is_on_loopback() -> bool {
        LIVE_DNS_ON_LOOPBACK.load(Ordering::Relaxed)
    }

    /// Simulate a machine whose adapters still resolve through the loopback core, so a restore
    /// that cannot read its snapshot is genuinely unprovable.
    pub(crate) fn set_live_dns_on_loopback(on_loopback: bool) {
        LIVE_DNS_ON_LOOPBACK.store(on_loopback, Ordering::Relaxed);
    }

    static LIVE_APPLY_FAILS: AtomicBool = AtomicBool::new(false);

    pub(crate) fn live_apply_fails() -> bool {
        LIVE_APPLY_FAILS.load(Ordering::Relaxed)
    }

    /// Simulate the machine from the real regression: PowerShell/CIM reports the live apply as
    /// failed (which records `live_apply_failed` and starts the streak) while the registry
    /// restore underneath it succeeded.
    pub(crate) fn set_live_apply_fails(fails: bool) {
        LIVE_APPLY_FAILS.store(fails, Ordering::Relaxed);
    }
}

async fn engine_flush_cache() -> Result<()> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        return bounded_dns_call(DNS_FLUSH_TIMEOUT, "flush", engine::flush_resolver_cache).await;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(())
    }
}

// --- Facade ---

/// Whether the state machine runs on this build (real service on Windows; stubbed engine
/// under test builds, which is what the unit tests drive).
const SUPPORTED: bool = cfg!(any(windows, test));

static LIVE_APPLY_FAILURES: Lazy<std::sync::Mutex<std::collections::BTreeSet<String>>> =
    Lazy::new(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));
/// Last committed/live-verified DNS observation. IPC reads clone this synchronously instead of
/// waiting behind a CIM mutation. The background reconciler refreshes it and repairs drift.
static DNS_STATUS_CACHE: Lazy<Mutex<DnsProtectionStatus>> =
    Lazy::new(|| Mutex::new(DnsProtectionStatus::default()));
const DNS_WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// Consecutive failed repairs after which the watchdog stops re-running `enable()`. Five
/// attempts (≈ 1 minute with the backoff) is enough for anything transient — a hot-plugged
/// adapter, a service still starting — and anything that survives it is a machine condition
/// that retrying cannot fix.
const DNS_RECONCILE_MAX_FAILURES: u32 = 5;
/// Ceiling for the reconciliation backoff, so even a long-lived failure costs at most one
/// repair attempt per minute instead of one every two seconds.
const DNS_RECONCILE_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

fn ensure_supported() -> Result<()> {
    if SUPPORTED {
        Ok(())
    } else {
        bail!("protected DNS is unsupported on this platform")
    }
}

fn record_outcome<T>(result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            *DNS_LAST_ERROR.lock().unwrap() = None;
            Ok(value)
        }
        Err(error) => {
            *DNS_LAST_ERROR.lock().unwrap() = Some(format!("{error:#}"));
            Err(error)
        }
    }
}

/// Record per-adapter live-apply results in memory and into the snapshot's per-adapter flags.
fn note_live_results(snapshot: &mut DnsSnapshot, results: &[(String, bool)]) {
    let mut failures = LIVE_APPLY_FAILURES.lock().unwrap();
    for (guid, ok) in results {
        if *ok {
            failures.remove(guid);
        } else {
            failures.insert(guid.clone());
        }
        if let Some(adapter) = snapshot
            .adapters
            .iter_mut()
            .find(|adapter| &adapter.interface_guid == guid)
        {
            adapter.live_apply_failed = !ok;
        }
    }
}

/// Move an unreadable `protected-dns.json` aside instead of deleting it: it may still be the
/// only record of the original resolvers, and a support case can decode by hand what this build
/// could not. Called *only* after [`restore_established_without_snapshot`] has held, so the
/// file is never removed from the disarm path while the machine could still be redirected.
async fn quarantine_snapshot(reason: &str) -> Result<()> {
    let path = snapshot_path();
    let quarantined = path.with_extension(format!("corrupt-{}.json", now_unix()));
    if let Err(error) = tokio::fs::rename(&path, &quarantined).await {
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error).context("failed to quarantine the protected-dns snapshot");
    }
    crate::core::platform_security::secure_private_service_file_if_exists(&quarantined)?;
    tracing::error!(
        "dns: {reason}; no adapter still resolves through the loopback core, so restoration \
         holds without it — the file was quarantined as {} and protection starts from a clean \
         snapshot",
        quarantined.display()
    );
    Ok(())
}

/// Recovery for a `protected-dns.json` this build cannot read (corrupt, or a newer schema).
///
/// Without this, an unreadable snapshot is terminal in both directions: `restore_protected`
/// can never prove a restore, `ensure_restored` therefore always fails, the WFP disarm is
/// refused, and because the file is only deleted *after* a proven restore it stays unreadable
/// across every retry and every reboot — a permanently blocked machine with no in-app way out.
///
/// The way out is evidence, not trust: read the live adapters and demand that *nothing* still
/// points at the loopback core (and that no live-apply failure is on record). That establishes
/// the property the disarm gate actually protects — the machine is not left resolving through a
/// core that is no longer running — without knowing what the servers used to be. Only then is
/// the file quarantined.
///
/// Every other outcome (still on loopback, a recorded live failure, or an engine call that
/// times out on the way to finding out) returns an error: nothing is deleted, nothing is
/// disarmed, and the message names the two documented ways forward.
async fn recover_unreadable_snapshot(reason: &str) -> Result<()> {
    let current = engine_collect().await?;
    let any_loopback = engine_any_loopback(&current).await?;
    let live_apply_failed = !LIVE_APPLY_FAILURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty();
    if !restore_established_without_snapshot(any_loopback, live_apply_failed) {
        bail!(
            "{DNS_SNAPSHOT_UNREADABLE_PREFIX}: protected-dns.json cannot be read ({reason}) and \
             the machine still resolves through the loopback core \
             (loopback_dns={any_loopback}, live_apply_failed={live_apply_failed}), so the \
             original DNS servers cannot be proven restored and protection stays armed. Set the \
             affected adapters back to automatic (DHCP) DNS — or to the servers you use — and \
             retry the disconnect; the elevated `--emergency-disarm` remains the documented \
             escape hatch. The unreadable file is kept for diagnosis."
        );
    }
    quarantine_snapshot(reason).await
}

/// Snapshot → set loopback → verify. Idempotent: a second call while protected keeps the
/// original snapshot — but if the adapters are not actually on loopback (a previous enable
/// died mid-apply), the loopback write is replayed first.
pub(crate) async fn enable() -> Result<DnsProtectionStatus> {
    ensure_supported()?;
    let _operation = DNS_OPERATION.lock().await;
    enable_unlocked(EnableTrigger::Request).await
}

/// The body of [`enable`], for callers that already hold `DNS_OPERATION`.
///
/// The watchdog must decide *and act* inside one acquisition (see [`spawn_status_watchdog`]),
/// which is only possible if the action itself does not re-acquire the lock.
async fn enable_unlocked(trigger: EnableTrigger) -> Result<DnsProtectionStatus> {
    if trigger == EnableTrigger::Request {
        // From here until an explicit restore, drift is worth repairing. Set before any work so
        // that a half-applied enable is still repaired by the watchdog.
        PROTECTION_WANTED.store(true, Ordering::Release);
    }
    let existing = match tokio::fs::read(snapshot_path()).await {
        Ok(bytes) => match parse_snapshot(&bytes) {
            Ok(snapshot) => Some(snapshot),
            // Quarantining an unreadable snapshot is a decision for an explicit request, never
            // for a background repair loop.
            Err(reason) if trigger == EnableTrigger::Reconcile => {
                bail!(
                    "{DNS_SNAPSHOT_UNREADABLE_PREFIX}: protected-dns.json cannot be read \
                     ({reason}); automatic reconciliation will not act on it — reconnect or \
                     disconnect to recover"
                );
            }
            // Quarantining first is what makes this safe: the recovery proves that no adapter
            // is on loopback, so the originals collected below are genuine. Enabling on top of
            // an unreadable snapshot without that proof would record our own loopback values as
            // the originals and destroy the way back.
            Err(reason) => {
                record_outcome(recover_unreadable_snapshot(&reason).await)?;
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let existing = existing
        .map(|snapshot| with_live_failures(&snapshot, &LIVE_APPLY_FAILURES.lock().unwrap()));
    let snapshot_present = existing.is_some();
    if trigger == EnableTrigger::Reconcile && !snapshot_present {
        // Repair means "re-apply the snapshot that is in force", never "capture new originals".
        // With no snapshot this call would be an *initial* enable: it would record the machine's
        // current (correct, just-restored) resolvers as the originals and point every adapter at
        // a loopback core that is no longer running — a machine-wide DNS outage that reports
        // itself as healthy. The lock now spans the watchdog's read and this call, so the race
        // that could produce it is closed; this is the belt-and-braces half.
        tracing::debug!("dns: nothing to reconcile — the snapshot is gone, so protection ended");
        return status_unlocked().await;
    }
    // Always collect before the idempotence decision. Network-change reconnects call `enable`
    // again, and a newly installed/hot-plugged adapter must have its original DNS appended to the
    // durable snapshot before it is pointed at loopback.
    let fresh = DnsSnapshot {
        version: SNAPSHOT_VERSION,
        taken_at: now_unix(),
        adapters: engine_collect().await?,
    };
    // Health and replay decisions cover adapters that are live now, not historical snapshot
    // entries that have since been disabled or unplugged. Their originals remain in `snapshot`
    // and are still restored in the registry on disconnect.
    let active_adapters = fresh.adapters.clone();
    let mut snapshot = merge_snapshot(existing, fresh);
    let all_loopback = snapshot_present && engine_all_loopback(&active_adapters).await?;
    let live_apply_failed = snapshot
        .adapters
        .iter()
        .any(|adapter| adapter.live_apply_failed);
    // Snapshot first, even on an otherwise idempotent replay: `snapshot` may now include adapters
    // that appeared after the first enable, and any later failure must retain their originals.
    atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
    if !needs_loopback_replay(snapshot_present, all_loopback, live_apply_failed) {
        return status_unlocked().await;
    }
    let outcome: Result<()> = async {
        let live = engine_apply_loopback(&snapshot.adapters).await?;
        note_apply_round(live.iter().any(|(_, ok)| !ok));
        note_live_results(&mut snapshot, &live);
        // Persist both failures and successful retries. Otherwise a recovered adapter keeps its
        // old `live_apply_failed` bit on disk and every later enable unnecessarily replays DNS.
        atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
        let failed = live.iter().filter(|(_, ok)| !ok).count();
        if failed > 0 {
            bail!("live DNS apply failed on {failed} adapter(s)");
        }
        if ENGINE_LIVE {
            let active_after_apply = engine_collect().await?;
            if !engine_all_loopback(&active_after_apply).await? {
                bail!("loopback DNS could not be verified on every active adapter");
            }
        }
        Ok(())
    }
    .await;
    record_outcome(outcome)?;
    // Loopback is applied and verified: flush the resolver cache best-effort. Real-IP answers
    // cached before the switch are otherwise served without consulting the loopback core, so the
    // fake-ip readiness probe never sees a 198.18/16 answer until the entries expire. A failed
    // flush must not fail enable — DNS protection itself is already in place.
    if let Err(error) = engine_flush_cache().await {
        tracing::warn!("DNS cache flush after enable failed: {error:#}");
    }
    status_unlocked().await
}

/// Restore every adapter from the snapshot, prove it by registry read-back *and* by a live read
/// that finds nothing left on the loopback core, then drop the snapshot. Failing any of that
/// keeps the snapshot — and, via the disarm invariant, the block armed.
pub(crate) async fn restore_protected() -> Result<DnsProtectionStatus> {
    if !SUPPORTED {
        return status_unlocked().await;
    }
    let _operation = DNS_OPERATION.lock().await;
    // Intent first, before any outcome is known: from the moment a restore is *requested*, the
    // loopback redirect is no longer wanted. A restore that fails — or an emergency disarm that
    // proceeds on an unproven one — must never be undone by the reconciler putting loopback back
    // while no core is listening. An explicit `enable` sets it again.
    PROTECTION_WANTED.store(false, Ordering::Release);
    let bytes = match tokio::fs::read(snapshot_path()).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return status_unlocked().await;
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = match parse_snapshot(&bytes) {
        Ok(snapshot) => snapshot,
        // The snapshot is unreadable: fall back to proving restoration from the live adapters
        // instead of leaving the disarm gate permanently unsatisfiable. This either establishes
        // that nothing resolves through loopback any more (and quarantines the file), or fails
        // closed with the marker and the two documented ways forward.
        Err(reason) => {
            record_outcome(recover_unreadable_snapshot(&reason).await)?;
            // Same reasoning as the proven path below: answers collected while DNS pointed at
            // the loopback core must not outlive the disconnect.
            if let Err(error) = engine_flush_cache().await {
                tracing::warn!("DNS cache flush after snapshot recovery failed: {error:#}");
            }
            return status_unlocked().await;
        }
    };
    let mut snapshot = with_live_failures(&snapshot, &LIVE_APPLY_FAILURES.lock().unwrap());
    // `Some(note)` = the restore was accepted on the documented degraded path and the note must
    // reach `last_error`; `None` = fully proven.
    let outcome: Result<Option<String>> = async {
        // The engine applies all adapters in one PowerShell batch and retries the failures
        // once in a second batch, reporting final per-adapter results.
        let live = engine_apply_snapshot(&snapshot).await?;
        let streak = note_apply_round(live.iter().any(|(_, ok)| !ok));
        note_live_results(&mut snapshot, &live);
        // Persist the refreshed flags either way; a refused disarm must keep accurate records.
        atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
        // The registry half of the proof, read back off the machine. The stub engine reports no
        // adapters at all, which would make the comparison vacuous, so off Windows the
        // snapshot's own entries stand in and the live evidence below is what decides.
        let current = if ENGINE_LIVE {
            engine_collect().await?
        } else {
            snapshot.adapters.clone()
        };
        // The live half: is anything on this machine still pointed at the loopback core? This is
        // the same evidence the corrupt-snapshot recovery runs on, and it is what replaced the
        // `live_apply_failed` veto — a stale flag from an earlier round now makes us insist on
        // this read, instead of overruling it.
        //
        // An engine that cannot answer leaves the restore *unproven*, never proven: the
        // question falls to the degraded exit below, which still demands an exact registry
        // match and a sustained streak.
        let owing_live_proof = adapters_owing_live_proof(&snapshot, &current);
        let live_loopback = match engine_any_loopback(&owing_live_proof).await {
            Ok(any_loopback) => Some(any_loopback),
            Err(error) => {
                tracing::warn!(
                    "dns: the live DNS state could not be read while proving the restore, so \
                     the restore stays unproven: {error:#}"
                );
                None
            }
        };
        if !restore_is_proven(&snapshot, &current, live_loopback) {
            let registry = registry_restore_matches(&snapshot, &current);
            let loopback = live_loopback_label(live_loopback);
            if live_loopback == Some(true) {
                // Provably still on loopback: refused before the degraded exit is even
                // considered. No failure streak may release protection while the machine would
                // be left resolving through a core that is about to stop answering — that is
                // the ordering invariant the disarm gate exists to hold.
                bail!(
                    "DNS restore could not be proven: adapters on this machine still resolve \
                     through Tono's loopback resolver (registry_match={registry}, \
                     still_on_loopback={loopback}, \
                     consecutive_live_apply_failures={streak}), so protection stays armed rather \
                     than leaving DNS pointed at a resolver that is about to stop answering. \
                     Try Disconnect again; if it keeps failing, right-click the Start-Menu entry \
                     \"Tono — 恢复网络 (Restore Network)\" and choose \"Run as administrator\", \
                     or run `tono-service.exe --emergency-disarm` from an elevated prompt — \
                     either one releases the block and puts the saved DNS servers back."
                );
            }
            if !accepts_degraded_restore(streak, registry) {
                bail!(
                    "DNS restore could not be proven (registry_match={registry}, \
                     still_on_loopback={loopback}, \
                     consecutive_live_apply_failures={streak}); protection remains armed. Try \
                     Disconnect again; if it keeps failing, right-click the Start-Menu entry \
                     \"Tono — 恢复网络 (Restore Network)\" and choose \"Run as administrator\", \
                     or run `tono-service.exe --emergency-disarm` from an elevated prompt — \
                     either one releases the block and puts the saved DNS servers back."
                );
            }
            // The live mechanism is structurally unavailable on this machine, but the
            // registry — what the DNS Client reads for the next lookup — holds exactly the
            // saved values. Accept, and start the streak again so the next session must
            // earn this exit on its own.
            CONSECUTIVE_LIVE_FAILURES.store(0, Ordering::Relaxed);
            return Ok(Some(format!(
                "{DNS_RESTORE_DEGRADED_PREFIX}: the original DNS servers were restored in \
                 the registry and verified by read-back, but the live apply failed {streak} \
                 rounds in a row and the live DNS state could not be confirmed \
                 (still_on_loopback={loopback}). Disconnect was allowed rather than leaving \
                 the machine locked in Protected Offline. If name resolution misbehaves, \
                 disable and re-enable the network adapter (or reboot); PowerShell/WMI on this \
                 machine appears to be restricted."
            )));
        }
        Ok(None)
    }
    .await;
    let degraded = record_outcome(outcome)?;
    match tokio::fs::remove_file(snapshot_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(note) = degraded {
        // `record_outcome` cleared `last_error` on the way through: a degraded acceptance is a
        // success for the caller, but it must never be silent — put it back so it reaches the
        // status payload (`status_unlocked` reads `DNS_LAST_ERROR`) and the service log.
        tracing::error!("dns: {note}");
        *DNS_LAST_ERROR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(note);
    }
    // The restore is proven (or degraded-accepted on registry evidence): flush the resolver
    // cache unconditionally. Fake-ip (198.18/16) answers and negative cache entries collected
    // while DNS pointed at the loopback core would otherwise outlive the disconnect (see
    // `engine::flush_resolver_cache`) — and after a degraded acceptance the flush is the one
    // thing that still nudges the running resolver.
    if let Err(error) = engine_flush_cache().await {
        tracing::warn!("DNS cache flush after restore failed: {error:#}");
    }
    status_unlocked().await
}

/// The disarm gate: succeed when no protection is active, or after a proven restore. An
/// error here must keep the kill switch armed (see the invariant at the top of this file).
pub(crate) async fn ensure_restored() -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    match tokio::fs::metadata(snapshot_path()).await {
        Ok(_) => restore_protected().await.map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn status() -> DnsProtectionStatus {
    // Status is the recovery/diagnosis path: do not turn a past panic into permanent silence.
    DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn publish_status(status: &DnsProtectionStatus) {
    *DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = status.clone();
}

fn publish_status_error(error: &anyhow::Error) {
    let mut status = DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    status.last_error = Some(format!("{error:#}"));
}

/// Populate the fast snapshot before IPC is opened. A corrupt recovery file is represented as a
/// status error rather than preventing the Service from starting; WFP remains independently
/// fail-closed and the GUI can still offer diagnostics/emergency recovery.
pub async fn initialize_status_cache() {
    let _operation = DNS_OPERATION.lock().await;
    match status_unlocked().await {
        Ok(status) => {
            // A snapshot on disk at service start means protection was in force when this
            // machine last ran: keep repairing drift for it. Anything else (including a snapshot
            // this build cannot read) leaves reconciliation disarmed until an explicit enable.
            PROTECTION_WANTED.store(status.snapshot_present, Ordering::Release);
            publish_status(&status);
        }
        Err(error) => publish_status_error(&error),
    }
}

/// Keep the cached snapshot fresh and repair a new/drifted adapter while protection is active.
/// The expensive live read runs here, never in a request handler. `enable` preserves the original
/// snapshot and only reapplies loopback after this probe finds drift.
///
/// This loop is a *writer* of machine state, so it is fenced three ways:
/// * it observes and repairs inside **one** `DNS_OPERATION` acquisition, so no other operation
///   can change the state between the decision and the action;
/// * it calls `enable_unlocked(EnableTrigger::Reconcile)`, which refuses to perform an initial
///   enable — repair can only ever re-apply a snapshot that already exists;
/// * it acts only while `PROTECTION_WANTED` holds, so a snapshot that outlived a disarm (an
///   emergency disarm proceeds on an unproven restore and keeps the file) can never be turned
///   back into a loopback redirect.
///
/// With no snapshot on disk the status read makes no engine calls at all, so a released
/// protection leaves the loop idle rather than busy.
pub fn spawn_status_watchdog() {
    if !SUPPORTED {
        return;
    }
    tokio::spawn(async {
        let mut failures: u32 = 0;
        // When the next repair may run. Backoff is expressed as a deadline rather than a sleep
        // so that no delay is ever awaited while holding `DNS_OPERATION`.
        let mut next_attempt = std::time::Instant::now();
        loop {
            tokio::time::sleep(DNS_WATCHDOG_INTERVAL).await;
            // One acquisition covers the observation *and* the repair. Reading the state, then
            // dropping the lock, then acting on what was read is how a concurrent release used
            // to turn a repair into an initial enable: the snapshot could be deleted in between,
            // and the repair would then capture the freshly restored resolvers as "originals"
            // and point the machine at a loopback core that is no longer running. This mirrors
            // the WFP watchdog, which reads `armed_guard()` while holding `WFP_OPERATION`.
            let _operation = DNS_OPERATION.lock().await;
            let status = match status_unlocked().await {
                Ok(status) => status,
                Err(error) => {
                    publish_status_error(&error);
                    continue;
                }
            };
            publish_status(&status);
            // `PROTECTION_WANTED` is the intent gate: a snapshot that outlived a disarm is
            // evidence to keep, not a reason to re-apply loopback.
            let repair = PROTECTION_WANTED.load(Ordering::Acquire)
                && status.snapshot_present
                && !status.enabled;
            if !repair {
                if failures > 0 {
                    // Nothing left to repair — protection is healthy again, was released, or is
                    // no longer wanted. The failure streak is spent: re-arm for the next drift.
                    tracing::info!(
                        "dns: nothing left to reconcile; automatic reconciliation re-armed"
                    );
                    failures = 0;
                    next_attempt = std::time::Instant::now();
                }
                continue;
            }
            if reconcile_backoff(failures).is_none() {
                continue; // suspended at the cap; the log line was written when it tripped
            }
            if std::time::Instant::now() < next_attempt {
                continue;
            }
            match enable_unlocked(EnableTrigger::Reconcile).await {
                Ok(_) => {
                    failures = 0;
                    next_attempt = std::time::Instant::now();
                }
                Err(error) => {
                    failures += 1;
                    next_attempt = std::time::Instant::now()
                        + reconcile_backoff(failures).unwrap_or(DNS_RECONCILE_MAX_BACKOFF);
                    publish_status_error(&error);
                    tracing::warn!(
                        "protected DNS reconciliation failed (attempt {failures}): {error:#}"
                    );
                    if failures >= DNS_RECONCILE_MAX_FAILURES {
                        tracing::error!(
                            "dns: automatic reconciliation is suspended after {failures} \
                             consecutive failures; protection stays in its current state \
                             (snapshot kept, kill switch armed) and an explicit connect still \
                             retries it"
                        );
                    }
                }
            }
        }
    });
}

async fn status_unlocked() -> Result<DnsProtectionStatus> {
    let snapshot = match tokio::fs::read(snapshot_path()).await {
        // Status only reports; the recovery itself belongs to `enable`/`restore_protected`,
        // which hold the operation lock and may change the machine. Reporting the reason (with
        // the marker) keeps the App able to explain the state.
        Ok(bytes) => Some(parse_snapshot(&bytes).map_err(|reason| {
            anyhow::anyhow!("{DNS_SNAPSHOT_UNREADABLE_PREFIX}: protected-dns.json ({reason})")
        })?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let enabled = match snapshot.as_ref() {
        Some(_snapshot) if ENGINE_LIVE => {
            // Include adapters that appeared since the last enable. Checking only saved GUIDs can
            // report a false healthy state while a fresh adapter still uses an external resolver.
            let current = engine_collect().await?;
            engine_all_loopback(&current).await?
        }
        Some(snapshot) => engine_all_loopback(&snapshot.adapters).await?,
        None => false,
    };
    let status = DnsProtectionStatus {
        enabled,
        snapshot_present: snapshot.is_some(),
        adapters: snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.adapters.len() as u32),
        last_error: DNS_LAST_ERROR.lock().unwrap().clone(),
    };
    publish_status(&status);
    Ok(status)
}

/// Only an operational adapter with a **bound IP stack** has a live resolver that can leak DNS.
/// Registry interface keys outlive disabled and removed adapters, while the software loopback
/// has no configurable DNS instance; including either class makes one irrelevant apply failure
/// abort protection for every real adapter.
///
/// Link state alone is not that test: a Hyper-V internal vSwitch, `vEthernet (WSL)` before
/// configuration, a Bluetooth PAN, a TAP adapter with no bound IP stack, or our own WinTUN
/// adapter mid-initialisation are all `OperStatus == Up` with nothing to configure. They used
/// to land in the failure list on every round, which persisted a `live_apply_failed` flag,
/// pinned `needs_loopback_replay` on forever, and made both the watchdog's repair loop and the
/// restore proof permanently unsatisfiable. `has_bound_ip` is the IP-Helper equivalent of
/// `IPEnabled`: at least one unicast address *and* a non-zero interface index in at least one
/// family. Adapters that fail it are non-participants — they have no resolver to protect — not
/// failures.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn is_active_dns_adapter(oper_status: i32, if_type: u32, has_bound_ip: bool) -> bool {
    const IF_OPER_STATUS_UP: i32 = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    oper_status == IF_OPER_STATUS_UP && if_type != IF_TYPE_SOFTWARE_LOOPBACK && has_bound_ip
}

// --- Windows engine: registry snapshot/set + best-effort CIM live-apply ---

#[cfg(all(windows, not(feature = "test")))]
mod engine {
    use super::{
        AdapterDnsSnapshot, DnsSnapshot, is_active_dns_adapter, is_loopback_value,
        is_protected_v6_value,
    };
    use anyhow::{Context as _, Result, bail};
    use std::ffi::CStr;
    use windows_sys::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_DATA,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_SZ, RegCloseKey,
        RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };

    const TCPIP4_INTERFACES: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    const TCPIP6_INTERFACES: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
    const NAME_SERVER: &str = "NameServer";
    const PROFILE_NAME_SERVER: &str = "ProfileNameServer";

    struct RegKey(HKEY);

    impl RegKey {
        fn open(subkey: &str, write: bool) -> Result<Option<Self>> {
            let wide = super_wide(subkey);
            let mut handle = std::ptr::null_mut();
            // SAFETY: valid NUL-terminated key path; `handle` is a valid out-pointer.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide.as_ptr(),
                    0,
                    KEY_WOW64_64KEY | if write { KEY_WRITE } else { KEY_READ },
                    &mut handle,
                )
            };
            match status {
                0 => Ok(Some(Self(handle))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                _ => Err(std::io::Error::from_raw_os_error(status as i32))
                    .with_context(|| format!("failed to open registry key {subkey}")),
            }
        }
    }

    impl Drop for RegKey {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `RegOpenKeyExW` and closes once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn super_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_sz(subkey: &str, value: &str) -> Result<Option<String>> {
        let Some(key) = RegKey::open(subkey, false)? else {
            return Ok(None);
        };
        let value_wide = super_wide(value);
        let mut size = 0_u32;
        // SAFETY: valid key handle and value name; null data pointer queries the size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 && status != ERROR_MORE_DATA {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to size registry value {subkey}\\{value}"));
        }
        if size == 0 || size % 2 != 0 {
            return Ok(None);
        }
        let mut buffer = vec![0_u16; size as usize / 2];
        let mut actual = size;
        // SAFETY: `buffer` is `size` bytes of writable memory, as reported by the query.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut actual,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to read registry value {subkey}\\{value}"));
        }
        let used = actual as usize / 2;
        buffer.truncate(used);
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        Ok(Some(
            String::from_utf16(&buffer).context("registry DNS value is not valid UTF-16")?,
        ))
    }

    fn write_sz(subkey: &str, value: &str, data: &str) -> Result<()> {
        let Some(key) = RegKey::open(subkey, true)? else {
            bail!("registry key {subkey} does not exist");
        };
        let value_wide = super_wide(value);
        let wide = super_wide(data);
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer of `len * 2` bytes, alive here.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                value_wide.as_ptr(),
                0,
                REG_SZ,
                wide.as_ptr().cast(),
                (wide.len() * 2) as u32,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to write registry value {subkey}\\{value}"));
        }
        Ok(())
    }

    fn delete_value(subkey: &str, value: &str) -> Result<()> {
        let Some(key) = RegKey::open(subkey, true)? else {
            return Ok(());
        };
        let value_wide = super_wide(value);
        // SAFETY: valid key handle and value name.
        let status = unsafe { RegDeleteValueW(key.0, value_wide.as_ptr()) };
        if status != 0 && status != ERROR_FILE_NOT_FOUND {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to delete registry value {subkey}\\{value}"));
        }
        Ok(())
    }

    /// One adapter that can actually carry a resolver, with the interface indices its live
    /// mechanisms are keyed by. The indices are re-read from IP Helper on every operation and
    /// never persisted: they are not stable across reboots or adapter reinstalls.
    #[derive(Debug, Clone)]
    pub(super) struct ActiveAdapter {
        pub guid: String,
        /// IPv4 interface index, or 0 when IPv4 is not bound (nothing to apply or prove).
        pub ipv4_index: u32,
        /// IPv6 interface index, or 0 when IPv6 is not bound.
        pub ipv6_index: u32,
    }

    fn active_adapters() -> Result<Vec<ActiveAdapter>> {
        // `Parameters\Interfaces` is historical state, not a list of live adapters: it commonly
        // contains disabled, unplugged, removed, and pseudo interfaces. Those either have no
        // Win32_NetworkAdapterConfiguration object or return 84 (IP not enabled), which used to
        // make the whole DNS enable fail permanently. IP Helper gives the current cheap in-process
        // view and is also what the service's network-change monitor is built on.
        const INITIAL_BUFFER_BYTES: u32 = 15 * 1024;
        const MAX_BUFFER_ATTEMPTS: usize = 4;
        // Unicast addresses are *not* skipped any more: their presence is half of the
        // "IP is enabled on this adapter" test (`is_active_dns_adapter`), and the enumeration
        // stays a single cheap in-process call.
        let flags = GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER
            | GAA_FLAG_SKIP_FRIENDLY_NAME;
        let mut bytes = INITIAL_BUFFER_BYTES;
        for _ in 0..MAX_BUFFER_ATTEMPTS {
            let entries = (bytes as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
            // A vector of the actual structure gives the backing allocation the alignment required
            // by the linked records that `GetAdaptersAddresses` writes into the byte-sized buffer.
            let mut buffer = vec![IP_ADAPTER_ADDRESSES_LH::default(); entries.max(1)];
            // SAFETY: `buffer` is writable for at least `bytes` bytes and stays alive while the
            // returned linked list is traversed; the reserved pointer is required to be null.
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buffer.as_mut_ptr(),
                    &mut bytes,
                )
            };
            if status == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if status == ERROR_NO_DATA {
                return Ok(Vec::new());
            }
            if status != 0 {
                return Err(std::io::Error::from_raw_os_error(status as i32))
                    .context("GetAdaptersAddresses failed while selecting DNS adapters");
            }

            let mut adapters: Vec<ActiveAdapter> = Vec::new();
            let mut current = buffer.as_ptr();
            while !current.is_null() {
                // SAFETY: `current` starts inside `buffer`; each `Next` pointer belongs to the same
                // successful `GetAdaptersAddresses` result and is valid until `buffer` is dropped.
                let adapter = unsafe { &*current };
                // SAFETY: the anonymous union's `IfIndex` member is always initialised by
                // `GetAdaptersAddresses`; reading a `u32` out of it is valid for any bit pattern.
                let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                let ipv6_index = adapter.Ipv6IfIndex;
                let has_bound_ip =
                    !adapter.FirstUnicastAddress.is_null() && (ipv4_index != 0 || ipv6_index != 0);
                if is_active_dns_adapter(adapter.OperStatus, adapter.IfType, has_bound_ip)
                    && !adapter.AdapterName.is_null()
                {
                    // SAFETY: Windows documents AdapterName as a NUL-terminated ANSI adapter GUID.
                    let guid = unsafe { CStr::from_ptr(adapter.AdapterName.cast()) }
                        .to_str()
                        .context("adapter GUID from GetAdaptersAddresses was not UTF-8")?;
                    if !adapters
                        .iter()
                        .any(|saved| saved.guid.eq_ignore_ascii_case(guid))
                    {
                        adapters.push(ActiveAdapter {
                            guid: guid.to_owned(),
                            ipv4_index,
                            ipv6_index,
                        });
                    }
                }
                current = adapter.Next;
            }
            return Ok(adapters);
        }
        bail!("GetAdaptersAddresses size kept changing while selecting DNS adapters")
    }

    /// The active adapters keyed by upper-case GUID, the form every caller compares in.
    fn active_adapter_map() -> Result<std::collections::BTreeMap<String, ActiveAdapter>> {
        Ok(active_adapters()?
            .into_iter()
            .map(|adapter| (adapter.guid.to_ascii_uppercase(), adapter))
            .collect())
    }

    fn v4_key(guid: &str) -> String {
        format!(r"{TCPIP4_INTERFACES}\{guid}")
    }

    fn v6_key(guid: &str) -> String {
        format!(r"{TCPIP6_INTERFACES}\{guid}")
    }

    fn read_adapter(guid: &str) -> Result<AdapterDnsSnapshot> {
        Ok(AdapterDnsSnapshot {
            interface_guid: guid.to_owned(),
            ipv4_name_server: read_sz(&v4_key(guid), NAME_SERVER)?,
            ipv4_profile_name_server: read_sz(&v4_key(guid), PROFILE_NAME_SERVER)?,
            ipv6_name_server: read_sz(&v6_key(guid), NAME_SERVER)?,
            ipv6_profile_name_server: read_sz(&v6_key(guid), PROFILE_NAME_SERVER)?,
            live_apply_failed: false,
        })
    }

    pub(super) fn collect_adapters() -> Result<Vec<AdapterDnsSnapshot>> {
        active_adapters()?
            .iter()
            .map(|adapter| read_adapter(&adapter.guid))
            .collect()
    }

    /// Live application, **per address family**, in ONE PowerShell process (cold start is the
    /// dominant cost). The registry writes are the authoritative record this module verifies
    /// against; the live apply is what makes the running resolver pick the change up without an
    /// interface bounce.
    ///
    /// * IPv4 goes through CIM
    ///   (`Win32_NetworkAdapterConfiguration.SetDNSServerSearchOrder`, the architecture doc's
    ///   primary mechanism: it handles static and DHCP adapters without touching leases) and
    ///   every `Invoke-CimMethod` checks its `ReturnValue` — piping to `Out-Null` would report
    ///   success for a rejected call.
    /// * IPv6 goes through `netsh interface ipv6 set/add dnsservers`, keyed by the IPv6
    ///   interface index, in three shapes: `source=dhcp` (`$null`, restore a family that had no
    ///   saved value), `source=static address=none` (an empty list — the protected state, since
    ///   the core has no `[::1]:53` listener to point at), and `source=static` plus one `add`
    ///   per extra server when restoring saved ones. The CIM method is documented for IPv4
    ///   addresses only: handing it an IPv6 address is how an older version could either fail on
    ///   every adapter forever or, worse, have the address silently dropped and leave an IPv6
    ///   resolver pointing at the ISP while the registry read-back still said "protected".
    /// * The script then *reads the live list back per family* (`Get-DnsClientServerAddress`)
    ///   and only reports success when what it reads matches what it applied — exactly the
    ///   loopback list for IPv4 and exactly *nothing* for IPv6 when protecting, and "the
    ///   loopback address is gone" when restoring
    ///   (a restored family's servers may legitimately come back from DHCP in another order).
    ///   A family with no live DNS instance, an interface index of 0, or a CIM `ReturnValue` of
    ///   84 ("IP not enabled on adapter") is a non-participant: there is no resolver on it to
    ///   leak, and recording it as a failure is what used to pin `live_apply_failed` on forever.
    ///
    /// The script prints `fails|skips`; results are recorded per adapter and required for any
    /// restore proof (see the module docs). An adapter that reports *no* configurable family at
    /// all is a skip, not a failure — that is the difference between ignoring a Hyper-V/WSL
    /// pseudo adapter and bricking the machine on it.
    ///
    /// 注意:运行时尚未实测 — wrapped so any failure is logged, never fatal.
    struct LiveApplyEntry {
        guid: String,
        /// Live IPv4/IPv6 interface indices; 0 means the family is not bound here.
        ipv4_index: u32,
        ipv6_index: u32,
        /// `None` restores DHCP for that family (CIM `$null` / `netsh … source=dhcp`);
        /// `Some(empty)` is a *static* list with no servers at all (`netsh … source=static
        /// address=none`), which is the protected IPv6 state. The two are not interchangeable:
        /// DHCP would put the ISP's resolvers back.
        ipv4_servers: Option<Vec<String>>,
        ipv6_servers: Option<Vec<String>>,
    }

    /// What the live read-back has to prove.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ApplyMode {
        /// Protecting: the family's live list must be *exactly* what was applied — the loopback
        /// address for IPv4, and nothing at all for IPv6.
        Loopback,
        /// Restoring: the family's live list must no longer contain the loopback address.
        /// Exact equality is the registry's job (`restore_is_proven`), and DHCP may legitimately
        /// return the saved servers in another order or with an extra suffix server.
        ///
        /// An IPv6 family that comes back *empty* is deliberately not a failure here: a network
        /// that supplies no DHCPv6 resolvers legitimately reads that way, and an empty list
        /// strands nobody — only an IPv4 resolver still pointed at a stopped core can do that.
        /// Exactness for IPv6 is enforced where it is unambiguous: the registry read-back.
        Restore,
    }

    const POWERSHELL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn remaining(deadline: std::time::Instant) -> std::time::Duration {
        deadline.saturating_duration_since(std::time::Instant::now())
    }

    /// Owns a child until it is proven gone. Every `?`/`bail!` in [`run_with_timeout`] passes
    /// through this drop, so no error path can orphan a powershell.exe that nobody waits on.
    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Both calls are no-ops on a child that already exited and was reaped.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `CreateProcess` is itself the most common hang on a locked-down machine: creating
    /// powershell.exe traverses every minifilter and runs every AMSI/AV image-load callback,
    /// none of which this process controls. So the spawn happens on a throwaway thread and is
    /// handed over through a *rendezvous* channel: if the caller has already reached the
    /// deadline, the hand-over finds no receiver, fails, and the worker kills the process it
    /// just created instead of leaving it behind. A spawn that never returns leaks only that
    /// thread — never the caller, and never a stray child.
    fn spawn_before_deadline(
        program: &str,
        args: &[&str],
        deadline: std::time::Instant,
    ) -> Result<std::process::Child> {
        let spawn_program = program.to_owned();
        let spawn_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Result<std::process::Child>>(0);
        std::thread::spawn(move || {
            let spawned = std::process::Command::new(&spawn_program)
                .args(&spawn_args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .with_context(|| format!("failed to start {spawn_program}"));
            if let Err(std::sync::mpsc::SendError(Ok(mut child))) = sender.send(spawned) {
                let _ = child.kill();
                let _ = child.wait();
            }
        });
        match receiver.recv_timeout(remaining(deadline)) {
            Ok(spawned) => spawned,
            Err(_) => bail!(
                "{program} could not be started within the deadline; process creation is still \
                 inside the loader (minifilter/AMSI/AV) and the process, if it ever appears, is \
                 killed by the spawning thread"
            ),
        }
    }

    /// Read one pipe to EOF on its own thread. EOF is *not* the same event as process exit: a
    /// grandchild (a WMI/CIM helper, an injected AV shim) that inherited the write handle keeps
    /// the pipe open after the child is gone, so this read may never finish and must never be
    /// awaited without a deadline. Draining both pipes from the start also removes the reverse
    /// deadlock, where a child blocks writing into a full pipe while we wait for its exit.
    fn read_pipe<R: std::io::Read + Send + 'static>(
        pipe: Option<R>,
    ) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buffer);
            }
            let _ = sender.send(buffer);
        });
        receiver
    }

    /// Spawn a process and collect stdout under one hard deadline that covers *process
    /// creation, the run, and the output read* — the three separate ways this can block.
    /// A child that outlives the deadline is killed, and incomplete output is an error, never
    /// an empty result: the batch script reports its failures *on stdout*, so treating an
    /// unfinished read as "no failures" would report an unproven live-apply as proven.
    /// Nothing here may ever park the facade's DNS operation lock on a hung PowerShell.
    fn run_with_timeout(
        program: &str,
        args: &[&str],
        timeout: std::time::Duration,
    ) -> Result<String> {
        let deadline = std::time::Instant::now() + timeout;
        let mut child = ChildGuard(spawn_before_deadline(program, args, deadline)?);
        let stdout = read_pipe(child.0.stdout.take());
        let stderr = read_pipe(child.0.stderr.take());
        let status = loop {
            // A `?` here would drop the guard, which kills the child rather than orphaning it.
            let waited = child
                .0
                .try_wait()
                .with_context(|| format!("failed to wait for {program}"))?;
            match waited {
                Some(status) => break status,
                None if std::time::Instant::now() >= deadline => {
                    bail!("{program} timed out after {timeout:?} and was killed");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        };
        let Ok(stdout) = stdout.recv_timeout(remaining(deadline)) else {
            bail!(
                "{program} exited but its output pipe stayed open past the {timeout:?} deadline \
                 (a grandchild still holds the write handle); the result is treated as failed"
            );
        };
        if !status.success() {
            let stderr = stderr.recv_timeout(remaining(deadline)).unwrap_or_default();
            bail!(
                "{program} exited {status}: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// Only these characters ever reach the generated script. GUIDs come from registry subkey
    /// names and server strings from our own snapshot writes; anything else fails closed.
    fn script_safe(value: &str, extra: &str) -> bool {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte as char))
    }

    /// The per-family apply and the per-family live read-back, shared by every entry in the
    /// batch. Kept as one prelude so the generated script stays one short line per adapter:
    /// the `-Command` argument has a hard length limit and a machine can carry many adapters.
    const SCRIPT_PRELUDE: &str = r#"$global:fails = @()
$global:skips = @()
function Test-Family($index, $family, $want, $restoring) {
  if ($index -eq 0) { return $true }
  $entry = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily $family -ErrorAction SilentlyContinue
  if ($null -eq $entry) { return $true }
  $have = @($entry.ServerAddresses)
  $loop = if ($family -eq 'IPv4') { '127.0.0.1' } else { '::1' }
  if ($restoring) {
    foreach ($s in $have) { if ($s -eq $loop) { return $false } }
    return $true
  }
  if ($null -eq $want) { return $true }
  if ($have.Count -ne $want.Count) { return $false }
  for ($k = 0; $k -lt $want.Count; $k++) { if ($have[$k] -ne $want[$k]) { return $false } }
  return $true
}
function Set-AdapterDns($g, $i4, $i6, $v4, $v6, $restoring) {
  $touched = $false
  if ($i4 -ne 0) {
    $c = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "SettingID='$g'" -ErrorAction SilentlyContinue
    if ($null -eq $c) { $global:fails += $g; return }
    $r = Invoke-CimMethod -InputObject $c -MethodName SetDNSServerSearchOrder -Arguments @{ DNSServerSearchOrder = $v4 } -ErrorAction SilentlyContinue
    if ($r -and $r.ReturnValue -eq 84) { $global:skips += $g; return }
    if (-not $r -or $r.ReturnValue -ne 0) { $global:fails += $g; return }
    $touched = $true
  }
  if ($i6 -ne 0) {
    $e = 0
    if ($null -eq $v6) {
      netsh interface ipv6 set dnsservers "name=$i6" source=dhcp | Out-Null
      $e = $e + $LASTEXITCODE
    } elseif ($v6.Count -eq 0) {
      netsh interface ipv6 set dnsservers "name=$i6" source=static address=none | Out-Null
      $e = $e + $LASTEXITCODE
    } else {
      netsh interface ipv6 set dnsservers "name=$i6" source=static "address=$($v6[0])" register=none validate=no | Out-Null
      $e = $e + $LASTEXITCODE
      for ($k = 1; $k -lt $v6.Count; $k++) {
        netsh interface ipv6 add dnsservers "name=$i6" "address=$($v6[$k])" "index=$($k + 1)" validate=no | Out-Null
        $e = $e + $LASTEXITCODE
      }
    }
    if ($e -ne 0) { $global:fails += $g; return }
    $touched = $true
  }
  if (-not $touched) { $global:skips += $g; return }
  if (-not (Test-Family $i4 'IPv4' $v4 $restoring)) { $global:fails += $g; return }
  if (-not (Test-Family $i6 'IPv6' $v6 $restoring)) { $global:fails += $g; return }
}
"#;

    /// The result marker the batch must print. Its presence is what distinguishes "the script
    /// ran and found no failures" from "the script produced nothing useful"; without it the
    /// batch is treated as a total failure.
    const RESULT_SEPARATOR: char = '|';

    fn powershell_list(servers: &Option<Vec<String>>) -> String {
        match servers {
            None => "$null".to_owned(),
            Some(servers) => format!(
                "@({})",
                servers
                    .iter()
                    .map(|server| format!("'{server}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    fn parse_guid_list(value: &str) -> std::collections::BTreeSet<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|guid| !guid.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }

    fn live_apply_batch(entries: &[LiveApplyEntry], mode: ApplyMode) -> Vec<(String, bool)> {
        let restoring = mode == ApplyMode::Restore;
        let mut script = String::from(SCRIPT_PRELUDE);
        let mut rejected: std::collections::BTreeSet<String> = Default::default();
        for entry in entries {
            let servers_ok =
                [&entry.ipv4_servers, &entry.ipv6_servers]
                    .into_iter()
                    .all(|servers| {
                        servers.as_ref().is_none_or(|servers| {
                            servers.iter().all(|server| script_safe(server, ".:"))
                        })
                    });
            if !script_safe(&entry.guid, "{}-") || !servers_ok {
                rejected.insert(entry.guid.clone());
                continue;
            }
            script.push_str(&format!(
                "Set-AdapterDns '{}' {} {} {} {} ${restoring}\n",
                entry.guid,
                entry.ipv4_index,
                entry.ipv6_index,
                powershell_list(&entry.ipv4_servers),
                powershell_list(&entry.ipv6_servers),
            ));
        }
        script.push_str(
            "[Console]::Out.Write(($global:fails -join ',') + '|' + ($global:skips -join ','))",
        );
        let run = run_with_timeout(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            POWERSHELL_TIMEOUT,
        );
        let reported = match run {
            Ok(stdout) => stdout
                .lines()
                .rev()
                .find_map(|line| line.split_once(RESULT_SEPARATOR))
                .map(|(failed, skipped)| (parse_guid_list(failed), parse_guid_list(skipped))),
            Err(error) => {
                tracing::warn!("dns: live batch apply failed: {error:#}");
                None
            }
        };
        // The whole batch failed (timeout, spawn error, non-zero exit, or output without the
        // result marker — a script that died half way through): every entry is a failure. The
        // proof path stays closed and the DNS lock is never held hostage.
        let Some((failed, skipped)) = reported else {
            tracing::warn!(
                "dns: live batch apply produced no result marker; all {} adapter(s) are recorded \
                 as failed",
                entries.len()
            );
            return entries
                .iter()
                .map(|entry| (entry.guid.clone(), false))
                .collect();
        };
        if !skipped.is_empty() {
            // Not a failure: these adapters have no configurable resolver on either family, so
            // there is nothing on them that could leak.
            tracing::debug!("dns: adapters without a configurable live resolver: {skipped:?}");
        }
        entries
            .iter()
            .map(|entry| {
                let ok = !failed.contains(&entry.guid) && !rejected.contains(&entry.guid);
                (entry.guid.clone(), ok)
            })
            .collect()
    }

    /// One batch, then one batched retry for the failures (aligned with the previous
    /// per-adapter retry semantics, without paying a PowerShell cold start per adapter).
    fn live_apply_with_retry(entries: Vec<LiveApplyEntry>, mode: ApplyMode) -> Vec<(String, bool)> {
        let first = live_apply_batch(&entries, mode);
        let failed: std::collections::BTreeSet<String> = first
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(guid, _)| guid.clone())
            .collect();
        if failed.is_empty() {
            return first;
        }
        let retry_entries: Vec<LiveApplyEntry> = entries
            .into_iter()
            .filter(|entry| failed.contains(&entry.guid))
            .collect();
        let retried = live_apply_batch(&retry_entries, mode);
        first
            .into_iter()
            .map(|(guid, ok)| {
                let ok = ok
                    || retried
                        .iter()
                        .any(|(retry_guid, retry_ok)| *retry_ok && *retry_guid == guid);
                (guid, ok)
            })
            .collect()
    }

    /// Flush the resolver cache after a restore. Fake-ip (198.18/16) answers and negative
    /// cache entries served while DNS pointed at the loopback core are the classic post-
    /// disconnect pollution; without a flush, restored resolvers keep them until TTL expiry.
    pub(super) fn flush_resolver_cache() -> Result<()> {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        // DnsFlushResolverCache (Vista+) is exported by dnsapi.dll but is not in
        // any SDK import library — it must be resolved at runtime (the same
        // approach Mullvad's winfw takes).
        type FlushFn = unsafe extern "system" fn() -> i32;
        let module_name: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        // SAFETY: null-terminated wide literal; the handle is validity-checked
        // before use and the module stays loaded for the process lifetime.
        let module = unsafe { LoadLibraryW(module_name.as_ptr()) };
        if !module.is_null() {
            // SAFETY: live module handle; null-terminated ANSI name literal.
            let proc = unsafe { GetProcAddress(module, c"DnsFlushResolverCache".as_ptr() as _) };
            if let Some(proc) = proc {
                let flush: FlushFn = unsafe { std::mem::transmute(proc) };
                // SAFETY: no inputs; the signature matches the documented ABI.
                if unsafe { flush() } != 0 {
                    return Ok(());
                }
            }
        }
        run_with_timeout(
            "ipconfig.exe",
            &["/flushdns"],
            std::time::Duration::from_secs(5),
        )
        .map(|_| ())
        .context("DnsFlushResolverCache failed and ipconfig /flushdns did not succeed either")
    }

    /// Whether the adapter's per-family registry subkey exists. Single-stack adapters lack one
    /// family entirely; both apply and verify must skip the absent family instead of failing.
    fn key_exists(subkey: &str) -> Result<bool> {
        Ok(RegKey::open(subkey, false)?.is_some())
    }

    /// `guid` is the caller's spelling — per-adapter results are matched back against the
    /// snapshot by exact string — while `active` only supplies the live interface indices.
    fn apply_loopback(guid: &str, active: &ActiveAdapter) -> Result<LiveApplyEntry> {
        if key_exists(&v4_key(guid))? {
            write_sz(&v4_key(guid), NAME_SERVER, super::LOOPBACK_V4)?;
            write_sz(&v4_key(guid), PROFILE_NAME_SERVER, super::LOOPBACK_V4)?;
        }
        if key_exists(&v6_key(guid))? {
            // Empty, not `::1`: the core listens on `127.0.0.1:53` only, so an adapter pointed
            // at `::1` has a configured IPv6 resolver that never answers and every system
            // lookup pays the full OS timeout before falling back — the `securingDNS` failure
            // this replaced. Empty is also not the same as *deleting* the value: deletion means
            // DHCP, which would hand the ISP's IPv6 resolvers back and would be a real leak.
            // With no IPv6 servers Windows uses the IPv4 loopback resolver, which answers.
            write_sz(&v6_key(guid), NAME_SERVER, super::NO_NAME_SERVERS)?;
            write_sz(&v6_key(guid), PROFILE_NAME_SERVER, super::NO_NAME_SERVERS)?;
        }
        Ok(LiveApplyEntry {
            guid: guid.to_owned(),
            ipv4_index: active.ipv4_index,
            ipv6_index: active.ipv6_index,
            // One family per list: the IPv4 mechanism never sees an IPv6 address and the IPv6
            // mechanism never sees `127.0.0.1`, and each is proven on its own family.
            ipv4_servers: Some(vec![super::LOOPBACK_V4.to_owned()]),
            // `Some(empty)` = a static list with no servers; `None` would mean DHCP.
            ipv6_servers: Some(Vec::new()),
        })
    }

    pub(super) fn apply_loopback_set(guids: &[String]) -> Result<Vec<(String, bool)>> {
        let active = active_adapter_map()?;
        // An adapter that is no longer active has no live resolver to point anywhere.
        let mut results = guids
            .iter()
            .filter(|guid| !active.contains_key(&guid.to_ascii_uppercase()))
            .map(|guid| (guid.clone(), true))
            .collect::<Vec<_>>();
        let entries = guids
            .iter()
            .filter_map(|guid| {
                active
                    .get(&guid.to_ascii_uppercase())
                    .map(|adapter| (guid, adapter))
            })
            .map(|(guid, adapter)| apply_loopback(guid, adapter))
            .collect::<Result<Vec<_>>>()?;
        results.extend(live_apply_with_retry(entries, ApplyMode::Loopback));
        Ok(results)
    }

    fn restore_value(subkey: &str, value: &str, saved: &Option<String>) -> Result<()> {
        match saved {
            Some(data) => write_sz(subkey, value, data),
            None => delete_value(subkey, value),
        }
    }

    fn restore_entry(adapter: &AdapterDnsSnapshot, active: &ActiveAdapter) -> LiveApplyEntry {
        LiveApplyEntry {
            guid: adapter.interface_guid.clone(),
            ipv4_index: active.ipv4_index,
            ipv6_index: active.ipv6_index,
            ipv4_servers: super::restored_live_servers_v4(adapter),
            ipv6_servers: super::restored_live_servers_v6(adapter),
        }
    }

    pub(super) fn apply_snapshot(snapshot: &DnsSnapshot) -> Result<Vec<(String, bool)>> {
        let active = active_adapter_map()?;
        let mut live_results = snapshot
            .adapters
            .iter()
            .filter(|adapter| !active.contains_key(&adapter.interface_guid.to_ascii_uppercase()))
            .map(|adapter| (adapter.interface_guid.clone(), true))
            .collect::<Vec<_>>();
        let entries = snapshot
            .adapters
            .iter()
            .filter_map(|adapter| {
                active
                    .get(&adapter.interface_guid.to_ascii_uppercase())
                    .map(|live| restore_entry(adapter, live))
            })
            .collect::<Vec<_>>();
        // The live apply first makes the running resolver adopt the saved per-family list. Both
        // mechanisms rewrite `NameServer` while doing so, therefore restore all four exact
        // registry values afterwards; the facade's read-back proof then checks those originals
        // rather than the normalized representation CIM or netsh leaves behind.
        live_results.extend(live_apply_with_retry(entries, ApplyMode::Restore));
        for adapter in &snapshot.adapters {
            let guid = &adapter.interface_guid;
            if key_exists(&v4_key(guid))? {
                restore_value(&v4_key(guid), NAME_SERVER, &adapter.ipv4_name_server)?;
                restore_value(
                    &v4_key(guid),
                    PROFILE_NAME_SERVER,
                    &adapter.ipv4_profile_name_server,
                )?;
            }
            if key_exists(&v6_key(guid))? {
                restore_value(&v6_key(guid), NAME_SERVER, &adapter.ipv6_name_server)?;
                restore_value(
                    &v6_key(guid),
                    PROFILE_NAME_SERVER,
                    &adapter.ipv6_profile_name_server,
                )?;
            }
        }
        Ok(live_results)
    }

    /// Whether *any* adapter still points at the loopback resolver — the mirror image of
    /// [`all_loopback`], and the only evidence the snapshot-less recovery path has. Deliberately
    /// checks every value of both families: one leftover `ProfileNameServer` is enough to leave
    /// the machine resolving through a core that is no longer running.
    pub(super) fn any_loopback(guids: &[String]) -> Result<bool> {
        for guid in guids {
            let adapter = read_adapter(guid)?;
            if is_loopback_value(adapter.ipv4_name_server.as_deref())
                || is_loopback_value(adapter.ipv4_profile_name_server.as_deref())
                || is_loopback_value(adapter.ipv6_name_server.as_deref())
                || is_loopback_value(adapter.ipv6_profile_name_server.as_deref())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether every adapter is in the protected state. The two families do not answer the same
    /// question: IPv4 must be on the loopback resolver, while IPv6 must have **no servers at
    /// all** — that is what the protect path writes, and reading it as drift would have the
    /// watchdog rewrite the registry every two seconds for ever.
    pub(super) fn all_loopback(guids: &[String]) -> Result<bool> {
        for guid in guids {
            let adapter = read_adapter(guid)?;
            // Each present family must be fully protected — NameServer and, when set,
            // ProfileNameServer (which overrides NameServer for the active profile). An absent
            // family is skipped, matching the apply side.
            if key_exists(&v4_key(guid))?
                && (!is_loopback_value(adapter.ipv4_name_server.as_deref())
                    || (adapter.ipv4_profile_name_server.is_some()
                        && !is_loopback_value(adapter.ipv4_profile_name_server.as_deref())))
            {
                return Ok(false);
            }
            if key_exists(&v6_key(guid))?
                && (!is_protected_v6_value(adapter.ipv6_name_server.as_deref())
                    || (adapter.ipv6_profile_name_server.is_some()
                        && !is_protected_v6_value(adapter.ipv6_profile_name_server.as_deref())))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn adapter(guid: &str, v4: Option<&str>) -> AdapterDnsSnapshot {
        AdapterDnsSnapshot {
            interface_guid: guid.to_owned(),
            ipv4_name_server: v4.map(ToOwned::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn name_server_lists_tolerate_messy_registry_values() {
        assert_eq!(
            parse_name_server_list(" 1.1.1.1 , ,8.8.8.8, "),
            vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]
        );
        assert!(parse_name_server_list("").is_empty());
        assert_eq!(
            format_name_server_list(&["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]),
            "1.1.1.1,8.8.8.8"
        );
    }

    #[test]
    fn loopback_detection_is_exact() {
        assert!(is_loopback_value(Some("127.0.0.1")));
        assert!(
            is_loopback_value(Some(LOOPBACK_V6)),
            "the protect path no longer writes ::1, but an adapter left there by an older build \
             is still pointed at a resolver that never answers and must not read as restored"
        );
        assert!(is_loopback_value(Some("127.0.0.1, ::1")));
        assert!(!is_loopback_value(Some("127.0.0.1, 1.1.1.1")));
        assert!(!is_loopback_value(Some("1.1.1.1")));
        assert!(!is_loopback_value(Some("")));
        assert!(!is_loopback_value(None));
    }

    /// The IPv6 half of the `securingDNS` regression. Nothing listens on `[::1]:53`
    /// (`tono_core::config::DNS_LISTEN` is `127.0.0.1:53`), so the protected IPv6 state is an
    /// empty static server list — and "protected" therefore has to mean something different per
    /// family, or the watchdog reads the state it just wrote as drift and rewrites it for ever.
    #[test]
    fn an_empty_ipv6_server_list_is_the_protected_state() {
        assert!(
            is_protected_v6_value(Some(NO_NAME_SERVERS)),
            "an empty static list is what the protect path writes"
        );
        assert!(is_protected_v6_value(Some("  ,  ")));
        assert!(
            is_protected_v6_value(Some(LOOPBACK_V6)),
            "an upgrade over a build that wrote ::1 must not read as drift"
        );
        assert!(
            !is_protected_v6_value(None),
            "an absent value is DHCP — the ISP's resolvers — not protection"
        );
        assert!(!is_protected_v6_value(Some("2606:4700:4700::1111")));
        assert!(
            !is_loopback_value(Some(NO_NAME_SERVERS)),
            "an empty list resolves through nothing at all, so it is not evidence that the \
             machine is still pointed at the loopback core"
        );
    }

    #[test]
    fn only_up_non_loopback_adapters_with_a_bound_ip_stack_are_protected() {
        assert!(is_active_dns_adapter(1, 6, true), "up ethernet");
        assert!(is_active_dns_adapter(1, 71, true), "up wi-fi");
        assert!(is_active_dns_adapter(1, 131, true), "up tunnel");
        assert!(!is_active_dns_adapter(2, 6, true), "down ethernet");
        assert!(!is_active_dns_adapter(1, 24, true), "software loopback");
        assert!(
            !is_active_dns_adapter(1, 6, false),
            "up with no bound IP stack (Hyper-V/WSL switch, TAP, WinTUN mid-init) has no \
             resolver to protect and must not become a permanent failure"
        );
    }

    #[test]
    fn enable_preserves_originals_and_appends_new_adapters() {
        let original = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let fresh = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 2,
            adapters: vec![
                adapter("{A}", Some(LOOPBACK_V4)),
                adapter("{NEW}", Some("9.9.9.9")),
            ],
        };
        let merged = merge_snapshot(Some(original.clone()), fresh.clone());
        assert_eq!(merged.taken_at, original.taken_at);
        assert_eq!(
            merged.adapters[0], original.adapters[0],
            "saved DNS is never overwritten"
        );
        assert_eq!(
            merged.adapters[1], fresh.adapters[1],
            "a fresh adapter keeps its original DNS"
        );
        assert_eq!(merge_snapshot(None, fresh.clone()), fresh);
    }

    #[test]
    fn restore_proof_requires_exact_saved_values() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![
                adapter("{A}", Some("1.1.1.1")),
                adapter("{B}", None), // DHCP: restore deletes the value
            ],
        };
        let restored = vec![adapter("{A}", Some("1.1.1.1")), adapter("{B}", None)];
        assert!(restore_is_proven(&snapshot, &restored, Some(false)));

        let still_loopback = vec![adapter("{A}", Some(LOOPBACK_V4)), adapter("{B}", None)];
        assert!(!restore_is_proven(&snapshot, &still_loopback, Some(true)));

        let wrong_server = vec![adapter("{A}", Some("8.8.8.8")), adapter("{B}", None)];
        assert!(!restore_is_proven(&snapshot, &wrong_server, Some(false)));

        let missing_adapter = vec![adapter("{A}", Some("1.1.1.1"))];
        assert!(
            restore_is_proven(&snapshot, &missing_adapter, Some(false)),
            "an adapter whose registry key vanished has no live resolver left to restore"
        );
    }

    /// The live half of the proof, which is what replaced the `live_apply_failed` veto. Only
    /// "nothing is on loopback" can prove a restore; "something still is" refuses it, and
    /// "we could not look" is unproven — never proven.
    #[test]
    fn restore_proof_needs_positive_live_evidence() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let restored = vec![adapter("{A}", Some("1.1.1.1"))];
        assert!(restore_is_proven(&snapshot, &restored, Some(false)));
        assert!(
            !restore_is_proven(&snapshot, &restored, Some(true)),
            "an exact registry match cannot outvote an adapter that is provably still on \
             loopback — that ordering is the whole point of the disarm gate"
        );
        assert!(
            !restore_is_proven(&snapshot, &restored, None),
            "evidence that could not be gathered (a wedged engine, a timed-out call) is \
             unproven; the degraded exit is the only way past it"
        );
    }

    /// A machine that ran its own local resolver before Tono started had `127.0.0.1` all along.
    /// Restoring it puts `127.0.0.1` back — correctly — so the blunt "is anything on loopback?"
    /// question must not be asked about that adapter, or every disconnect is refused for ever.
    #[test]
    fn the_live_loopback_read_skips_adapters_whose_originals_were_loopback() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![
                adapter("{LOCAL-RESOLVER}", Some(LOOPBACK_V4)),
                adapter("{NORMAL}", Some("1.1.1.1")),
            ],
        };
        let current = vec![
            adapter("{LOCAL-RESOLVER}", Some(LOOPBACK_V4)),
            adapter("{NORMAL}", Some("1.1.1.1")),
        ];
        let owing = adapters_owing_live_proof(&snapshot, &current);
        assert_eq!(owing.len(), 1);
        assert_eq!(owing[0].interface_guid, "{NORMAL}");

        // An adapter that appeared after the snapshot owes the proof: nothing says it was on
        // loopback of its own accord.
        let with_new = vec![adapter("{NEW}", Some(LOOPBACK_V4))];
        assert_eq!(adapters_owing_live_proof(&snapshot, &with_new).len(), 1);
    }

    #[test]
    fn live_restore_uses_profile_overrides_and_keeps_the_families_apart() {
        let saved = AdapterDnsSnapshot {
            interface_guid: "{DUAL}".to_owned(),
            ipv4_name_server: Some("1.1.1.1".to_owned()),
            ipv4_profile_name_server: Some("8.8.8.8, 8.8.4.4".to_owned()),
            ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
            ipv6_profile_name_server: None,
            live_apply_failed: false,
        };
        // No IPv6 address may reach the IPv4-only CIM method, and no IPv4 address may reach
        // the IPv6 mechanism: a merged list is either rejected wholesale or silently truncated.
        assert_eq!(
            restored_live_servers_v4(&saved),
            Some(vec!["8.8.8.8".to_owned(), "8.8.4.4".to_owned()])
        );
        assert_eq!(
            restored_live_servers_v6(&saved),
            Some(vec!["2606:4700:4700::1111".to_owned()])
        );

        let dhcp = AdapterDnsSnapshot {
            interface_guid: "{DHCP}".to_owned(),
            ..Default::default()
        };
        assert_eq!(restored_live_servers_v4(&dhcp), None);
        assert_eq!(restored_live_servers_v6(&dhcp), None);

        // A v4-only adapter must not be handed an empty v6 list that would reset a family it
        // never had, and vice versa.
        let v4_only = AdapterDnsSnapshot {
            interface_guid: "{V4}".to_owned(),
            ipv4_name_server: Some("1.1.1.1".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            restored_live_servers_v4(&v4_only),
            Some(vec!["1.1.1.1".to_owned()])
        );
        assert_eq!(restored_live_servers_v6(&v4_only), None);
    }

    #[test]
    fn restore_proof_covers_v6_only_adapters() {
        let v6_only = AdapterDnsSnapshot {
            interface_guid: "{V6}".to_owned(),
            ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
            ..Default::default()
        };
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![v6_only.clone()],
        };
        assert!(restore_is_proven(
            &snapshot,
            std::slice::from_ref(&v6_only),
            Some(false)
        ));

        let wrong_v6 = AdapterDnsSnapshot {
            ipv6_name_server: Some("2001:db8::53".to_owned()),
            ..v6_only.clone()
        };
        assert!(!restore_is_proven(&snapshot, &[wrong_v6], Some(false)));

        // The protect path leaves IPv6 with no servers now, so this is what a *failed* v6
        // restore looks like: the registry no longer holds the user's resolver.
        let still_protected = AdapterDnsSnapshot {
            ipv6_name_server: Some(NO_NAME_SERVERS.to_owned()),
            ..v6_only.clone()
        };
        assert!(
            !restore_is_proven(&snapshot, &[still_protected], Some(false)),
            "an IPv6 family still holding the empty protected list is not restored, even though \
             an empty list is not itself a loopback value"
        );

        let left_on_loopback_by_an_older_build = AdapterDnsSnapshot {
            ipv6_name_server: Some(LOOPBACK_V6.to_owned()),
            ..v6_only
        };
        assert!(
            !restore_is_proven(&snapshot, &[left_on_loopback_by_an_older_build], Some(true)),
            "still on loopback is not a proven restore"
        );
    }

    #[test]
    fn restore_proof_ignores_adapters_added_after_the_snapshot() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let current = vec![
            adapter("{A}", Some("1.1.1.1")),
            adapter("{NEW}", Some("8.8.8.8")), // appeared later; not ours to prove
        ];
        assert!(restore_is_proven(&snapshot, &current, Some(false)));
    }

    /// The exact real-machine failure, in pure form. The registry held the user's own
    /// resolvers again (`registry_match=true`) and nothing was on loopback, yet the release was
    /// refused because one adapter carried a live-apply-failure flag — and the degraded exit
    /// that exists to prevent that deadlock needs a streak of three, which one click on
    /// Disconnect never reaches. The flag now makes us *demand* live evidence, not overrule it.
    #[test]
    fn a_live_apply_failure_no_longer_vetoes_a_restore_the_live_state_confirms() {
        let mut flagged = adapter("{A}", Some("1.1.1.1"));
        flagged.live_apply_failed = true;
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![flagged],
        };
        let current = vec![adapter("{A}", Some("1.1.1.1"))];
        assert!(
            restore_is_proven(&snapshot, &current, Some(false)),
            "registry restored + nothing on loopback is a proven restore, whatever an earlier \
             round recorded"
        );
        assert!(
            !restore_is_proven(&snapshot, &current, Some(true)),
            "the flag is not what refuses a restore — being provably still on loopback is"
        );
        assert!(
            !restore_is_proven(&snapshot, &current, None),
            "a flagged adapter with no obtainable live evidence stays unproven"
        );

        // Memory failures still merge into the snapshot; they simply no longer decide.
        let clean = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let merged = with_live_failures(&clean, &["{A}".to_owned()].into_iter().collect());
        assert!(merged.adapters[0].live_apply_failed);
        assert!(restore_is_proven(&merged, &current, Some(false)));
        assert!(!restore_is_proven(&merged, &current, Some(true)));
    }

    #[test]
    fn enable_replays_loopback_only_when_protection_drifted() {
        assert!(
            needs_loopback_replay(false, false, false),
            "the first enable must snapshot adapters and apply loopback"
        );
        assert!(!needs_loopback_replay(true, true, false));
        assert!(
            needs_loopback_replay(true, false, false),
            "snapshot present but adapters off loopback: replay the write"
        );
        assert!(
            needs_loopback_replay(true, true, true),
            "a recorded live-apply failure must replay even when the registry is loopback"
        );
        assert!(needs_loopback_replay(false, false, true));
    }

    #[test]
    fn registry_match_ignores_the_live_apply_flag() {
        let mut saved = adapter("{A}", Some("1.1.1.1"));
        saved.live_apply_failed = true;
        let current = adapter("{A}", Some("1.1.1.1"));
        assert!(registry_values_match(&saved, &current));
        let drifted = adapter("{A}", Some("8.8.8.8"));
        assert!(!registry_values_match(&saved, &drifted));
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 42,
            adapters: vec![AdapterDnsSnapshot {
                interface_guid: "{GUID}".to_owned(),
                ipv4_name_server: Some("1.1.1.1,8.8.8.8".to_owned()),
                ipv4_profile_name_server: None,
                ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
                ipv6_profile_name_server: None,
                live_apply_failed: false,
            }],
        };
        let bytes = serde_json::to_vec_pretty(&snapshot).expect("snapshot should serialize");
        assert_eq!(
            serde_json::from_slice::<DnsSnapshot>(&bytes).expect("snapshot should deserialize"),
            snapshot
        );

        // Snapshots written before live-apply tracking must still load (flag defaults off).
        let legacy = serde_json::json!({
            "version": 1,
            "taken_at": 1,
            "adapters": [{
                "interface_guid": "{A}",
                "ipv4_name_server": "1.1.1.1",
                "ipv4_profile_name_server": null,
                "ipv6_name_server": null,
                "ipv6_profile_name_server": null
            }]
        });
        let decoded: DnsSnapshot =
            serde_json::from_value(legacy).expect("legacy snapshot should deserialize");
        assert!(!decoded.adapters[0].live_apply_failed);
    }

    #[test]
    fn an_unreadable_snapshot_is_named_rather_than_thrown() {
        let good = serde_json::to_vec(&DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        })
        .expect("snapshot should serialize");
        assert!(parse_snapshot(&good).is_ok());

        let corrupt = parse_snapshot(b"{not json").expect_err("a corrupt file is unreadable");
        assert!(corrupt.contains("corrupt"), "{corrupt}");

        // A file from a newer build must not be reinterpreted: its `None`/`Some` values decide
        // between deleting and rewriting a registry value.
        let newer = serde_json::json!({
            "version": SNAPSHOT_VERSION + 1,
            "taken_at": 1,
            "adapters": [],
        });
        let reason = parse_snapshot(&serde_json::to_vec(&newer).expect("json"))
            .expect_err("a newer schema is unreadable");
        assert!(reason.contains("newer build"), "{reason}");
    }

    #[test]
    fn the_degraded_restore_exit_needs_a_streak_and_an_exact_registry_match() {
        assert!(
            !accepts_degraded_restore(0, true),
            "a first failure is never degraded-accepted"
        );
        for streak in 1..DEGRADED_RESTORE_STREAK {
            assert!(
                !accepts_degraded_restore(streak, true),
                "streak {streak} is below the documented threshold"
            );
        }
        assert!(
            accepts_degraded_restore(DEGRADED_RESTORE_STREAK, true),
            "a sustained live-apply failure with an exact registry match must not deadlock the \
             user in Protected Offline"
        );
        assert!(
            !accepts_degraded_restore(DEGRADED_RESTORE_STREAK + 10, false),
            "no streak makes a registry mismatch acceptable"
        );
    }

    /// The watchdog may only ever re-apply an existing snapshot. `Reconcile` on a machine with
    /// no snapshot would be an initial enable: it would capture the just-restored resolvers as
    /// "the originals" and point every adapter at a loopback core that is not running.
    #[tokio::test]
    #[serial]
    async fn reconciliation_never_starts_protection_from_nothing() -> Result<()> {
        let snapshot = snapshot_path();
        let _ = tokio::fs::remove_file(&snapshot).await;
        let before = tokio::fs::metadata(&snapshot).await.is_ok();
        assert!(!before, "the test needs a machine with no snapshot");

        let status = enable_unlocked(EnableTrigger::Reconcile).await?;
        assert!(
            !status.snapshot_present,
            "a repair with nothing to repair must not create a snapshot"
        );
        assert!(!status.enabled);
        assert!(
            tokio::fs::metadata(&snapshot).await.is_err(),
            "no snapshot file may be written by the reconciler"
        );
        Ok(())
    }

    /// Put the DNS globals back where a fresh process would have them; these tests drive the
    /// real facade, and a leaked failure flag or streak would decide the next test's proof.
    async fn reset_dns_state() {
        let _ = tokio::fs::remove_file(snapshot_path()).await;
        LIVE_APPLY_FAILURES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        CONSECUTIVE_LIVE_FAILURES.store(0, Ordering::Relaxed);
        *DNS_LAST_ERROR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        test_hooks::set_live_dns_on_loopback(false);
        test_hooks::set_live_apply_fails(false);
    }

    /// The real-machine regression, end to end. `securingDNS` aside, this is the half that
    /// stranded the user: the registry restore had succeeded (`registry_match=true`), the live
    /// apply reported a failure for one adapter (`consecutive_live_apply_failures=1`), nothing
    /// was left on loopback — and the release was refused anyway, because a `live_apply_failed`
    /// flag vetoed the proof. The degraded exit that exists to prevent exactly that deadlock
    /// needs three consecutive failures, which one click on Disconnect can never reach.
    #[tokio::test]
    #[serial]
    async fn a_live_apply_failure_does_not_strand_a_machine_whose_dns_is_restored() -> Result<()> {
        reset_dns_state().await;
        // The live apply fails this round; `engine::apply_snapshot` writes the four registry
        // values regardless, which is why the machine's resolvers are the user's own again.
        test_hooks::set_live_apply_fails(true);
        let mut flagged = adapter("{A}", Some("1.1.1.1"));
        flagged.live_apply_failed = true; // and an earlier round had already recorded one
        atomic_write(
            &snapshot_path(),
            &serde_json::to_vec_pretty(&DnsSnapshot {
                version: SNAPSHOT_VERSION,
                taken_at: 1,
                adapters: vec![flagged],
            })?,
        )
        .await?;

        let status = restore_protected().await?;

        assert!(
            !status.snapshot_present,
            "a proven restore drops the snapshot, which is what opens the disarm gate"
        );
        assert!(
            tokio::fs::metadata(snapshot_path()).await.is_err(),
            "the snapshot file must be gone once the restore is proven"
        );
        assert_eq!(
            status.last_error, None,
            "the live state confirms the restore outright — this is not the degraded exit"
        );
        reset_dns_state().await;
        Ok(())
    }

    /// The other half of the same change: dropping the historical veto must not drop the
    /// ordering invariant. A machine that is provably still resolving through the loopback core
    /// is refused however good the registry looks and however long the failure streak is, and
    /// the refusal has to tell the user what to do about it.
    #[tokio::test]
    #[serial]
    async fn a_restore_is_still_refused_while_an_adapter_is_provably_on_loopback() -> Result<()> {
        reset_dns_state().await;
        test_hooks::set_live_dns_on_loopback(true);
        atomic_write(
            &snapshot_path(),
            &serde_json::to_vec_pretty(&DnsSnapshot {
                version: SNAPSHOT_VERSION,
                taken_at: 1,
                adapters: vec![adapter("{A}", Some("1.1.1.1"))],
            })?,
        )
        .await?;

        let error = restore_protected()
            .await
            .expect_err("a machine still on loopback may not release protection");
        let message = format!("{error:#}");
        assert!(message.contains("registry_match=true"), "{message}");
        assert!(message.contains("still_on_loopback=yes"), "{message}");
        assert!(
            message.contains("consecutive_live_apply_failures="),
            "the diagnosis that made the real failure readable must survive: {message}"
        );
        assert!(
            message.contains("--emergency-disarm") && message.contains("Restore Network"),
            "a refusal must name both documented ways out: {message}"
        );
        assert!(
            tokio::fs::metadata(snapshot_path()).await.is_ok(),
            "a refused restore keeps its snapshot for the retry"
        );
        reset_dns_state().await;
        Ok(())
    }

    #[test]
    fn restoration_without_a_snapshot_needs_positive_evidence() {
        assert!(
            restore_established_without_snapshot(false, false),
            "nothing points at loopback and no live-apply failed: the machine is demonstrably \
             not stranded on a dead resolver"
        );
        assert!(
            !restore_established_without_snapshot(true, false),
            "still on loopback: never disarm on an unreadable snapshot"
        );
        assert!(
            !restore_established_without_snapshot(false, true),
            "a recorded live-apply failure means the running resolver is unproven"
        );
        assert!(!restore_established_without_snapshot(true, true));
    }

    #[test]
    fn reconciliation_backs_off_and_then_suspends() {
        assert_eq!(reconcile_backoff(0), Some(std::time::Duration::ZERO));
        assert_eq!(reconcile_backoff(1), Some(DNS_WATCHDOG_INTERVAL));
        assert_eq!(reconcile_backoff(2), Some(DNS_WATCHDOG_INTERVAL * 2));
        assert!(
            reconcile_backoff(DNS_RECONCILE_MAX_FAILURES - 1) <= Some(DNS_RECONCILE_MAX_BACKOFF)
        );
        assert_eq!(
            reconcile_backoff(DNS_RECONCILE_MAX_FAILURES),
            None,
            "the repair loop must stop rather than spawn PowerShell forever"
        );
        assert_eq!(reconcile_backoff(DNS_RECONCILE_MAX_FAILURES + 100), None);
    }

    /// The S1 residual risk in miniature, and the mirror of the WFP module's test: a DNS engine
    /// call that never returns must produce a mappable error, and the abandoned blocking thread
    /// must keep the single-writer claim until the call really comes back. The engine itself is
    /// Windows-only, so the closure stands in for a wedged Dnscache/registry sweep — the
    /// ownership rules under test are the engine-independent part.
    #[tokio::test]
    #[serial]
    async fn a_wedged_dns_call_times_out_and_blocks_a_second_writer() -> Result<()> {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let wedged = move || -> Result<()> {
            let _ = blocked.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        };

        let timed_out = bounded_dns_call(std::time::Duration::from_millis(50), "flush", wedged)
            .await
            .expect_err("a call that never returns must not be awaited forever");
        let message = format!("{timed_out:#}");
        assert!(message.contains(DNS_ENGINE_WEDGED_PREFIX), "{message}");
        assert!(message.contains("flush"), "{message}");

        // The claim is still held by the running thread, so nothing may start a second DNS
        // writer — the refusal names the operation that is stuck.
        let refused = bounded_dns_call(std::time::Duration::from_secs(5), "collect", || Ok(()))
            .await
            .expect_err("a second writer must be refused while the first is still running");
        let message = format!("{refused:#}");
        assert!(message.contains(DNS_ENGINE_WEDGED_PREFIX), "{message}");
        assert!(message.contains("flush"), "{message}");

        // Only the abandoned call itself releases the claim, and it does so on its own thread.
        release.send(()).expect("the wedged call is still running");
        for _ in 0..300 {
            if dns_call_in_flight().is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            dns_call_in_flight().is_none(),
            "the blocking thread must release the claim when the call finally returns"
        );
        bounded_dns_call(std::time::Duration::from_secs(5), "collect", || Ok(())).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn a_healthy_dns_call_leaves_no_claim_behind() -> Result<()> {
        bounded_dns_call(std::time::Duration::from_secs(5), "collect", || Ok(())).await?;
        assert!(
            dns_call_in_flight().is_none(),
            "a completed call must not keep the next operation out"
        );
        let error = bounded_dns_call(
            std::time::Duration::from_secs(5),
            "flush",
            || -> Result<()> { bail!("engine said no") },
        )
        .await
        .expect_err("engine errors still propagate");
        assert!(format!("{error:#}").contains("engine said no"));
        assert!(dns_call_in_flight().is_none());
        Ok(())
    }
}
