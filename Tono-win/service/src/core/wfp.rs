//! The WFP engine for the Tono kill switch (`docs/wfp-kill-switch.md`).
//!
//! This module is the *only* place that talks to `Fwpm*`: all `unsafe` FFI for the kill switch
//! lives here, behind a small safe API the cross-platform facade (`windows_kill_switch.rs`)
//! drives. What gets installed is decided entirely by the pure rule model (`wfp_model.rs`);
//! this file only renders [`FilterSpec`]s into `FWPM_FILTER0`s, applies them transactionally,
//! and verifies them by key.
//!
//! Provider isolation is the safety boundary: every object carries
//! [`TONO_WFP_PROVIDER_KEY`], so enumeration, verification, and emergency deletion never touch
//! another provider, sublayer, or any Windows Defender Firewall policy.

use crate::core::wfp_model::{
    self as model, Condition, FilterAction, FilterSpec, Guid, LayerKind, TONO_WFP_PROVIDER_KEY,
    TONO_WFP_SUBLAYER_KEY, TONO_WFP_SUBLAYER_WEIGHT,
};
use anyhow::{Context as _, Result, anyhow, bail};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, GetIfEntry2, IF_TYPE_PROP_VIRTUAL, IF_TYPE_TUNNEL, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK, FWP_CONDITION_FLAG_IS_NON_APPCONTAINER_LOOPBACK,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ANY_SET,
    FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V6, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFilterGetByKey0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmProviderGetByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDeleteByKey0,
    FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0, FwpmSubLayerGetByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::core::GUID;

// WFP error codes (fwpmu.h); windows-sys does not expose the FWP_E_* constants.
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0002;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0004;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
/// `RPC_C_AUTHN_WINNT`: negotiate the machine's own authentication for the local BFE RPC.
const RPC_C_AUTHN_WINNT: u32 = 10;

/// What the SCM says about the Base Filtering Engine: `(is_running, state_name)`.
///
/// Every `Fwpm*` call in this file is an RPC to that service — it is the declared start
/// dependency of this one (`install_service.rs`) — so its state is the single most useful
/// thing to log before the first `FwpmEngineOpen0`. This is an SCM query, not WFP: it does not
/// touch the engine and cannot itself be blocked by a wedged filtering transaction.
pub(crate) fn bfe_service_state() -> Result<(bool, String)> {
    use platform_lib::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connecting to the service control manager")?;
    let service = manager
        .open_service("BFE", ServiceAccess::QUERY_STATUS)
        .context("opening the Base Filtering Engine (BFE) service")?;
    let state = service
        .query_status()
        .context("querying the Base Filtering Engine (BFE) service status")?
        .current_state;
    Ok((state == ServiceState::Running, format!("{state:?}")))
}

fn to_sys(guid: Guid) -> GUID {
    let bytes = guid.into_u128().to_be_bytes();
    GUID {
        data1: u32::from_be_bytes(bytes[0..4].try_into().expect("guid segment")),
        data2: u16::from_be_bytes(bytes[4..6].try_into().expect("guid segment")),
        data3: u16::from_be_bytes(bytes[6..8].try_into().expect("guid segment")),
        data4: bytes[8..16].try_into().expect("guid segment"),
    }
}

fn from_sys(guid: GUID) -> Guid {
    let mut bytes = [0_u8; 16];
    bytes[0..4].copy_from_slice(&guid.data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.data4);
    Guid::from_u128(u128::from_be_bytes(bytes))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(status: u32, what: &str) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(anyhow!("{what} failed: WFP error {status:#010x}"))
    }
}

/// Free an engine-allocated block. `FwpmFreeMemory0` takes the address of the pointer so it
/// can null it.
///
/// SAFETY: `ptr` must be null or a pointer previously returned by a `Fwpm*Get*`/`Fwpm*Enum*`/
/// `FwpmGetAppIdFromFileName0` call; it is consumed exactly once here.
unsafe fn free_block<T>(ptr: *mut T) {
    if !ptr.is_null() {
        let mut block = ptr.cast::<c_void>();
        // SAFETY: upheld by the caller contract above.
        unsafe { FwpmFreeMemory0(&mut block) };
    }
}

struct Engine(HANDLE);

impl Engine {
    fn open() -> Result<Self> {
        let mut handle = std::ptr::null_mut();
        // Default (non-dynamic) session: objects outlive this handle; only filters explicitly
        // flagged persistent survive a reboot — the model assigns that flag.
        // SAFETY: all out-parameters are valid stack slots; null server/session selects the
        // local engine with a default session.
        let status = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                std::ptr::null(),
                &mut handle,
            )
        };
        check(status, "FwpmEngineOpen0")?;
        Ok(Self(handle))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `FwpmEngineOpen0` and is closed once.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// Run `body` inside one WFP transaction: every multi-filter change commits atomically or not
/// at all.
fn transaction<T>(engine: &Engine, body: impl FnOnce(&Engine) -> Result<T>) -> Result<T> {
    // SAFETY: valid engine handle; flags 0 = read/write transaction.
    check(
        unsafe { FwpmTransactionBegin0(engine.0, 0) },
        "FwpmTransactionBegin0",
    )?;
    match body(engine) {
        Ok(value) => {
            if let Err(error) = check(
                // SAFETY: valid engine handle with an open transaction.
                unsafe { FwpmTransactionCommit0(engine.0) },
                "FwpmTransactionCommit0",
            ) {
                // A failed commit leaves the transaction open; abort it explicitly so the
                // engine cannot hold a half-committed change against this session.
                // SAFETY: valid engine handle with an open transaction.
                let _ = unsafe { FwpmTransactionAbort0(engine.0) };
                return Err(error);
            }
            Ok(value)
        }
        Err(error) => {
            // SAFETY: valid engine handle with an open transaction.
            let _ = unsafe { FwpmTransactionAbort0(engine.0) };
            Err(error)
        }
    }
}

fn ensure_provider_and_sublayer(engine: &Engine) -> Result<()> {
    transaction(engine, |engine| {
        add_provider(engine)?;
        add_sublayer(engine)
    })
}

fn add_provider(engine: &Engine) -> Result<()> {
    let name = wide("Tono");
    let description = wide("Tono kill switch provider");
    let provider = FWPM_PROVIDER0 {
        providerKey: to_sys(TONO_WFP_PROVIDER_KEY),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..Default::default()
    };
    // SAFETY: `provider` and the wide strings it points to outlive the call; no security
    // descriptor (engine default).
    let status = unsafe { FwpmProviderAdd0(engine.0, &provider, std::ptr::null_mut()) };
    if status != 0 && status != FWP_E_ALREADY_EXISTS {
        bail!("FwpmProviderAdd0 failed: WFP error {status:#010x}");
    }
    Ok(())
}

fn add_sublayer(engine: &Engine) -> Result<()> {
    let name = wide("tono-kill-switch");
    let description = wide("Tono kill switch sublayer");
    let mut provider_key = to_sys(TONO_WFP_PROVIDER_KEY);
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: to_sys(TONO_WFP_SUBLAYER_KEY),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        providerData: FWP_BYTE_BLOB::default(),
        weight: TONO_WFP_SUBLAYER_WEIGHT,
    };
    // SAFETY: as for the provider; `provider_key` outlives the call.
    let status = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, std::ptr::null_mut()) };
    if status != 0 && status != FWP_E_ALREADY_EXISTS {
        bail!("FwpmSubLayerAdd0 failed: WFP error {status:#010x}");
    }
    Ok(())
}

/// Heap-pinned condition values. `FWPM_FILTER_CONDITION0` borrows masks, ranges, and the
/// weight/app-id by pointer, so everything pointed at lives here until the add call returns
/// (WFP copies synchronously during `FwpmFilterAdd0`).
#[derive(Default)]
struct Keepalive {
    v4_masks: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6_masks: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    ranges: Vec<Box<FWP_RANGE0>>,
    u64s: Vec<Box<u64>>,
}

fn condition_value_u16(value: u16) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
    }
}

fn build_condition(
    condition: &Condition,
    app_id: *mut FWP_BYTE_BLOB,
    keep: &mut Keepalive,
) -> Result<FWPM_FILTER_CONDITION0> {
    let built = match condition {
        Condition::RemoteAddressV4 { addr, prefix } => {
            let mask = if *prefix == 0 {
                0
            } else {
                u32::MAX << (32 - *prefix)
            };
            keep.v4_masks.push(Box::new(FWP_V4_ADDR_AND_MASK {
                addr: u32::from_be_bytes(*addr),
                mask,
            }));
            let ptr = keep.v4_masks.last_mut().map(|v| &mut **v).expect("pushed");
            (
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: ptr },
                },
            )
        }
        Condition::RemoteAddressV6 { addr, prefix } => {
            keep.v6_masks.push(Box::new(FWP_V6_ADDR_AND_MASK {
                addr: *addr,
                prefixLength: *prefix,
            }));
            let ptr = keep.v6_masks.last_mut().map(|v| &mut **v).expect("pushed");
            (
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: ptr },
                },
            )
        }
        Condition::Protocol(protocol) => (
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_MATCH_EQUAL,
            FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: protocol.number(),
                },
            },
        ),
        Condition::LocalPort(port) => (
            FWPM_CONDITION_IP_LOCAL_PORT,
            FWP_MATCH_EQUAL,
            condition_value_u16(*port),
        ),
        Condition::RemotePort(port) => (
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_MATCH_EQUAL,
            condition_value_u16(*port),
        ),
        Condition::IcmpV6TypeRange { min, max } => {
            // FWPM_CONDITION_ICMP_TYPE is a `#define` alias of FWPM_CONDITION_IP_LOCAL_PORT
            // in fwpmu.h, so the metadata-based bindings only carry the latter; the SDK's C
            // code resolves to exactly this field key for ICMP types.
            keep.ranges.push(Box::new(FWP_RANGE0 {
                valueLow: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: *min },
                },
                valueHigh: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: *max },
                },
            }));
            let ptr = keep.ranges.last_mut().map(|v| &mut **v).expect("pushed");
            (
                FWPM_CONDITION_IP_LOCAL_PORT,
                FWP_MATCH_RANGE,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_RANGE_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { rangeValue: ptr },
                },
            )
        }
        Condition::AleLoopback => (
            FWPM_CONDITION_FLAGS,
            FWP_MATCH_FLAGS_ANY_SET,
            FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK
                        | FWP_CONDITION_FLAG_IS_NON_APPCONTAINER_LOOPBACK,
                },
            },
        ),
        Condition::AleAppId => {
            if app_id.is_null() {
                bail!("filter requires the staged core app-id, which was not resolved");
            }
            (
                FWPM_CONDITION_ALE_APP_ID,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                },
            )
        }
        Condition::LocalInterface(luid) => {
            keep.u64s.push(Box::new(*luid));
            let ptr = keep.u64s.last_mut().map(|v| &mut **v).expect("pushed");
            (
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint64: ptr },
                },
            )
        }
    };
    Ok(FWPM_FILTER_CONDITION0 {
        fieldKey: built.0,
        matchType: built.1,
        conditionValue: built.2,
    })
}

fn layer_key(layer: LayerKind) -> GUID {
    match layer {
        LayerKind::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        LayerKind::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        LayerKind::AleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        LayerKind::OutboundTransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        LayerKind::OutboundTransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
    }
}

fn add_filter(engine: &Engine, spec: &FilterSpec, app_id: *mut FWP_BYTE_BLOB) -> Result<()> {
    let mut keep = Keepalive::default();
    let mut conditions = spec
        .conditions
        .iter()
        .map(|condition| build_condition(condition, app_id, &mut keep))
        .collect::<Result<Vec<_>>>()?;
    keep.u64s.push(Box::new(spec.weight));
    let weight_ptr = keep.u64s.last_mut().map(|v| &mut **v).expect("pushed");

    let name = wide(&spec.name);
    let description = wide("Tono kill switch filter");
    let mut provider_key = to_sys(TONO_WFP_PROVIDER_KEY);
    let mut flags = 0;
    if spec.persistent {
        flags |= FWPM_FILTER_FLAG_PERSISTENT;
    }
    if spec.hard_permit {
        debug_assert_eq!(spec.action, FilterAction::Permit);
        flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    }

    let mut filter = FWPM_FILTER0 {
        filterKey: to_sys(spec.key),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags,
        providerKey: &mut provider_key,
        layerKey: layer_key(spec.layer),
        subLayerKey: to_sys(TONO_WFP_SUBLAYER_KEY),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 { uint64: weight_ptr },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: if conditions.is_empty() {
            std::ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: match spec.action {
                FilterAction::Permit => FWP_ACTION_PERMIT,
                FilterAction::Block => FWP_ACTION_BLOCK,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: every pointer inside `filter` (wide strings, provider key, condition array and
    // the heap-pinned values it references in `keep`) is valid until this call returns, and
    // WFP copies what it needs synchronously.
    let status = unsafe {
        FwpmFilterAdd0(
            engine.0,
            &mut filter,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 && status != FWP_E_ALREADY_EXISTS {
        bail!(
            "FwpmFilterAdd0 ({}) failed: WFP error {status:#010x}",
            spec.name
        );
    }
    Ok(())
}

fn delete_filter_if_exists(engine: &Engine, key: Guid) -> Result<()> {
    let key = to_sys(key);
    // SAFETY: valid engine handle; `key` outlives the call.
    let status = unsafe { FwpmFilterDeleteByKey0(engine.0, &key) };
    if status != 0 && status != FWP_E_FILTER_NOT_FOUND {
        bail!("FwpmFilterDeleteByKey0 failed: WFP error {status:#010x}");
    }
    Ok(())
}

/// The resolved `ALE_APP_ID` blob of the staged core binary. Freed on drop.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    /// `None` when no path is recorded (emergency intent). That is only benign while the plan
    /// contains no app-scoped rule; `install` turns it into the fail-closed fallback otherwise,
    /// because a null blob would abort the transaction that carries the block itself.
    fn resolve(path: &str) -> Result<Option<Self>> {
        if path.is_empty() {
            return Ok(None);
        }
        let wide = wide(path);
        let mut blob = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the call; `blob` is a
        // valid out-pointer.
        let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
        if status != 0 {
            bail!(
                "FwpmGetAppIdFromFileName0 ({path}) failed: WFP error {status:#010x} \
                 (the staged core binary must exist at its recorded path)"
            );
        }
        Ok(Some(Self(blob)))
    }

    fn ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `FwpmGetAppIdFromFileName0` and is freed once.
        unsafe { free_block(self.0) };
    }
}

/// Absolute deadline for one enumeration loop, checked between pages. Enumerating a whole
/// engine is milliseconds when it is healthy, and this sits well inside the facade's per-call
/// budget (`WFP_CALL_TIMEOUT`, 25 s): the blocking thread therefore terminates — and releases
/// the facade's single-writer claim, which only that thread can release — before its caller
/// gives up on the answer.
const ENUM_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// Hard cap on the entries one enumeration may return. Every provider's filters on a real
/// machine amount to a few thousand; 2^18 is far beyond that and still finite, so an engine
/// that keeps handing back pages — or hands back the same page forever — cannot keep this
/// thread inside the loop for the life of the process.
const ENUM_MAX_ENTRIES: usize = 262_144;

/// The bound on one `Fwpm*Enum0` loop: an absolute deadline and an entry cap.
///
/// Those loops stop only when the engine reports zero entries, so without this a single
/// misbehaving enumeration is permanent, not merely slow: the caller's budget abandons the
/// *answer* but deliberately leaves the in-flight claim standing until this thread returns, and
/// every later WFP operation — arm, lock, verify, release, emergency disarm — is then refused
/// until the process restarts.
///
/// Exceeding either bound is an error, never a short result. A truncated enumeration read as
/// "these are all our filters" would make the install diff delete filters that are still live,
/// or make the residual check report a clean machine that is in fact still blocked.
struct EnumBudget {
    what: &'static str,
    /// The start, not a precomputed deadline: `Instant::elapsed` cannot panic, whereas
    /// `Instant` arithmetic can.
    started_at: std::time::Instant,
    seen: usize,
}

impl EnumBudget {
    fn new(what: &'static str) -> Self {
        Self {
            what,
            started_at: std::time::Instant::now(),
            seen: 0,
        }
    }

    /// Charge one returned page. Called after the page has been consumed and freed, so an
    /// over-budget enumeration cannot leak the engine allocation it was reading.
    fn charge(&mut self, returned: u32) -> Result<()> {
        self.seen = self.seen.saturating_add(returned as usize);
        if self.seen > ENUM_MAX_ENTRIES {
            bail!(
                "{} returned more than {ENUM_MAX_ENTRIES} entries without finishing; the result \
                 is incomplete and is discarded rather than treated as the full set",
                self.what
            );
        }
        if self.started_at.elapsed() >= ENUM_DEADLINE {
            bail!(
                "{} did not finish within {ENUM_DEADLINE:?} ({} entries so far); the result is \
                 incomplete and is discarded rather than treated as the full set",
                self.what,
                self.seen
            );
        }
        Ok(())
    }
}

/// A Tono filter found in the engine: its key and the sublayer it lives in (needed by the
/// legacy sweep, which must empty a foreign sublayer before deleting it).
struct FilterInfo {
    key: Guid,
    sublayer: Guid,
}

/// Every Tono-provider filter currently installed — any layer, any sublayer. The enum
/// template is NULL (every filter in the engine) and provider scoping happens in userspace,
/// so a rule left by an older build on a layer or in a sublayer the current model no longer
/// uses is still found for reconciliation and the emergency sweep. No other provider's
/// objects are ever collected.
///
/// Bounded by [`EnumBudget`] and all-or-nothing: callers diff against this list and delete what
/// is missing from it, so a partial answer is returned as an error, never as a short `Vec`.
fn enumerate_our_filters(engine: &Engine) -> Result<Vec<FilterInfo>> {
    let mut filters = Vec::new();
    let mut enum_handle = std::ptr::null_mut();
    // SAFETY: valid engine handle; NULL template enumerates all filters in the engine.
    let status =
        unsafe { FwpmFilterCreateEnumHandle0(engine.0, std::ptr::null(), &mut enum_handle) };
    check(status, "FwpmFilterCreateEnumHandle0")?;
    let result = (|| -> Result<()> {
        let mut budget = EnumBudget::new("FwpmFilterEnum0 (Tono filter enumeration)");
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned = 0_u32;
            // SAFETY: valid handles; `entries`/`returned` are valid out-pointers.
            let status =
                unsafe { FwpmFilterEnum0(engine.0, enum_handle, 128, &mut entries, &mut returned) };
            check(status, "FwpmFilterEnum0")?;
            if returned == 0 {
                // Free the empty page too: the zero-count call is how *every* enumeration
                // ends, so skipping it would leak one engine allocation per install, residual
                // check and legacy sweep. `free_block` ignores a null pointer.
                // SAFETY: `entries` is null or the engine-allocated array from the call above.
                unsafe { free_block(entries) };
                break;
            }
            for index in 0..returned as isize {
                // SAFETY: `entries` points to an array of `returned` pointers owned by the
                // engine allocation freed below.
                let filter = unsafe { *entries.offset(index) };
                if filter.is_null() {
                    continue;
                }
                // SAFETY: non-null element of the enumerated array; `providerKey` is either
                // null (providerless filters) or a valid GUID pointer for the call duration.
                let (key, provider, sublayer) = unsafe {
                    let filter = &*filter;
                    let provider =
                        (!filter.providerKey.is_null()).then(|| from_sys(*filter.providerKey));
                    (filter.filterKey, provider, filter.subLayerKey)
                };
                if provider == Some(TONO_WFP_PROVIDER_KEY) {
                    filters.push(FilterInfo {
                        key: from_sys(key),
                        sublayer: from_sys(sublayer),
                    });
                }
            }
            // SAFETY: `entries` is the engine-allocated array from the call above.
            unsafe { free_block(entries) };
            budget.charge(returned)?;
        }
        Ok(())
    })();
    // SAFETY: valid engine + enum handles.
    let destroy = unsafe { FwpmFilterDestroyEnumHandle0(engine.0, enum_handle) };
    result?;
    check(destroy, "FwpmFilterDestroyEnumHandle0")?;
    Ok(filters)
}

fn enumerate_our_filter_keys(engine: &Engine) -> Result<Vec<Guid>> {
    Ok(enumerate_our_filters(engine)?
        .into_iter()
        .map(|info| info.key)
        .collect())
}

/// Every Tono-provider sublayer key, current or left by an older build.
fn enumerate_our_sublayer_keys(engine: &Engine) -> Result<Vec<Guid>> {
    let mut keys = Vec::new();
    let mut enum_handle = std::ptr::null_mut();
    // SAFETY: valid engine handle; NULL template enumerates all sublayers in the engine.
    let status =
        unsafe { FwpmSubLayerCreateEnumHandle0(engine.0, std::ptr::null(), &mut enum_handle) };
    check(status, "FwpmSubLayerCreateEnumHandle0")?;
    let result = (|| -> Result<()> {
        let mut budget = EnumBudget::new("FwpmSubLayerEnum0 (Tono sublayer enumeration)");
        loop {
            let mut entries: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
            let mut returned = 0_u32;
            // SAFETY: valid handles; `entries`/`returned` are valid out-pointers.
            let status = unsafe {
                FwpmSubLayerEnum0(engine.0, enum_handle, 64, &mut entries, &mut returned)
            };
            check(status, "FwpmSubLayerEnum0")?;
            if returned == 0 {
                // As for filters: free the terminating empty page as well.
                // SAFETY: `entries` is null or the engine-allocated array from the call above.
                unsafe { free_block(entries) };
                break;
            }
            for index in 0..returned as isize {
                // SAFETY: as for filters; provider scoping happens in userspace.
                let sublayer = unsafe { *entries.offset(index) };
                if sublayer.is_null() {
                    continue;
                }
                let (key, provider) = unsafe {
                    let sublayer = &*sublayer;
                    let provider =
                        (!sublayer.providerKey.is_null()).then(|| from_sys(*sublayer.providerKey));
                    (sublayer.subLayerKey, provider)
                };
                if provider == Some(TONO_WFP_PROVIDER_KEY) {
                    keys.push(from_sys(key));
                }
            }
            // SAFETY: engine-allocated array from the call above.
            unsafe { free_block(entries) };
            budget.charge(returned)?;
        }
        Ok(())
    })();
    // SAFETY: valid engine + enum handles.
    let destroy = unsafe { FwpmSubLayerDestroyEnumHandle0(engine.0, enum_handle) };
    result?;
    check(destroy, "FwpmSubLayerDestroyEnumHandle0")?;
    Ok(keys)
}

/// Upgrade/migration sweep: any Tono-provider sublayer that is not the current one is a
/// leftover from an older build. Its filters must go first (a sublayer cannot be deleted
/// while it holds filters), then the sublayer itself. Returns how many sublayers were
/// removed.
pub(crate) fn remove_legacy_sublayers() -> Result<usize> {
    let engine = Engine::open()?;
    if !provider_exists(&engine)? {
        return Ok(0);
    }
    let filters = enumerate_our_filters(&engine)?;
    let legacy = enumerate_our_sublayer_keys(&engine)?
        .into_iter()
        .filter(|key| *key != TONO_WFP_SUBLAYER_KEY)
        .collect::<Vec<_>>();
    if legacy.is_empty() {
        return Ok(0);
    }
    let removed = legacy.len();
    transaction(&engine, |engine| {
        for info in filters
            .iter()
            .filter(|info| legacy.contains(&info.sublayer))
        {
            delete_filter_if_exists(engine, info.key)?;
        }
        for key in &legacy {
            let sys = to_sys(*key);
            // SAFETY: valid engine handle; `sys` outlives the call.
            let status = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sys) };
            if status != 0 && status != FWP_E_SUBLAYER_NOT_FOUND {
                bail!("FwpmSubLayerDeleteByKey0 (legacy) failed: WFP error {status:#010x}");
            }
        }
        Ok(())
    })?;
    Ok(removed)
}

fn provider_exists(engine: &Engine) -> Result<bool> {
    let key = to_sys(TONO_WFP_PROVIDER_KEY);
    let mut provider = std::ptr::null_mut();
    // SAFETY: valid engine handle; valid out-pointer.
    let status = unsafe { FwpmProviderGetByKey0(engine.0, &key, &mut provider) };
    match status {
        0 => {
            // SAFETY: engine-allocated on success.
            unsafe { free_block(provider) };
            Ok(true)
        }
        FWP_E_PROVIDER_NOT_FOUND => Ok(false),
        other => Err(anyhow!(
            "FwpmProviderGetByKey0 failed: WFP error {other:#010x}"
        )),
    }
}

fn apply_plan(engine: &Engine, plan: &model::ChangePlan, app_id: Option<&AppId>) -> Result<()> {
    transaction(engine, |engine| {
        // Installs strictly before removes (the plan's ordering contract): a new endpoint
        // permit is committed together with the old one's removal, so the switch is atomic
        // and never passes through a direct-traffic window.
        let blob = app_id.map_or(std::ptr::null_mut(), AppId::ptr);
        for spec in &plan.install {
            add_filter(engine, spec, blob)?;
        }
        for key in &plan.remove {
            delete_filter_if_exists(engine, *key)?;
        }
        Ok(())
    })
}

fn verify_by_key(engine: &Engine, expected: &[FilterSpec]) -> Result<()> {
    for key in [TONO_WFP_PROVIDER_KEY, TONO_WFP_SUBLAYER_KEY] {
        let sys = to_sys(key);
        if key == TONO_WFP_PROVIDER_KEY {
            let mut provider = std::ptr::null_mut();
            // SAFETY: valid engine handle; valid out-pointer.
            let status = unsafe { FwpmProviderGetByKey0(engine.0, &sys, &mut provider) };
            if status != 0 {
                bail!("kill-switch provider missing: WFP error {status:#010x}");
            }
            // SAFETY: engine-allocated on success.
            unsafe { free_block(provider) };
        } else {
            let mut sublayer = std::ptr::null_mut();
            // SAFETY: valid engine handle; valid out-pointer.
            let status = unsafe { FwpmSubLayerGetByKey0(engine.0, &sys, &mut sublayer) };
            if status != 0 {
                bail!("kill-switch sublayer missing: WFP error {status:#010x}");
            }
            // SAFETY: engine-allocated on success.
            unsafe { free_block(sublayer) };
        }
    }
    for spec in expected {
        let key = to_sys(spec.key);
        let mut filter = std::ptr::null_mut();
        // SAFETY: valid engine handle; valid out-pointer.
        let status = unsafe { FwpmFilterGetByKey0(engine.0, &key, &mut filter) };
        if status != 0 {
            bail!(
                "expected kill-switch filter missing ({}): WFP error {status:#010x}",
                spec.name
            );
        }
        // SAFETY: engine-allocated on success.
        unsafe { free_block(filter) };
    }
    Ok(())
}

/// Install exactly `expected`: ensure provider + sublayer, add missing filters, remove stale
/// ones (single transaction), then verify every expected object by key.
pub(crate) fn install(expected: &[FilterSpec], app_path: &str) -> Result<()> {
    let engine = Engine::open()?;
    ensure_provider_and_sublayer(&engine)?;
    let current = enumerate_our_filter_keys(&engine)?;
    let plan = model::diff(&current, expected);

    let needs_app_id = plan
        .install
        .iter()
        .any(|spec| spec.conditions.contains(&Condition::AleAppId));
    let app_id = if needs_app_id {
        // `Ok(None)` (no recorded path) is as fatal as a resolve failure once the plan actually
        // contains an app-scoped rule, and it must take the same fail-closed fallback: handing
        // `apply_plan` a null blob makes `build_condition` bail *inside* the transaction, which
        // aborts the whole commit — the block-all floor included — and leaves the machine fully
        // open while the intent still says wanted. Collapse it into the error case here.
        match AppId::resolve(app_path).and_then(|resolved| {
            resolved.context("no staged core path is recorded for the app-scoped permit")
        }) {
            Ok(app_id) => Some(app_id),
            Err(error) => {
                // Fail closed: install everything except the app-scoped permits so the block
                // is live, then surface why the endpoint permit is missing. The watchdog will
                // keep retrying the full set.
                let without_app_rules = model::ChangePlan {
                    install: plan
                        .install
                        .iter()
                        .filter(|spec| !spec.conditions.contains(&Condition::AleAppId))
                        .cloned()
                        .collect(),
                    remove: plan.remove.clone(),
                };
                apply_plan(&engine, &without_app_rules, None)?;
                return Err(error).context(
                    "installed the block without the core endpoint permit; traffic stays blocked",
                );
            }
        }
    } else {
        None
    };

    apply_plan(&engine, &plan, app_id.as_ref())?;
    verify_by_key(&engine, expected)
}

/// Verify the provider, the sublayer, and every expected filter by key.
pub(crate) fn verify(expected: &[FilterSpec]) -> Result<()> {
    let engine = Engine::open()?;
    if !provider_exists(&engine)? {
        bail!("kill-switch provider is not installed");
    }
    verify_by_key(&engine, expected)
}

/// Remove every Tono filter; provider and sublayer stay, inert — the counterpart of the macOS
/// helper keeping its empty anchor attached during normal operation.
pub(crate) fn remove_all_filters() -> Result<()> {
    let engine = Engine::open()?;
    if !provider_exists(&engine)? {
        return Ok(());
    }
    let keys = enumerate_our_filter_keys(&engine)?;
    transaction(&engine, |engine| {
        for key in &keys {
            delete_filter_if_exists(engine, *key)?;
        }
        Ok(())
    })?;
    let remaining = enumerate_our_filter_keys(&engine)?;
    if !remaining.is_empty() {
        bail!("{} kill-switch filters survived removal", remaining.len());
    }
    Ok(())
}

/// Whether any Tono filter exists — the residual-object check for fail-closed startup.
pub(crate) fn any_filters_exist() -> Result<bool> {
    let engine = Engine::open()?;
    if !provider_exists(&engine)? {
        return Ok(false);
    }
    Ok(!enumerate_our_filter_keys(&engine)?.is_empty())
}

/// The escape hatch: delete filters → legacy sublayers → sublayer → provider, scoped by the
/// Tono provider key. Nothing outside the provider is touched.
pub(crate) fn emergency_disarm() -> Result<()> {
    let engine = Engine::open()?;
    if !provider_exists(&engine)? {
        return Ok(());
    }
    remove_all_filters()?;
    // Older builds may have used other sublayer GUIDs: sweep them too, or their filters
    // would keep blocking after the provider is gone.
    remove_legacy_sublayers()?;
    transaction(&engine, |engine| {
        let sys = to_sys(TONO_WFP_SUBLAYER_KEY);
        // SAFETY: valid engine handle; `sys` outlives the call.
        let status = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &sys) };
        if status != 0 && status != FWP_E_SUBLAYER_NOT_FOUND {
            bail!("FwpmSubLayerDeleteByKey0 failed: WFP error {status:#010x}");
        }
        let sys = to_sys(TONO_WFP_PROVIDER_KEY);
        // SAFETY: valid engine handle; `sys` outlives the call.
        let status = unsafe { FwpmProviderDeleteByKey0(engine.0, &sys) };
        if status != 0 && status != FWP_E_PROVIDER_NOT_FOUND {
            bail!("FwpmProviderDeleteByKey0 failed: WFP error {status:#010x}");
        }
        Ok(())
    })
}

/// Resolve a network interface alias (e.g. `Tono`) to its LUID, and prove the result is
/// really a tunnel device.
pub(crate) fn luid_for_interface(name: &str) -> Result<u64> {
    let wide = wide(name);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer; `luid` is a valid out-pointer.
    let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if status != 0 {
        bail!("interface alias {name:?} did not resolve to a LUID: Windows error {status}");
    }
    // SAFETY: `Value` is the plain u64 view of the union, valid after a successful call.
    let luid = unsafe { luid.Value };
    validate_tunnel_luid(luid)?;
    Ok(luid)
}

/// A name match is not enough: a same-named *physical* adapter would otherwise receive the
/// lock phase's weight-8 permit — a fail-open primitive for every process on the machine.
/// Wintun devices describe themselves as "Wintun Userspace Tunnel"; anything that is neither
/// that nor an unmistakably virtual/tunnel interface type fails the lock (the caller's retry
/// path handles a still-initializing adapter).
fn validate_tunnel_luid(luid: u64) -> Result<()> {
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    // SAFETY: `row` is a valid in/out buffer; the LUID identifies the requested interface.
    let status = unsafe { GetIfEntry2(&mut row) };
    if status != 0 {
        bail!("GetIfEntry2 failed for LUID {luid}: Windows error {status}");
    }
    let end = row
        .Description
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(row.Description.len());
    let description = String::from_utf16_lossy(&row.Description[..end]).to_lowercase();
    if description.contains("wintun") {
        return Ok(());
    }
    if row.Type == IF_TYPE_PROP_VIRTUAL || row.Type == IF_TYPE_TUNNEL {
        tracing::info!(
            "tunnel LUID {luid} accepted by interface type {} (description {description:?})",
            row.Type
        );
        return Ok(());
    }
    bail!(
        "interface LUID {luid} is not a tunnel device (type {}, description {description:?}); refusing to lock",
        row.Type
    )
}
