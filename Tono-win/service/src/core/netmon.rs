//! Network and power change monitoring for the Windows kill switch.
//!
//! `NotifyIpInterfaceChange` / `NotifyRouteChange2` callbacks and `SERVICE_CONTROL_POWEREVENT`
//! all funnel into one debounced (750 ms) event note. The service-side contract per
//! `docs/wfp-kill-switch.md`'s failure matrix is deliberately narrow: **the barrier stays** —
//! every event is recorded for `/status` reporting and the log, an armed kill switch stays
//! armed, and "Connected invalidated → reconnect behind the barrier" is the product layer's
//! job (it owns the UI `Connected` state; the service merely guarantees the fail-closed link
//! in the chain: event → invalidation signal → still blocking).

use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_RECORDED_EVENTS: usize = 32;
#[cfg(not(feature = "test"))]
const DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(750);

static EVENTS: Lazy<Mutex<VecDeque<String>>> = Lazy::new(|| Mutex::new(VecDeque::new()));
static LAST_KIND: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
static LAST_AT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
static CHANGE_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg_attr(feature = "test", allow(dead_code))]
static STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "test"))]
static PENDING_RAW: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "test"))]
static LAST_RAW_MILLIS: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Record an event. Never disarms anything — see the module doc.
pub(crate) fn note_event(kind: &str) {
    CHANGE_COUNT.fetch_add(1, Ordering::Relaxed);
    *LAST_KIND.lock().unwrap() = Some(kind.to_owned());
    LAST_AT.store(now_unix() as i64, Ordering::Relaxed);
    let event = format!("{kind} @{}", now_unix());
    tracing::info!("netmon: {event}");
    let mut events = EVENTS.lock().unwrap();
    events.push_back(event);
    while events.len() > MAX_RECORDED_EVENTS {
        events.pop_front();
    }
}

/// `SERVICE_CONTROL_POWEREVENT` from the SCM control handler: sleep/wake invalidates
/// `Connected`; the WFP barrier is untouched.
pub fn note_power_event() {
    note_event("power-event");
}

/// Bounded recent-event log for `/status` reporting.
pub fn recent_events() -> Vec<String> {
    EVENTS.lock().unwrap().iter().cloned().collect()
}

/// The pollable counter + latest-event summary the product layer watches via `/status`.
pub fn status() -> crate::core::structure::NetworkEventsStatus {
    crate::core::structure::NetworkEventsStatus {
        counter: CHANGE_COUNT.load(Ordering::Relaxed),
        last_kind: LAST_KIND.lock().unwrap().clone(),
        last_at: match LAST_AT.load(Ordering::Relaxed) {
            0 => None,
            value => Some(value),
        },
    }
}

/// Total events seen since service start (test/diagnostic hook).
#[cfg(test)]
pub fn change_count() -> u64 {
    CHANGE_COUNT.load(Ordering::Relaxed)
}

/// Register the IP-interface and route change notifications plus the debounce task.
/// Idempotent; the registrations live for the service's lifetime by design.
pub fn start() {
    #[cfg(not(feature = "test"))]
    imp::start();
}

#[cfg(not(feature = "test"))]
mod imp {
    use super::{DEBOUNCE, LAST_RAW_MILLIS, PENDING_RAW, STARTED, note_event};
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
        NotifyRouteChange2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    // `Instant::elapsed` against a process-lifetime anchor is what the debounce wants; keep a
    // lazy anchor rather than a global `Instant` (const-unfriendly).
    fn anchor() -> std::time::Instant {
        static ANCHOR: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        *ANCHOR.get_or_init(std::time::Instant::now)
    }

    fn raw_notify(kind: &str, notification_type: MIB_NOTIFICATION_TYPE) {
        let _ = anchor();
        PENDING_RAW.store(true, Ordering::Release);
        LAST_RAW_MILLIS.store(anchor().elapsed().as_millis() as u64, Ordering::Relaxed);
        tracing::debug!("netmon raw notification: {kind} (type {notification_type})");
    }

    /// SAFETY: registered with `NotifyIpInterfaceChange`; called on an IPHelper thread with a
    /// valid (possibly null) row pointer we never dereference.
    unsafe extern "system" fn on_ip_interface_change(
        _context: *const core::ffi::c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        raw_notify("ip-interface", notification_type);
    }

    /// SAFETY: registered with `NotifyRouteChange2`; same contract as above.
    unsafe extern "system" fn on_route_change(
        _context: *const core::ffi::c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        raw_notify("route", notification_type);
    }

    pub(super) fn start() {
        if STARTED.swap(true, Ordering::AcqRel) {
            return;
        }
        anchor();
        // Leaked out-handle slots: registrations are process-lifetime by design, so the slots
        // must never be freed or reused (also keeps edition-2024 `static_mut_refs` out).
        let interface_handle: &'static mut windows_sys::Win32::Foundation::HANDLE =
            Box::leak(Box::new(std::ptr::null_mut()));
        let route_handle: &'static mut windows_sys::Win32::Foundation::HANDLE =
            Box::leak(Box::new(std::ptr::null_mut()));
        // SAFETY: the out-handles live for the process lifetime; callbacks are valid
        // `extern "system"` fns with a null context.
        unsafe {
            let status = NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(on_ip_interface_change),
                std::ptr::null(),
                false,
                interface_handle,
            );
            if status != 0 {
                tracing::warn!("NotifyIpInterfaceChange failed: Windows error {status}");
            }
            let status = NotifyRouteChange2(
                AF_UNSPEC,
                Some(on_route_change),
                std::ptr::null(),
                false,
                route_handle,
            );
            if status != 0 {
                tracing::warn!("NotifyRouteChange2 failed: Windows error {status}");
            }
        }

        tokio::spawn(async {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                interval.tick().await;
                if !PENDING_RAW.load(Ordering::Acquire) {
                    continue;
                }
                let elapsed = anchor().elapsed().as_millis() as u64;
                let quiet = elapsed.saturating_sub(LAST_RAW_MILLIS.load(Ordering::Relaxed));
                if quiet >= DEBOUNCE.as_millis() as u64 && PENDING_RAW.swap(false, Ordering::AcqRel)
                {
                    note_event("network-change (ip-interface/route)");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn events_are_recorded_and_bounded() {
        for index in 0..(super::MAX_RECORDED_EVENTS + 8) {
            super::note_event(&format!("test-event-{index}"));
        }
        let events = super::recent_events();
        assert_eq!(events.len(), super::MAX_RECORDED_EVENTS);
        assert!(events.last().unwrap().contains("test-event-"));
        assert!(super::change_count() >= super::MAX_RECORDED_EVENTS as u64);
    }
}
