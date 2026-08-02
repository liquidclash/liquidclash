use crate::core::structure::{ServiceOperationKind, ServiceOperationSnapshot};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);
static SNAPSHOT_GENERATION: AtomicU64 = AtomicU64::new(0);
static ACTIVE: Lazy<Mutex<Option<ServiceOperationSnapshot>>> = Lazy::new(|| Mutex::new(None));

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// RAII marker for the one privileged lifecycle writer. The owner lifecycle mutex remains the
/// serialization primitive for now; this marker makes it observable without making reads join
/// that queue. Clearing is id-checked so an unwind from an old handler cannot erase a newer one.
pub(crate) struct OperationGuard {
    id: u64,
}

impl OperationGuard {
    pub(crate) fn begin(kind: ServiceOperationKind, budget: Duration) -> Self {
        let id = NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
        let started_at_ms = epoch_millis();
        let deadline_at_ms =
            started_at_ms.saturating_add(u64::try_from(budget.as_millis()).unwrap_or(u64::MAX));
        *ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ServiceOperationSnapshot {
            id,
            kind,
            started_at_ms,
            deadline_at_ms,
        });
        SNAPSHOT_GENERATION.fetch_add(1, Ordering::Release);
        Self { id }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .as_ref()
            .is_some_and(|operation| operation.id == self.id)
        {
            active.take();
            SNAPSHOT_GENERATION.fetch_add(1, Ordering::Release);
        }
    }
}

pub(crate) fn snapshot() -> (u64, Option<ServiceOperationSnapshot>) {
    // Read generation after the mutex-protected clone. A begin/end that races this read either
    // appears in both values or advances the generation, allowing the client to discard the
    // stale aggregate on its next poll.
    let active = ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let generation = SNAPSHOT_GENERATION.load(Ordering::Acquire);
    (generation, active)
}

#[cfg(test)]
mod tests {
    use super::{OperationGuard, snapshot};
    use crate::ServiceOperationKind;
    use serial_test::serial;
    use std::time::Duration;

    #[test]
    #[serial]
    fn guard_publishes_and_clears_without_an_async_lock() {
        let before = snapshot().0;
        let guard = OperationGuard::begin(ServiceOperationKind::StartCore, Duration::from_secs(60));
        let (during, active) = snapshot();
        assert!(during > before);
        let active = active.expect("operation must be published while its guard is live");
        assert_eq!(active.kind, ServiceOperationKind::StartCore);
        assert!(active.deadline_at_ms >= active.started_at_ms);
        drop(guard);
        let (after, active) = snapshot();
        assert!(after > during);
        assert!(active.is_none());
    }
}
