//! Synthetic mainland-China latency used only by the real-Windows integration build.
//!
//! Production binaries compile this to a no-op. Enabling `windows-integration-test`
//! makes every explicitly marked remote operation pay a conservative 1 s delay by
//! default, so a fast US test machine cannot accidentally validate only the happy
//! path. Set `TONO_WINDOWS_INTEGRATION_LATENCY_MS=0` to disable it for a diagnostic
//! run, or choose another value up to five seconds.

use std::time::Duration;

const DEFAULT_MAINLAND_LATENCY_MS: u64 = 1_000;
const MAX_INTEGRATION_LATENCY_MS: u64 = 5_000;

#[cfg(any(test, all(windows, feature = "windows-integration-test")))]
fn parse_latency_ms(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAINLAND_LATENCY_MS)
        .min(MAX_INTEGRATION_LATENCY_MS)
}

#[cfg(all(windows, feature = "windows-integration-test"))]
pub(crate) fn remote_latency() -> Duration {
    Duration::from_millis(parse_latency_ms(
        std::env::var("TONO_WINDOWS_INTEGRATION_LATENCY_MS").ok().as_deref(),
    ))
}

#[cfg(not(all(windows, feature = "windows-integration-test")))]
pub(crate) fn remote_latency() -> Duration {
    Duration::ZERO
}

pub(crate) async fn delay_remote_operation() {
    let latency = remote_latency();
    if !latency.is_zero() {
        tokio::time::sleep(latency).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAINLAND_LATENCY_MS, MAX_INTEGRATION_LATENCY_MS, parse_latency_ms};

    #[test]
    fn mainland_profile_is_on_by_default_and_has_safe_overrides() {
        assert_eq!(parse_latency_ms(None), DEFAULT_MAINLAND_LATENCY_MS);
        assert_eq!(parse_latency_ms(Some(" 1250 ")), 1_250);
        assert_eq!(parse_latency_ms(Some("0")), 0);
        assert_eq!(parse_latency_ms(Some("999999")), MAX_INTEGRATION_LATENCY_MS);
        assert_eq!(parse_latency_ms(Some("not-a-number")), DEFAULT_MAINLAND_LATENCY_MS);
    }
}
