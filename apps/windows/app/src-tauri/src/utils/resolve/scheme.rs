use anyhow::Result;
use clash_verge_logging::{Type, logging};

/// Tono: the clash:// install pipeline is disabled (P0-4) — deep links are
/// acknowledged and dropped; no subscription ever reaches the core.
pub(super) async fn resolve_scheme(param: &str) -> Result<()> {
    let _ = param;
    logging!(warn, Type::Config, "Tono: deep-link subscription intake is disabled");
    Ok(())
}
