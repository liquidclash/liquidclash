//! Proving what the binary about to be run as LocalSystem *is*, not merely where it sits.
//!
//! `SECURITY.md` promises that Mihomo "is staged with SHA-256 verification and (in signed builds)
//! Authenticode verification before every start". Until this module existed, the install-location
//! allowlist in [`super::assets`] was the whole of it — and a location rule answers a different
//! question. It says a client may not name a core outside the directories the installer owns; it
//! says nothing about the bytes at that path, which is exactly what an attacker who ever manages
//! to write inside one of those directories needs it to say.
//!
//! The pin is a digest rather than a signature because a digest is checkable with what this crate
//! already depends on. Authenticode is the other half of the promise and is deliberately not
//! implemented here: `WinVerifyTrust` lives behind a `windows-sys` feature this crate does not
//! enable (`Win32_Security_WinTrust`), so it cannot be added without touching `Cargo.toml`, and a
//! signature check is only as good as the publisher pin that goes with it — accepting "any
//! Authenticode-signed executable" would accept most of the malware on the internet. The
//! replacement for this module is `WinVerifyTrust` plus a pinned subject/thumbprint, checked in
//! addition to the digest, never instead of it.

use crate::ServiceErrorCode;
use crate::core::auth::ServiceError;
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::Path;

/// The digest of the core this service was built to run, pinned when the service is compiled.
///
/// `option_env!` rather than `env!` so a build that has not been given a pin still compiles; what
/// it does *not* do is still start a core, because an absent pin is a refusal below and not a
/// waiver. Release builds set `TONO_CORE_SHA256` to the digest of the `verge-mihomo.exe` the
/// installer ships.
const COMPILED_IN_CORE_SHA256: Option<&str> = option_env!("TONO_CORE_SHA256");

/// Where an installer may instead record the digest of the core it just installed.
///
/// Read from [`crate::service_paths`]`().install_dir()`, which the installer creates through
/// `ensure_private_installer_directory` — SYSTEM and Administrators only. A pin an unprivileged
/// user could rewrite would prove nothing, so the location matters as much as the content.
pub(super) const CORE_DIGEST_PIN_FILE_NAME: &str = "core-sha256.txt";

/// What the measured digest of a core binary amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreDigestVerdict {
    /// The core is the one that was pinned.
    Verified,
    /// A pin exists and this is not it.
    Mismatched,
    /// Nothing pins the core, so nothing about it can be proven.
    Unpinned,
    /// A pin exists but is not a SHA-256 digest, so it cannot be compared with anything.
    PinMalformed,
}

/// The rule, pure so it is testable without a filesystem, a pin, or a Windows machine.
///
/// Every outcome other than [`CoreDigestVerdict::Verified`] is a refusal at the call site. That is
/// the whole point: "nobody told us what the core should be" and "the core is not what we were
/// told" have to end the same way, or the check is decorative — an attacker who can suppress the
/// pin would otherwise get the same result as one who can match it.
pub(super) fn classify_core_digest(pin: Option<&str>, measured: &str) -> CoreDigestVerdict {
    let Some(pin) = pin else {
        return CoreDigestVerdict::Unpinned;
    };
    let Some(expected) = normalize_digest(pin) else {
        return CoreDigestVerdict::PinMalformed;
    };
    match normalize_digest(measured) {
        Some(measured) if measured == expected => CoreDigestVerdict::Verified,
        _ => CoreDigestVerdict::Mismatched,
    }
}

/// A SHA-256 digest in the one spelling comparisons are made in, or nothing.
///
/// Tolerates the trailing newline a pin file written by `echo` or by a build script carries, and
/// the `sha256:` prefix some tooling prints. Refuses anything else rather than comparing loosely:
/// a pin that is 63 characters because it was truncated in transit must not quietly match nothing
/// and must not quietly match everything.
fn normalize_digest(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix("sha256:").unwrap_or(trimmed).trim();
    (trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| trimmed.to_ascii_lowercase())
}

/// Hash a file in bounded memory, the same way `install_service` hashes the service binary.
///
/// Streaming matters here for a reason that is not style: the core is tens of megabytes, and this
/// runs on every start.
pub(super) fn sha256_hex(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The digest this installation expects its core to have, if anything does.
///
/// The compile-time pin wins: it is part of the build that also decides which core is shipped, and
/// it cannot be edited on the machine at all. The pin file is the fallback for a build that ships
/// the core and the service separately.
fn pinned_core_digest() -> Option<String> {
    if let Some(pin) = COMPILED_IN_CORE_SHA256 {
        return Some(pin.to_owned());
    }
    let path = crate::service_paths()
        .install_dir()
        .join(CORE_DIGEST_PIN_FILE_NAME);
    match std::fs::read_to_string(&path) {
        Ok(pin) => Some(pin),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            // Unreadable is not "absent", but both refuse below, so this is only ever a log line
            // that tells an operator which of the two they are looking at.
            tracing::warn!(
                path = ?path,
                error = %error,
                "Core digest pin exists but could not be read"
            );
            None
        }
    }
}

/// Refuse to hand a core to the process launcher unless it is the one that was pinned.
///
/// Fail-closed in every direction: an unreadable file, an absent pin and a wrong digest are all
/// errors. The caller runs this before the core path reaches `start_core` — and, on Windows, before
/// the WFP app-id permit is armed for it, so an unverified binary does not inherit the one
/// executable-scoped hole in the kill switch either.
pub(super) fn verify_core_binary(core_path: &Path) -> Result<(), ServiceError> {
    let measured = sha256_hex(core_path).map_err(|error| {
        refused(format!(
            "core binary {core_path:?} could not be read for verification: {error}"
        ))
    })?;
    match classify_core_digest(pinned_core_digest().as_deref(), &measured) {
        CoreDigestVerdict::Verified => {
            tracing::debug!(core_path = ?core_path, "Core binary matches its pinned digest");
            Ok(())
        }
        CoreDigestVerdict::Mismatched => Err(refused(format!(
            "core binary {core_path:?} does not match the SHA-256 digest this installation pinned"
        ))),
        CoreDigestVerdict::Unpinned => Err(refused(format!(
            "no SHA-256 digest is pinned for the core binary, so {core_path:?} cannot be verified \
             (measured {measured}); reinstall Tono"
        ))),
        CoreDigestVerdict::PinMalformed => Err(refused(
            "the pinned core digest is not a SHA-256 hex digest; reinstall Tono",
        )),
    }
}

/// Reported as an install-location failure because it is one: the client is told to reinstall,
/// which is the only thing that can put a core the service will run back on the machine.
fn refused(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ServiceErrorCode::InvalidInstallLocation, message)
}

#[cfg(test)]
mod tests {
    use super::{
        CoreDigestVerdict, classify_core_digest, normalize_digest, sha256_hex, verify_core_binary,
    };

    /// The published SHA-256 of "abc", so the hashing is checked against something outside itself.
    const ABC_DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn hashes_a_file_the_way_the_installer_does() -> anyhow::Result<()> {
        let path =
            std::env::temp_dir().join(format!("service-core-digest-{}.bin", std::process::id()));
        std::fs::write(&path, b"abc")?;

        assert_eq!(sha256_hex(&path)?, ABC_DIGEST);

        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn a_pinned_core_verifies_however_the_pin_was_spelled() {
        for pin in [
            ABC_DIGEST.to_owned(),
            format!("{ABC_DIGEST}\n"),
            format!("sha256:{ABC_DIGEST}"),
            ABC_DIGEST.to_uppercase(),
        ] {
            assert_eq!(
                classify_core_digest(Some(&pin), ABC_DIGEST),
                CoreDigestVerdict::Verified,
                "rejected {pin}"
            );
        }
    }

    #[test]
    fn an_unpinned_core_is_refused_rather_than_waved_through() {
        // The escalation this whole module exists for ends with a binary of the attacker's
        // choosing. "Nothing pins the core" must therefore not be a way of passing: an attacker
        // who can remove the pin would otherwise get exactly what one who can forge it gets.
        assert_eq!(
            classify_core_digest(None, ABC_DIGEST),
            CoreDigestVerdict::Unpinned
        );
    }

    #[test]
    fn a_pin_that_is_not_a_digest_never_matches() {
        for pin in ["", "not-a-digest", &ABC_DIGEST[..63], "sha256:"] {
            assert_eq!(
                classify_core_digest(Some(pin), ABC_DIGEST),
                CoreDigestVerdict::PinMalformed,
                "accepted {pin}"
            );
        }
        assert!(normalize_digest("not-a-digest").is_none());
    }

    #[test]
    fn a_core_that_is_not_the_pinned_one_is_refused() {
        assert_eq!(
            classify_core_digest(Some(ABC_DIGEST), &"0".repeat(64)),
            CoreDigestVerdict::Mismatched
        );
        // A measured digest that is itself unreadable is a mismatch, not a match.
        assert_eq!(
            classify_core_digest(Some(ABC_DIGEST), ""),
            CoreDigestVerdict::Mismatched
        );
    }

    #[test]
    fn a_binary_nothing_vouches_for_never_verifies() {
        // Whatever this installation is pinned to — a compile-time digest, a pin file, or nothing
        // at all — a freshly written scratch file is not it, and every one of those cases is a
        // refusal.
        let path = std::env::temp_dir().join(format!(
            "service-core-unverified-{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, b"not the core this build ships").expect("scratch core");

        assert!(verify_core_binary(&path).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_core_that_cannot_be_read_is_refused() {
        let missing = std::env::temp_dir().join("service-core-that-does-not-exist.bin");

        assert!(verify_core_binary(&missing).is_err());
    }
}
