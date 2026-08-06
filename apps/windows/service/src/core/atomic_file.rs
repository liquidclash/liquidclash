use std::path::Path;

#[cfg(unix)]
pub(crate) async fn replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    tokio::fs::rename(source, destination).await
}

/// How long a caller will wait for one `MOVEFILE_WRITE_THROUGH` rename.
///
/// Every caller holds `OWNER_LIFECYCLE_LOCK` (staging, maintenance, desired state), and
/// write-through forces the metadata all the way to the volume, so a stalled disk or a
/// network-backed state directory turns this into the wait that blocks status, release and stop.
/// Generous enough that a genuinely slow disk still commits; short enough that a dead volume
/// gives the lock back.
#[cfg(windows)]
const REPLACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(windows)]
pub(crate) async fn replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // The signature has always been `async`, but the call underneath is a synchronous kernel
    // round-trip, so it belongs on a blocking worker rather than on the four runtime workers the
    // service has. Timing out abandons the wait, not the rename: the rename either committed or
    // did not, and reporting it as failed is the fail-closed reading of "unproven".
    let rename = tokio::task::spawn_blocking(move || {
        // SAFETY: Both paths are NUL-terminated UTF-16 buffers owned by this closure.
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    });
    match tokio::time::timeout(REPLACE_TIMEOUT, rename).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(std::io::Error::other(format!(
            "atomic replace task failed: {error}"
        ))),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "atomic replace did not complete before its deadline",
        )),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn replace_overwrites_an_existing_destination() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "clash-verge-service-atomic-replace-{}",
            std::process::id()
        ));
        let source = root.join("state.json.tmp");
        let destination = root.join("state.json");
        std::fs::create_dir_all(&root)?;
        std::fs::write(&source, b"new")?;
        std::fs::write(&destination, b"old")?;

        super::replace(&source, &destination).await?;

        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination)?, b"new");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn replace_reports_a_missing_source_instead_of_waiting() {
        let root = std::env::temp_dir().join(format!(
            "clash-verge-service-atomic-missing-{}",
            std::process::id()
        ));

        let error = super::replace(&root.join("absent.tmp"), &root.join("absent"))
            .await
            .expect_err("a missing source must be reported, not awaited");

        assert_ne!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
