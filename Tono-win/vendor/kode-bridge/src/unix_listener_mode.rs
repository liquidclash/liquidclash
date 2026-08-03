use std::{
    ffi::{CString, NulError},
    io,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::ffi::OsStrExt as _,
    },
    path::Path,
};

#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW_ANY: libc::c_int = 0x0800;

/// The flags `fchmodat` is given so that it refuses to follow a symlink.
///
/// Darwin has `AT_SYMLINK_NOFOLLOW_ANY` and honours `AT_SYMLINK_NOFOLLOW`. Linux honours neither
/// here — `fchmodat` returns `ENOTSUP` for `AT_SYMLINK_NOFOLLOW` — so there the entry is changed
/// directly, and what rules out a swapped symlink is the verification afterwards: it refuses
/// anything that is not a socket, owned by this process, carrying exactly the requested mode. The
/// parent has already been shown to be owned by the effective user and unwritable by group or
/// other, so nothing unprivileged can put a symlink there to begin with.
#[cfg(target_os = "macos")]
const NO_FOLLOW_CHMOD_FLAGS: libc::c_int = libc::AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY;
#[cfg(not(target_os = "macos"))]
const NO_FOLLOW_CHMOD_FLAGS: libc::c_int = 0;

fn invalid_path(error: NulError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn open_secure_parent(path: &Path) -> io::Result<(OwnedFd, CString)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("listener path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("listener path has no name"))?;
    let parent = CString::new(parent.as_os_str().as_bytes()).map_err(invalid_path)?;
    let name = CString::new(name.as_bytes()).map_err(invalid_path)?;
    let raw = unsafe {
        libc::open(
            parent.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "listener parent must be owned by the effective user and not writable by group or other",
        ));
    }

    Ok((fd, name))
}

pub(crate) fn validate_listener_parent(path: &Path) -> io::Result<()> {
    open_secure_parent(path).map(|_| ())
}

/// Stat an entry without following it, refusing anything that is not this process's own socket.
fn require_own_socket(parent: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_uid != unsafe { libc::geteuid() } || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "listener entry owner or type verification failed",
        ));
    }
    Ok(stat)
}

pub(crate) fn apply_bound_socket_mode(path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let (parent, name) = open_secure_parent(path)?;

    // Checked before the change, not only after it. Where `fchmodat` cannot be told to refuse a
    // symlink — Linux answers `ENOTSUP` to `AT_SYMLINK_NOFOLLOW` — it follows one instead, and
    // would apply this mode to whatever the link points at. Noticing that afterwards is too late:
    // the target has already been changed. What remains is the window between this check and the
    // change, and only the effective user and root can create entries in a parent that
    // `open_secure_parent` has already shown to be theirs and unwritable by anyone else.
    require_own_socket(&parent, &name)?;

    if unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), mode, NO_FOLLOW_CHMOD_FLAGS) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let stat = require_own_socket(&parent, &name)?;
    if stat.st_mode & 0o777 != mode & 0o777 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "listener entry mode verification failed",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::Permissions,
        io,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new(mode: u32) -> io::Result<Self> {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("kode-bridge-listener-mode-{}-{sequence}", std::process::id(),));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(&path, Permissions::from_mode(mode))?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn applies_exact_mode_to_bound_socket() -> io::Result<()> {
        let fixture = Fixture::new(0o700)?;
        let socket = fixture.path().join("service.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket)?;

        apply_bound_socket_mode(&socket, 0o666)?;

        assert_eq!(std::fs::symlink_metadata(socket)?.permissions().mode() & 0o777, 0o666,);
        Ok(())
    }

    #[test]
    fn rejects_writable_parent() -> io::Result<()> {
        let fixture = Fixture::new(0o770)?;
        let socket = fixture.path().join("service.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket)?;

        assert_eq!(
            apply_bound_socket_mode(&socket, 0o666).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
        );
        Ok(())
    }

    #[test]
    fn symlink_never_changes_target_mode() -> io::Result<()> {
        let fixture = Fixture::new(0o700)?;
        let target = fixture.path().join("target");
        std::fs::write(&target, b"target")?;
        std::fs::set_permissions(&target, Permissions::from_mode(0o600))?;
        let socket = fixture.path().join("service.sock");
        std::os::unix::fs::symlink(&target, &socket)?;

        assert!(apply_bound_socket_mode(&socket, 0o666).is_err());
        assert_eq!(std::fs::metadata(target)?.permissions().mode() & 0o777, 0o600,);
        Ok(())
    }
}
