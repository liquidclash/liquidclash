use interprocess::local_socket::tokio::prelude::LocalSocketStream;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use tokio::sync::{Semaphore, SemaphorePermit};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, TokenUser, WinLocalSystemSid, SECURITY_MAX_SID_SIZE,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

/// Tono: how many pipe opens may sit inside the OS or the verifier at the same time.
///
/// Opening the pipe and verifying the server behind it are synchronous calls, so they run on a
/// blocking thread (see [`open_off_runtime`]). `spawn_blocking` work cannot be cancelled: when the
/// caller's timeout fires we stop *waiting* for it, but the thread stays parked inside
/// `CreateFileW` or inside the caller-supplied verifier until the OS returns — and a verifier that
/// talks to a wedged service can stay there for a long time. This cap is what bounds that leak:
/// at most this many threads can be detached at any instant, and further attempts are refused
/// straight away rather than parking more threads. Refusing is safe by construction — a refused
/// attempt is a failed connection, never an unverified one.
const MAX_BLOCKING_CONNECTS: usize = 8;

/// Tono: slots for [`MAX_BLOCKING_CONNECTS`]. A permit is moved *into* the blocking closure, so it
/// is released when the OS call actually returns, not when the awaiting future is dropped.
static BLOCKING_CONNECT_SLOTS: Semaphore = Semaphore::const_new(MAX_BLOCKING_CONNECTS);

/// Tono: reserve one blocking-connect slot, or refuse the connection outright.
fn reserve_blocking_connect_slot() -> io::Result<SemaphorePermit<'static>> {
    BLOCKING_CONNECT_SLOTS.try_acquire().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "too many Windows named-pipe server verifications are already in flight",
        )
    })
}

pub(crate) async fn connect_local_system_server(path: PathBuf) -> io::Result<LocalSocketStream> {
    connect_verified_server(path, verify_process_is_local_system).await
}

/// Tono: this used to be a synchronous `fn` that callers invoked from an `async fn` without
/// `.await` and without `spawn_blocking`, which parked the polling worker for the whole of
/// `CreateFileW` + `GetNamedPipeServerProcessId` + the caller-supplied verifier. Any
/// `tokio::time::timeout` wrapped around it could therefore never fire. The synchronous work now
/// runs on a blocking thread and this future yields at the `.await` below, so surrounding timeouts
/// are enforceable again.
///
/// The verifier contract is unchanged: it is still called with the process ID behind the connected
/// pipe handle, and the handle is only handed back if it returns `Ok`.
pub(crate) async fn connect_verified_server(
    path: PathBuf,
    verifier: fn(u32) -> io::Result<()>,
) -> io::Result<LocalSocketStream> {
    let permit = reserve_blocking_connect_slot()?;

    let handle = open_off_runtime(move || {
        // Tono: held for the duration of the blocking call so a detached thread keeps occupying
        // its slot until the OS actually returns.
        let _permit = permit;
        open_verified_pipe(&path, verifier)
    })
    .await?;

    // Tono: attaching the handle to the runtime's completion port does not block, so it stays on
    // the async side where a runtime is guaranteed to be entered.
    let stream = interprocess::os::windows::named_pipe::local_socket::tokio::Stream::try_from(handle)?;
    Ok(LocalSocketStream::from(stream))
}

/// Tono: run one synchronous pipe open on a blocking thread.
///
/// Fail-closed in every direction: the closure only yields a handle it has already verified, a
/// join failure (panic or runtime shutdown) becomes an error, and if the caller gives up first the
/// dropped `JoinHandle` discards the `OwnedHandle` the thread eventually produces, which closes
/// the pipe. Nothing here can hand back a connection that was not verified.
async fn open_off_runtime<F>(open: F) -> io::Result<OwnedHandle>
where
    F: FnOnce() -> io::Result<OwnedHandle> + Send + 'static,
{
    match tokio::task::spawn_blocking(open).await {
        Ok(opened) => opened,
        Err(error) => Err(io::Error::other(format!(
            "Windows named-pipe connect task did not complete: {}",
            error
        ))),
    }
}

/// Tono: the synchronous half, split out so it can be handed to [`open_off_runtime`] whole.
fn open_verified_pipe(path: &Path, verifier: fn(u32) -> io::Result<()>) -> io::Result<OwnedHandle> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named-pipe path contains NUL",
        ));
    }
    wide.push(0);

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // Tono: `?` here drops `handle`, which closes the pipe. A rejected server can never leak a
    // usable connection back to the caller.
    verify_pipe_server(handle.as_raw_handle(), verifier)?;

    Ok(handle)
}

fn verify_pipe_server(pipe: *mut c_void, verifier: fn(u32) -> io::Result<()>) -> io::Result<()> {
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    verifier(process_id)
}

fn verify_process_is_local_system(process_id: u32) -> io::Result<()> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut required = 0_u32;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, std::ptr::null_mut(), 0, &mut required) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut user = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };

    let sid_words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<usize>());
    let mut system_sid = vec![0_usize; sid_words];
    let mut system_sid_size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut system_sid_size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows named-pipe server is not LocalSystem",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn rejects_a_non_system_server_process() {
        let result = super::verify_process_is_local_system(std::process::id());
        assert!(matches!(
            result,
            Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    /// Tono: regression test for the blocking-in-async defect. A single-threaded runtime is the
    /// harshest case — before the fix the blocking open parked the only worker and the timeout
    /// below could not fire.
    #[tokio::test]
    async fn a_blocking_open_still_lets_the_caller_time_out() {
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            super::open_off_runtime(|| {
                std::thread::sleep(Duration::from_millis(750));
                Err(io::Error::other("wedged server"))
            }),
        )
        .await;

        assert!(result.is_err(), "the surrounding timeout must be able to fire");
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    /// Tono: a cancelled attempt is a refused attempt — nothing is handed back to the caller.
    #[tokio::test]
    async fn a_missing_pipe_is_refused_without_blocking_the_runtime() {
        let result = super::connect_verified_server(
            PathBuf::from(r"\\.\pipe\kode-bridge-does-not-exist-connect-test"),
            |_| Ok(()),
        )
        .await;

        assert!(result.is_err());
    }

    /// Tono: the leak bound is real — once every slot is taken, further attempts are refused
    /// instead of parking more threads.
    #[test]
    fn exhausted_blocking_slots_refuse_further_attempts() {
        let held: Vec<_> = (0..super::MAX_BLOCKING_CONNECTS)
            .map(|_| super::reserve_blocking_connect_slot())
            .collect();
        assert!(held.iter().all(std::result::Result::is_ok));

        assert!(matches!(
            super::reserve_blocking_connect_slot(),
            Err(ref error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        drop(held);
        assert!(super::reserve_blocking_connect_slot().is_ok());
    }
}
