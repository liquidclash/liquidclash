#[cfg(unix)]
use crate::owner_key;
use crate::{
    IPC_AUTH_EXPECT, OwnerCredentials, OwnerIdentity, SESSION_TOKEN_HEX_LEN, ServiceErrorCode,
};
use kode_bridge::errors::KodeBridgeError;
use kode_bridge::ipc_http_server::RequestContext;
use sha2::{Digest as _, Sha256};
use std::{fmt, path::PathBuf, time::Duration};

/// How long the runtime will wait for the pre-authentication filesystem probes.
///
/// Everything [`authenticate_owner`] does to `app_data_dir` — `CreateFileW`, `canonicalize`,
/// `symlink_metadata`, `read_exact` — is a synchronous kernel call on a *client-supplied* path,
/// and it runs before the token compare. On a path the kernel cannot reach quickly that wait is
/// the redirector's, not ours. Local volumes answer in microseconds, so this only ever expires on
/// a path that was never going to authenticate.
const OWNER_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOwner {
    pub key: String,
    pub identity: OwnerIdentity,
    pub app_data_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

impl ServiceError {
    pub(crate) fn new(code: ServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorCode::UnauthorizedOwner, message)
    }

    pub(crate) fn not_active() -> Self {
        Self::new(
            ServiceErrorCode::NotActive,
            "owner is authenticated but is not active",
        )
    }

    pub(crate) fn owner_switch_failed(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorCode::OwnerSwitchFailed, message)
    }

    pub(crate) fn protocol_mismatch() -> Self {
        Self::new(
            ServiceErrorCode::ProtocolMismatch,
            "service protocol version does not match",
        )
    }

    pub(crate) fn stale_owner_session() -> Self {
        Self::new(
            ServiceErrorCode::StaleOwnerSession,
            "owner session is stale or invalid",
        )
    }

    pub(crate) fn invalid_proxy_config(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorCode::InvalidProxyConfig, message)
    }

    pub(crate) fn proxy_clear_failed(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorCode::ProxyClearFailed, message)
    }

    pub(crate) fn proxy_apply_failed(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorCode::ProxyApplyFailed, message)
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthStatus {
    Authorized,
}

pub(crate) fn hash_session_token(token: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        token.len() == SESSION_TOKEN_HEX_LEN
            && token
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "owner session token must be 64 lowercase hexadecimal characters"
    );
    Ok(Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn ipc_request_context_to_auth_context(
    ctx: &RequestContext,
) -> Result<AuthStatus, KodeBridgeError> {
    let headers = &ctx.headers;
    match headers.get("X-IPC-Magic") {
        Some(token) if token == IPC_AUTH_EXPECT => Ok(AuthStatus::Authorized),
        Some(_) => Err(KodeBridgeError::ClientError { status: 401 }),
        None => Err(KodeBridgeError::ClientError { status: 401 }),
    }
}

#[cfg(unix)]
pub fn validate_unix_identity(
    declared: &OwnerIdentity,
    peer: Option<(u32, u32)>,
) -> Result<(), ServiceError> {
    let OwnerIdentity::Unix { uid, gid } = declared else {
        return Err(ServiceError::unauthorized(
            "owner identity does not match the Unix transport",
        ));
    };
    let Some((peer_uid, peer_gid)) = peer else {
        return Err(ServiceError::unauthorized(
            "kernel peer credentials are unavailable",
        ));
    };

    if *uid != peer_uid || *gid != peer_gid {
        return Err(ServiceError::unauthorized(
            "declared owner does not match kernel peer credentials",
        ));
    }

    Ok(())
}

/// The transport half of a credential check, taken from the request before the filesystem half
/// leaves the runtime thread: `RequestContext` is borrowed and cannot cross into a blocking task.
#[derive(Clone, Copy, Default)]
pub struct PeerIdentity {
    #[cfg(unix)]
    credentials: Option<(u32, u32)>,
    /// The process the kernel recorded on the other end of the named pipe, if it named one.
    ///
    /// This is the only thing in a Windows request the caller does not get to write. Everything
    /// else the Windows path examines lives at a path the caller chose.
    #[cfg(windows)]
    process_id: Option<u32>,
}

impl PeerIdentity {
    fn from_context(context: &RequestContext) -> Self {
        #[cfg(unix)]
        {
            Self {
                credentials: context
                    .client_info
                    .peer_credentials
                    .uid
                    .zip(context.client_info.peer_credentials.gid),
            }
        }
        #[cfg(windows)]
        {
            Self {
                process_id: context.client_info.peer_credentials.pid,
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = context;
            Self::default()
        }
    }

    /// The current process, for the Windows tests that call the authentication path directly.
    #[cfg(all(test, windows, feature = "test"))]
    fn current_process() -> Self {
        Self {
            process_id: Some(std::process::id()),
        }
    }
}

/// What the transport was able to establish about the process on the other end of the connection.
///
/// Every way of *failing* to identify the caller is its own case rather than a shared `None`, so
/// that none of them can be silently folded into "checked, and fine" by a later edit.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsPeer {
    /// The connecting process runs under the SID the request declared.
    DeclaredOwner,
    /// The connecting process was identified, and is some other principal.
    OtherPrincipal,
    /// The connection named no process at all.
    Unnamed,
    /// The process could not be opened: it exited, or the service was refused a handle to it.
    Unopenable,
    /// The process was opened, but its token — or the user inside it — could not be read.
    TokenUnreadable,
}

/// Bind the connection to the declared owner, before any of the filesystem evidence is trusted.
///
/// Everything the Windows path checks after this — the root's owner SID, the token file's DACL,
/// the 32 secret bytes — is read from a path the *caller* names, so all of it together proves only
/// that whoever is asking can reach a directory that looks like the owner's. The token is the only
/// real secret in that set, which made a copy of it — from a backup, a crash dump, a directory
/// that was mis-ACLed for a while — sufficient on its own, from any session. This check is the one
/// the caller cannot furnish the evidence for: the process id comes from the kernel's record of
/// the pipe instance, and the SID comes from that process's own token.
///
/// It fails closed. Exactly one outcome returns `Ok` — a peer that was positively identified *and*
/// is the declared owner. Not being able to say who called is refused as firmly as calling as
/// somebody else, because a service that cannot name its peer cannot tell those two apart.
#[cfg(any(windows, test))]
fn require_declared_owner_peer(
    declared: &OwnerIdentity,
    peer: WindowsPeer,
) -> Result<(), ServiceError> {
    let OwnerIdentity::Windows { .. } = declared else {
        return Err(ServiceError::unauthorized(
            "owner identity does not match the Windows transport",
        ));
    };

    match peer {
        WindowsPeer::DeclaredOwner => Ok(()),
        WindowsPeer::OtherPrincipal => Err(ServiceError::unauthorized(
            "connecting process does not run as the declared owner",
        )),
        WindowsPeer::Unnamed => Err(ServiceError::unauthorized(
            "connection does not identify the calling process",
        )),
        WindowsPeer::Unopenable => Err(ServiceError::unauthorized(
            "calling process could not be opened for identification",
        )),
        WindowsPeer::TokenUnreadable => Err(ServiceError::unauthorized(
            "calling process token could not be read",
        )),
    }
}

/// Authenticate without occupying a runtime worker, and without waiting forever.
///
/// This runs at the head of every protected route, before the token compare, on a path the
/// caller chose. Left on a worker it is a pre-authentication denial of service: the service runs
/// four workers, so four requests naming an unreachable path make status, release and service
/// stop unschedulable while the machine stays armed. The probes therefore run on a blocking
/// worker with a deadline.
///
/// Nothing about the decision is relaxed. The probes are the same probes, in the same order, and
/// a request whose credentials could not be *proved* — task failure, deadline, or a path this
/// service cannot verify at all — is refused exactly as a wrong token is. Abandoning the wait is
/// safe because the probes only read.
pub async fn authenticate_owner_off_runtime(
    context: &RequestContext,
    credentials: &OwnerCredentials,
) -> Result<AuthenticatedOwner, ServiceError> {
    reject_unverifiable_app_data_root(&credentials.app_data_dir)?;

    let peer = PeerIdentity::from_context(context);
    let credentials = credentials.clone();
    let probe = tokio::task::spawn_blocking(move || authenticate_owner(peer, &credentials));
    match tokio::time::timeout(OWNER_AUTH_TIMEOUT, probe).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(ServiceError::unauthorized(
            "owner credentials could not be verified",
        )),
        Err(_) => Err(ServiceError::unauthorized(
            "owner credentials could not be verified before the deadline",
        )),
    }
}

/// Refuse a root whose answers this service could not trust anyway, before opening anything.
///
/// A UNC or device path is served by a remote party that chooses every byte the checks below
/// read — the owner SID and the DACL that are supposed to *be* the proof of ownership — so it
/// could assert whatever it liked while holding the probe open for as long as it liked. Only a
/// local drive-letter root can carry a trustworthy answer, so this tightens authentication
/// rather than relaxing it.
#[cfg(windows)]
fn reject_unverifiable_app_data_root(path: &str) -> Result<(), ServiceError> {
    if !is_local_drive_path(path) {
        return Err(ServiceError::unauthorized(
            "application data root must be a local drive-letter path",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_unverifiable_app_data_root(path: &str) -> Result<(), ServiceError> {
    // Unix roots carry no syntactic marker for "answered by a remote server"; the deadline above
    // is the whole bound there, and the uid check below is not delegated to the filesystem.
    let _ = path;
    Ok(())
}

/// Whether `path` is a plain local drive-letter path (`C:\...`, or its `\\?\C:\...` spelling).
///
/// Kept platform-independent so the classification stays unit-testable off Windows.
#[cfg(any(windows, test))]
fn is_local_drive_path(path: &str) -> bool {
    let tail = path.strip_prefix(r"\\?\").unwrap_or(path).as_bytes();
    tail.len() >= 3
        && tail[0].is_ascii_alphabetic()
        && tail[1] == b':'
        && (tail[2] == b'\\' || tail[2] == b'/')
}

/// The decision itself, unchanged and still synchronous — it is all blocking filesystem work.
/// [`authenticate_owner_off_runtime`] is the only production caller and it runs this on a
/// blocking worker.
fn authenticate_owner(
    peer: PeerIdentity,
    credentials: &OwnerCredentials,
) -> Result<AuthenticatedOwner, ServiceError> {
    #[cfg(all(feature = "test", unix))]
    if let Some(result) = authenticate_synthetic_test_owner(credentials) {
        return result;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        validate_unix_identity(&credentials.identity, peer.credentials)?;

        let app_data_root = std::fs::canonicalize(&credentials.app_data_dir)
            .map_err(|_| ServiceError::unauthorized("application data root is unavailable"))?;
        let metadata = std::fs::metadata(&app_data_root).map_err(|_| {
            ServiceError::unauthorized("application data root metadata is unavailable")
        })?;
        let OwnerIdentity::Unix { uid, .. } = credentials.identity else {
            return Err(ServiceError::unauthorized(
                "owner identity does not match the Unix transport",
            ));
        };
        if !metadata.is_dir() || metadata.uid() != uid {
            return Err(ServiceError::unauthorized(
                "application data root is not an owner-controlled directory",
            ));
        }

        Ok(AuthenticatedOwner {
            key: owner_key(&credentials.identity),
            identity: credentials.identity.clone(),
            app_data_root,
        })
    }

    #[cfg(windows)]
    {
        windows_auth::authenticate(peer, credentials)
    }
}

#[cfg(all(feature = "test", unix))]
fn authenticate_synthetic_test_owner(
    credentials: &OwnerCredentials,
) -> Option<Result<AuthenticatedOwner, ServiceError>> {
    use crate::core::test_credentials::SYNTHETIC_TEST_OWNER_TOKEN_PREFIX;
    use std::os::unix::fs::MetadataExt as _;

    let token = credentials.token.as_deref()?;
    if !token.starts_with(SYNTHETIC_TEST_OWNER_TOKEN_PREFIX) {
        return None;
    }
    let expected = format!(
        "{SYNTHETIC_TEST_OWNER_TOKEN_PREFIX}{}",
        owner_key(&credentials.identity)
    );
    if token != expected {
        return Some(Err(ServiceError::unauthorized(
            "synthetic test owner token does not match",
        )));
    }
    let OwnerIdentity::Unix { .. } = credentials.identity else {
        return Some(Err(ServiceError::unauthorized(
            "synthetic test owner must use a Unix identity",
        )));
    };
    let app_data_root = match std::fs::canonicalize(&credentials.app_data_dir) {
        Ok(path) => path,
        Err(_) => {
            return Some(Err(ServiceError::unauthorized(
                "synthetic test owner root is unavailable",
            )));
        }
    };
    let metadata = match std::fs::metadata(&app_data_root) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Some(Err(ServiceError::unauthorized(
                "synthetic test owner root metadata is unavailable",
            )));
        }
    };
    if !metadata.is_dir() || metadata.uid() != unsafe { platform_lib::geteuid() } {
        return Some(Err(ServiceError::unauthorized(
            "synthetic test owner root is not controlled by the test process",
        )));
    }
    Some(Ok(AuthenticatedOwner {
        key: owner_key(&credentials.identity),
        identity: credentials.identity.clone(),
        app_data_root,
    }))
}

#[cfg(windows)]
mod windows_auth {
    use super::{AuthenticatedOwner, PeerIdentity, ServiceError, WindowsPeer};
    use crate::{OWNER_TOKEN_FILE_NAME, OwnerCredentials, OwnerIdentity, owner_key};
    use std::ffi::c_void;
    use std::io::Read as _;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const TOKEN_BYTES: usize = 32;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    pub(super) fn authenticate(
        peer: PeerIdentity,
        credentials: &OwnerCredentials,
    ) -> Result<AuthenticatedOwner, ServiceError> {
        let OwnerIdentity::Windows { sid } = &credentials.identity else {
            return Err(unauthorized(
                "owner identity does not match the Windows transport",
            ));
        };
        let request_token = credentials
            .token
            .as_deref()
            .and_then(decode_token)
            .ok_or_else(|| unauthorized("owner token is missing or malformed"))?;
        let declared_sid = LocalSid::from_string(sid)?;
        // The transport gate, ahead of the filesystem evidence: everything below is read from a
        // path the caller named and could therefore have arranged, so none of it is worth
        // consulting until the connection itself has been bound to the declared owner. Placing it
        // here also means an unidentifiable peer costs no filesystem work at all.
        super::require_declared_owner_peer(
            &credentials.identity,
            classify_peer(peer, declared_sid.as_ptr()),
        )?;
        let app_data_root = canonical_app_data_root(Path::new(&credentials.app_data_dir))?;

        let root = open_no_reparse(&app_data_root, true, READ_CONTROL)?;
        validate_file_kind(&root, true)?;
        validate_owner(root.as_raw_handle(), declared_sid.as_ptr())?;

        let token_path = app_data_root.join(OWNER_TOKEN_FILE_NAME);
        let mut token_file = open_no_reparse(&token_path, false, GENERIC_READ | READ_CONTROL)?;
        validate_file_kind(&token_file, false)?;
        validate_token_security(token_file.as_raw_handle(), declared_sid.as_ptr())?;

        let mut stored_token = [0_u8; TOKEN_BYTES];
        token_file
            .read_exact(&mut stored_token)
            .map_err(|_| unauthorized("owner token file could not be read"))?;
        if !constant_time_eq(&stored_token, &request_token) {
            return Err(unauthorized("owner token does not match"));
        }

        Ok(AuthenticatedOwner {
            key: owner_key(&credentials.identity),
            identity: credentials.identity.clone(),
            app_data_root,
        })
    }

    /// Ask the kernel who opened this connection, and compare that to the declared owner.
    ///
    /// Returns a classification rather than an error because the caller refuses every one of these
    /// outcomes anyway; keeping them apart is what stops "could not tell" from being written as an
    /// `Option` that somebody later reads as "nothing to check".
    ///
    /// `PROCESS_QUERY_LIMITED_INFORMATION` is the weakest right that still yields a token handle,
    /// and the service runs as SYSTEM, so the open succeeds for any live peer. The one race left
    /// is process-id reuse, which needs the peer to have exited while its pipe handle survived in
    /// another process; a stale id then names either nothing (`Unopenable`) or an unrelated
    /// process (`OtherPrincipal`), both of which are refused.
    fn classify_peer(peer: PeerIdentity, declared_sid: PSID) -> WindowsPeer {
        let Some(process_id) = peer.process_id else {
            return WindowsPeer::Unnamed;
        };

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return WindowsPeer::Unopenable;
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };

        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
            return WindowsPeer::TokenUnreadable;
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };

        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if required == 0 {
            return WindowsPeer::TokenUnreadable;
        }
        // A `TOKEN_USER` is followed in the same buffer by the SID it points at, so the buffer is
        // allocated as pointer-sized words to give that SID the alignment the SID calls expect.
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return WindowsPeer::TokenUnreadable;
        }

        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
            return WindowsPeer::TokenUnreadable;
        }
        if unsafe { EqualSid(user.User.Sid, declared_sid) } == 0 {
            return WindowsPeer::OtherPrincipal;
        }
        WindowsPeer::DeclaredOwner
    }

    fn canonical_app_data_root(path: &Path) -> Result<PathBuf, ServiceError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| unauthorized("application data root is unavailable"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unauthorized(
                "application data root is not an ordinary directory",
            ));
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| unauthorized("application data root could not be canonicalized"))?;
        // The caller screened the string it was handed; screen what it actually resolved to as
        // well. Everything below reads its identity evidence — the owner SID, the token DACL —
        // from whatever answers this path, so a root that resolves off the local volume would
        // let the answering party choose that evidence. Checked here so no resolution trick can
        // slip between the two.
        if !super::is_local_drive_path(&canonical.to_string_lossy()) {
            return Err(unauthorized(
                "application data root does not resolve to a local drive-letter path",
            ));
        }
        Ok(canonical)
    }

    fn open_no_reparse(
        path: &Path,
        directory: bool,
        access: u32,
    ) -> Result<std::fs::File, ServiceError> {
        let wide = wide_path(path)?;
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(unauthorized("owner credential path could not be opened"));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }

    fn validate_file_kind(file: &std::fs::File, directory: bool) -> Result<(), ServiceError> {
        let handle = file.as_raw_handle();
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(unauthorized("owner credential metadata is unavailable"));
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && unsafe { GetFileType(handle) } != FILE_TYPE_DISK)
        {
            return Err(unauthorized(
                "owner credential path has an invalid file type",
            ));
        }
        if !directory
            && (information.nFileSizeHigh != 0 || information.nFileSizeLow != TOKEN_BYTES as u32)
        {
            return Err(unauthorized("owner token file has an invalid size"));
        }
        Ok(())
    }

    fn validate_owner(handle: *mut c_void, declared_sid: PSID) -> Result<(), ServiceError> {
        let security = SecurityInfo::read(handle, OWNER_SECURITY_INFORMATION)?;
        if security.owner.is_null() || unsafe { EqualSid(security.owner, declared_sid) } == 0 {
            return Err(unauthorized(
                "owner credential path has an unexpected owner",
            ));
        }
        Ok(())
    }

    fn validate_token_security(
        handle: *mut c_void,
        declared_sid: PSID,
    ) -> Result<(), ServiceError> {
        let security = SecurityInfo::read(
            handle,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        )?;
        if security.owner.is_null() || unsafe { EqualSid(security.owner, declared_sid) } == 0 {
            return Err(unauthorized("owner token file has an unexpected owner"));
        }
        if security.dacl.is_null() {
            return Err(unauthorized("owner token file has no restrictive DACL"));
        }

        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe {
            GetSecurityDescriptorControl(security.descriptor.0, &mut control, &mut revision)
        } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(unauthorized("owner token DACL is not protected"));
        }

        let mut owner_ace = false;
        let mut system_ace = false;
        let mut administrators_ace = false;
        for index in 0..unsafe { (*security.dacl).AceCount } as u32 {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(security.dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(unauthorized("owner token DACL could not be inspected"));
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || allowed.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
            {
                return Err(unauthorized("owner token DACL contains an unexpected ACE"));
            }
            let ace_sid = std::ptr::addr_of!(allowed.SidStart)
                .cast_mut()
                .cast::<c_void>();
            if unsafe { IsValidSid(ace_sid) } == 0 {
                return Err(unauthorized("owner token DACL contains an invalid SID"));
            }
            if unsafe { EqualSid(ace_sid, declared_sid) } != 0 {
                owner_ace = true;
            } else if unsafe { IsWellKnownSid(ace_sid, WinLocalSystemSid) } != 0 {
                system_ace = true;
            } else if unsafe { IsWellKnownSid(ace_sid, WinBuiltinAdministratorsSid) } != 0 {
                administrators_ace = true;
            } else {
                return Err(unauthorized(
                    "owner token DACL grants access to another SID",
                ));
            }
        }
        if !owner_ace || !system_ace || !administrators_ace {
            return Err(unauthorized(
                "owner token DACL is missing a required principal",
            ));
        }
        Ok(())
    }

    fn decode_token(value: &str) -> Option<[u8; TOKEN_BYTES]> {
        if value.len() != TOKEN_BYTES * 2 {
            return None;
        }
        let mut token = [0_u8; TOKEN_BYTES];
        for (index, output) in token.iter_mut().enumerate() {
            let offset = index * 2;
            let high = decode_nibble(value.as_bytes()[offset])?;
            let low = decode_nibble(value.as_bytes()[offset + 1])?;
            *output = high << 4 | low;
        }
        Some(token)
    }

    fn decode_nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }

    fn constant_time_eq(left: &[u8; TOKEN_BYTES], right: &[u8; TOKEN_BYTES]) -> bool {
        left.iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, ServiceError> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(unauthorized("owner credential path contains NUL"));
        }
        wide.push(0);
        Ok(wide)
    }

    fn unauthorized(message: impl Into<String>) -> ServiceError {
        ServiceError::unauthorized(message)
    }

    struct LocalSid(*mut c_void);

    impl LocalSid {
        fn from_string(value: &str) -> Result<Self, ServiceError> {
            let mut wide: Vec<u16> = value.encode_utf16().collect();
            wide.push(0);
            let mut sid = std::ptr::null_mut();
            if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0
                || unsafe { IsValidSid(sid) } == 0
            {
                return Err(unauthorized("declared Windows SID is invalid"));
            }
            Ok(Self(sid))
        }

        fn as_ptr(&self) -> PSID {
            self.0
        }
    }

    impl Drop for LocalSid {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    struct SecurityInfo {
        owner: PSID,
        dacl: *mut ACL,
        descriptor: LocalSecurityDescriptor,
    }

    impl SecurityInfo {
        fn read(handle: *mut c_void, information: u32) -> Result<Self, ServiceError> {
            let mut owner = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = unsafe {
                GetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    information,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            if status != 0 || descriptor.is_null() {
                return Err(unauthorized(
                    "owner credential security could not be inspected",
                ));
            }
            Ok(Self {
                owner,
                dacl,
                descriptor: LocalSecurityDescriptor(descriptor),
            })
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }
}

#[cfg(test)]
mod peer_tests {
    use super::{OwnerIdentity, ServiceErrorCode, WindowsPeer, require_declared_owner_peer};

    fn declared_owner() -> OwnerIdentity {
        OwnerIdentity::Windows {
            sid: "S-1-5-21-1004336348-1177238915-682003330-1001".to_string(),
        }
    }

    #[test]
    fn only_a_peer_proved_to_be_the_declared_owner_is_admitted() {
        assert!(require_declared_owner_peer(&declared_owner(), WindowsPeer::DeclaredOwner).is_ok());
    }

    /// The whole point of the gate: every answer other than "it is the owner" is refused, and the
    /// three ways of not knowing are refused on the same terms as knowing it is somebody else.
    /// A stolen token presented from another session is `OtherPrincipal`; the rest are what the
    /// service must do when it cannot tell, and none of them may fall back to trusting the token.
    #[test]
    fn an_unproved_peer_is_refused_exactly_as_a_wrong_one_is() {
        for peer in [
            WindowsPeer::OtherPrincipal,
            WindowsPeer::Unnamed,
            WindowsPeer::Unopenable,
            WindowsPeer::TokenUnreadable,
        ] {
            let error = require_declared_owner_peer(&declared_owner(), peer)
                .expect_err("a peer that was not proved to be the owner must be refused");

            assert_eq!(error.code, ServiceErrorCode::UnauthorizedOwner);
        }
    }

    /// The gate is not a free pass for a request that named the wrong kind of identity: a Unix
    /// identity arriving on the Windows path has no SID for the peer to have matched.
    #[test]
    fn a_unix_identity_does_not_satisfy_the_windows_gate() {
        let error = require_declared_owner_peer(
            &OwnerIdentity::Unix { uid: 501, gid: 20 },
            WindowsPeer::DeclaredOwner,
        )
        .expect_err("a Unix identity must not pass the Windows transport gate");

        assert_eq!(error.code, ServiceErrorCode::UnauthorizedOwner);
    }
}

#[cfg(test)]
mod path_tests {
    use super::is_local_drive_path;

    #[test]
    fn only_local_drive_letter_roots_are_accepted() {
        assert!(is_local_drive_path(r"C:\Users\Alice\AppData\Roaming\app"));
        assert!(is_local_drive_path(r"\\?\C:\Users\Alice\AppData\Roaming\app"));
        // The parked-worker vector, plus the two other spellings of "somebody else answers".
        assert!(!is_local_drive_path(r"\\10.255.255.1\share"));
        assert!(!is_local_drive_path(r"\\?\UNC\10.255.255.1\share"));
        assert!(!is_local_drive_path(r"\\.\pipe\anything"));
        assert!(!is_local_drive_path(r"relative\app"));
        assert!(!is_local_drive_path("C:"));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::authenticate_owner_off_runtime;
    use super::validate_unix_identity;
    use crate::{OwnerCredentials, OwnerIdentity, ServiceErrorCode};
    use http::{HeaderMap, Method};
    use kode_bridge::{ClientInfo, PeerCredentials, RequestContext};
    use std::{collections::HashMap, time::Instant};

    #[test]
    fn unix_owner_must_match_kernel_peer_credentials() {
        let declared = OwnerIdentity::Unix { uid: 502, gid: 20 };

        let error = validate_unix_identity(&declared, Some((501, 20)))
            .expect_err("mismatched UID must be rejected");

        assert_eq!(error.code, ServiceErrorCode::UnauthorizedOwner);
    }

    #[tokio::test]
    async fn authenticated_unix_owner_uses_canonical_owned_app_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let uid = unsafe { platform_lib::geteuid() };
        let gid = unsafe { platform_lib::getegid() };
        let app_root =
            std::env::temp_dir().join(format!("service-owner-auth-{}", std::process::id()));
        std::fs::create_dir_all(&app_root)?;
        let context = RequestContext {
            method: Method::POST,
            uri: "/clash/start".parse()?,
            path_params: HashMap::new(),
            headers: HeaderMap::new(),
            body: Default::default(),
            client_info: ClientInfo {
                connection_id: 1,
                connected_at: Instant::now(),
                peer_credentials: PeerCredentials {
                    uid: Some(uid),
                    gid: Some(gid),
                    pid: None,
                },
            },
            timestamp: Instant::now(),
        };
        let credentials = OwnerCredentials {
            identity: OwnerIdentity::Unix { uid, gid },
            app_data_dir: app_root.to_string_lossy().into_owned(),
            token: None,
        };

        let owner = authenticate_owner_off_runtime(&context, &credentials).await?;

        assert_eq!(owner.key, uid.to_string());
        assert_eq!(owner.app_data_root, std::fs::canonicalize(&app_root)?);
        std::fs::remove_dir_all(app_root)?;
        Ok(())
    }
}

#[cfg(all(test, windows, feature = "test"))]
mod windows_tests {
    use super::PeerIdentity;
    use super::windows_auth::authenticate;
    use crate::{OWNER_TOKEN_FILE_NAME, OwnerIdentity, ServiceErrorCode, test_owner_credentials};
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };

    fn test_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cvs-auth-{name}-{}", std::process::id()))
    }

    fn apply_everyone_dacl(path: &std::path::Path) -> anyhow::Result<()> {
        let mut sddl = "D:P(A;;FA;;;WD)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_mut_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        struct Descriptor(*mut std::ffi::c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe { LocalFree(self.0) };
            }
        }
        let descriptor = Descriptor(descriptor);
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        if unsafe {
            SetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    #[test]
    fn valid_token_authenticates_and_wrong_token_or_owner_is_rejected() -> anyhow::Result<()> {
        let root = test_root("valid");
        let _ = std::fs::remove_dir_all(&root);
        let credentials = test_owner_credentials(&root)?;

        assert_eq!(
            authenticate(PeerIdentity::current_process(), &credentials)?.app_data_root,
            root.canonicalize()?
        );

        let mut wrong_token = credentials.clone();
        wrong_token.token = Some("00".repeat(32));
        assert_eq!(
            authenticate(PeerIdentity::current_process(), &wrong_token)
                .expect_err("wrong owner token must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        let mut wrong_owner = credentials.clone();
        wrong_owner.identity = OwnerIdentity::Windows {
            sid: "S-1-5-18".to_string(),
        };
        assert_eq!(
            authenticate(PeerIdentity::current_process(), &wrong_owner)
                .expect_err("wrong owner SID must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The transport gate, exercised against credentials that are otherwise perfect.
    ///
    /// Holding a copy of the 32 secret bytes is no longer enough: the request has to arrive from a
    /// process running as the owner. A connection the service cannot attribute to any process is
    /// refused rather than falling back to what the token alone would have proved.
    #[test]
    fn valid_credentials_are_refused_when_the_peer_is_not_proved() -> anyhow::Result<()> {
        let root = test_root("peer");
        let _ = std::fs::remove_dir_all(&root);
        let credentials = test_owner_credentials(&root)?;

        authenticate(PeerIdentity::current_process(), &credentials)?;

        assert_eq!(
            authenticate(PeerIdentity::default(), &credentials)
                .expect_err("a connection that names no process must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        // Not a multiple of four, so never a live process id: the peer exited, or never existed.
        assert_eq!(
            authenticate(
                PeerIdentity {
                    process_id: Some(u32::MAX)
                },
                &credentials
            )
            .expect_err("a peer that cannot be opened must be rejected")
            .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn token_directory_reparse_root_and_everyone_dacl_are_rejected() -> anyhow::Result<()> {
        let directory_root = test_root("directory");
        let _ = std::fs::remove_dir_all(&directory_root);
        let directory_credentials = test_owner_credentials(&directory_root)?;
        let token_path = directory_root.join(OWNER_TOKEN_FILE_NAME);
        std::fs::remove_file(&token_path)?;
        std::fs::create_dir(&token_path)?;
        assert_eq!(
            authenticate(PeerIdentity::current_process(), &directory_credentials)
                .expect_err("token directory must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );
        std::fs::remove_dir_all(&directory_root)?;

        let dacl_root = test_root("dacl");
        let _ = std::fs::remove_dir_all(&dacl_root);
        let dacl_credentials = test_owner_credentials(&dacl_root)?;
        apply_everyone_dacl(&dacl_root.join(OWNER_TOKEN_FILE_NAME))?;
        assert_eq!(
            authenticate(PeerIdentity::current_process(), &dacl_credentials)
                .expect_err("Everyone token DACL must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        let link_root = test_root("link");
        let _ = std::fs::remove_dir_all(&link_root);
        if let Err(error) = std::os::windows::fs::symlink_dir(&dacl_root, &link_root) {
            if error.raw_os_error() == Some(1314) {
                std::fs::remove_dir_all(dacl_root)?;
                return Ok(());
            }
            return Err(error.into());
        }
        let mut link_credentials = dacl_credentials;
        link_credentials.app_data_dir = link_root.to_string_lossy().into_owned();
        assert_eq!(
            authenticate(PeerIdentity::current_process(), &link_credentials)
                .expect_err("reparse-point app root must be rejected")
                .code,
            ServiceErrorCode::UnauthorizedOwner
        );

        std::fs::remove_dir(&link_root)?;
        std::fs::remove_dir_all(dacl_root)?;
        Ok(())
    }
}
