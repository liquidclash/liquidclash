use anyhow::{Context as _, Result, bail};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError,
    INVALID_HANDLE_VALUE, LocalFree,
};
#[cfg(not(feature = "test"))]
use windows_sys::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, SetLastError};
#[cfg(not(feature = "test"))]
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetSecurityInfo,
};
#[cfg(not(feature = "test"))]
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, CreateWellKnownSid, EqualSid, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
    SECURITY_MAX_SID_SIZE, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    GetFileInformationByHandle, GetFileType, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
#[cfg(not(feature = "test"))]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[cfg(not(feature = "test"))]
const PRIVATE_SERVICE_DIRECTORY_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
#[cfg(feature = "test")]
const PRIVATE_SERVICE_DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const PRIVATE_INSTALLER_DIRECTORY_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
#[cfg(not(feature = "test"))]
const PRIVATE_SERVICE_FILE_SDDL: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
#[cfg(feature = "test")]
const PRIVATE_SERVICE_FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

pub(crate) fn ensure_private_service_directory(path: &Path) -> Result<()> {
    ensure_private_directory(path, PRIVATE_SERVICE_DIRECTORY_SDDL, true)
}

pub(crate) fn ensure_private_installer_directory(path: &Path) -> Result<()> {
    ensure_private_directory(path, PRIVATE_INSTALLER_DIRECTORY_SDDL, false)
}

fn ensure_private_directory(path: &Path, sddl: &str, migrate_owner: bool) -> Result<()> {
    ensure_private_directory_with_recovery(path, sddl, migrate_owner, true)
}

fn ensure_private_directory_with_recovery(
    path: &Path,
    sddl: &str,
    migrate_owner: bool,
    allow_empty_recreation: bool,
) -> Result<()> {
    let descriptor = LocalDescriptor::from_sddl(sddl)?;
    let wide = wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0
        && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to create private service directory {path:?}"));
    }

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open private service directory {path:?}"));
    }
    let handle = OwnedHandle(handle);

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.0, &mut information) } == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK
    {
        bail!("service directory {path:?} is not an ordinary directory");
    }
    #[cfg(not(feature = "test"))]
    if migrate_owner {
        ensure_local_system_owner(handle.0, path)?;
    } else if !installer_owner_is_trusted(handle.0)? {
        drop(handle);
        if allow_empty_recreation {
            std::fs::remove_dir(path).with_context(|| {
                format!(
                    "service install path {path:?} has an unexpected owner and is not an empty directory that can be safely reclaimed"
                )
            })?;
            return ensure_private_directory_with_recovery(path, sddl, migrate_owner, false);
        }
        bail!("service install path {path:?} still has an unexpected owner after safe recreation");
    }
    #[cfg(feature = "test")]
    let _ = (migrate_owner, allow_empty_recreation);
    descriptor.apply_dacl(handle.0)?;
    Ok(())
}

pub(crate) fn secure_private_directory(path: &Path) -> Result<()> {
    ensure_private_service_directory(path)
}

pub(crate) fn secure_private_service_file_if_exists(path: &Path) -> Result<()> {
    let descriptor = LocalDescriptor::from_sddl(PRIVATE_SERVICE_FILE_SDDL)?;
    let wide = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(()),
            _ => Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to open private service file {path:?}")),
        };
    }
    let handle = OwnedHandle(handle);
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.0, &mut information) } == 0
        || information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        || unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK
    {
        bail!("service file {path:?} is not an ordinary file");
    }
    #[cfg(not(feature = "test"))]
    ensure_local_system_owner(handle.0, path)?;
    descriptor.apply_dacl(handle.0)
}

#[cfg(not(feature = "test"))]
fn ensure_local_system_owner(handle: *mut std::ffi::c_void, path: &Path) -> Result<()> {
    let (owner, security) = read_owner(handle)?;
    let mut system_sid = well_known_sid(WinLocalSystemSid, "LocalSystem")?;
    if unsafe { EqualSid(owner, system_sid.as_mut_ptr().cast()) } != 0 {
        return Ok(());
    }
    let mut administrators_sid =
        well_known_sid(WinBuiltinAdministratorsSid, "Builtin Administrators")?;
    if unsafe { EqualSid(owner, administrators_sid.as_mut_ptr().cast()) } == 0 {
        bail!(
            "service path {path:?} has an unexpected owner; only legacy Builtin Administrators ownership can be migrated"
        );
    }
    drop(security);

    // An elevated administrator token contains SeRestorePrivilege but leaves it disabled. Merely
    // opening the file with WRITE_OWNER is therefore insufficient for assigning LocalSystem as
    // owner: SetSecurityInfo returns ERROR_INVALID_OWNER (1307). That exact path made the
    // uninstall helper fail before removing WFP, because its atomic kill-switch tombstone is
    // created under the administrator token and inherits Builtin Administrators ownership.
    // Enable the privilege only for this assignment and restore the token state on drop; the
    // long-running service must not keep a broader token than it needs.
    let _restore_privilege = RestorePrivilegeGuard::enable()
        .context("enabling SeRestorePrivilege for LocalSystem owner migration")?;
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            system_sid.as_mut_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        bail!(
            "failed to migrate service path {path:?} to LocalSystem ownership: Windows error {status}"
        );
    }
    Ok(())
}

/// Scoped SeRestorePrivilege enablement for the one owner migration above.
///
/// `AdjustTokenPrivileges` can return success while setting `ERROR_NOT_ALL_ASSIGNED`; treating
/// that as success would simply turn the original 1307 into a later opaque failure, so both
/// signals are checked. The previous single-privilege state is restored even when
/// `SetSecurityInfo` fails.
#[cfg(not(feature = "test"))]
struct RestorePrivilegeGuard {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}

#[cfg(not(feature = "test"))]
impl RestorePrivilegeGuard {
    fn enable() -> Result<Self> {
        let mut token = std::ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } == 0
            || token.is_null()
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to open the current process token");
        }
        let token = OwnedHandle(token);

        let mut luid = Default::default();
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_RESTORE_NAME, &mut luid) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to resolve SeRestorePrivilege");
        }
        let desired = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut previous_len = 0_u32;
        unsafe { SetLastError(0) };
        if unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &desired,
                std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut previous_len,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to enable SeRestorePrivilege");
        }
        let last_error = unsafe { GetLastError() };
        if last_error == ERROR_NOT_ALL_ASSIGNED {
            bail!("the elevated process token does not contain SeRestorePrivilege");
        }
        if last_error != 0 {
            bail!("enabling SeRestorePrivilege returned Windows error {last_error}");
        }

        Ok(Self { token, previous })
    }
}

#[cfg(not(feature = "test"))]
impl Drop for RestorePrivilegeGuard {
    fn drop(&mut self) {
        // Best effort: the process is already elevated and the only safe fallback is to exit,
        // which every current caller does after its maintenance operation.
        unsafe {
            AdjustTokenPrivileges(
                self.token.0,
                0,
                &self.previous,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
    }
}

#[cfg(not(feature = "test"))]
fn installer_owner_is_trusted(handle: *mut std::ffi::c_void) -> Result<bool> {
    let (owner, _security) = read_owner(handle)?;
    let mut system_sid = well_known_sid(WinLocalSystemSid, "LocalSystem")?;
    let mut administrators_sid =
        well_known_sid(WinBuiltinAdministratorsSid, "Builtin Administrators")?;
    Ok(
        unsafe { EqualSid(owner, system_sid.as_mut_ptr().cast()) } != 0
            || unsafe { EqualSid(owner, administrators_sid.as_mut_ptr().cast()) } != 0,
    )
}

#[cfg(not(feature = "test"))]
fn read_owner(handle: *mut std::ffi::c_void) -> Result<(*mut std::ffi::c_void, LocalDescriptor)> {
    let mut owner = std::ptr::null_mut();
    let mut security = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security,
        )
    };
    if status != 0 || security.is_null() || owner.is_null() {
        bail!("failed to inspect service path owner: Windows error {status}");
    }
    let security = LocalDescriptor(security);
    Ok((owner, security))
}

#[cfg(not(feature = "test"))]
fn well_known_sid(kind: i32, label: &str) -> Result<Vec<usize>> {
    let words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<usize>());
    let mut sid = vec![0_usize; words];
    let mut sid_size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to create {label} SID"));
    }
    Ok(sid)
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("service directory path contains NUL");
    }
    wide.push(0);
    Ok(wide)
}

struct OwnedHandle(*mut std::ffi::c_void);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalDescriptor(*mut std::ffi::c_void);

impl LocalDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let mut wide: Vec<u16> = sddl.encode_utf16().collect();
        wide.push(0);
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to build private service directory security descriptor");
        }
        Ok(Self(descriptor))
    }

    fn apply_dacl(&self, handle: *mut std::ffi::c_void) -> Result<()> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
            || dacl.is_null()
        {
            bail!("private service directory descriptor has no DACL");
        }
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            bail!("failed to apply private service directory DACL: Windows error {status}");
        }
        Ok(())
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::{PRIVATE_INSTALLER_DIRECTORY_SDDL, PRIVATE_SERVICE_DIRECTORY_SDDL};

    #[test]
    fn installer_directory_assigns_builtin_administrators_as_owner() {
        assert!(PRIVATE_INSTALLER_DIRECTORY_SDDL.starts_with("O:BAD:P"));
    }

    #[test]
    fn private_directory_dacl_excludes_ordinary_users() {
        #[cfg(not(feature = "test"))]
        assert!(PRIVATE_SERVICE_DIRECTORY_SDDL.starts_with("O:SYD:P"));
        #[cfg(feature = "test")]
        assert!(PRIVATE_SERVICE_DIRECTORY_SDDL.starts_with("D:P"));
        assert!(PRIVATE_SERVICE_DIRECTORY_SDDL.contains(";;;SY)"));
        assert!(PRIVATE_SERVICE_DIRECTORY_SDDL.contains(";;;BA)"));
        assert!(!PRIVATE_SERVICE_DIRECTORY_SDDL.contains(";;;WD)"));
        assert!(!PRIVATE_SERVICE_DIRECTORY_SDDL.contains(";;;AU)"));
    }
}
