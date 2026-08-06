#[cfg(windows)]
use anyhow::Context as _;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ProcessIdentity {
    pub(super) executable: String,
    pub(super) started_at: u64,
}

pub(super) fn process_identity(pid: u32) -> Result<Option<ProcessIdentity>> {
    if !is_process_alive(pid) {
        return Ok(None);
    }

    #[cfg(target_os = "linux")]
    {
        let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?
            .canonicalize()?
            .to_string_lossy()
            .into_owned();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields = stat
            .rsplit_once(')')
            .ok_or_else(|| anyhow::anyhow!("invalid /proc stat for process {pid}"))?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let started_at = fields
            .get(19)
            .ok_or_else(|| anyhow::anyhow!("missing start time for process {pid}"))?
            .parse()?;
        Ok(Some(ProcessIdentity {
            executable,
            started_at,
        }))
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStringExt as _;

        let mut path = vec![0u8; platform_lib::PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_len = unsafe {
            platform_lib::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32)
        };
        if path_len <= 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        path.truncate(path_len as usize);
        let executable = std::path::PathBuf::from(std::ffi::OsString::from_vec(path))
            .canonicalize()?
            .to_string_lossy()
            .into_owned();
        let mut info = unsafe { std::mem::zeroed::<platform_lib::proc_bsdinfo>() };
        let info_len = unsafe {
            platform_lib::proc_pidinfo(
                pid as i32,
                platform_lib::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut platform_lib::proc_bsdinfo).cast(),
                std::mem::size_of::<platform_lib::proc_bsdinfo>() as i32,
            )
        };
        if info_len != std::mem::size_of::<platform_lib::proc_bsdinfo>() as i32 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Some(ProcessIdentity {
            executable,
            started_at: info
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
        }))
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        struct ProcessHandle(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for ProcessHandle {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let handle = ProcessHandle(handle);
        let mut path = vec![0u16; 32_768];
        let mut path_len = path.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut path_len) } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        path.truncate(path_len as usize);
        let executable = std::path::PathBuf::from(String::from_utf16(&path)?)
            .canonicalize()?
            .to_string_lossy()
            .into_owned();
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let started_at =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        Ok(Some(ProcessIdentity {
            executable,
            started_at,
        }))
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "lstart=", "-o", "comm=", "-p", &pid.to_string()])
            .output()?;
        if !output.status.success() {
            return Ok(None);
        }
        let identity = String::from_utf8(output.stdout)?;
        Ok(Some(ProcessIdentity {
            executable: identity.trim().to_string(),
            started_at: 0,
        }))
    }
}

pub(super) fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let result = unsafe { platform_lib::kill(pid as i32, 0) };
        let exists = result == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(platform_lib::EPERM);
        if !exists {
            return false;
        }
        // A zombie has exited and no longer owns files or locks, even though kill(pid, 0)
        // continues to report it until its parent reaps it.
        let zombie = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .is_some_and(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim_start()
                    .starts_with('Z')
            });
        !zombie
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
        };

        if pid == 0 {
            return false;
        }
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION
                    | windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            // Invalid PID means gone. Access-denied or another inspection failure is treated as
            // alive: startup reconciliation must fail closed rather than open the network around
            // a process it could not prove had exited.
            return std::io::Error::last_os_error().raw_os_error()
                != Some(ERROR_INVALID_PARAMETER as i32);
        }
        // SAFETY: `OpenProcess` returned an owned process handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        match unsafe { WaitForSingleObject(handle.as_raw_handle() as HANDLE, 0) } {
            WAIT_OBJECT_0 => false,
            WAIT_TIMEOUT => true,
            _ => true,
        }
    }
}

pub(super) async fn terminate_process(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        warn!("Terminating process {}", pid);
        if unsafe { platform_lib::kill(pid as i32, platform_lib::SIGTERM) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(platform_lib::ESRCH)
        {
            return Err(std::io::Error::last_os_error().into());
        }

        for _ in 0..10 {
            if !is_process_alive(pid) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        warn!("Process {} did not exit, sending SIGKILL", pid);
        if unsafe { platform_lib::kill(pid as i32, platform_lib::SIGKILL) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(platform_lib::ESRCH)
        {
            return Err(std::io::Error::last_os_error().into());
        }
        for _ in 0..10 {
            if !is_process_alive(pid) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("process {pid} is still alive after SIGKILL");
    }

    #[cfg(windows)]
    {
        warn!("Terminating process {}", pid);
        tokio::task::spawn_blocking(move || terminate_process_windows(pid))
            .await
            .context("Windows process termination worker failed")??;
        Ok(())
    }
}

/// Native, locale-independent Windows process termination with a hard wait bound. This is the
/// recovery path for a core left by an older Service; cores started by this build additionally
/// live in a kill-on-close Job Object (see `manager.rs`).
#[cfg(windows)]
fn terminate_process_windows(pid: u32) -> Result<()> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    if pid == 0 {
        return Ok(());
    }
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(());
        }
        return Err(error).with_context(|| format!("failed to open process {pid} for termination"));
    }
    // SAFETY: `OpenProcess` returned an owned process handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let raw = handle.as_raw_handle() as HANDLE;

    if unsafe { TerminateProcess(raw, 1) } == 0 {
        // The process may have exited between OpenProcess and TerminateProcess.
        if unsafe { WaitForSingleObject(raw, 0) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to terminate process {pid}"));
        }
    }
    match unsafe { WaitForSingleObject(raw, 2_000) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => bail!("process {pid} did not terminate within 2 seconds"),
        _ => Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed while waiting for process {pid} to terminate")),
    }
}
