use anyhow::Result;
use smartstring::alias::String;

pub type CmdResult<T = ()> = Result<T, String>;

const USER_ERROR_PREFIX: &str = "CVR_ERROR:";

pub fn coded_error(code: &str, detail: impl std::fmt::Display) -> String {
    format!("{USER_ERROR_PREFIX}{code}\n{detail}").into()
}

// Command modules
pub mod app;
pub mod backup;
pub mod clash;
pub mod lightweight;
pub mod listener;
pub mod media_unlock_checker;
pub mod network;
pub mod profile;
pub mod proxy;
pub mod runtime;
pub mod save_profile;
pub mod service;
pub mod system;
pub mod uwp;
pub mod validate;
pub mod verge;
pub mod webdav;

// Re-export all command functions for backwards compatibility
pub use app::*;
pub use backup::*;
pub use clash::*;
pub use lightweight::*;
pub use listener::*;
pub use media_unlock_checker::*;
pub use network::*;
pub use profile::*;
pub use proxy::*;
pub use runtime::*;
pub use save_profile::*;
pub use service::*;
pub use system::*;
pub use uwp::*;
pub use validate::*;
pub use verge::*;
pub use webdav::*;

pub trait StringifyErr<T> {
    fn stringify_err(self) -> CmdResult<T>;
    #[allow(dead_code)]
    fn stringify_err_log<F>(self, log_fn: F) -> CmdResult<T>
    where
        F: Fn(&str);
}

pub trait WithErrorCode<T> {
    fn with_error_code(self, code: &str) -> CmdResult<T>;
}

impl<T, E: std::fmt::Display> StringifyErr<T> for Result<T, E> {
    fn stringify_err(self) -> CmdResult<T> {
        self.map_err(|e| e.to_string().into())
    }

    fn stringify_err_log<F>(self, log_fn: F) -> CmdResult<T>
    where
        F: Fn(&str),
    {
        self.map_err(|e| {
            let msg = String::from(e.to_string());
            log_fn(&msg);
            msg
        })
    }
}

/// Run blocking OS work off the caller's thread and flatten the join failure into the command's
/// own error type.
///
/// A synchronous `#[tauri::command]` is invoked inline on the Tauri main thread, so a command
/// that touches the OS — a subprocess, the SCM, the registry, a path enterprise policy can
/// redirect onto a network share — freezes the window for as long as that call takes. None of
/// those calls carry a timeout of their own, so "as long as it takes" has no upper bound.
/// Commands route through here instead of each rolling its own hop.
pub async fn blocking<T, F>(work: F) -> CmdResult<T>
where
    F: FnOnce() -> CmdResult<T> + Send + 'static,
    T: Send + 'static,
{
    crate::process::AsyncHandler::spawn_blocking(work)
        .await
        .map_err(|err| -> String { format!("background task did not finish: {err}").into() })?
}

impl<T, E: std::fmt::Display> WithErrorCode<T> for Result<T, E> {
    fn with_error_code(self, code: &str) -> CmdResult<T> {
        self.map_err(|error| coded_error(code, error))
    }
}

#[cfg(test)]
mod tests {
    use super::coded_error;

    #[test]
    fn coded_error_preserves_stable_code_and_diagnostic_detail() {
        assert_eq!(
            coded_error("CORE_RESTART_FAILED", "connection refused"),
            "CVR_ERROR:CORE_RESTART_FAILED\nconnection refused"
        );
    }
}
