//! tono-core: portable product layer for the Tono Windows client.
//!
//! Implements the normative rules of `docs/product-contract.md` without any
//! Windows API dependency: catalog admission and caching, owned Mihomo
//! runtime generation, API models and session logic, the connect state
//! machine, and credential storage abstractions.

#![forbid(unsafe_code)]

pub mod auth;
pub mod catalog;
pub mod config;
pub mod connection;
pub mod credentials;
pub mod node;
pub mod policy;

pub use catalog::{CatalogError, CatalogTracker, ExitCatalogResponse, InstallOutcome};
pub use config::{
    DirectPlan, OwnedRuntime, build_owned_runtime, generate_controller_secret, redact_secret,
};
pub use connection::{ConnectStage, ConnectionStatus, ReconnectBackoff, UiState};
pub use credentials::{CredentialKey, CredentialStore};
pub use node::{EXIT_GROUP_NAME, NodeRejection, ValidatedNode};
