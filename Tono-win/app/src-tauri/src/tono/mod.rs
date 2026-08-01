//! Tono product layer: account session, exit catalog, and the §6 connect
//! transaction, built on the portable `tono-core` crate and the Service IPC
//! client in `core::service`. Nothing here touches the legacy CVR feature
//! set; the two coexist until the legacy UI is retired.

pub mod audit;
pub mod bootstrap;
pub mod catalog_sync;
pub mod commands;
pub mod connection;
pub mod credentials;
pub mod policy_sync;
pub mod state;
pub mod steps;
pub mod transport;

pub use state::TonoState;
