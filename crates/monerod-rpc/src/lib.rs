//! A typed async client for the monerod daemon RPC.
//!
//! This crate is deliberately the only thing in the workspace that talks to the
//! network, and it knows nothing about HTML, templates, or the explorer's own
//! data model. It speaks monerod's wire format and nothing else.
//!
//! ```no_run
//! # async fn f() -> Result<(), monerod_rpc::RpcError> {
//! let node = monerod_rpc::Client::new("http://127.0.0.1:18081")?;
//! # Ok(()) }
//! ```

pub mod client;
pub mod epee;
pub mod error;
pub mod types;
mod url;

pub use client::{Client, ClientBuilder, DEFAULT_MAX_RESPONSE_BYTES};
pub use error::{RpcError, Status, TransportKind};
pub use types::NestedJsonError;
