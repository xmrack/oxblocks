//! Domain model, chain access and decoding for oxblocks.
//!
//! This crate sits between [`monerod_rpc`] and the web layer. It knows about
//! Monero, but nothing about HTTP.

pub mod amount;
pub mod cache;
pub mod chain;
pub mod curve_tree;
pub mod fcmp;
pub mod fmt;
pub mod hash;
pub mod hex;
pub mod rpc_source;
pub mod tx;
pub mod tx_extra;

pub use amount::Amount;
pub use cache::{Cache, REORG_WINDOW, safe_to_cache_by_height};
pub use chain::{BlockId, BlockIdError, ChainError, ResolvedInput, RingMember};
pub use fmt::{age, decimal, timestamp_utc};
pub use hash::{Hash32, HashParseError};
pub use rpc_source::{
    BlockTree, BlockWithTxs, DEFAULT_MAX_INFLIGHT_RPC, FetchedTxs, RpcChainSource,
    unexpanded_inputs,
};
pub use tx::TxFacts;
pub use tx_extra::{ParsedTxExtra, PaymentId8, TxExtraField};
