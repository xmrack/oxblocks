//! monerod's RPC wire types.
//!
//! These are a transcription of what monerod v0.18.5.1 (RPC 3.16) actually puts
//! on the wire, which is not the same thing as what its C++ structs declare.
//! epee's key-value serializer drops fields on the way out, in three ways that
//! all bite:
//!
//! * **Empty containers vanish.** The container writer returns early without
//!   emitting even the key, so `missed_tx`, `txs`, `tx_hashes`,
//!   `output_indices`, `transactions` and every other array are simply absent
//!   when empty. Every `Vec` below is `#[serde(default)]` for that reason; a
//!   required one fails on ordinary, everyday responses.
//! * **`KV_SERIALIZE_OPT` fields vanish when they equal their declared
//!   default.** `block_weight` and `long_term_weight` disappear from a block
//!   header whenever they are zero, and `quantization_mask` disappears when it
//!   is **1** — hence [`default_quantization_mask`], because a plain
//!   `#[serde(default)]` there yields 0 and divides fee maths by zero.
//! * **Strings never vanish.** `pow_hash`, `txid`, `as_json` and the `wide_*`
//!   fields arrive present-but-empty rather than absent. `""` is a value to
//!   handle, not evidence that a key was missing.
//!
//! Some responses carry a second JSON document *encoded as a string*:
//! `get_block`'s `json`, `/get_transactions`' `as_json`, and
//! `/get_transaction_pool`'s `tx_json`. Those come from a different serializer
//! (`obj_to_json_str`) with the opposite convention — empty arrays *are* kept —
//! and need a second parse. See [`BlockJson`] and [`TxJson`], and note that the
//! string can be empty: [`NestedJsonError::Absent`].
//!
//! The FCMP++ and Carrot hard fork (version 17) is described too, as the
//! `fcmp++-beta-stressnet-v3` branch of monerod writes it. It adds a `carrot_v1`
//! output target, RingCT type 7 with its proof in `rctsig_prunable`, inputs
//! with no ring, two curve-tree fields on the block, and `unified_ids` beside
//! `output_indices`. Every addition is optional on the Rust side, so the same
//! types still read a daemon that has never heard of the fork.
//!
//! Request types live here too, and several of them hide their fields. That is
//! deliberate: the traps in this protocol are almost all "a field you did not
//! set defaulted to something that silently returns the wrong data" (see
//! [`OutKeyRequest`] and [`GetBlockRequest`]).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// The JSON-RPC error codes this explorer acts on.
///
/// Only the ones with a distinct consequence are kept. The transport-level
/// codes (-32700, -32600, -32602, -32603) are omitted deliberately: reaching
/// them would mean this crate sent malformed JSON-RPC, which is a bug here
/// rather than a condition to handle, and an unrecognised code is already
/// treated as "unavailable" rather than as "not found".
pub mod error_code {
    /// Unknown method — **and also** how a method gated off by
    /// `--restricted-rpc` presents, because the dispatcher's `else if` simply
    /// fails to match and falls through. "Restricted" and "daemon too old" are
    /// indistinguishable here; treat both as "feature unavailable".
    pub const METHOD_NOT_FOUND: i64 = -32601;

    pub const WRONG_PARAM: i64 = -1;
    pub const TOO_BIG_HEIGHT: i64 = -2;
    pub const INTERNAL: i64 = -5;
    pub const CORE_BUSY: i64 = -9;
    /// Returned when a *parameter* exceeds what restricted mode allows — e.g.
    /// a block-header range wider than 1000. Note this is -19, not -2: the
    /// range and hash-count limits both use this code, with the message
    /// "Too many block headers requested.".
    pub const RESTRICTED: i64 = -19;
}

// ---------------------------------------------------------------------------
// 128-bit split values
// ---------------------------------------------------------------------------

/// Rebuild a 128-bit value from monerod's low/high pair.
///
/// `store_128` splits every 128-bit quantity into three fields: the plain field
/// holding the **low** 64 bits, a `*_top64` field holding the **high** 64, and
/// a `wide_*` hex string holding the whole thing. Reading only the plain field
/// silently truncates.
///
/// `top64` is 0 on mainnet today and will stay 0 for decades, so this is cheap
/// insurance rather than a live concern — but it is insurance that costs one
/// shift.
#[must_use]
pub const fn reassemble_u128(low: u64, top64: u64) -> u128 {
    ((top64 as u128) << 64) | (low as u128)
}

/// Parse a `wide_*` hex string (`"0x1ee54bb2b1777aa7"`, lowercase, no leading
/// zeros, `"0x0"` for zero).
///
/// Returns `None` for `""`, which monerod emits whenever `store_128` was never
/// reached — an all-default `block_header` has `wide_difficulty: ""`, and so
/// does `get_coinbase_tx_sum`'s error path. Prefer [`reassemble_u128`] and use
/// this only as a cross-check.
#[must_use]
pub fn parse_wide(s: &str) -> Option<u128> {
    u128::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// `quantization_mask` is `KV_SERIALIZE_OPT(quantization_mask, 1)`, so it is
/// omitted precisely when it is 1 — the one field in this file whose serde
/// default must not be zero.
#[must_use]
pub fn default_quantization_mask() -> u64 {
    1
}

// ---------------------------------------------------------------------------
// get_info
// ---------------------------------------------------------------------------

/// `get_info` result.
///
/// Under `--restricted-rpc` several of these are silently **falsified** rather
/// than omitted: peer counts, connection counts and `start_time` become 0,
/// `free_space` becomes `u64::MAX`, `version` becomes `""`, and `database_size`
/// is rounded up to a 5 GiB multiple. [`GetInfo::restricted`] is the flag that
/// says this happened — check it before displaying any of them.
///
/// **Every field oxblocks does not act on is `#[serde(default)]`.** monerod
/// removes fields when it removes features, and `get_info` is asked for by
/// nearly every page, so one absent field it never reads would take the whole
/// explorer down rather than one value off one page. That is not a
/// hypothetical: master dropped three bootstrap-daemon fields in 2026-05, and
/// this struct required them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetInfo {
    /// Blockchain height, i.e. top block height + 1.
    pub height: u64,
    /// 0 when synced, rather than equal to `height`.
    pub target_height: u64,
    pub difficulty: u64,
    pub difficulty_top64: u64,
    #[serde(default)]
    pub wide_difficulty: String,
    pub target: u64,
    /// Excludes coinbase transactions.
    pub tx_count: u64,
    pub tx_pool_size: u64,
    pub alt_blocks_count: u64,
    pub outgoing_connections_count: u64,
    pub incoming_connections_count: u64,
    #[serde(default)]
    pub rpc_connections_count: u64,
    pub white_peerlist_size: u64,
    pub grey_peerlist_size: u64,
    #[serde(default)]
    pub mainnet: bool,
    pub testnet: bool,
    pub stagenet: bool,
    /// `"mainnet"`, `"testnet"`, `"stagenet"` or `"fakechain"`.
    pub nettype: String,
    pub top_block_hash: String,
    pub cumulative_difficulty: u64,
    pub cumulative_difficulty_top64: u64,
    #[serde(default)]
    pub wide_cumulative_difficulty: String,
    pub block_size_limit: u64,
    pub block_size_median: u64,
    /// `KV_SERIALIZE_OPT(0)` — absent when zero.
    #[serde(default)]
    pub block_weight_limit: u64,
    /// `KV_SERIALIZE_OPT(0)` — absent when zero.
    #[serde(default)]
    pub block_weight_median: u64,
    #[serde(default)]
    pub adjusted_time: u64,
    pub start_time: u64,
    #[serde(default)]
    pub free_space: u64,
    #[serde(default)]
    pub offline: bool,
    /// Gone from monerod master: `a01b4c2a3`, "daemon: remove bootstrap mode"
    /// (2026-05-31), took this and the two below with it. Kept so that a
    /// release-v0.18 daemon's response is still described here, defaulted so
    /// that a master daemon's is too.
    #[serde(default)]
    pub bootstrap_daemon_address: String,
    #[serde(default)]
    pub height_without_bootstrap: u64,
    #[serde(default)]
    pub was_bootstrap_ever_used: bool,
    #[serde(default)]
    pub database_size: u64,
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub busy_syncing: bool,
    pub version: String,
    #[serde(default)]
    pub synchronized: bool,
    /// True when the daemon is running `--restricted-rpc`, which means several
    /// fields above are falsified.
    pub restricted: bool,

    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

impl GetInfo {
    /// Network difficulty, with the high 64 bits folded back in.
    #[must_use]
    pub const fn difficulty(&self) -> u128 {
        reassemble_u128(self.difficulty, self.difficulty_top64)
    }

    #[must_use]
    pub const fn cumulative_difficulty(&self) -> u128 {
        reassemble_u128(self.cumulative_difficulty, self.cumulative_difficulty_top64)
    }
}

// ---------------------------------------------------------------------------
// Block headers
// ---------------------------------------------------------------------------

/// The `block_header` object, shared by five calls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_hash: String,
    pub nonce: u32,
    pub orphan_status: bool,
    pub height: u64,
    /// `current_height - height - 1`, so 0 for the tip.
    pub depth: u64,
    pub hash: String,
    pub difficulty: u64,
    pub difficulty_top64: u64,
    pub wide_difficulty: String,
    pub cumulative_difficulty: u64,
    pub cumulative_difficulty_top64: u64,
    pub wide_cumulative_difficulty: String,
    /// Sum of the miner transaction's outputs.
    pub reward: u64,
    pub block_size: u64,
    /// `KV_SERIALIZE_OPT(0)` — **absent** when zero, which is exactly what an
    /// all-default header looks like. Always equals `block_size` when present.
    #[serde(default)]
    pub block_weight: u64,
    pub num_txes: u64,
    /// `""` unless `fill_pow_hash` was requested *and* the daemon is
    /// unrestricted. Present either way.
    pub pow_hash: String,
    /// `KV_SERIALIZE_OPT(0)` — absent when zero.
    #[serde(default)]
    pub long_term_weight: u64,
    pub miner_tx_hash: String,
}

impl BlockHeader {
    #[must_use]
    pub const fn difficulty(&self) -> u128 {
        reassemble_u128(self.difficulty, self.difficulty_top64)
    }

    #[must_use]
    pub const fn cumulative_difficulty(&self) -> u128 {
        reassemble_u128(self.cumulative_difficulty, self.cumulative_difficulty_top64)
    }
}

/// `get_block_header_by_height`, `get_last_block_header`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetBlockHeader {
    pub block_header: BlockHeader,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetBlockHeadersRange {
    #[serde(default)]
    pub headers: Vec<BlockHeader>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

/// `get_block_count`. Derives from the plain response base: **no** `credits`,
/// **no** `top_hash`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetBlockCount {
    pub count: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
}

// ---------------------------------------------------------------------------
// get_block
// ---------------------------------------------------------------------------

/// `get_block`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetBlock {
    pub block_header: BlockHeader,
    pub miner_tx_hash: String,
    /// Absent for a block with no user transactions, not empty.
    #[serde(default)]
    pub tx_hashes: Vec<String>,
    /// Hex of the whole serialized block.
    pub blob: String,
    /// A JSON **document encoded as a string**. Parse with
    /// [`GetBlock::parse_json`], never by treating it as an object.
    pub json: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

impl GetBlock {
    /// Parse the nested `json` string.
    ///
    /// Errors rather than panicking on the empty string, which monerod does
    /// emit — `obj_to_json_str` returns `""` on serialization failure.
    pub fn parse_json(&self) -> Result<BlockJson, NestedJsonError> {
        parse_nested_json(&self.json)
    }

    /// Parse only the curve-tree fields of the nested `json` string.
    ///
    /// [`GetBlock::parse_json`] builds the whole block, miner transaction and
    /// every transaction hash included, which is a lot to build for two
    /// scalars. This walks past the rest without keeping it.
    pub fn parse_tree(&self) -> Result<BlockTreeJson, NestedJsonError> {
        parse_nested_json(&self.json)
    }
}

/// The curve-tree fields of [`BlockJson`], and nothing else. See
/// [`BlockJson::fcmp_pp_tree_root`] for what they mean.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct BlockTreeJson {
    #[serde(default)]
    pub fcmp_pp_n_tree_layers: Option<u8>,
    #[serde(default)]
    pub fcmp_pp_tree_root: Option<String>,
}

/// The decoded contents of [`GetBlock::json`].
///
/// This is the *inner* serializer's view of a block, so the names differ from
/// the outer [`BlockHeader`]: `prev_id` here is `prev_hash` there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockJson {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_id: String,
    pub nonce: u32,
    pub miner_tx: TxJson,
    /// Present and empty (`[ ]`) for a coinbase-only block — the inner
    /// serializer keeps empty arrays, unlike epee.
    #[serde(default)]
    pub tx_hashes: Vec<String>,
    /// From hard fork 17 only; absent below it, because the block format
    /// itself gains the field at the fork. The curve tree's layer count, which
    /// with the root below lets a light client check an FCMP++ proof without
    /// the tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fcmp_pp_n_tree_layers: Option<u8>,
    /// From hard fork 17 only. The root of the curve tree this block commits
    /// to, hex. An output joins the tree when it unlocks rather than when it
    /// is mined, so the root does not cover the outputs of this block itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fcmp_pp_tree_root: Option<String>,
}

// ---------------------------------------------------------------------------
// get_fee_estimate, get_alternate_chains
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fee: u64,
    /// Absent when it equals **1**, not when it equals 0.
    #[serde(default = "default_quantization_mask")]
    pub quantization_mask: u64,
    /// Absent entirely on a daemon below the 2021-scaling hard fork, and
    /// absent when empty in any case. Index 0 equals `fee` when present.
    #[serde(default)]
    pub fees: Vec<u64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

/// The hard fork that widens a wallet's fee estimate to 1000 grace blocks
/// (monerod's `HF_VERSION_2026_SCALING`).
pub const HF_VERSION_2026_SCALING: u8 = 17;

/// The grace window wallet2 asks a fee estimate for at hard fork `hf`, its
/// `FEE_ESTIMATE_GRACE_BLOCKS_2021` and `_2026`. Another window gives another
/// fee from the one wallets pay, and monerod logs it as a possible wallet
/// fingerprint.
#[must_use]
pub const fn wallet_grace_blocks(hf: u8) -> u64 {
    if hf >= HF_VERSION_2026_SCALING {
        1000
    } else {
        10
    }
}

/// The widest grace window the daemon is asked for. monerod loops once per
/// grace block with its chain lock held, so a window of `u64::MAX` stops the
/// node.
pub const MAX_GRACE_BLOCKS: u64 = 1000;

/// One alternative chain. `difficulty` here is the **cumulative** difficulty of
/// the alt chain's tip, not the per-block difficulty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainInfo {
    pub block_hash: String,
    /// Height of the chain's tip, the block `block_hash` names. Its first
    /// block is `length - 1` below.
    pub height: u64,
    /// Number of blocks in the chain.
    pub length: u64,
    pub difficulty: u64,
    pub difficulty_top64: u64,
    pub wide_difficulty: String,
    #[serde(default)]
    pub block_hashes: Vec<String>,
    pub main_chain_parent_block: String,
}

impl ChainInfo {
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> u128 {
        reassemble_u128(self.difficulty, self.difficulty_top64)
    }
}

/// `get_alternate_chains`. Restricted daemons do not expose this method at all;
/// it comes back as [`error_code::METHOD_NOT_FOUND`]. No `credits`/`top_hash`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetAlternateChains {
    #[serde(default)]
    pub chains: Vec<ChainInfo>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
}

// ---------------------------------------------------------------------------
// get_txids_loose
// ---------------------------------------------------------------------------

/// `get_txids_loose` request: every transaction id matching a template in its
/// low `num_matching_bits` bits.
///
/// This is what makes a k-anonymous transaction lookup possible without
/// reading the database: the caller supplies a partial id and the daemon
/// returns everything that matches, so nobody learns which one was wanted.
///
/// **Not present in any released monerod.** It is in `master` and
/// `release-v0.19`; v0.18.5.1 answers `Method not found`. Probe for it rather
/// than assuming, and degrade when it is absent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetTxidsLooseRequest {
    /// A full-width hash with the searched suffix in place and zeros above it.
    txid_template: String,
    /// How many low bits of the template must match. monerod rejects more than
    /// 256, and rejects a value so low that the expected result set exceeds
    /// its own cap.
    num_matching_bits: u32,
}

impl GetTxidsLooseRequest {
    /// Build a request from a **whole number of bytes** of hex suffix.
    ///
    /// monerod matches on bits but the template is parsed as a hash, so only
    /// whole bytes can be expressed. An odd-length hex suffix must be widened
    /// by the caller and the surplus filtered afterwards.
    ///
    /// Returns `None` if the suffix is not even-length lowercase hex of at
    /// most 64 characters.
    #[must_use]
    pub fn from_hex_suffix(suffix: &str) -> Option<Self> {
        if suffix.is_empty()
            || !suffix.len().is_multiple_of(2)
            || suffix.len() > 64
            || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let suffix = suffix.to_ascii_lowercase();
        let mut template = "0".repeat(64 - suffix.len());
        template.push_str(&suffix);
        // Bounded by the length check above, so this cannot truncate.
        let bits = u32::try_from(suffix.len()).ok()?.saturating_mul(4);
        Some(Self {
            txid_template: template,
            num_matching_bits: bits,
        })
    }

    #[must_use]
    pub fn template(&self) -> &str {
        &self.txid_template
    }

    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.num_matching_bits
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetTxidsLooseResponse {
    #[serde(default)]
    pub txids: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

// ---------------------------------------------------------------------------
// /get_height
// ---------------------------------------------------------------------------

/// `/get_height`. No `credits`/`top_hash`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetHeight {
    /// Blockchain height, i.e. top block height + 1.
    pub height: u64,
    /// Top block hash.
    pub hash: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
}

// ---------------------------------------------------------------------------
// /get_transactions
// ---------------------------------------------------------------------------

/// `/get_transactions` response.
///
/// `status` can be `"Failed"` **while `txs` is non-empty**: monerod sets the
/// status mid-loop and returns the partially populated array. Nothing about the
/// shape of this struct implies the array is trustworthy — check the status
/// first. [`crate::Client`] does that centrally for calls made through it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    /// Absent when every requested hash was missed — even though `status` is
    /// still `"OK"` in that case.
    #[serde(default)]
    pub txs: Vec<TxEntry>,
    /// Absent when nothing was missed. This, not `status`, is how you learn a
    /// transaction was not found.
    #[serde(default)]
    pub missed_tx: Vec<String>,
    /// Legacy mirror of each entry's `as_hex`, so it is `[""]`-shaped whenever
    /// the split form was used. Prefer [`TxEntry::raw_hex`].
    #[serde(default)]
    pub txs_as_hex: Vec<String>,
    /// Absent unless `decode_as_json` was requested.
    #[serde(default)]
    pub txs_as_json: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

impl GetTransactionsResponse {
    /// Whether `status` is exactly `"OK"`.
    ///
    /// Exists because `txs` is only meaningful when it is. A response decoded
    /// outside [`crate::Client`] — a replayed fixture, a cached body — has not
    /// been through the central status check.
    #[must_use]
    pub fn status_is_ok(&self) -> bool {
        self.status == "OK"
    }
}

/// One transaction in a `/get_transactions` response.
///
/// Which of the trailing fields are populated depends on `in_pool`: a confirmed
/// transaction carries `block_height`/`confirmations`/`block_timestamp`/
/// `output_indices`, a mempool one carries `relayed`/`received_timestamp`, and
/// the other set is absent rather than zeroed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxEntry {
    pub tx_hash: String,
    /// The whole blob as hex — **or `""`**. monerod switches to the split form
    /// whenever `split` or `prune` was requested *or* the prunable blob is
    /// empty, and on every released 0.18.x daemon a coinbase's prunable blob is
    /// always empty. So this is empty for every coinbase on the chain, pruned
    /// node or not. Never use its emptiness as a pruning test.
    #[serde(default)]
    pub as_hex: String,
    /// The transaction prefix plus, for v2, the RingCT base.
    #[serde(default)]
    pub pruned_as_hex: String,
    /// The prunable half. Empty when the daemon no longer holds it, when
    /// `prune: true` was requested, or when there is genuinely nothing to prune
    /// (a coinbase).
    #[serde(default)]
    pub prunable_as_hex: String,
    /// All-zero for any v1 transaction and the keccak of the empty string for a
    /// v2 coinbase. Never pruned, so never a pruning signal.
    #[serde(default)]
    pub prunable_hash: String,
    /// A JSON **document encoded as a string**, or `""`. Parse with
    /// [`TxEntry::parse_json`].
    #[serde(default)]
    pub as_json: String,
    pub in_pool: bool,
    #[serde(default)]
    pub double_spend_seen: bool,

    // Present only when `in_pool` is false.
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub block_timestamp: u64,
    #[serde(default)]
    pub output_indices: Vec<u64>,
    /// One per output, like `output_indices`, from a daemon built with FCMP++.
    /// The output's index among every output on the chain, whatever its
    /// amount, where `output_indices` counts within one denomination. It is
    /// not the output's leaf in the curve tree: outputs join the tree in the
    /// order they unlock. Absent from an older daemon, and absent (not empty)
    /// whenever `output_indices` is.
    #[serde(default)]
    pub unified_ids: Vec<u64>,

    // Present only when `in_pool` is true.
    #[serde(default)]
    pub relayed: bool,
    #[serde(default)]
    pub received_timestamp: u64,
}

impl TxEntry {
    /// The unified ids, one per output, or `None` when there is not exactly
    /// one per output. They are matched to outputs by position, so a list of
    /// any other length cannot say which output an id belongs to.
    #[must_use]
    pub fn unified_ids_per_output(&self, outputs: usize) -> Option<&[u64]> {
        (outputs > 0 && self.unified_ids.len() == outputs).then_some(self.unified_ids.as_slice())
    }

    /// Parse the nested `as_json` string.
    ///
    /// `as_json` is `""` on every request that did not set `decode_as_json`,
    /// and also whenever monerod's own serializer failed — so the empty case is
    /// routine, not exceptional, and gets its own error variant.
    pub fn parse_json(&self) -> Result<TxJson, NestedJsonError> {
        parse_nested_json(&self.as_json)
    }

    /// Whatever raw hex monerod gave us, reassembled.
    ///
    /// Returns `None` when neither form was populated. Note this is *not*
    /// necessarily the complete blob: when the daemon has pruned the
    /// transaction, only the pruned prefix exists. Ask
    /// [`TxEntry::prunable_missing`] before presenting it as the full blob.
    #[must_use]
    pub fn raw_hex(&self) -> Option<String> {
        if !self.as_hex.is_empty() {
            return Some(self.as_hex.clone());
        }
        if self.pruned_as_hex.is_empty() {
            return None;
        }
        Some(format!("{}{}", self.pruned_as_hex, self.prunable_as_hex))
    }

    /// The length of [`Self::raw_hex`], without assembling it.
    #[must_use]
    pub fn raw_hex_len(&self) -> Option<usize> {
        if !self.as_hex.is_empty() {
            return Some(self.as_hex.len());
        }
        if self.pruned_as_hex.is_empty() {
            return None;
        }
        Some(self.pruned_as_hex.len() + self.prunable_as_hex.len())
    }

    /// Whether *this node* no longer holds the transaction's prunable half.
    ///
    /// The pruned encoding is not request-driven: monerod decides with
    /// `pruned = prunable_blob.empty()`, so a pruned daemon returns pruned
    /// transactions even when `prune: false` was sent, and a single response
    /// can mix pruned and complete entries. That is why this is a per-entry
    /// question and not a per-request one.
    ///
    /// Two carve-outs, both structural rather than heuristic: a coinbase has no
    /// prunable half to lose, and v1 transactions are never pruned by the
    /// database at all.
    #[must_use]
    pub fn prunable_missing(&self, decoded: &TxJson) -> bool {
        // Non-split form: everything is in as_hex, so nothing was withheld.
        if !self.as_hex.is_empty() {
            return false;
        }
        if !self.prunable_as_hex.is_empty() {
            return false;
        }
        if decoded.is_coinbase() {
            return false;
        }
        if decoded.version <= 1 {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// /get_transaction_pool
// ---------------------------------------------------------------------------

/// `/get_transaction_pool`.
///
/// An empty pool returns `{"credits":0,"status":"OK","top_hash":"","untrusted":false}`
/// — both arrays are absent, not empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetTransactionPool {
    #[serde(default)]
    pub transactions: Vec<PoolTxInfo>,
    #[serde(default)]
    pub spent_key_images: Vec<SpentKeyImageInfo>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolTxInfo {
    pub id_hash: String,
    /// Same encoding as [`TxEntry::as_json`]: a JSON document as a string.
    #[serde(default)]
    pub tx_json: String,
    pub blob_size: u64,
    /// `KV_SERIALIZE_OPT(0)` — absent when zero.
    #[serde(default)]
    pub weight: u64,
    pub fee: u64,
    pub max_used_block_id_hash: String,
    pub max_used_block_height: u64,
    pub kept_by_block: bool,
    pub last_failed_height: u64,
    pub last_failed_id_hash: String,
    pub receive_time: u64,
    pub relayed: bool,
    pub last_relayed_time: u64,
    pub do_not_relay: bool,
    pub double_spend_seen: bool,
    /// Hex.
    pub tx_blob: String,
}

impl PoolTxInfo {
    /// Parse the nested `tx_json` string.
    pub fn parse_json(&self) -> Result<TxJson, NestedJsonError> {
        parse_nested_json(&self.tx_json)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpentKeyImageInfo {
    /// The key image itself, despite the name.
    pub id_hash: String,
    #[serde(default)]
    pub txs_hashes: Vec<String>,
}

/// `/get_transaction_pool_stats` result.
///
/// The pool's aggregate figures without the pool itself. `/api/networkinfo`
/// needs exactly one number from the pool -- its total size in bytes -- and
/// asking for the pool in order to add it up ships every transaction's blob
/// and decoded JSON to get there. Measured on a 12-transaction testnet pool:
/// 187,092 bytes against 868, and the totals agree exactly. On a busy node the
/// pool is the most expensive thing monerod will hand out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GetTransactionPoolStats {
    #[serde(default)]
    pub pool_stats: PoolStats,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

/// The aggregate figures themselves.
///
/// Only the two fields this explorer reads are named; monerod sends a dozen
/// more -- fee and size histograms, double-spend and failing counts -- and
/// serde ignores them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PoolStats {
    /// Sum of every pool transaction's `blob_size`. The JSON API publishes it
    /// as `tx_pool_size_kbytes`, which is a byte count despite the name.
    #[serde(default)]
    pub bytes_total: u64,
    #[serde(default)]
    pub txs_total: u64,
}

// ---------------------------------------------------------------------------
// /get_outs
// ---------------------------------------------------------------------------

/// One entry of a `/get_outs` request: an output identified by *both* its
/// amount and its index.
///
/// The fields are private on purpose. For a pre-RingCT input the cumulative
/// key-offset sum indexes the output set **for that denomination**; only for
/// RingCT (amount 0) is it a global index. An entry built with the amount left
/// at its default therefore asks monerod about a completely different output
/// and gets a plausible-looking answer back, which is the easiest way to render
/// silently wrong ring data. The only ways to make one are the two named
/// constructors below and [`TxInToKey::ring_members`], which carries the
/// input's own amount through.
///
/// Deliberately `Serialize` only. Deriving `Deserialize` would reopen the hole
/// the private fields close: `{"amount":0,"index":4732}` would parse straight
/// into the pre-RingCT-index-without-its-amount object this type exists to
/// prevent. Nothing ever deserializes a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OutKeyRequest {
    amount: u64,
    index: u64,
}

impl OutKeyRequest {
    /// A RingCT output. `amount` is 0 by construction and `index` is the global
    /// RingCT output index.
    #[must_use]
    pub const fn ringct(index: u64) -> Self {
        Self { amount: 0, index }
    }

    /// A pre-RingCT output. `index` is an index into the output set for this
    /// exact `amount`, not a global one.
    #[must_use]
    pub const fn pre_ringct(amount: u64, index: u64) -> Self {
        Self { amount, index }
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    #[must_use]
    pub const fn is_ringct(&self) -> bool {
        self.amount == 0
    }
}

/// `/get_outs` request.
///
/// `get_txid` has no serde default and no `Default` impl on the struct, so it
/// cannot be forgotten: the JSON endpoint declares it as a plain field whose
/// omission means **false**, the opposite of `/get_outs.bin` where omission
/// means true.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetOutsRequest {
    pub outputs: Vec<OutKeyRequest>,
    pub get_txid: bool,
}

impl GetOutsRequest {
    #[must_use]
    pub const fn new(outputs: Vec<OutKeyRequest>, get_txid: bool) -> Self {
        Self { outputs, get_txid }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetOutsResponse {
    #[serde(default)]
    pub outs: Vec<OutKey>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutKey {
    /// One-time public key.
    pub key: String,
    /// Pedersen commitment; for a pre-RingCT output, a commitment to the known
    /// amount.
    pub mask: String,
    pub unlocked: bool,
    /// Height of the block the output was created in.
    pub height: u64,
    /// Present but **empty** when `get_txid` was false — not absent.
    #[serde(default)]
    pub txid: String,
}

// ---------------------------------------------------------------------------
// /get_path_by_unified_id.bin
// ---------------------------------------------------------------------------

/// How many outputs the curve tree held as of a block: the size of an FCMP++
/// transaction's anonymity set, when asked for its reference block.
///
/// monerod reports the figure as `n_leaf_tuples`, and only in binary: from
/// `/get_path_by_unified_id.bin`, and from `/getblocks.bin` when asked to
/// start a tree sync, beside a batch of whole blocks. The first is the cheap
/// one. It exists to hand a wallet the tree paths of its own outputs, and it
/// answers the tree size beside them. It answers 0 when asked about no
/// outputs at all, so it has to be asked about one.
///
/// The one asked about is the **probe**, and choosing it well keeps the call
/// cheap and safe. For an output that joins the tree only after the block
/// asked about, monerod skips the leaf search and the path read, so the call
/// cannot fail on a missing leaf. Every output of the transaction being looked
/// at is such an output: it was created in a block after the reference block,
/// and an output joins the tree only when it unlocks, some blocks after that.
/// So the probe is the transaction's own first output, by its unified id.
///
/// What the call still costs the daemon, whatever the probe: reading the
/// probe transaction's output data, and the tree's size and last path as of
/// the block asked about. A few database reads, not a scan.
///
/// The fields are private so that the one-block offset cannot be dropped:
/// monerod takes a block *count*, and treats a count of 0 as "now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeSizeQuery {
    as_of_n_blocks: u64,
    probe: [u64; 1],
}

impl TreeSizeQuery {
    pub const ENDPOINT: &'static str = "get_path_by_unified_id.bin";

    /// The largest answer accepted.
    ///
    /// The answer is 115 bytes when the probe is not yet in the tree and about
    /// 3 KB when it is, with a path that grows by one chunk per tree layer,
    /// and monerod caps the tree at 12 layers.
    pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

    /// The root entries [`Self::answer`] reads. Everything else in the answer,
    /// the paths included, is walked past without being kept.
    pub const WANTED: &'static [&'static str] = &["n_leaf_tuples"];

    /// The tree as of `reference_block`, probed with `probe_unified_id`.
    ///
    /// `None` only for a reference block of `u64::MAX`, which has no count.
    #[must_use]
    pub fn as_of_block(reference_block: u64, probe_unified_id: u64) -> Option<Self> {
        Some(Self {
            as_of_n_blocks: reference_block.checked_add(1)?,
            probe: [probe_unified_id],
        })
    }

    #[must_use]
    pub fn fields(&self) -> [(&'static str, crate::epee::Field<'_>); 2] {
        [
            (
                "as_of_n_blocks",
                crate::epee::Field::U64(self.as_of_n_blocks),
            ),
            ("unified_ids", crate::epee::Field::U64s(&self.probe)),
        ]
    }

    /// The tree size from the daemon's answer. `None` when the answer does
    /// not carry one, and for 0: a tree that an FCMP++ proof was built against
    /// holds at least the output being spent, so 0 is the daemon's answer to
    /// a question other than the one asked.
    #[must_use]
    pub fn answer(root: &crate::epee::Root) -> Option<u64> {
        root.unsigned("n_leaf_tuples").filter(|n| *n > 0)
    }
}

/// Outputs' paths through the curve tree, from the same endpoint as
/// [`TreeSizeQuery`], as of one block.
///
/// A path is what a wallet needs to prove it spends one of the tree's leaves
/// without saying which: the group of up to [`SELENE_CHUNK_WIDTH`] leaves
/// holding the output, then at each layer above the whole group holding that
/// layer's ancestor of the output, up to the root. Each parent is a hash of
/// its whole group, so every member of the group is needed to recompute it,
/// not one sibling as in a binary tree.
///
/// A path belongs to one state of the tree. Outputs join the tree at its
/// right edge, which changes the last group of every layer, so a path taken
/// as of another block can differ from this one in those groups.
///
/// monerod answers every id it is asked about, in order: with an empty path
/// for an output not yet in the tree as of the block asked about, because it
/// has not unlocked, and with an error for an id it does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathQuery {
    as_of_n_blocks: u64,
    unified_ids: Vec<u64>,
}

impl PathQuery {
    pub const ENDPOINT: &'static str = TreeSizeQuery::ENDPOINT;

    /// The most ids one call asks about: `MAX_RESTRICTED_PATHS_COUNT` in
    /// `src/rpc/core_rpc_server.cpp`, which a public node enforces.
    pub const MAX_IDS: usize = 50;

    /// The largest answer accepted: [`Self::MAX_IDS`] paths through a tree of
    /// monerod's most layers, 12, with every group full, is about 700 KB.
    pub const MAX_ANSWER_BYTES: u64 = 1024 * 1024;

    pub const WANTED: &'static [&'static str] = &["n_leaf_tuples", "paths"];

    /// The paths of `unified_ids` as of block `as_of_block`.
    ///
    /// `None` for no ids, for more than [`Self::MAX_IDS`], and for a block of
    /// `u64::MAX`, which has no count.
    #[must_use]
    pub fn as_of_block(as_of_block: u64, unified_ids: &[u64]) -> Option<Self> {
        if unified_ids.is_empty() || unified_ids.len() > Self::MAX_IDS {
            return None;
        }
        Some(Self {
            as_of_n_blocks: as_of_block.checked_add(1)?,
            unified_ids: unified_ids.to_vec(),
        })
    }

    #[must_use]
    pub fn fields(&self) -> [(&'static str, crate::epee::Field<'_>); 2] {
        [
            (
                "as_of_n_blocks",
                crate::epee::Field::U64(self.as_of_n_blocks),
            ),
            ("unified_ids", crate::epee::Field::U64s(&self.unified_ids)),
        ]
    }

    /// The paths from the daemon's answer, one per id asked about, in order.
    pub fn answer(&self, root: &crate::epee::Root) -> Result<TreePaths, PathAnswerError> {
        let n_leaf_tuples = root
            .unsigned("n_leaf_tuples")
            .ok_or(PathAnswerError::Missing("n_leaf_tuples"))?;
        let entries = root
            .array("paths")
            .ok_or(PathAnswerError::Missing("paths"))?;
        if entries.len() != self.unified_ids.len() {
            return Err(PathAnswerError::Count {
                asked: self.unified_ids.len(),
                answered: entries.len(),
            });
        }
        let paths = entries
            .iter()
            .map(TreePath::read)
            .collect::<Result<_, _>>()?;
        Ok(TreePaths {
            n_leaf_tuples,
            paths,
        })
    }
}

/// Why an answer to a [`PathQuery`] cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathAnswerError {
    #[error("the answer has no {0}")]
    Missing(&'static str),
    #[error("{answered} paths answer {asked} ids")]
    Count { asked: usize, answered: usize },
    #[error("a path's {0} is malformed")]
    Malformed(&'static str),
}

/// The answer to a [`PathQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePaths {
    /// Leaves in the tree as of the block asked about.
    pub n_leaf_tuples: u64,
    /// One per id asked about, in order: `None` for an output not in the tree
    /// as of that block.
    pub paths: Vec<Option<TreePath>>,
}

/// One output's path. See [`PathQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePath {
    /// The output's position among the tree's leaves.
    pub leaf_idx: u64,
    /// The group of leaves holding the output, in the tree's order.
    pub leaves: Vec<PathLeaf>,
    /// From the leaves' parents up: at each layer the group holding the
    /// output's ancestor, as compressed points. The last is the root alone.
    /// The layers alternate curves, Selene first.
    pub layers: Vec<Vec<[u8; 32]>>,
}

/// A leaf of the tree as a path carries it: the output as it is on chain,
/// before the tree derives its leaf values from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLeaf {
    pub unified_id: u64,
    pub kind: LeafKind,
    /// The output's one-time key `O`, as on chain.
    pub output_key: [u8; 32],
    /// The output's amount commitment `C`, as on chain.
    pub commitment: [u8; 32],
}

/// How the tree derives a leaf from an output: `OutputPairType` in
/// `src/fcmp_pp/fcmp_pp_types.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// An output from before Carrot. Its key and commitment may carry torsion,
    /// which the tree clears, and its key image generator is the older,
    /// biased hash of its key.
    Legacy,
    /// A Carrot output, checked for torsion when it was mined, whose key image
    /// generator is the unbiased hash of its key.
    Carrot,
    /// A type this build does not know.
    Other(u8),
}

impl LeafKind {
    const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Legacy,
            1 => Self::Carrot,
            other => Self::Other(other),
        }
    }
}

impl TreePath {
    /// One entry of the answer's `paths`. Whether its leaf is the output
    /// asked about is left to the check of the whole path.
    fn read(entry: &crate::epee::Value) -> Result<Option<Self>, PathAnswerError> {
        use crate::epee::Value;
        let Value::Section(entry) = entry else {
            return Err(PathAnswerError::Malformed("entry"));
        };
        let path = entry
            .section("path")
            .ok_or(PathAnswerError::Malformed("entry"))?;
        let leaves = path
            .section("leaves")
            .ok_or(PathAnswerError::Malformed("leaves"))?;
        // epee leaves an empty blob or list out, so an output with no path
        // arrives as a path with empty leaves and no layers.
        let blob = |name| leaves.bytes(name).unwrap_or_default();
        let ids = blob("unified_ids");
        let kinds = blob("output_types");
        let keys = blob("output_pubkeys");
        let commitments = blob("commitments");
        let n = kinds.len();
        if ids.len() != n * 8 || keys.len() != n * 32 || commitments.len() != n * 32 {
            return Err(PathAnswerError::Malformed("leaves"));
        }
        let chunks = path.array("layer_chunks").unwrap_or_default();
        if n == 0 {
            return if chunks.is_empty() {
                Ok(None)
            } else {
                Err(PathAnswerError::Malformed("leaves"))
            };
        }
        // The lengths were checked above, so the chunks leave no remainder.
        let leaves = ids
            .as_chunks::<8>()
            .0
            .iter()
            .zip(kinds)
            .zip(
                keys.as_chunks::<32>()
                    .0
                    .iter()
                    .zip(commitments.as_chunks::<32>().0),
            )
            .map(|((id, &kind), (key, commitment))| PathLeaf {
                unified_id: u64::from_le_bytes(*id),
                kind: LeafKind::from_byte(kind),
                output_key: *key,
                commitment: *commitment,
            })
            .collect::<Vec<_>>();
        let layers = chunks
            .iter()
            .map(|chunk| {
                let elems = match chunk {
                    Value::Section(c) => c.bytes("elems").unwrap_or_default(),
                    _ => return Err(PathAnswerError::Malformed("layer_chunks")),
                };
                let (points, rest) = elems.as_chunks::<32>();
                if points.is_empty() || !rest.is_empty() {
                    return Err(PathAnswerError::Malformed("layer_chunks"));
                }
                Ok(points.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if layers.is_empty() {
            return Err(PathAnswerError::Malformed("layer_chunks"));
        }
        Ok(Some(Self {
            leaf_idx: entry
                .unsigned("leaf_idx")
                .ok_or(PathAnswerError::Malformed("entry"))?,
            leaves,
            layers,
        }))
    }
}

// ---------------------------------------------------------------------------
// /is_key_image_spent
// ---------------------------------------------------------------------------

/// A key image that monerod would accept and answer wrongly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("key image {index} is not {KEY_IMAGE_HEX_LEN} hex characters: {value:?}")]
pub struct InvalidKeyImage {
    pub index: usize,
    pub value: String,
}

/// Hex width of a key image.
pub const KEY_IMAGE_HEX_LEN: usize = 64;

/// `/is_key_image_spent` request.
///
/// The field is private because this is the one endpoint where a malformed
/// argument does not produce an error: monerod's length check sets a status and
/// then *forgets to return*, so a short key image is reinterpreted over a short
/// buffer, the status is overwritten with `"OK"` further down, and a confident
/// `spent_status` comes back for an image that was never asked about. Nothing
/// downstream can detect that, so the check has to happen here.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IsKeyImageSpentRequest {
    key_images: Vec<String>,
}

impl IsKeyImageSpentRequest {
    /// Reject anything that is not exactly 64 hex characters.
    pub fn new(key_images: Vec<String>) -> Result<Self, InvalidKeyImage> {
        for (index, ki) in key_images.iter().enumerate() {
            if ki.len() != KEY_IMAGE_HEX_LEN || !ki.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InvalidKeyImage {
                    index,
                    value: ki.clone(),
                });
            }
        }
        Ok(Self { key_images })
    }

    #[must_use]
    pub fn key_images(&self) -> &[String] {
        &self.key_images
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IsKeyImageSpentResponse {
    /// Positionally matched to the request. `std::vector<int>` in C++, hence
    /// signed.
    #[serde(default)]
    pub spent_status: Vec<i32>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentStatus {
    Unspent,
    SpentInBlockchain,
    SpentInPool,
    /// A value this daemon knows about and we do not. Never treat it as
    /// unspent.
    Unknown(i32),
}

impl SpentStatus {
    #[must_use]
    pub const fn from_raw(raw: i32) -> Self {
        match raw {
            0 => Self::Unspent,
            1 => Self::SpentInBlockchain,
            2 => Self::SpentInPool,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn is_spent(&self) -> bool {
        matches!(self, Self::SpentInBlockchain | Self::SpentInPool)
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// `get_block` request.
///
/// Fields are private so that exactly one selector is set. monerod prefers
/// `hash` over `height` without saying so, and accepts *neither* being set by
/// silently returning the genesis block.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetBlockRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    fill_pow_hash: bool,
}

impl GetBlockRequest {
    #[must_use]
    pub const fn by_height(height: u64) -> Self {
        Self {
            hash: None,
            height: Some(height),
            fill_pow_hash: false,
        }
    }

    #[must_use]
    pub fn by_hash(hash: impl Into<String>) -> Self {
        Self {
            hash: Some(hash.into()),
            height: None,
            fill_pow_hash: false,
        }
    }

    /// Ask for `pow_hash` as well. Silently ignored by a restricted daemon,
    /// which returns `""` regardless.
    #[must_use]
    pub fn fill_pow_hash(mut self, yes: bool) -> Self {
        self.fill_pow_hash = yes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetBlockHeadersRangeRequest {
    pub start_height: u64,
    pub end_height: u64,
    pub fill_pow_hash: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetFeeEstimateRequest {
    pub grace_blocks: u64,
}

/// `/get_transactions` request.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetTransactionsRequest {
    txs_hashes: Vec<String>,
    decode_as_json: bool,
    /// Always false, and unreachable from outside this module.
    ///
    /// `prune: true` forces the pruned encoding even when the daemon holds the
    /// data, and suppresses `prunable_as_hex` unconditionally. That destroys
    /// the only signal distinguishing "this node pruned it" from "you asked for
    /// it pruned", which would make [`TxEntry::prunable_missing`] answer a
    /// different question than the one it documents.
    ///
    /// This was a public field carrying a "do not set this" comment. A comment
    /// is not an invariant: a caller could set it and silently get every v2
    /// transaction reported as pruned. Keeping the field private makes
    /// `prunable_missing`'s precondition hold by construction.
    prune: bool,
    /// Ask for the prefix and prunable halves separately. Worth setting
    /// unconditionally: it is forced anyway whenever the prunable blob is
    /// empty, so asking for it gives one response shape on every daemon.
    split: bool,
}

impl GetTransactionsRequest {
    /// The shape oxblocks should always use: decoded JSON, split halves, never
    /// pruned.
    ///
    /// There is no pruned variant on purpose. Asking for one would save a lot
    /// of bandwidth on the endpoints that answer with a set -- the prunable
    /// half is ~79% of a BulletproofPlus transaction -- but what comes back is
    /// then not the transaction that was broadcast, and its size is not the
    /// size anyone means. This explorer reports what a node holds, not a
    /// shortened copy of it.
    #[must_use]
    pub const fn decoded(txs_hashes: Vec<String>) -> Self {
        Self {
            txs_hashes,
            decode_as_json: true,
            prune: false,
            split: true,
        }
    }

    #[must_use]
    pub fn txs_hashes(&self) -> &[String] {
        &self.txs_hashes
    }

    #[must_use]
    pub const fn decode_as_json(&self) -> bool {
        self.decode_as_json
    }

    #[must_use]
    pub const fn split(&self) -> bool {
        self.split
    }

    /// Always `false`. Present so tests can assert the invariant rather than
    /// trusting it.
    #[must_use]
    pub const fn prune(&self) -> bool {
        self.prune
    }
}

// ---------------------------------------------------------------------------
// The nested transaction JSON
// ---------------------------------------------------------------------------

/// Why a nested JSON string could not be turned into a document.
#[derive(Debug, thiserror::Error)]
pub enum NestedJsonError {
    /// The string was empty. monerod leaves `as_json` empty on every request
    /// that did not ask for it, and `obj_to_json_str` returns `""` rather than
    /// partial output when its own serialization fails. Either way there is no
    /// document, and feeding `""` to a JSON parser only produces a confusing
    /// error.
    #[error("monerod returned no decoded JSON for this object")]
    Absent,
    #[error("monerod's decoded JSON did not parse: {0}")]
    Malformed(#[from] serde_json::Error),
}

fn parse_nested_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, NestedJsonError> {
    if raw.is_empty() {
        return Err(NestedJsonError::Absent);
    }
    Ok(serde_json::from_str(raw)?)
}

/// A decoded transaction, total across every era of the chain: v1 pre-RingCT
/// through BulletproofPlus and FCMP++, pruned and complete, coinbase and not.
///
/// Modelled as one flat struct with optional halves rather than as an untagged
/// enum. The variant is chosen by a *sibling scalar* (`version`, then `type`),
/// which serde's untagged representation cannot see; it would brute-force the
/// arms, buffer a 60 KB bulletproof transaction to do it, and report failure as
/// "data did not match any variant".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxJson {
    /// 1 (pre-RingCT) or 2 (RingCT). Kept as a `u64` rather than a `u8` so that
    /// a malformed document fails a check here rather than in the deserializer.
    pub version: u64,
    pub unlock_time: u64,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    /// An array of **byte integers**, not a hex string.
    pub extra: Vec<u8>,

    /// v1 only, one entry per input. Absent for v2, and absent for a v1
    /// transaction in pruned form — including every coinbase fetched with
    /// `split: true`, whose prunable blob is always empty. Present-and-empty
    /// (`[ ]`) for a coinbase fetched in the non-split form, so absent and
    /// empty are different facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<String>>,

    /// v2 only. `{"type": 0}` and nothing else for a coinbase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rct_signatures: Option<RctSigBase>,

    /// v2 only, and absent for a coinbase (type 0) **and** for any transaction
    /// whose prunable half this node no longer has. Do not infer "coinbase"
    /// from its absence — use [`TxJson::is_coinbase`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rctsig_prunable: Option<RctSigPrunable>,
}

impl TxJson {
    /// The canonical test: one input, and it is a `gen`.
    #[must_use]
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && matches!(self.vin.first(), Some(TxIn::Gen(_)))
    }

    #[must_use]
    pub fn is_v1(&self) -> bool {
        self.version <= 1
    }

    /// Whether this transaction spends with FCMP++ rather than with rings.
    ///
    /// Read from the RingCT type, not from empty `key_offsets`: a malformed
    /// ring-era input with no offsets is not an FCMP++ spend, and an FCMP++
    /// coinbase does not exist (a coinbase is type 0 in every era).
    #[must_use]
    pub fn is_fcmp_pp(&self) -> bool {
        self.rct_type() == Some(RctType::FcmpPlusPlus)
    }

    /// The FCMP++ reference block, or `None` for a ring-era transaction and
    /// for an FCMP++ one whose prunable half this node no longer holds: the
    /// field is in `rctsig_prunable`, so pruning takes it.
    #[must_use]
    pub fn reference_block(&self) -> Option<u64> {
        if !self.is_fcmp_pp() {
            return None;
        }
        self.rctsig_prunable.as_ref()?.reference_block
    }

    /// The curve tree's layer count the FCMP++ proof was built for. `None` in
    /// the same cases as [`TxJson::reference_block`].
    #[must_use]
    pub fn n_tree_layers(&self) -> Option<u8> {
        if !self.is_fcmp_pp() {
            return None;
        }
        self.rctsig_prunable.as_ref()?.n_tree_layers
    }

    /// The RingCT type, or `None` for a v1 transaction.
    ///
    /// Returning `None` rather than `RctType::Null` keeps "pre-RingCT" and "a
    /// v2 coinbase" distinguishable; both would otherwise read as type 0.
    #[must_use]
    pub fn rct_type(&self) -> Option<RctType> {
        self.rct_signatures
            .as_ref()
            .map(|r| RctType::from_raw(r.rct_type))
    }

    /// The pseudo-outputs, fetched from whichever object holds them for this
    /// transaction's RingCT type.
    ///
    /// They live in `rct_signatures` for type 2 and in `rctsig_prunable` for
    /// types 3 through 7, and do not exist at all for type 1. Looking in only
    /// one place silently yields nothing for half of the chain's history.
    #[must_use]
    pub fn pseudo_outs(&self) -> &[String] {
        const NONE: &[String] = &[];
        match self.rct_type() {
            Some(RctType::Simple) => self
                .rct_signatures
                .as_ref()
                .and_then(|b| b.pseudo_outs.as_deref())
                .unwrap_or(NONE),
            Some(
                RctType::Bulletproof
                | RctType::Bulletproof2
                | RctType::Clsag
                | RctType::BulletproofPlus
                | RctType::FcmpPlusPlus,
            ) => self
                .rctsig_prunable
                .as_ref()
                .and_then(|p| p.pseudo_outs.as_deref())
                .unwrap_or(NONE),
            // A scheme we do not know about. The `Unknown` arm exists so a
            // future type degrades instead of failing to parse, but answering
            // "there are none" when the document plainly carries some is a
            // wrong answer, not a degraded one. Look in both places.
            Some(RctType::Unknown(_)) => self
                .rctsig_prunable
                .as_ref()
                .and_then(|p| p.pseudo_outs.as_deref())
                .or_else(|| {
                    self.rct_signatures
                        .as_ref()
                        .and_then(|b| b.pseudo_outs.as_deref())
                })
                .unwrap_or(NONE),
            _ => NONE,
        }
    }

    /// The per-ring-member signatures for input `index` of a v1 transaction.
    ///
    /// `signatures[i]` is a *single string* holding that input's whole ring
    /// concatenated, 128 hex characters per member — not one array entry per
    /// member and not a nested array. Returns `None` when there are no
    /// signatures (v2, or the pruned form), when the input is not a key input,
    /// or when the entry's width does not match the input's ring size, which
    /// would mean the two arrays are not aligned.
    #[must_use]
    pub fn ring_signatures_for_input(&self, index: usize) -> Option<Vec<&str>> {
        let entry = self.signatures.as_ref()?.get(index)?;
        let input = match self.vin.get(index)? {
            TxIn::Key(k) => k,
            _ => return None,
        };
        let parts = split_ring_signatures(entry)?;
        (parts.len() == input.key_offsets.len()).then_some(parts)
    }

    /// Whether this document is the *pruned* form — monerod dropped the
    /// prunable half before encoding it.
    ///
    /// Carves out the two cases where the half is legitimately absent: a
    /// coinbase never has one, and a v1 transaction's `signatures` key is also
    /// dropped when `prune: true` was requested even though the database never
    /// prunes v1.
    ///
    /// This is the cross-check for when only `as_json` was kept;
    /// [`TxEntry::prunable_missing`] is the better answer when the entry is
    /// still to hand, because it can also see `prunable_as_hex`.
    #[must_use]
    pub fn looks_pruned(&self) -> bool {
        if self.is_coinbase() {
            return false;
        }
        if self.is_v1() {
            return self.signatures.is_none();
        }
        match self.rct_type() {
            // Type 0 on a non-coinbase is rejected by consensus in every era,
            // so this is a malformed document rather than a pruned one.
            None | Some(RctType::Null) => false,
            Some(_) => self.rctsig_prunable.is_none(),
        }
    }
}

/// Number of hex characters in one `crypto::signature`.
pub const RING_SIGNATURE_HEX_LEN: usize = 128;

/// Split one `signatures[i]` entry into its per-ring-member signatures.
///
/// Returns `None` if the entry is not a whole number of 128-character
/// signatures or contains a non-hex character — both of which mean the caller
/// would otherwise slice a string at an offset that means nothing.
#[must_use]
pub fn split_ring_signatures(entry: &str) -> Option<Vec<&str>> {
    if entry.is_empty() || !entry.len().is_multiple_of(RING_SIGNATURE_HEX_LEN) {
        return None;
    }
    if !entry.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Safe to chunk by bytes: the alphabet check above proves every byte is a
    // single-byte character, so no chunk can land mid-codepoint.
    entry
        .as_bytes()
        .chunks(RING_SIGNATURE_HEX_LEN)
        .map(|c| std::str::from_utf8(c).ok())
        .collect()
}

/// A transaction input.
///
/// monerod's variant encoding is `{"<tag>": <body>}`, which is exactly serde's
/// default externally-tagged representation. `script` and `scripthash` are dead
/// CryptoNote leftovers with zero chain occurrences; they are kept as raw
/// values so that an exotic historical blob parses rather than erroring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxIn {
    #[serde(rename = "gen")]
    Gen(TxInGen),
    #[serde(rename = "key")]
    Key(TxInToKey),
    #[serde(rename = "script")]
    Script(serde_json::Value),
    /// monerod's tag has no underscore.
    #[serde(rename = "scripthash")]
    ScriptHash(serde_json::Value),
}

impl TxIn {
    #[must_use]
    pub fn as_key(&self) -> Option<&TxInToKey> {
        match self {
            Self::Key(k) => Some(k),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_gen(&self) -> bool {
        matches!(self, Self::Gen(_))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxInGen {
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxInToKey {
    /// 0 for a RingCT input; the exact denomination for a pre-RingCT one.
    pub amount: u64,
    /// **Relative** offsets. Member `i` sits at `sum(key_offsets[0..=i])`; only
    /// the first is absolute. See [`TxInToKey::ring_members`].
    ///
    /// Present and **empty** for every input of an FCMP++ transaction (RingCT
    /// type 7). Such an input spends one of the outputs in the curve tree, not one
    /// of a ring, so there are no members to name.
    pub key_offsets: Vec<u64>,
    pub k_image: String,
}

impl TxInToKey {
    /// Ring size, i.e. `mixin + 1`.
    #[must_use]
    pub fn ring_size(&self) -> usize {
        self.key_offsets.len()
    }

    /// This input's ring members as `/get_outs` request entries.
    ///
    /// Each carries this input's `amount` alongside the resolved index, because
    /// the index means different things depending on it: for a pre-RingCT input
    /// the cumulative sum indexes the output set **for that denomination**, and
    /// only for a RingCT input (amount 0) is it the global index. Handing back
    /// bare indices would let a caller build a request that looks right and
    /// resolves a different output entirely.
    ///
    /// Returns `None` if the offsets sum past `u64::MAX`, which no real
    /// transaction does but remote input is remote input.
    #[must_use]
    pub fn ring_members(&self) -> Option<Vec<OutKeyRequest>> {
        let mut absolute = 0u64;
        let mut out = Vec::with_capacity(self.key_offsets.len());
        for offset in &self.key_offsets {
            absolute = absolute.checked_add(*offset)?;
            out.push(OutKeyRequest {
                amount: self.amount,
                index: absolute,
            });
        }
        Some(out)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxOut {
    /// 0 for a RingCT output; denominated for v1 and for **every** coinbase
    /// output, including a v2 coinbase's.
    pub amount: u64,
    pub target: TxOutTarget,
}

/// An output target.
///
/// The live variants nest differently, which is the trap: `key`'s body is a
/// bare hex string because the C++ type is blob-serialized, while
/// `tagged_key`'s and `carrot_v1`'s bodies are objects. A `struct { key:
/// String }` parses every pre-view-tag output and then fails on everything
/// after mainnet height 2689608.
///
/// `carrot_v1` is the FCMP++ fork's output (hard fork 17), on wire tag `0x01`.
/// A daemon without FCMP++ names that tag `scripthash`, which no output on any
/// chain uses, and `ScriptHash` parses such a daemon's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxOutTarget {
    #[serde(rename = "key")]
    Key(String),
    #[serde(rename = "tagged_key")]
    TaggedKey(TaggedKey),
    #[serde(rename = "carrot_v1")]
    CarrotV1(CarrotV1),
    #[serde(rename = "script")]
    Script(serde_json::Value),
    #[serde(rename = "scripthash")]
    ScriptHash(serde_json::Value),
}

impl TxOutTarget {
    /// The one-time public key, whichever variant carries it.
    #[must_use]
    pub fn public_key(&self) -> Option<&str> {
        match self {
            Self::Key(k) => Some(k),
            Self::TaggedKey(t) => Some(&t.key),
            Self::CarrotV1(c) => Some(&c.key),
            _ => None,
        }
    }

    /// The view tag, if this output has one. One byte before Carrot and three
    /// bytes from it, so two or six hex characters; `None` for a tag of any
    /// other form.
    #[must_use]
    pub fn view_tag(&self) -> Option<&str> {
        match self {
            Self::TaggedKey(t) => hex_of_len(&t.view_tag, 2),
            Self::CarrotV1(c) => hex_of_len(&c.view_tag, 6),
            _ => None,
        }
    }

    /// The encrypted Janus anchor, which only a Carrot output has: 32 hex
    /// characters, and `None` for an anchor of any other form.
    #[must_use]
    pub fn encrypted_janus_anchor(&self) -> Option<&str> {
        match self {
            Self::CarrotV1(c) => hex_of_len(&c.encrypted_janus_anchor, 32),
            _ => None,
        }
    }

    /// Whether this is a Carrot output.
    #[must_use]
    pub const fn is_carrot(&self) -> bool {
        matches!(self, Self::CarrotV1(_))
    }
}

/// `s` when it is exactly `len` hex characters.
#[must_use]
pub fn hex_of_len(s: &str, len: usize) -> Option<&str> {
    (s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaggedKey {
    pub key: String,
    /// One byte, so exactly two hex characters.
    pub view_tag: String,
}

/// The hard fork that brings FCMP++ and Carrot, and with them the block's
/// curve-tree fields. A block below it has no tree to report.
pub const HF_VERSION_FCMP_PLUS_PLUS: u8 = 17;

/// How far a block's own tree root runs ahead of its height.
///
/// A transaction's `reference_block` R and a block's `fcmp_pp_tree_root` count
/// the tree differently. The proof is checked against the tree as it stood
/// when R was the chain tip. Block H commits to the tree as of tip
/// `get_default_last_locked_block_index(H - 1)`, which is `H - 1 + 9`: the
/// default spendable age of 10 blocks, less one. So the root a proof naming R
/// was checked against is the one block `R - 8` carries, not block R's. The
/// root is in the block's body, after its transaction list, not in the header
/// the header calls return; only `get_block` has it.
///
/// From the check in `Blockchain::handle_block_to_main_chain`
/// (`src/cryptonote_core/blockchain.cpp`) and
/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` in `src/cryptonote_config.h`.
pub const TREE_ROOT_LAG: u64 = 8;

/// The last block at which an output with `unlock_time`, mined in block
/// `height`, is still locked. It joins the curve tree with that block: the
/// tree as of that block and every later one holds it.
///
/// Never sooner than the default spendable age of 10 blocks allows. An
/// `unlock_time` below 500,000,000 is a height, and above it a Unix time,
/// converted at two minutes a block from hard fork 15's time and height, as
/// monerod converts it.
///
/// `get_last_locked_block_index` in
/// `src/cryptonote_basic/cryptonote_format_utils.cpp`.
#[must_use]
pub const fn last_locked_block(unlock_time: u64, height: u64) -> u64 {
    const SPENDABLE_AGE: u64 = 10;
    const MAX_BLOCK_NUMBER: u64 = 500_000_000;
    const HF_V15_TIME: u64 = 1_656_629_118;
    const HF_V15_HEIGHT: u64 = 2_689_608;
    const TARGET: u64 = 120;

    let default = height.saturating_add(SPENDABLE_AGE - 1);
    let named = if unlock_time == 0 {
        default
    } else if unlock_time < MAX_BLOCK_NUMBER {
        unlock_time - 1
    } else if HF_V15_TIME > unlock_time {
        let blocks_since = (HF_V15_TIME - unlock_time) / TARGET;
        if HF_V15_HEIGHT > blocks_since {
            HF_V15_HEIGHT - blocks_since
        } else {
            default
        }
    } else {
        HF_V15_HEIGHT.saturating_add((unlock_time - HF_V15_TIME) / TARGET)
    };
    if named > default { named } else { default }
}

/// The height of the block that would carry the root an FCMP++ proof naming
/// `reference_block` was checked against: `reference_block - 8`, or `None`
/// below height 8.
///
/// Arithmetic only, so it answers for heights no block can serve. Consensus
/// accepts a reference block from one block before the fork, and blocks carry
/// a tree only from the fork on, so for the first reference blocks after the
/// fork this names a block from before it, which has no root at all. A caller
/// that shows the root has to check the block it names really carries one.
#[must_use]
pub const fn tree_root_block(reference_block: u64) -> Option<u64> {
    reference_block.checked_sub(TREE_ROOT_LAG)
}

/// Children per parent in the curve tree. The leaves' parents are Selene
/// nodes, theirs Helios, alternating up to the root.
///
/// `SELENE_CHUNK_WIDTH` and `HELIOS_CHUNK_WIDTH` in
/// `src/fcmp_pp/curve_trees.h`.
pub const SELENE_CHUNK_WIDTH: u64 = 38;
pub const HELIOS_CHUNK_WIDTH: u64 = 18;

/// The node count of each layer of a curve tree holding `leaves` outputs,
/// from the leaves' parents up to the root. Its length is the tree's layer
/// count.
///
/// `CurveTrees::n_elems_per_layer` in `src/fcmp_pp/curve_trees.cpp`.
#[must_use]
pub fn tree_layers(leaves: u64) -> Vec<u64> {
    let mut layers = Vec::new();
    if leaves == 0 {
        return layers;
    }
    let (mut children, mut selene) = (leaves, true);
    loop {
        let width = if selene {
            SELENE_CHUNK_WIDTH
        } else {
            HELIOS_CHUNK_WIDTH
        };
        children = children.div_ceil(width);
        layers.push(children);
        selene = !selene;
        if children <= 1 {
            return layers;
        }
    }
}

/// `txout_to_carrot_v1`.
///
/// The amount commitment and the encrypted amount are not here. They sit in
/// `rct_signatures` (`outPk` and `ecdhInfo`), as they do for every RingCT
/// output, which lets a coinbase and an ordinary transaction share this one
/// output type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrotV1 {
    /// The one-time address `K_o`.
    pub key: String,
    /// Three bytes, so exactly six hex characters.
    pub view_tag: String,
    /// The Janus anchor, encrypted: 16 bytes, so 32 hex characters. The
    /// recipient decrypts it to check that the sender did not build the output
    /// against a different address of theirs.
    pub encrypted_janus_anchor: String,
}

// ---------------------------------------------------------------------------
// RingCT
// ---------------------------------------------------------------------------

/// The RingCT signature scheme in use, which is what everything else about a
/// RingCT transaction's shape keys off.
///
/// Dispatch on this, never on block height: v1 transactions persist long past
/// the RingCT fork whenever they spend unmixable dust, and two MLSAG
/// transactions are grandfathered in after the CLSAG fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RctType {
    /// Coinbase. `rct_signatures` is `{"type": 0}` and stops there.
    Null,
    Full,
    Simple,
    Bulletproof,
    Bulletproof2,
    Clsag,
    BulletproofPlus,
    /// FCMP++, from hard fork 17. Bulletproofs+ still prove the ranges; what
    /// changes is the spend proof. Each input proves membership in the set of
    /// every spendable output rather than in a ring of 16, so an input has
    /// no `key_offsets` and there are no ring members to look up.
    FcmpPlusPlus,
    /// A scheme this build does not know. Kept rather than rejected so that a
    /// future fork degrades instead of failing to parse.
    Unknown(u8),
}

impl RctType {
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Null,
            1 => Self::Full,
            2 => Self::Simple,
            3 => Self::Bulletproof,
            4 => Self::Bulletproof2,
            5 => Self::Clsag,
            6 => Self::BulletproofPlus,
            7 => Self::FcmpPlusPlus,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn to_raw(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Full => 1,
            Self::Simple => 2,
            Self::Bulletproof => 3,
            Self::Bulletproof2 => 4,
            Self::Clsag => 5,
            Self::BulletproofPlus => 6,
            Self::FcmpPlusPlus => 7,
            Self::Unknown(other) => other,
        }
    }

    /// Which object holds `pseudoOuts` for this scheme.
    #[must_use]
    pub const fn pseudo_outs_location(self) -> PseudoOutsLocation {
        match self {
            Self::Simple => PseudoOutsLocation::Base,
            Self::Bulletproof
            | Self::Bulletproof2
            | Self::Clsag
            | Self::BulletproofPlus
            | Self::FcmpPlusPlus => PseudoOutsLocation::Prunable,
            Self::Null | Self::Full | Self::Unknown(_) => PseudoOutsLocation::Absent,
        }
    }

    /// Which `ecdhInfo` encoding this scheme emits, or `None` where there is no
    /// `ecdhInfo` at all.
    #[must_use]
    pub const fn ecdh_form(self) -> Option<EcdhForm> {
        match self {
            Self::Full | Self::Simple | Self::Bulletproof => Some(EcdhForm::Full),
            Self::Bulletproof2 | Self::Clsag | Self::BulletproofPlus | Self::FcmpPlusPlus => {
                Some(EcdhForm::Compact)
            }
            Self::Null | Self::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoOutsLocation {
    /// Inside `rct_signatures`, so it survives pruning.
    Base,
    /// Inside `rctsig_prunable`, so it does not.
    Prunable,
    Absent,
}

/// `rct_signatures`.
///
/// Everything past `type` is optional because type 0 truncates the object
/// immediately: a coinbase's `rct_signatures` really is just `{"type": 0}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RctSigBase {
    #[serde(rename = "type")]
    pub rct_type: u8,
    #[serde(default, rename = "txnFee", skip_serializing_if = "Option::is_none")]
    pub txn_fee: Option<u64>,
    /// Present here for type 2 only; types 3 to 7 put it in `rctsig_prunable`.
    /// Use [`TxJson::pseudo_outs`] rather than reaching in.
    #[serde(
        default,
        rename = "pseudoOuts",
        skip_serializing_if = "Option::is_none"
    )]
    pub pseudo_outs: Option<Vec<String>>,
    #[serde(default, rename = "ecdhInfo", skip_serializing_if = "Option::is_none")]
    pub ecdh_info: Option<Vec<EcdhInfo>>,
    /// Bare commitment hex strings, not `{dest, mask}` objects.
    #[serde(default, rename = "outPk", skip_serializing_if = "Option::is_none")]
    pub out_pk: Option<Vec<String>>,
}

impl RctSigBase {
    #[must_use]
    pub const fn rct_type(&self) -> RctType {
        RctType::from_raw(self.rct_type)
    }
}

/// The shape an `ecdhInfo` element takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhForm {
    /// Types 1, 2, 3: `{"mask": <64 hex>, "amount": <64 hex>}`.
    Full,
    /// Types 4 to 7: `{"amount": <16 hex>}`, with `mask` gone — the key is
    /// absent, not null, and the amount is 8 bytes rather than 32.
    Compact,
}

/// Hex width of a 32-byte `ecdhInfo` amount (types 1, 2, 3).
pub const ECDH_FULL_HEX_LEN: usize = 64;
/// Hex width of the truncated 8-byte `ecdhInfo` amount (types 4 to 7).
pub const ECDH_COMPACT_HEX_LEN: usize = 16;

/// One `ecdhInfo` element.
///
/// Modelled as a struct with an optional `mask` rather than as an untagged
/// enum. An untagged enum here has to tell the two forms apart by content, and
/// gets it wrong unless every arm's hex length is strictly checked: serde
/// ignores unknown fields when matching an untagged variant, so a `{amount}`
/// arm happily swallows a `{mask, amount}` object and discards the mask.
/// [`EcdhInfo::form`] does the strict-length classification explicitly, so
/// nothing here depends on variant ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdhInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    pub amount: String,
}

impl EcdhInfo {
    /// Classify by **width**, not by the transaction's RingCT type and not by
    /// which fields happen to be present.
    ///
    /// Returns `None` for anything monerod does not emit — a mask alongside a
    /// truncated amount, a 32-byte amount with no mask, a wrong-length blob.
    /// Those are not forms to guess at.
    #[must_use]
    pub fn form(&self) -> Option<EcdhForm> {
        match (self.mask.as_deref(), self.amount.len()) {
            (Some(mask), ECDH_FULL_HEX_LEN) if mask.len() == ECDH_FULL_HEX_LEN => {
                Some(EcdhForm::Full)
            }
            (None, ECDH_COMPACT_HEX_LEN) => Some(EcdhForm::Compact),
            _ => None,
        }
    }
}

/// `rctsig_prunable`.
///
/// A flat struct with every field optional, rather than an untagged enum over
/// the per-type layouts: order-independent, forward-compatible with a scheme
/// this build has not heard of, and it reports a bad field as a bad field
/// instead of "data did not match any variant".
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RctSigPrunable {
    /// Number of bulletproofs. A **number**, not an array — present for types 3
    /// to 7 and absent for types 1 and 2, which emit `rangeSigs` instead. It
    /// can exceed 1: pre-padding wallets emitted several proofs per
    /// transaction, so `bp[0]` is not necessarily the whole proof set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbp: Option<u32>,
    /// Borromean range proofs — types 1 and 2.
    #[serde(default, rename = "rangeSigs", skip_serializing_if = "Option::is_none")]
    pub range_sigs: Option<Vec<RangeSig>>,
    /// Bulletproofs — types 3, 4, 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bp: Option<Vec<Bulletproof>>,
    /// Bulletproof+ — types 6 and 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpp: Option<Vec<BulletproofPlus>>,
    /// MLSAGs — types 1, 2, 3, 4.
    #[serde(default, rename = "MGs", skip_serializing_if = "Option::is_none")]
    pub mgs: Option<Vec<MgSig>>,
    /// CLSAGs — types 5, 6.
    #[serde(default, rename = "CLSAGs", skip_serializing_if = "Option::is_none")]
    pub clsags: Option<Vec<Clsag>>,
    /// FCMP++ — type 7. The block whose curve tree the proof was built
    /// against: the transaction proves that each input spends one of the
    /// outputs in that tree, and the verifier reads the tree root as of this
    /// block. A height, not a hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_block: Option<u64>,
    /// FCMP++ — type 7. The curve tree's layer count as of `reference_block`.
    /// Stored although it could be derived, because the proof's length depends
    /// on it and deserializing the proof must not need a database read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_tree_layers: Option<u8>,
    /// FCMP++ — type 7. One flat hex blob: the membership proof for every
    /// input at once, preceded by each input's re-randomized tuple and its
    /// spend-authorization proof. Its length is fixed by the input count and
    /// `n_tree_layers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fcmp_pp: Option<String>,
    /// Types 3 to 7 only. Use [`TxJson::pseudo_outs`].
    #[serde(
        default,
        rename = "pseudoOuts",
        skip_serializing_if = "Option::is_none"
    )]
    pub pseudo_outs: Option<Vec<String>>,
}

impl RctSigPrunable {
    /// Byte length of the FCMP++ proof, or `None` where there is none or its
    /// hex is odd-length.
    #[must_use]
    pub fn fcmp_pp_len(&self) -> Option<usize> {
        let hex = self.fcmp_pp.as_deref()?;
        hex.len().is_multiple_of(2).then_some(hex.len() / 2)
    }

    /// The FCMP++ proof split into its parts, for a transaction with
    /// `inputs` inputs. `None` where there is no proof, or it is too short to
    /// hold them.
    ///
    /// Each input's tuple and spend-authorization proof in input order, then
    /// the membership proof for all of them, ending in the root blind's proof
    /// of knowledge: `FcmpPlusPlus::write` in monero-oxide's `ringct/fcmp++`,
    /// and `Fcmp::write` in its `crypto/fcmps`.
    #[must_use]
    pub fn fcmp_pp_parts(&self, inputs: usize) -> Option<FcmpPpParts<'_>> {
        let hex = self.fcmp_pp.as_deref()?;
        let per_input = 2 * (FCMP_PP_TUPLE_LEN + FCMP_PP_SAL_LEN);
        let own = per_input.checked_mul(inputs)?;
        let membership = hex.len().checked_sub(own)?;
        if !membership.is_multiple_of(2) || membership / 2 <= FCMP_PP_ROOT_POK_LEN {
            return None;
        }
        let word = |at: usize| hex.get(at..at + 64);
        let parts = (0..inputs)
            .map(|i| {
                let at = i * per_input;
                Some(FcmpPpInput {
                    o_tilde: word(at)?,
                    i_tilde: word(at + 64)?,
                    r: word(at + 128)?,
                })
            })
            .collect::<Option<_>>()?;
        Some(FcmpPpParts {
            inputs: parts,
            membership_len: membership / 2,
        })
    }
}

/// Bytes of an FCMP++ input tuple as serialized: O~, I~ and R. Its fourth
/// member, C~, is the input's pseudo-out and is not repeated in the proof.
pub const FCMP_PP_TUPLE_LEN: usize = 3 * 32;
/// Bytes of one input's spend-authorization and linkability proof.
pub const FCMP_PP_SAL_LEN: usize = 12 * 32;
/// Bytes of the proof of knowledge of the root's blind, which ends the
/// membership proof.
pub const FCMP_PP_ROOT_POK_LEN: usize = 64;

/// See [`RctSigPrunable::fcmp_pp_parts`].
#[derive(Debug, PartialEq, Eq)]
pub struct FcmpPpParts<'a> {
    pub inputs: Vec<FcmpPpInput<'a>>,
    /// Bytes of the membership proof, [`FCMP_PP_ROOT_POK_LEN`] included.
    pub membership_len: usize,
}

/// One input's re-randomized output, as hex.
#[derive(Debug, PartialEq, Eq)]
pub struct FcmpPpInput<'a> {
    pub o_tilde: &'a str,
    pub i_tilde: &'a str,
    pub r: &'a str,
}

/// A Borromean range proof. Both members are blob-serialized, so they are two
/// enormous flat hex strings — 8256 and 4096 characters — not nested
/// structures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSig {
    pub asig: String,
    #[serde(rename = "Ci")]
    pub ci: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case, reason = "field names are monerod's, verbatim")]
pub struct Bulletproof {
    pub A: String,
    pub S: String,
    pub T1: String,
    pub T2: String,
    pub taux: String,
    pub mu: String,
    /// Same length as `R`, and never empty.
    pub L: Vec<String>,
    pub R: Vec<String>,
    pub a: String,
    pub b: String,
    pub t: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case, reason = "field names are monerod's, verbatim")]
pub struct BulletproofPlus {
    pub A: String,
    pub A1: String,
    pub B: String,
    pub r1: String,
    pub s1: String,
    pub d1: String,
    pub L: Vec<String>,
    pub R: Vec<String>,
}

/// An MLSAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgSig {
    /// `Vec<Vec<_>>`, not a fixed-width matrix: each row is 2 wide for types 2,
    /// 3 and 4, but `n_inputs + 1` wide for type 1, which consensus permits.
    pub ss: Vec<Vec<String>>,
    pub cc: String,
}

/// A CLSAG. The key image `I` is deliberately not serialized — it is
/// reconstructed — so there is no field for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case, reason = "field names are monerod's, verbatim")]
pub struct Clsag {
    pub s: Vec<String>,
    pub c1: String,
    pub D: String,
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Panicking is the correct failure mode in a test; the workspace lints
    // exist to keep panics out of request handling, not out of assertions.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]

    use super::*;

    #[test]
    fn reassembles_a_128_bit_value_from_its_halves() {
        // Real testnet values: top64 is zero and stays zero for decades, so the
        // low word alone is right today...
        assert_eq!(reassemble_u128(134_861, 0), 134_861);
        assert_eq!(parse_wide("0x20ecd"), Some(134_861));
        assert_eq!(
            reassemble_u128(2_226_268_821_658_237_607, 0),
            parse_wide("0x1ee54bb2b1777aa7").unwrap()
        );

        // ...and wrong the moment it is not.
        assert_eq!(reassemble_u128(0, 1), 1u128 << 64);
        assert_eq!(
            reassemble_u128(u64::MAX, u64::MAX),
            u128::MAX,
            "both halves must be preserved, not saturated"
        );
        assert_eq!(
            reassemble_u128(7, 3),
            parse_wide("0x30000000000000007").unwrap()
        );
    }

    #[test]
    fn wide_values_that_monerod_actually_emits_parse_and_the_empty_one_does_not() {
        assert_eq!(parse_wide("0x0"), Some(0));
        // An all-default block_header and get_coinbase_tx_sum's error path both
        // produce "", which must not panic or read as zero.
        assert_eq!(parse_wide(""), None);
        assert_eq!(parse_wide("20ecd"), None, "the 0x prefix is not optional");
        assert_eq!(parse_wide("0xnothex"), None);
        // 33 hex digits: wider than u128.
        assert_eq!(parse_wide(&format!("0x1{}", "0".repeat(32))), None);
    }

    #[test]
    fn quantization_mask_defaults_to_one_not_zero() {
        // Omitted precisely when it equals 1, so a zero default silently
        // divides fee maths by zero.
        let json = r#"{"fee":520000,"status":"OK"}"#;
        let fee: FeeEstimate = serde_json::from_str(json).unwrap();
        assert_eq!(fee.quantization_mask, 1);
        assert!(fee.fees.is_empty());
    }

    #[test]
    fn ecdh_forms_are_told_apart_by_width_not_by_field_presence() {
        let full: EcdhInfo = serde_json::from_str(
            r#"{"mask":"48077bcc00000000000000000000000000000000000000000000000000000000",
                "amount":"d8a4356c00000000000000000000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        assert_eq!(full.form(), Some(EcdhForm::Full));

        let compact: EcdhInfo = serde_json::from_str(r#"{"amount":"64717b40fad782d9"}"#).unwrap();
        assert_eq!(compact.form(), Some(EcdhForm::Compact));
        assert!(compact.mask.is_none(), "the key is gone, not null");

        // A truncated amount carrying a mask, or a full amount without one, is
        // not a form monerod emits. Guessing would mean handing a caller 8
        // bytes where it expects 32.
        let hybrid: EcdhInfo = serde_json::from_str(
            r#"{"mask":"48077bcc00000000000000000000000000000000000000000000000000000000",
                "amount":"64717b40fad782d9"}"#,
        )
        .unwrap();
        assert_eq!(hybrid.form(), None);

        let maskless_full: EcdhInfo = serde_json::from_str(
            r#"{"amount":"d8a4356c00000000000000000000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        assert_eq!(maskless_full.form(), None);
    }

    #[test]
    fn rct_type_knows_where_pseudo_outs_live() {
        assert_eq!(
            RctType::Simple.pseudo_outs_location(),
            PseudoOutsLocation::Base
        );
        for t in [
            RctType::Bulletproof,
            RctType::Bulletproof2,
            RctType::Clsag,
            RctType::BulletproofPlus,
            RctType::FcmpPlusPlus,
        ] {
            assert_eq!(t.pseudo_outs_location(), PseudoOutsLocation::Prunable);
        }
        assert_eq!(
            RctType::Full.pseudo_outs_location(),
            PseudoOutsLocation::Absent
        );
        assert_eq!(
            RctType::Null.pseudo_outs_location(),
            PseudoOutsLocation::Absent
        );
    }

    #[test]
    fn rct_type_knows_which_ecdh_form_to_expect() {
        assert_eq!(RctType::Simple.ecdh_form(), Some(EcdhForm::Full));
        assert_eq!(RctType::Bulletproof.ecdh_form(), Some(EcdhForm::Full));
        // The cutover is at type 4, not at a height.
        assert_eq!(RctType::Bulletproof2.ecdh_form(), Some(EcdhForm::Compact));
        assert_eq!(
            RctType::BulletproofPlus.ecdh_form(),
            Some(EcdhForm::Compact)
        );
        assert_eq!(RctType::FcmpPlusPlus.ecdh_form(), Some(EcdhForm::Compact));
        assert_eq!(RctType::Null.ecdh_form(), None);
    }

    #[test]
    fn unknown_rct_type_round_trips_rather_than_being_rejected() {
        let t = RctType::from_raw(8);
        assert_eq!(t, RctType::Unknown(8));
        assert_eq!(t.to_raw(), 8);
        assert_eq!(t.ecdh_form(), None);
        for raw in 0u8..=7 {
            assert_eq!(RctType::from_raw(raw).to_raw(), raw);
        }
    }

    #[test]
    fn ring_signatures_split_into_128_character_chunks() {
        let one = "ab".repeat(64);
        assert_eq!(one.len(), 128);
        assert_eq!(split_ring_signatures(&one), Some(vec![one.as_str()]));

        let ring16 = "cd".repeat(64 * 16);
        assert_eq!(ring16.len(), 2048);
        let parts = split_ring_signatures(&ring16).unwrap();
        assert_eq!(parts.len(), 16);
        assert!(parts.iter().all(|p| p.len() == 128));
    }

    #[test]
    fn a_signature_entry_that_is_not_a_whole_number_of_signatures_is_rejected() {
        assert_eq!(split_ring_signatures(""), None);
        assert_eq!(split_ring_signatures(&"ab".repeat(63)), None);
        assert_eq!(split_ring_signatures(&"ab".repeat(65)), None);
        // Non-hex must be refused rather than chunked: multi-byte input would
        // otherwise be sliced mid-character.
        assert_eq!(split_ring_signatures(&"é".repeat(64)), None);
        assert_eq!(
            split_ring_signatures(&format!("{}zz", "ab".repeat(63))),
            None
        );
    }

    #[test]
    fn nested_json_that_is_empty_is_absent_rather_than_malformed() {
        let entry: TxEntry = serde_json::from_str(
            r#"{"tx_hash":"aa","as_json":"","in_pool":false,"double_spend_seen":false}"#,
        )
        .unwrap();
        assert!(matches!(entry.parse_json(), Err(NestedJsonError::Absent)));

        let broken: TxEntry = serde_json::from_str(
            r#"{"tx_hash":"aa","as_json":"{\"version\": }","in_pool":false,"double_spend_seen":false}"#,
        )
        .unwrap();
        assert!(matches!(
            broken.parse_json(),
            Err(NestedJsonError::Malformed(_))
        ));
    }

    #[test]
    fn get_outs_entries_cannot_be_built_without_an_amount() {
        let ringct = OutKeyRequest::ringct(47_664);
        assert_eq!(ringct.amount(), 0);
        assert!(ringct.is_ringct());

        let pre = OutKeyRequest::pre_ringct(7_000_000_000_000, 4_732);
        assert_eq!(pre.amount(), 7_000_000_000_000);
        assert!(!pre.is_ringct());

        // The wire shape monerod expects.
        assert_eq!(
            serde_json::to_value(pre).unwrap(),
            serde_json::json!({"amount": 7_000_000_000_000u64, "index": 4732})
        );
    }

    #[test]
    fn get_outs_request_always_serialises_get_txid() {
        // The JSON endpoint's get_txid is a plain field, so an omitted key
        // means false -- the opposite of /get_outs.bin. Sending it explicitly
        // is the only way to be sure which one you asked for.
        let req = GetOutsRequest::new(vec![OutKeyRequest::ringct(1)], true);
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["get_txid"], serde_json::json!(true));

        let req = GetOutsRequest::new(vec![OutKeyRequest::ringct(1)], false);
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v.get("get_txid"),
            Some(&serde_json::json!(false)),
            "false must be sent, not omitted"
        );
    }

    #[test]
    fn get_block_request_sends_exactly_one_selector() {
        let by_height = serde_json::to_value(GetBlockRequest::by_height(134_721)).unwrap();
        assert_eq!(by_height["height"], serde_json::json!(134_721));
        assert!(
            by_height.get("hash").is_none(),
            "an empty hash alongside a height is fine, but sending both invites the \
             undocumented hash-wins precedence"
        );

        let by_hash = serde_json::to_value(GetBlockRequest::by_hash("785cd4")).unwrap();
        assert_eq!(by_hash["hash"], serde_json::json!("785cd4"));
        assert!(by_hash.get("height").is_none());
        assert_eq!(by_hash["fill_pow_hash"], serde_json::json!(false));

        let pow = serde_json::to_value(GetBlockRequest::by_height(1).fill_pow_hash(true)).unwrap();
        assert_eq!(pow["fill_pow_hash"], serde_json::json!(true));
    }

    #[test]
    fn the_recommended_get_transactions_request_never_prunes() {
        let req = GetTransactionsRequest::decoded(vec!["aa".to_owned()]);
        assert!(req.decode_as_json);
        assert!(req.split);
        assert!(
            !req.prune,
            "prune:true suppresses prunable_as_hex, which is the signal that \
             distinguishes a pruned node from a pruned request"
        );
    }

    /// Regression: `prune` was a public field with a "do not set this" doc
    /// comment. A reviewer set it and showed that a transaction whose prunable
    /// half the node demonstrably still held (25152 hex chars of it) was
    /// reported by `prunable_missing()` as pruned. The field is now private, so
    /// the only reachable request shape is the honest one.
    #[test]
    fn a_get_transactions_request_can_never_ask_for_the_pruned_encoding() {
        let req = GetTransactionsRequest::decoded(vec!["aa".to_owned()]);
        assert!(!req.prune());
        assert!(req.decode_as_json());
        assert!(req.split());

        // The serialized form is what actually reaches monerod.
        let wire = serde_json::to_value(&req).expect("serialises");
        assert_eq!(
            wire["prune"],
            serde_json::Value::Bool(false),
            "prune must be false on the wire, not merely in the struct"
        );
    }

    /// Regression: an unknown RCT type reported "no pseudo-outputs" even when
    /// the document carried them. Degrading is fine; answering wrongly is not.
    #[test]
    fn an_unknown_rct_scheme_still_finds_pseudo_outs_that_are_present() {
        let raw = r#"{"version":2,"unlock_time":0,
             "vin":[{"key":{"amount":0,"key_offsets":[1,2],"k_image":"aa"}}],
             "vout":[],"extra":[],
             "rct_signatures":{"type":8},
             "rctsig_prunable":{"pseudoOuts":["a"]}}"#;
        let tx: TxJson = serde_json::from_str(raw).expect("parses");

        assert_eq!(tx.rct_type(), Some(RctType::Unknown(8)));
        assert_eq!(
            tx.pseudo_outs(),
            ["a".to_owned()],
            "an unfamiliar scheme must not claim the pseudo-outs it can see are absent"
        );
    }

    /// The same document with genuinely no pseudo-outs must still say so.
    #[test]
    fn an_unknown_rct_scheme_reports_none_when_there_really_are_none() {
        let raw = r#"{"version":2,"unlock_time":0,
             "vin":[{"key":{"amount":0,"key_offsets":[1],"k_image":"aa"}}],
             "vout":[],"extra":[],
             "rct_signatures":{"type":8},
             "rctsig_prunable":{}}"#;
        let tx: TxJson = serde_json::from_str(raw).expect("parses");
        assert!(tx.pseudo_outs().is_empty());
    }

    #[test]
    fn a_short_key_image_is_refused_before_it_reaches_the_daemon() {
        let good = "1".repeat(64);
        let req = IsKeyImageSpentRequest::new(vec![good.clone()]).unwrap();
        assert_eq!(req.key_images(), std::slice::from_ref(&good));

        // "dead" is what the daemon answers `spent_status: [0]` to, with
        // status "OK" -- a wrong answer that nothing downstream can spot.
        let err = IsKeyImageSpentRequest::new(vec![good, "dead".to_owned()]).unwrap_err();
        assert_eq!(err.index, 1);
        assert!(IsKeyImageSpentRequest::new(vec!["z".repeat(64)]).is_err());
    }

    #[test]
    fn spent_status_never_reads_an_unknown_code_as_unspent() {
        assert_eq!(SpentStatus::from_raw(0), SpentStatus::Unspent);
        assert_eq!(SpentStatus::from_raw(1), SpentStatus::SpentInBlockchain);
        assert_eq!(SpentStatus::from_raw(2), SpentStatus::SpentInPool);
        assert!(SpentStatus::from_raw(1).is_spent());
        assert!(SpentStatus::from_raw(2).is_spent());
        assert!(!SpentStatus::from_raw(0).is_spent());

        let future = SpentStatus::from_raw(3);
        assert_eq!(future, SpentStatus::Unknown(3));
        assert!(!future.is_spent());
        assert_ne!(future, SpentStatus::Unspent);

        // std::vector<int> in C++, so negatives are representable.
        assert_eq!(SpentStatus::from_raw(-1), SpentStatus::Unknown(-1));
    }

    #[test]
    fn a_failed_status_can_arrive_with_a_populated_txs_array() {
        // monerod sets status mid-loop and returns anyway, so the array is
        // present but must not be believed.
        let raw = r#"{"status":"Failed","txs":[{"tx_hash":"aa","in_pool":false,
            "double_spend_seen":false,"as_hex":"","pruned_as_hex":"","prunable_as_hex":"",
            "prunable_hash":"","as_json":""}],"untrusted":false}"#;
        let resp: GetTransactionsResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.txs.len(), 1);
        assert!(!resp.status_is_ok());
    }

    #[test]
    fn every_vector_survives_being_omitted() {
        // The empty-pool response, verbatim.
        let pool: GetTransactionPool =
            serde_json::from_str(r#"{"credits":0,"status":"OK","top_hash":"","untrusted":false}"#)
                .unwrap();
        assert!(pool.transactions.is_empty());
        assert!(pool.spent_key_images.is_empty());

        let outs: GetOutsResponse =
            serde_json::from_str(r#"{"credits":0,"status":"OK","top_hash":"","untrusted":false}"#)
                .unwrap();
        assert!(outs.outs.is_empty());

        let spent: IsKeyImageSpentResponse =
            serde_json::from_str(r#"{"credits":0,"status":"OK","top_hash":"","untrusted":false}"#)
                .unwrap();
        assert!(spent.spent_status.is_empty());

        // All-missed: txs and txs_as_hex are both gone, and status is still OK.
        let missed: GetTransactionsResponse = serde_json::from_str(
            r#"{"credits":0,"missed_tx":["00"],"status":"OK","top_hash":"","untrusted":false}"#,
        )
        .unwrap();
        assert!(missed.status_is_ok());
        assert!(missed.txs.is_empty());
        assert!(missed.txs_as_hex.is_empty());
        assert_eq!(missed.missed_tx.len(), 1);

        let chains: GetAlternateChains =
            serde_json::from_str(r#"{"status":"OK","untrusted":false}"#).unwrap();
        assert!(chains.chains.is_empty());
    }

    #[test]
    fn responses_without_credits_do_not_require_them() {
        // get_block_count, get_alternate_chains and /get_height derive from the
        // plain base, so a shared struct with required credits/top_hash would
        // fail on exactly these three.
        let count: GetBlockCount =
            serde_json::from_str(r#"{"count":134861,"status":"OK","untrusted":false}"#).unwrap();
        assert_eq!(count.count, 134_861);

        let height: GetHeight = serde_json::from_str(
            r#"{"hash":"785cd4","height":134861,"status":"OK","untrusted":false}"#,
        )
        .unwrap();
        assert_eq!(height.height, 134_861);
    }

    #[test]
    fn ring_members_carry_the_amount_through_the_relative_offset_sum() {
        // Real testnet input: a pre-RingCT denomination, so these indices are
        // into that denomination's output set and mean nothing without it.
        let input = TxInToKey {
            amount: 7_000_000_000_000,
            key_offsets: vec![4732, 5082, 1524],
            k_image: "122d48cf".to_owned(),
        };
        let members = input.ring_members().unwrap();
        assert_eq!(
            members.iter().map(OutKeyRequest::index).collect::<Vec<_>>(),
            vec![4732, 9814, 11338]
        );
        assert!(
            members.iter().all(|m| m.amount() == 7_000_000_000_000),
            "a pre-RingCT index without its amount resolves a different output"
        );
        assert_eq!(input.ring_size(), 3);
    }

    #[test]
    fn ring_members_refuse_to_overflow_rather_than_panicking() {
        // overflow-checks is on in release, so a plain add here would abort the
        // process on hostile input.
        let input = TxInToKey {
            amount: 0,
            key_offsets: vec![u64::MAX, 1],
            k_image: String::new(),
        };
        assert_eq!(input.ring_members(), None);
    }

    #[test]
    fn a_v2_coinbase_is_just_a_type_zero_rct_signatures() {
        let raw = r#"{"version":2,"unlock_time":2489060,
            "vin":[{"gen":{"height":2489000}}],
            "vout":[{"amount":805589454799,"target":{"key":"45613e8c"}}],
            "extra":[1,2,3],
            "rct_signatures":{"type":0}}"#;
        let tx: TxJson = serde_json::from_str(raw).unwrap();
        assert!(tx.is_coinbase());
        assert_eq!(tx.rct_type(), Some(RctType::Null));
        assert!(tx.rctsig_prunable.is_none());
        assert!(tx.signatures.is_none());
        assert!(
            !tx.looks_pruned(),
            "a coinbase has no prunable half to lose"
        );
        assert!(tx.pseudo_outs().is_empty());
    }

    #[test]
    fn a_view_tagged_output_nests_differently_from_a_bare_key() {
        let bare: TxOut =
            serde_json::from_str(r#"{"amount":0,"target":{"key":"f21fd68e"}}"#).unwrap();
        assert_eq!(bare.target.public_key(), Some("f21fd68e"));
        assert_eq!(bare.target.view_tag(), None);

        let tagged: TxOut = serde_json::from_str(
            r#"{"amount":0,"target":{"tagged_key":{"key":"57048229","view_tag":"9f"}}}"#,
        )
        .unwrap();
        assert_eq!(tagged.target.public_key(), Some("57048229"));
        assert_eq!(tagged.target.view_tag(), Some("9f"));
        assert!(!tagged.target.is_carrot());
    }

    /// Block H carries the root of the tree as of H + 8, so the root a proof
    /// naming R was checked against is block R - 8's. Heights with no such
    /// block have none.
    #[test]
    fn a_proofs_root_is_eight_blocks_below_its_reference() {
        assert_eq!(tree_root_block(120), Some(112));
        assert_eq!(tree_root_block(8), Some(0));
        assert_eq!(tree_root_block(7), None);
    }

    /// Every 32-byte word of the synthetic proof names its own place, so an
    /// off-by-one in any offset reads back the wrong word.
    #[test]
    fn an_fcmp_pp_proof_splits_into_each_inputs_tuple_and_one_membership_proof() {
        let word = |tag: &str| format!("{tag:0>64}");
        let mut hex = String::new();
        for i in 0..2 {
            for part in ["o", "i", "r"] {
                hex += &word(&format!("{part}{i}"));
            }
            for k in 0..12 {
                hex += &word(&format!("s{i}{k:02}"));
            }
        }
        for k in 0..5 {
            hex += &word(&format!("m{k}"));
        }
        let prunable = RctSigPrunable {
            fcmp_pp: Some(hex.clone()),
            ..RctSigPrunable::default()
        };

        let parts = prunable.fcmp_pp_parts(2).expect("splits");
        assert_eq!(parts.membership_len, 5 * 32);
        assert_eq!(parts.inputs.len(), 2);
        for (i, input) in parts.inputs.iter().enumerate() {
            assert_eq!(input.o_tilde, word(&format!("o{i}")));
            assert_eq!(input.i_tilde, word(&format!("i{i}")));
            assert_eq!(input.r, word(&format!("r{i}")));
        }

        // A third input leaves no room for the membership proof, and a proof
        // that is all root anchor has no membership proof before it.
        assert_eq!(prunable.fcmp_pp_parts(3), None);
        let bare = RctSigPrunable {
            fcmp_pp: Some(hex.get(..hex.len() - 3 * 64).expect("shorter").to_owned()),
            ..RctSigPrunable::default()
        };
        assert_eq!(bare.fcmp_pp_parts(2), None);
        assert_eq!(RctSigPrunable::default().fcmp_pp_parts(1), None);
    }

    /// Each boundary where one more output adds a layer: past 38, one Selene
    /// node is full; past 38 × 18, one Helios node is.
    #[test]
    fn a_layer_is_added_each_time_the_root_fills() {
        assert_eq!(tree_layers(0), Vec::<u64>::new());
        assert_eq!(tree_layers(1), [1]);
        assert_eq!(tree_layers(38), [1]);
        assert_eq!(tree_layers(39), [2, 1]);
        assert_eq!(tree_layers(684), [18, 1]);
        assert_eq!(tree_layers(685), [19, 2, 1]);
        assert_eq!(
            tree_layers(152_000_000),
            [4_000_000, 222_223, 5_848, 325, 9, 1]
        );
    }

    /// The count monerod takes is one past the block asked about, and the
    /// probe travels as a one-element array.
    #[test]
    fn a_tree_size_query_asks_for_the_block_after_as_a_count() {
        let q = TreeSizeQuery::as_of_block(420, 1234).unwrap();
        let [(n, count), (u, ids)] = q.fields();
        assert_eq!((n, count), ("as_of_n_blocks", crate::epee::Field::U64(421)));
        assert_eq!((u, ids), ("unified_ids", crate::epee::Field::U64s(&[1234])));
        assert!(TreeSizeQuery::as_of_block(u64::MAX, 0).is_none());

        let answer = |n: u64| {
            let bytes =
                crate::epee::encode(&[("n_leaf_tuples", crate::epee::Field::U64(n))]).unwrap();
            TreeSizeQuery::answer(&crate::epee::read_root(&bytes, TreeSizeQuery::WANTED).unwrap())
        };
        assert_eq!(answer(9_876), Some(9_876));
        assert_eq!(answer(0), None, "0 answers a different question");
    }

    #[test]
    fn an_output_joins_the_tree_when_it_unlocks() {
        // The default: ten blocks, the block it was mined in counting as one.
        assert_eq!(last_locked_block(0, 801), 810);
        // A coinbase's lock is a height 60 blocks on.
        assert_eq!(last_locked_block(861, 801), 860);
        // A lock shorter than the default does not shorten it.
        assert_eq!(last_locked_block(803, 801), 810);
        // A time a day after hard fork 15, at two minutes a block.
        assert_eq!(
            last_locked_block(1_656_629_118 + 86_400, 2_000_000),
            2_689_608 + 720
        );
        // A time before it, counted back from the fork's height.
        assert_eq!(
            last_locked_block(1_656_629_118 - 86_400, 2_000_000),
            2_689_608 - 720
        );
    }

    #[test]
    fn a_path_query_asks_about_one_to_fifty_ids_and_wants_one_path_each() {
        assert!(PathQuery::as_of_block(9, &[]).is_none());
        assert!(PathQuery::as_of_block(9, &[1; 51]).is_none());
        assert!(PathQuery::as_of_block(u64::MAX, &[1]).is_none());
        let q = PathQuery::as_of_block(9, &[1; 50]).unwrap();
        assert_eq!(
            q.fields()[0],
            ("as_of_n_blocks", crate::epee::Field::U64(10))
        );

        let q = PathQuery::as_of_block(9, &[1, 2]).unwrap();
        let bytes = crate::epee::encode(&[("n_leaf_tuples", crate::epee::Field::U64(5))]).unwrap();
        let root = crate::epee::read_root(&bytes, PathQuery::WANTED).unwrap();
        assert_eq!(q.answer(&root), Err(PathAnswerError::Missing("paths")));
    }

    /// Unified ids are positional, so a list that does not match the output
    /// count is no list at all.
    #[test]
    fn unified_ids_count_only_when_there_is_one_per_output() {
        let mut e: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": "aa", "in_pool": false, "unified_ids": [7, 8],
        }))
        .unwrap();
        assert_eq!(e.unified_ids_per_output(2), Some(&[7u64, 8][..]));
        assert_eq!(e.unified_ids_per_output(3), None);
        assert_eq!(e.unified_ids_per_output(1), None);
        e.unified_ids.clear();
        assert_eq!(e.unified_ids_per_output(0), None);
    }

    /// The FCMP++ fork's output parses, and its key and view tag come out
    /// through the same accessors as the other targets'.
    #[test]
    fn a_carrot_output_parses_and_answers_like_the_others() {
        let carrot: TxOut = serde_json::from_str(
            r#"{"amount":0,"target":{"carrot_v1":{"key":"8f3b62c1","view_tag":"a1b2c3",
                "encrypted_janus_anchor":"00112233445566778899aabbccddeeff"}}}"#,
        )
        .unwrap();
        assert!(carrot.target.is_carrot());
        assert_eq!(carrot.target.public_key(), Some("8f3b62c1"));
        assert_eq!(carrot.target.view_tag(), Some("a1b2c3"));
        assert_eq!(
            carrot.target.encrypted_janus_anchor(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            TxOutTarget::Key("aa".to_owned()).encrypted_janus_anchor(),
            None
        );
    }

    /// No fixture exists for a type 6 transaction — the local mainnet node has
    /// not reached the BulletproofPlus fork — so this is the spec's shape,
    /// constructed by hand.
    #[test]
    fn a_constructed_bulletproof_plus_transaction_parses() {
        let raw = r#"{"version":2,"unlock_time":0,
            "vin":[{"key":{"amount":0,"key_offsets":[8608351,301575],"k_image":"86e1cc68"}}],
            "vout":[{"amount":0,"target":{"tagged_key":{"key":"570482","view_tag":"9f"}}}],
            "extra":[1,39,23],
            "rct_signatures":{"type":6,"txnFee":30660000,
                "ecdhInfo":[{"amount":"64717b40fad782d9"}],
                "outPk":["aabb"]},
            "rctsig_prunable":{"nbp":1,
                "bpp":[{"A":"a1","A1":"a2","B":"b1","r1":"r","s1":"s","d1":"d",
                        "L":["l1","l2"],"R":["r1","r2"]}],
                "CLSAGs":[{"s":["s1","s2"],"c1":"c","D":"d"}],
                "pseudoOuts":["po1"]}}"#;
        let tx: TxJson = serde_json::from_str(raw).unwrap();
        assert_eq!(tx.rct_type(), Some(RctType::BulletproofPlus));
        assert!(!tx.is_coinbase());
        assert!(!tx.looks_pruned());
        assert!(!tx.is_fcmp_pp());
        assert_eq!(tx.reference_block(), None);

        let prunable = tx.rctsig_prunable.as_ref().unwrap();
        assert_eq!(prunable.nbp, Some(1));
        assert!(prunable.bp.is_none(), "type 6 emits bpp, not bp");
        assert!(prunable.mgs.is_none(), "type 6 emits CLSAGs, not MGs");
        assert_eq!(prunable.clsags.as_ref().unwrap().len(), 1);

        // pseudoOuts moved into the prunable half at type 3; looking only in
        // rct_signatures would silently find nothing.
        assert_eq!(tx.pseudo_outs(), &["po1".to_owned()]);
        let ecdh = tx
            .rct_signatures
            .as_ref()
            .unwrap()
            .ecdh_info
            .as_ref()
            .unwrap();
        assert_eq!(ecdh.first().unwrap().form(), Some(EcdhForm::Compact));
    }

    /// Likewise no fixture: a v2 transaction whose prunable half this node
    /// dropped. Built by deleting the key, which is exactly what monerod does.
    #[test]
    fn a_pruned_v2_transaction_is_recognised_as_pruned_not_as_signatureless() {
        let raw = r#"{"version":2,"unlock_time":0,
            "vin":[{"key":{"amount":90000000000,"key_offsets":[114734,115500],"k_image":"5c69da97"}}],
            "vout":[{"amount":0,"target":{"key":"54df59a6"}}],
            "extra":[1,110],
            "rct_signatures":{"type":1,"txnFee":26000000000,
                "ecdhInfo":[{"mask":"97a2ec95","amount":"50c90d39"}],
                "outPk":["bbdc7d98"]}}"#;
        let tx: TxJson = serde_json::from_str(raw).unwrap();
        assert!(tx.rctsig_prunable.is_none());
        assert!(
            tx.looks_pruned(),
            "absent rctsig_prunable on a non-coinbase v2 tx means the node dropped it"
        );

        let entry = TxEntry {
            tx_hash: "c5f50a2b".to_owned(),
            as_hex: String::new(),
            pruned_as_hex: "0200".to_owned(),
            prunable_as_hex: String::new(),
            prunable_hash: "2cc3a2e1".to_owned(),
            as_json: raw.to_owned(),
            in_pool: false,
            double_spend_seen: false,
            block_height: 1_220_521,
            confirmations: 1,
            block_timestamp: 0,
            output_indices: vec![24, 25],
            unified_ids: vec![],
            relayed: false,
            received_timestamp: 0,
        };
        assert!(entry.prunable_missing(&tx));
        assert_eq!(entry.raw_hex().as_deref(), Some("0200"));
    }

    #[test]
    fn an_unpruned_transaction_fetched_without_split_is_not_reported_as_pruned() {
        let raw = r#"{"version":2,"unlock_time":0,
            "vin":[{"key":{"amount":0,"key_offsets":[1,2],"k_image":"aa"}}],
            "vout":[{"amount":0,"target":{"key":"bb"}}],
            "extra":[1],
            "rct_signatures":{"type":5,"txnFee":1,"ecdhInfo":[{"amount":"0011223344556677"}],
                "outPk":["cc"]},
            "rctsig_prunable":{"nbp":1,"bp":[],"CLSAGs":[],"pseudoOuts":[]}}"#;
        let tx: TxJson = serde_json::from_str(raw).unwrap();
        let entry = TxEntry {
            tx_hash: "aa".to_owned(),
            // The non-split form: the whole blob lives here and prunable_as_hex
            // is empty even though nothing was withheld.
            as_hex: "0200deadbeef".to_owned(),
            pruned_as_hex: String::new(),
            prunable_as_hex: String::new(),
            prunable_hash: "bb".to_owned(),
            as_json: raw.to_owned(),
            in_pool: false,
            double_spend_seen: false,
            block_height: 1,
            confirmations: 1,
            block_timestamp: 0,
            output_indices: vec![],
            unified_ids: vec![],
            relayed: false,
            received_timestamp: 0,
        };
        assert!(!entry.prunable_missing(&tx));
        assert_eq!(entry.raw_hex().as_deref(), Some("0200deadbeef"));
    }

    // -----------------------------------------------------------------------
    // Required scalars, and the shape decisions that hang off them
    // -----------------------------------------------------------------------

    /// `rct_signatures.type` is the scalar every other shape decision reads:
    /// [`RctType::pseudo_outs_location`], [`RctType::ecdh_form`] and
    /// [`TxJson::looks_pruned`] all branch on it. A `#[serde(default)]` there
    /// turns any `rct_signatures` object that lost its type into a
    /// coinbase-shaped `RctType::Null`, which reverses `looks_pruned` and
    /// hides the pseudo-outs. It has to be an error instead.
    #[test]
    fn rct_signatures_without_a_type_is_rejected_rather_than_read_as_type_zero() {
        const WITHOUT: &str = r#"{"version":2,"unlock_time":0,
            "vin":[{"key":{"amount":0,"key_offsets":[1,2],"k_image":"e3311388"}}],
            "vout":[{"amount":0,"target":{"key":"bb"}}],
            "extra":[1],
            "rct_signatures":{"txnFee":30660000}}"#;
        let err = serde_json::from_str::<TxJson>(WITHOUT).unwrap_err();
        assert!(
            err.to_string().contains("missing field `type`"),
            "the error has to name the absent scalar: {err}"
        );

        // Restoring only that key makes the same document parse, so the
        // rejection above is about `type` and not about anything else here.
        let clsag = WITHOUT.replace(r#"{"txnFee"#, r#"{"type":5,"txnFee"#);
        let tx: TxJson = serde_json::from_str(&clsag).unwrap();
        assert_eq!(tx.rct_type(), Some(RctType::Clsag));
        assert!(
            tx.looks_pruned(),
            "a type 5 non-coinbase with no rctsig_prunable is the pruned form"
        );

        // And the verdict a defaulted type would have produced instead, which
        // is the wrong answer this test exists to keep unreachable.
        let null = WITHOUT.replace(r#"{"txnFee"#, r#"{"type":0,"txnFee"#);
        let null_tx: TxJson = serde_json::from_str(&null).unwrap();
        assert_eq!(null_tx.rct_type(), Some(RctType::Null));
        assert!(!null_tx.looks_pruned());
    }

    /// The same question for the scalars of a transaction document itself.
    /// `version` picks the v1/v2 era, `vin` decides `is_coinbase`, and a
    /// defaulted `vout`/`extra` would silently present an empty output list
    /// for a transaction that has outputs.
    #[test]
    fn a_transaction_document_missing_any_of_its_required_keys_is_rejected() {
        let complete = serde_json::json!({
            "version": 2,
            "unlock_time": 0,
            "vin": [{"key": {"amount": 0, "key_offsets": [1, 2], "k_image": "e3311388"}}],
            "vout": [{"amount": 0, "target": {"key": "bb"}}],
            "extra": [1, 2, 3],
            "rct_signatures": {"type": 5, "txnFee": 30660000},
        });
        let parsed: TxJson = serde_json::from_value(complete.clone()).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.extra, vec![1u8, 2, 3]);

        for key in ["version", "unlock_time", "vin", "vout", "extra"] {
            let mut doc = complete.clone();
            doc.as_object_mut().unwrap().remove(key);
            let err = serde_json::from_value::<TxJson>(doc)
                .expect_err("{key} must be required, not defaulted");
            assert!(
                err.to_string().contains(&format!("missing field `{key}`")),
                "dropping {key} produced {err}"
            );
        }

        // The other side: the genuinely optional halves may go missing, and
        // that is not an error. Without this the loop above would pass just as
        // well against a model where *everything* was required.
        for key in ["rct_signatures", "signatures", "rctsig_prunable"] {
            let mut doc = complete.clone();
            doc.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<TxJson>(doc).is_ok(),
                "{key} is absent on ordinary responses and must stay optional"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Boundaries, probed from both sides
    // -----------------------------------------------------------------------

    /// monerod's own length check on a key image sets a status and then forgets
    /// to `return`, so the image is reinterpreted over a buffer of the wrong
    /// size, the status is overwritten with "OK" further down, and a confident
    /// `spent_status` comes back for an image nobody asked about. That makes
    /// 65 characters exactly as dangerous as 63, and a `<` in the guard would
    /// wave the whole upper half through.
    #[test]
    fn a_key_image_is_refused_on_both_sides_of_sixty_four_characters() {
        let exact = "1".repeat(KEY_IMAGE_HEX_LEN);
        let req = IsKeyImageSpentRequest::new(vec![exact.clone()]).unwrap();
        assert_eq!(req.key_images(), std::slice::from_ref(&exact));

        let short = "1".repeat(KEY_IMAGE_HEX_LEN - 1);
        assert_eq!(
            IsKeyImageSpentRequest::new(vec![short.clone()])
                .unwrap_err()
                .value,
            short,
            "63 characters"
        );

        let long = "1".repeat(KEY_IMAGE_HEX_LEN + 1);
        assert_eq!(
            IsKeyImageSpentRequest::new(vec![long.clone()])
                .unwrap_err()
                .value,
            long,
            "65 characters"
        );

        // The realistic over-long case: two real key images concatenated by a
        // caller that joined a list without a separator. Every character is a
        // hex digit, so width is the only thing that can refuse it.
        let doubled = "e3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d".repeat(2);
        assert_eq!(doubled.len(), 2 * KEY_IMAGE_HEX_LEN);
        let err = IsKeyImageSpentRequest::new(vec![exact, doubled.clone()]).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.value, doubled);
    }

    /// A v1 transaction with one key input of `ring` members and one
    /// `signatures` entry holding `sigs` concatenated signatures. Each
    /// signature ends in its own index so the split can be asserted by value.
    fn v1_with_ring_and_signature_count(ring: usize, sigs: usize) -> TxJson {
        let offsets: Vec<String> = (0..ring).map(|i| (i + 1).to_string()).collect();
        let entry: String = (0..sigs).map(|i| format!("{:0126}{i:02x}", 0)).collect();
        let raw = format!(
            r#"{{"version":1,"unlock_time":0,
                "vin":[{{"key":{{"amount":7000000000000,"key_offsets":[{}],"k_image":"122d48cf"}}}}],
                "vout":[],"extra":[],
                "signatures":["{entry}"]}}"#,
            offsets.join(",")
        );
        serde_json::from_str(&raw).unwrap()
    }

    /// `signatures[i]` is one flat string per input; the only thing tying it to
    /// `vin[i]` is its width. An entry wider than the ring means the two arrays
    /// are not aligned, and handing the caller the extra signatures presents
    /// five signatures for a two-member ring as if they belonged to it.
    #[test]
    fn a_signature_entry_is_refused_when_it_is_either_wider_or_narrower_than_its_ring() {
        let aligned = v1_with_ring_and_signature_count(2, 2);
        assert_eq!(
            aligned.ring_signatures_for_input(0).unwrap(),
            vec![
                format!("{:0126}{:02x}", 0, 0).as_str(),
                format!("{:0126}{:02x}", 0, 1).as_str()
            ],
            "the two signatures come back in order and uncut"
        );

        assert_eq!(
            v1_with_ring_and_signature_count(2, 5).ring_signatures_for_input(0),
            None,
            "five signatures against a two-member ring is a misalignment, not a ring of five"
        );
        assert_eq!(
            v1_with_ring_and_signature_count(3, 1).ring_signatures_for_input(0),
            None,
            "and one signature against a three-member ring is the same misalignment"
        );

        // Ring 1 is the narrowest aligned case, so the guard is an equality
        // rather than a threshold either side of it.
        assert_eq!(
            v1_with_ring_and_signature_count(1, 1)
                .ring_signatures_for_input(0)
                .unwrap()
                .len(),
            1
        );
    }

    /// `form()` classifies by width, and the mask's width is half that claim.
    /// A short mask beside a full-width amount is not a shape monerod emits;
    /// calling it Full hands a caller four bytes of mask where it expects 32.
    #[test]
    fn an_ecdh_mask_of_the_wrong_width_is_not_the_full_form() {
        let with_mask = |mask: &str| EcdhInfo {
            mask: Some(mask.to_owned()),
            amount: "d8a4356c".repeat(8),
        };
        assert_eq!(
            with_mask(&"48077bcc".repeat(8)).form(),
            Some(EcdhForm::Full)
        );
        assert_eq!(with_mask("deadbeef").form(), None, "8 characters");
        assert_eq!(with_mask("").form(), None, "an empty mask is not a mask");
        assert_eq!(
            with_mask(&"4".repeat(ECDH_FULL_HEX_LEN - 1)).form(),
            None,
            "63 characters"
        );
        assert_eq!(
            with_mask(&"4".repeat(ECDH_FULL_HEX_LEN + 1)).form(),
            None,
            "65 characters"
        );

        // Arriving off the wire rather than built here, since that is how a
        // malformed element would actually reach `form()`.
        let from_wire: EcdhInfo = serde_json::from_str(&format!(
            r#"{{"mask":"deadbeef","amount":"{}"}}"#,
            "d8a4356c".repeat(8)
        ))
        .unwrap();
        assert_eq!(from_wire.mask.as_deref(), Some("deadbeef"));
        assert_eq!(from_wire.form(), None);
    }

    // -----------------------------------------------------------------------
    // Predicates whose two halves have to be separable
    // -----------------------------------------------------------------------

    /// Build a split-form entry around a decoded document: the pruned prefix is
    /// present and the prunable half is empty, which is what a pruning node
    /// returns and also what `prune: true` produces on a complete one.
    fn split_entry(as_json: &str) -> TxEntry {
        TxEntry {
            tx_hash: "2917a83ec63c66b14922ec0383ea682d2e3c2708aaeb1434d15762d32984eb83".to_owned(),
            as_hex: String::new(),
            pruned_as_hex: "0100".to_owned(),
            prunable_as_hex: String::new(),
            prunable_hash: "0".repeat(64),
            as_json: as_json.to_owned(),
            in_pool: false,
            double_spend_seen: false,
            block_height: 134_721,
            confirmations: 140,
            block_timestamp: 1_789_744_451,
            output_indices: vec![],
            unified_ids: vec![],
            relayed: false,
            received_timestamp: 0,
        }
    }

    /// "One input, and it is a gen" -- both halves. Consensus permits no such
    /// transaction, but nothing in a parser rejects one, and calling it a
    /// coinbase routes it through the carve-outs in [`TxJson::looks_pruned`]
    /// and [`TxEntry::prunable_missing`] that exist only because a coinbase has
    /// no prunable half. A pruned transaction would then report as complete.
    #[test]
    fn a_gen_input_beside_a_key_input_is_not_a_coinbase() {
        const TWO_INPUTS: &str = r#"{"version":2,"unlock_time":0,
            "vin":[{"gen":{"height":2489000}},
                   {"key":{"amount":0,"key_offsets":[1,2],"k_image":"e3311388"}}],
            "vout":[{"amount":0,"target":{"key":"bb"}}],
            "extra":[1],
            "rct_signatures":{"type":5,"txnFee":30660000}}"#;
        let two: TxJson = serde_json::from_str(TWO_INPUTS).unwrap();
        assert_eq!(two.vin.len(), 2);
        assert!(two.vin[0].is_gen(), "the first input really is a gen");
        assert!(
            !two.is_coinbase(),
            "two inputs is not a coinbase however the first one is tagged"
        );
        assert!(
            two.looks_pruned(),
            "no rctsig_prunable on a type 5 non-coinbase is the pruned form; the \
             coinbase carve-out would answer `false` here"
        );
        assert!(
            split_entry(TWO_INPUTS).prunable_missing(&two),
            "and the entry must agree, rather than reporting a half it does not \
             have as nothing to lose"
        );

        // The other half of the conjunct: the same document with the key input
        // removed is a coinbase, and then the carve-outs are right.
        const ONE_INPUT: &str = r#"{"version":2,"unlock_time":0,
            "vin":[{"gen":{"height":2489000}}],
            "vout":[{"amount":0,"target":{"key":"bb"}}],
            "extra":[1],
            "rct_signatures":{"type":0}}"#;
        let one: TxJson = serde_json::from_str(ONE_INPUT).unwrap();
        assert!(one.is_coinbase());
        assert!(!one.looks_pruned());
        assert!(!split_entry(ONE_INPUT).prunable_missing(&one));
    }

    /// The database never prunes v1 transactions, so a v1 entry in split form
    /// whose prunable half is empty is complete. `version <= 1` and
    /// `version < 1` differ only at exactly 1, and every v1 fixture returns on
    /// the coinbase carve-out above this one, so this is the only place the
    /// boundary is decided.
    #[test]
    fn a_v1_non_coinbase_in_split_form_is_complete_rather_than_pruned() {
        const V1: &str = r#"{"version":1,"unlock_time":0,
            "vin":[{"key":{"amount":7000000000000,"key_offsets":[4732,5082],"k_image":"122d48cf"}}],
            "vout":[{"amount":9000000000,"target":{"key":"bb"}}],
            "extra":[1]}"#;
        let v1: TxJson = serde_json::from_str(V1).unwrap();
        assert_eq!(v1.version, 1);
        assert!(
            !v1.is_coinbase(),
            "so the coinbase carve-out cannot be what answers"
        );
        let entry = split_entry(V1);
        assert!(entry.as_hex.is_empty() && entry.prunable_as_hex.is_empty());
        assert!(
            !entry.prunable_missing(&v1),
            "v1 transactions are never pruned by the database"
        );

        // Version 2 through the very same entry is pruned, so the carve-out is
        // what decides the v1 case rather than something about the entry.
        const V2: &str = r#"{"version":2,"unlock_time":0,
            "vin":[{"key":{"amount":0,"key_offsets":[4732,5082],"k_image":"122d48cf"}}],
            "vout":[{"amount":0,"target":{"key":"bb"}}],
            "extra":[1],
            "rct_signatures":{"type":5,"txnFee":1}}"#;
        let v2: TxJson = serde_json::from_str(V2).unwrap();
        assert!(split_entry(V2).prunable_missing(&v2));
    }

    /// `looks_pruned` is the only cross-check left when the entry is gone and
    /// all that survives is the decoded document. For v1 the signal is the
    /// `signatures` key: `prune: true` drops it even though the database never
    /// prunes v1, and absent is a different fact from present-and-empty.
    #[test]
    fn a_v1_non_coinbase_that_lost_its_signatures_key_looks_pruned() {
        let doc = |signatures: &str| -> TxJson {
            serde_json::from_str(&format!(
                r#"{{"version":1,"unlock_time":0,
                    "vin":[{{"key":{{"amount":7000000000000,"key_offsets":[4732,5082],"k_image":"122d48cf"}}}}],
                    "vout":[{{"amount":9000000000,"target":{{"key":"bb"}}}}],
                    "extra":[1]{signatures}}}"#
            ))
            .unwrap()
        };

        let absent = doc("");
        assert!(
            !absent.is_coinbase(),
            "the coinbase carve-out returns above this"
        );
        assert!(absent.signatures.is_none());
        assert!(
            absent.looks_pruned(),
            "no signatures key on a v1 non-coinbase means the prunable half was dropped"
        );

        // Present and empty: a different fact, and not pruned.
        let empty = doc(r#","signatures":[]"#);
        assert_eq!(empty.signatures.as_deref(), Some(&[] as &[String]));
        assert!(!empty.looks_pruned());

        // And a document that still carries its ring signatures.
        let full = doc(&format!(r#","signatures":["{}"]"#, "ab".repeat(128)));
        assert_eq!(full.signatures.as_deref().unwrap().len(), 1);
        assert!(!full.looks_pruned());
    }

    // -----------------------------------------------------------------------
    // /get_transaction_pool, which no capture reaches
    // -----------------------------------------------------------------------

    /// Both local nodes have an empty mempool -- `tx_pool_size` is 0 on each --
    /// so `testnet/get_transaction_pool.json` exercises none of the
    /// per-transaction fields. This is the response shape monerod emits for one
    /// pooled transaction, built from the spec.
    ///
    /// `tx_json` is a JSON document encoded as a string and `tx_blob` is the
    /// raw transaction in hex. Both are strings, both are non-empty, and both
    /// are named `tx_*`, so only the *content* of what comes back can say which
    /// one was decoded.
    #[test]
    fn a_pool_entry_decodes_its_tx_json_and_not_its_tx_blob() {
        const TX_JSON: &str = r#"{"version":2,"unlock_time":0,"vin":[{"key":{"amount":0,"key_offsets":[8608351,301575],"k_image":"e3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d"}}],"vout":[{"amount":0,"target":{"key":"570482291c53c3b5c4e0d0d6b6cf0bb4e55c9d3dd1b6f7f21c6e7e1e3f5a9b0d"}}],"extra":[1,39,23],"rct_signatures":{"type":5,"txnFee":30660000,"ecdhInfo":[{"amount":"64717b40fad782d9"}],"outPk":["b415d82ed00290c26a681ebfec0c78540e56e5a700193de7a9960a0429f9c28a"]}}"#;
        // A real mainnet prefix: version 2, one input, the same key image.
        const TX_BLOB: &str = "02000102000bd7f21f9f04a903d40ae501de1ca80be3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d";

        let raw = serde_json::json!({
            "credits": 0,
            "status": "OK",
            "top_hash": "",
            "untrusted": false,
            "spent_key_images": [{
                "id_hash": "e3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d",
                "txs_hashes": ["b3735b7c4196fac2da5b9838fc1db079f33a2bce42ff2bb12adf790cf0ebcf92"],
            }],
            "transactions": [{
                "id_hash": "b3735b7c4196fac2da5b9838fc1db079f33a2bce42ff2bb12adf790cf0ebcf92",
                "tx_json": TX_JSON,
                "blob_size": 1533u64,
                "weight": 1533u64,
                "fee": 30_660_000u64,
                "max_used_block_id_hash":
                    "3bc71f5db726561d444e1141652cfee863d69446ad1543f476ce768264eff97c",
                "max_used_block_height": 2_488_999u64,
                "kept_by_block": false,
                "last_failed_height": 0u64,
                "last_failed_id_hash": "0".repeat(64),
                "receive_time": 1_632_000_000u64,
                "relayed": true,
                "last_relayed_time": 1_632_000_060u64,
                "do_not_relay": false,
                "double_spend_seen": false,
                "tx_blob": TX_BLOB,
            }],
        });

        let pool: GetTransactionPool = serde_json::from_value(raw).unwrap();
        assert_eq!(pool.transactions.len(), 1);
        let info = &pool.transactions[0];
        assert_eq!(info.fee, 30_660_000);
        assert_eq!(info.blob_size, 1533);
        assert!(info.relayed && !info.do_not_relay);
        assert!(
            !info.tx_blob.is_empty(),
            "the blob is populated, so parsing it instead of the document is a \
             mistake this test can actually see"
        );

        let tx = info.parse_json().expect("tx_json is a JSON document");
        assert_eq!(tx.version, 2);
        assert_eq!(tx.rct_type(), Some(RctType::Clsag));
        assert_eq!(
            tx.vin[0].as_key().unwrap().k_image,
            "e3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d"
        );
        assert_eq!(
            tx.rct_signatures.as_ref().unwrap().txn_fee,
            Some(30_660_000)
        );
        assert_eq!(tx.extra, vec![1u8, 39, 23]);

        // The blob is hex and therefore not a JSON document: pointing the parse
        // at it is a hard failure, not a subtly different answer.
        assert!(matches!(
            parse_nested_json::<TxJson>(&info.tx_blob),
            Err(NestedJsonError::Malformed(_))
        ));

        // A pooled key image is reported under `id_hash`, despite the name.
        assert_eq!(pool.spent_key_images.len(), 1);
        assert_eq!(
            pool.spent_key_images[0].id_hash,
            "e3311388ec6d562424dc71ae1ad1913b97dee6e94d3f5da676140758dd8add2d"
        );
        assert_eq!(
            pool.spent_key_images[0].txs_hashes,
            vec!["b3735b7c4196fac2da5b9838fc1db079f33a2bce42ff2bb12adf790cf0ebcf92"]
        );
    }

    /// `weight` is `KV_SERIALIZE_OPT(0)` and `tx_json` is empty when the pool
    /// was fetched without decoding, so both go missing on ordinary responses.
    #[test]
    fn a_pool_entry_survives_its_optional_fields_going_missing() {
        let raw = serde_json::json!({
            "id_hash": "b3735b7c4196fac2da5b9838fc1db079f33a2bce42ff2bb12adf790cf0ebcf92",
            "blob_size": 1533u64,
            "fee": 30_660_000u64,
            "max_used_block_id_hash": "0".repeat(64),
            "max_used_block_height": 0u64,
            "kept_by_block": false,
            "last_failed_height": 0u64,
            "last_failed_id_hash": "0".repeat(64),
            "receive_time": 1_632_000_000u64,
            "relayed": true,
            "last_relayed_time": 1_632_000_060u64,
            "do_not_relay": false,
            "double_spend_seen": false,
            "tx_blob": "0200",
        });
        let info: PoolTxInfo = serde_json::from_value(raw).unwrap();
        assert_eq!(info.weight, 0);
        assert!(info.tx_json.is_empty());
        assert!(
            matches!(info.parse_json(), Err(NestedJsonError::Absent)),
            "an undecoded pool entry is absent, not malformed"
        );
    }

    /// Every way a path answer can be malformed is refused, not read short:
    /// each case is the captured answer as of block 814 with one thing
    /// wrong.
    #[test]
    fn a_malformed_path_answer_is_refused() {
        use crate::epee::{Root, Value, encode_root, read_root};

        const IDS: [u64; 4] = [802, 803, 804, 805];
        let bin = include_bytes!("../../../fixtures/fcmp/paths/get_path_by_unified_id_later.bin");
        let answer = read_root(bin, PathQuery::WANTED).unwrap();

        /// `root` with `name` given `f` of its value, and left out where `f`
        /// gives nothing.
        fn with(root: &Root, name: &str, f: impl Fn(&Value) -> Option<Value>) -> Root {
            Root::new(
                root.entries()
                    .iter()
                    .filter_map(|(k, v)| {
                        if k == name {
                            f(v).map(|v| (k.clone(), v))
                        } else {
                            Some((k.clone(), v.clone()))
                        }
                    })
                    .collect(),
            )
        }
        fn section(v: &Value) -> &Root {
            let Value::Section(s) = v else {
                panic!("a section")
            };
            s
        }
        // The answer with its first path's `path` section given `f`.
        let first_path = |f: &dyn Fn(&Root) -> Root| -> Root {
            with(&answer, "paths", |v| {
                let Value::Array(paths) = v else {
                    panic!("paths")
                };
                let mut paths = paths.clone();
                paths[0] = Value::Section(with(section(&paths[0]), "path", |p| {
                    Some(Value::Section(f(section(p))))
                }));
                Some(Value::Array(paths))
            })
        };
        let leaves = |name: &'static str, f: fn(&mut Vec<u8>)| {
            first_path(&move |p: &Root| {
                with(p, "leaves", |l| {
                    Some(Value::Section(with(section(l), name, |b| {
                        let Value::Bytes(b) = b else { panic!("bytes") };
                        let mut b = b.clone();
                        f(&mut b);
                        Some(Value::Bytes(b))
                    })))
                })
            })
        };
        let chunk = |f: fn(&mut Vec<u8>)| {
            first_path(&move |p: &Root| {
                with(p, "layer_chunks", |c| {
                    let Value::Array(chunks) = c else {
                        panic!("chunks")
                    };
                    let mut chunks = chunks.clone();
                    chunks[0] = Value::Section(with(section(&chunks[0]), "elems", |e| {
                        let Value::Bytes(e) = e else { panic!("elems") };
                        let mut e = e.clone();
                        f(&mut e);
                        Some(Value::Bytes(e))
                    }));
                    Some(Value::Array(chunks))
                })
            })
        };
        let read = |root: &Root, ids: &[u64]| {
            let bytes = encode_root(root).unwrap();
            PathQuery::as_of_block(814, ids)
                .unwrap()
                .answer(&read_root(&bytes, PathQuery::WANTED).unwrap())
        };

        // Unchanged, it reads, re-encoded as it is.
        assert_eq!(read(&answer, &IDS).unwrap().paths.len(), 4);

        let malformed = PathAnswerError::Malformed;
        for (what, root, why) in [
            (
                "an id short",
                leaves("unified_ids", |b| b.truncate(b.len() - 1)),
                malformed("leaves"),
            ),
            (
                "a key short",
                leaves("output_pubkeys", |b| b.truncate(b.len() - 1)),
                malformed("leaves"),
            ),
            (
                "a commitment short",
                leaves("commitments", |b| b.truncate(b.len() - 1)),
                malformed("leaves"),
            ),
            (
                "a type too many",
                leaves("output_types", |b| b.push(0)),
                malformed("leaves"),
            ),
            (
                "an empty chunk",
                chunk(Vec::clear),
                malformed("layer_chunks"),
            ),
            (
                "a byte past a point",
                chunk(|e| e.push(0)),
                malformed("layer_chunks"),
            ),
            (
                "no layers",
                first_path(&|p: &Root| with(p, "layer_chunks", |_| None)),
                malformed("layer_chunks"),
            ),
            (
                "layers with no leaves",
                first_path(&|p: &Root| {
                    with(p, "leaves", |_| Some(Value::Section(Root::default())))
                }),
                malformed("leaves"),
            ),
            (
                "no n_leaf_tuples",
                with(&answer, "n_leaf_tuples", |_| None),
                PathAnswerError::Missing("n_leaf_tuples"),
            ),
        ] {
            assert_eq!(read(&root, &IDS), Err(why), "{what}");
        }
        // Paths that are not sections.
        let not_a_section = with(&answer, "paths", |_| {
            Some(Value::Array(vec![Value::Unsigned(1); 4]))
        });
        assert_eq!(read(&not_a_section, &IDS), Err(malformed("entry")));

        // As many paths as ids, neither more nor fewer.
        for ids in [&IDS[..3], &[802, 803, 804, 805, 806][..]] {
            assert_eq!(
                read(&answer, ids),
                Err(PathAnswerError::Count {
                    asked: ids.len(),
                    answered: 4
                })
            );
        }
    }
}
