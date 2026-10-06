//! `/api/*` request handling.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use explorer_core::fmt::{decimal, timestamp_utc};
use explorer_core::{
    BlockId, BlockIdError, BlockTree, ChainError, Hash32, RpcChainSource, unexpanded_inputs,
};
use monerod_rpc::types::{GetTxidsLooseRequest, TxEntry, TxJson, wallet_grace_blocks};
use serde::Serialize;

use super::envelope::{ApiError, ApiOk, ApiPath, ApiQuery};
use super::shapes::{BlockDetail, TxDetail, TxSummary, normalise_hash};
use crate::config::Limits;

pub struct AppState {
    pub chain: RpcChainSource,
    /// The bounds on the k-anonymous endpoints, from the command line.
    pub limits: Limits,
    /// Checked paths through the curve tree. See [`crate::tree_paths::PathCache`].
    pub paths: crate::tree_paths::PathCache,
    /// The last `/api/transactions/recent` answer. See [`RecentAnswer`].
    pub recent: RecentAnswer,
    /// What the pages' tables show of each transaction.
    pub rows: crate::html::RowCache,
}

/// The last `/api/transactions/recent` answer, written out, with the tip and
/// the pool it was built from.
///
/// Every caller asks for the same window, so the answer is the same for all
/// of them until a block arrives or the pool changes: the tip's hash names
/// the window and the chain below it, and the pool is named by what the
/// answer reads of it, each transaction's hash and arrival in order. Built by
/// one caller at a time, and a caller that waited for another's build takes
/// that answer, whatever arrived meanwhile, so a wave of callers costs one
/// build however long it takes.
#[derive(Default)]
pub struct RecentAnswer {
    kept: std::sync::Mutex<Option<KeptRecent>>,
    turn: tokio::sync::Mutex<()>,
}

struct KeptRecent {
    tip: String,
    pool: Vec<(String, u64)>,
    built: u64,
    body: axum::body::Bytes,
}

/// What a recent answer reads of `pool`, in order.
fn pool_key(pool: &explorer_core::rpc_source::Mempool) -> Vec<(String, u64)> {
    pool.transactions
        .iter()
        .map(|t| (t.id_hash.clone(), t.receive_time))
        .collect()
}

impl RecentAnswer {
    fn get(&self, tip: &str, pool: &[(String, u64)]) -> Option<axum::body::Bytes> {
        let kept = self.kept.lock().ok()?;
        kept.as_ref()
            .filter(|k| k.tip == tip && k.pool == pool)
            .map(|k| k.body.clone())
    }

    /// How many answers have been built, to tell one built since.
    fn built(&self) -> u64 {
        self.kept
            .lock()
            .ok()
            .and_then(|k| k.as_ref().map(|k| k.built))
            .unwrap_or(0)
    }

    /// The answer built after the `since`th, if there is one.
    fn since(&self, since: u64) -> Option<axum::body::Bytes> {
        let kept = self.kept.lock().ok()?;
        kept.as_ref()
            .filter(|k| k.built > since)
            .map(|k| k.body.clone())
    }

    fn keep(&self, tip: String, pool: Vec<(String, u64)>, body: axum::body::Bytes) {
        if let Ok(mut kept) = self.kept.lock() {
            let built = kept.as_ref().map_or(0, |k| k.built).saturating_add(1);
            *kept = Some(KeptRecent {
                tip,
                pool,
                built,
                body,
            });
        }
    }
}

pub type Shared = State<Arc<AppState>>;

/// The length of a hash written out, which is the longest argument any route
/// here accepts.
const HASH_TEXT_LEN: usize = 64;

/// A caller's argument, on its way back into an error message.
///
/// Bounded, because the argument comes from a URL and the message it lands in
/// is read by a person. A well formed argument is at most 64 characters, so
/// anything this truncates was wrong already.
pub fn echo(arg: &str) -> String {
    if arg.chars().count() <= HASH_TEXT_LEN {
        return arg.to_owned();
    }
    let mut out: String = arg.chars().take(HASH_TEXT_LEN).collect();
    out.push_str("...");
    out
}

/// Map a chain failure onto an answer.
///
/// Not found and a range too large are the caller's; a full budget is ours,
/// for now; anything else is ours or the daemon's.
fn on_chain_error(e: &ChainError, what: &str) -> ApiError {
    match e {
        _ if e.is_not_found() => ApiError::not_found(what.to_owned()),
        ChainError::RangeTooLarge { .. } => ApiError::bad_request(e.public_message()),
        ChainError::Busy(_) => ApiError::busy(e.public_message()),
        ChainError::NeedsUnrestricted(_) => ApiError::unsupported(e.public_message()),
        _ => {
            // The operator gets the detail; the client does not. See
            // ChainError::public_message.
            tracing::warn!("{what}: {e}");
            ApiError::daemon(e.public_message())
        }
    }
}

// ---------------------------------------------------------------------------
// /api/version
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct VersionData {
    /// `(major << 16) | minor`. We implement the 1.3 shapes, so 65539.
    api: u64,
    blockchain_height: u64,
    /// Empty: oxblocks does not embed build metadata. The keys exist because
    /// clients index them; inventing values would be worse than admitting we
    /// have none.
    git_branch_name: String,
    last_git_commit_date: String,
    last_git_commit_hash: String,
    monero_version_full: String,
    /// An extra key, so a client can tell which explorer answered rather
    /// than guess from the absence of a commit hash.
    oxblocks_version: String,
}

pub async fn version(State(state): Shared) -> Result<ApiOk<VersionData>, ApiError> {
    let info = state
        .chain
        .info()
        .await
        .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;

    Ok(ApiOk(VersionData {
        api: (1 << 16) | 3,
        blockchain_height: info.height,
        git_branch_name: String::new(),
        last_git_commit_date: String::new(),
        last_git_commit_hash: String::new(),
        monero_version_full: info.version.clone(),
        oxblocks_version: env!("CARGO_PKG_VERSION").to_owned(),
    }))
}

// ---------------------------------------------------------------------------
// /api/transaction/<hash>
// ---------------------------------------------------------------------------

/// The transaction `raw` names, as the daemon holds it.
async fn fetch_tx(state: &AppState, raw: &str) -> Result<(Hash32, TxEntry), ApiError> {
    let hash: Hash32 = raw
        .parse()
        .map_err(|_| ApiError::bad_request(format!("Cant parse tx hash: {}", echo(raw))))?;
    let fetched = state
        .chain
        .transactions(std::slice::from_ref(&hash))
        .await
        .map_err(|e| on_chain_error(&e, &format!("Cant get tx: {hash}")))?;
    let entry = fetched
        .txs
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::not_found(format!("Cant find tx: {hash}")))?;
    Ok((hash, entry))
}

/// The transaction's own JSON, decoded. What did not decode is logged for the
/// operator; the caller is told only that it did not.
fn decode_tx(hash: &Hash32, entry: &TxEntry) -> Result<TxJson, ApiError> {
    entry.parse_json().map_err(|e| {
        tracing::warn!("tx {hash} did not decode: {e}");
        ApiError::daemon(format!("Cant parse tx {hash}"))
    })
}

pub async fn transaction(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<TxDetail>, ApiError> {
    let (hash, entry) = fetch_tx(&state, &raw).await?;
    let entry = &entry;
    let tx = decode_tx(&hash, entry)?;

    // One /get_outs for the transaction, and one per input where monerod
    // refuses that, so one bad input cannot blank every ring on the page.
    let rings = state.chain.resolve_rings(&tx).await;

    // A confirmed transaction already carries its confirmation count, so the
    // tip can be derived without a second round trip. A pool transaction has
    // neither, and needs one.
    let current_height = if entry.in_pool {
        state
            .chain
            .info()
            .await
            .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?
            .height
    } else {
        entry.block_height.saturating_add(entry.confirmations)
    };

    let mut detail = TxDetail::build(entry, &tx, &rings, current_height);
    // Only this handler pays for the tree size, for /api/transaction and for
    // /api/search on a transaction: it is one daemon call, and the list
    // endpoints would pay it once per transaction listed.
    detail.anonymity_set = state.chain.anonymity_set(&tx, entry, current_height).await;
    Ok(ApiOk(detail))
}

// ---------------------------------------------------------------------------
// /api/transaction/<hash>/paths
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PathsData {
    as_of_block: u64,
    n_layers: usize,
    n_leaf_tuples: u64,
    outputs: Vec<OutputPathData>,
    root: Option<String>,
    /// The block carrying the root of the tree as of `as_of_block`, and that
    /// root, where the block carries one.
    root_block: Option<u64>,
    /// `matches` when every path's hashes hold and end at `root`, `fails`
    /// when one does not, `unchecked` when there is no root or no path.
    root_check: &'static str,
    tx_hash: String,
}

#[derive(Serialize)]
pub struct OutputPathData {
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<&'static str>,
    /// The leaves' group first, the root last.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<GroupData>,
    index: usize,
    /// The last block the output is locked at; the tree holds it as of that
    /// block on.
    last_locked_block: u64,
    /// Absent for an output not in the tree as of `as_of_block`.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_idx: Option<u64>,
    unified_id: u64,
}

#[derive(Serialize)]
pub struct GroupData {
    curve: explorer_core::curve_tree::Curve,
    layer: usize,
    layer_size: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    leaves: Vec<LeafData>,
    /// Compressed points; absent for the leaves, which are in `leaves`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<String>,
    /// The output's ancestor's place in the group, or the output's own for
    /// the leaves.
    offset: u64,
    start: u64,
}

#[derive(Serialize)]
pub struct LeafData {
    commitment: String,
    kind: &'static str,
    output_key: String,
    unified_id: u64,
}

/// Paths through the curve tree of a transaction's outputs, as of `block` or
/// the tip: output `output` alone, counted from 1, or up to
/// [`crate::tree_paths::MAX_OUTPUTS`] of them from `from`, counted from 0.
pub async fn transaction_paths(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
    ApiQuery(q): ApiQuery<crate::tree_paths::PathsParams>,
) -> Result<ApiOk<PathsData>, ApiError> {
    use crate::tree_paths::{PathsError, gather};
    use explorer_core::curve_tree::Curve;
    use monerod_rpc::types::LeafKind;

    let q = q.read().map_err(ApiError::bad_request)?;

    let (hash, entry) = fetch_tx(&state, &raw).await?;
    let entry = &entry;
    let tx = decode_tx(&hash, entry)?;

    let paths = match q.outputs(tx.vout.len()) {
        Ok(which) => gather(&state, entry, &tx, q.block, which).await,
        Err(e) => Err(e),
    }
    .map_err(|e| match e {
        PathsError::InPool => {
            ApiError::not_found(format!("Tx {hash} is in the pool, so not in the tree"))
        }
        PathsError::NoIds => ApiError::unsupported("The daemon has no curve tree".to_owned()),
        PathsError::Ahead { asked, tip } => {
            ApiError::not_found(format!("Block {asked} is past the tip, {tip}"))
        }
        PathsError::NoSuchOutput { asked, total } => {
            ApiError::not_found(format!("Tx {hash} has {total} outputs, not output {asked}"))
        }
        PathsError::NoSuchOutputs { from, total } => {
            ApiError::not_found(format!("Tx {hash} has {total} outputs, none from {from}"))
        }
        PathsError::Chain(e) => on_chain_error(&e, &format!("Cant get paths of tx: {hash}")),
    })?;

    let outputs = paths
        .outputs
        .iter()
        .map(|o| {
            let placed = o.placed.as_ref();
            OutputPathData {
                index: o.index,
                unified_id: o.unified_id,
                last_locked_block: o.last_locked_block,
                leaf_idx: placed.map(|p| p.path.leaf_idx),
                check: placed.map(|p| p.check.as_str()),
                groups: placed
                    .map(|p| {
                        p.groups
                            .iter()
                            .map(|g| GroupData {
                                layer: g.layer,
                                curve: Curve::of_layer(g.layer),
                                layer_size: g.layer_size,
                                start: g.start,
                                offset: g.offset(),
                                members: p
                                    .members(g.layer)
                                    .unwrap_or_default()
                                    .iter()
                                    .map(explorer_core::hex::encode)
                                    .collect(),
                                leaves: if g.layer == 0 {
                                    p.path
                                        .leaves
                                        .iter()
                                        .map(|l| LeafData {
                                            unified_id: l.unified_id,
                                            kind: match l.kind {
                                                LeafKind::Legacy => "legacy",
                                                LeafKind::Carrot => "carrot",
                                                LeafKind::Other(_) => "unknown",
                                            },
                                            output_key: explorer_core::hex::encode(l.output_key),
                                            commitment: explorer_core::hex::encode(l.commitment),
                                        })
                                        .collect()
                                } else {
                                    Vec::new()
                                },
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    Ok(ApiOk(PathsData {
        tx_hash: hash.to_string(),
        as_of_block: paths.as_of_block,
        n_leaf_tuples: paths.n_leaf_tuples,
        n_layers: monerod_rpc::types::tree_layers(paths.n_leaf_tuples).len(),
        root_block: paths.root_block.as_ref().map(|(b, _)| *b),
        root: paths.root_block.as_ref().map(|(_, r)| r.clone()),
        root_check: paths.root_check().as_str(),
        outputs,
    }))
}

// ---------------------------------------------------------------------------
// /api/block/<height|hash>
// ---------------------------------------------------------------------------

/// Wrap [`BlockId::parse`] in the wording the API uses, which differs by
/// which shape was attempted.
fn parse_block_id(arg: &str) -> Result<BlockId, ApiError> {
    BlockId::parse(arg).map_err(|e| match e {
        BlockIdError::NotAHash => {
            ApiError::bad_request(format!("Cant parse blk hash: {}", echo(arg)))
        }
        BlockIdError::NotAHeight | BlockIdError::Unrecognised => {
            ApiError::bad_request(format!("Cant find blk using search string: {}", echo(arg)))
        }
    })
}

/// How a missing block is worded, which differs by how it was asked for.
///
/// For a hash the message carries **literal angle brackets** around a
/// lowercased hash. They are part of the message, not a placeholder for one.
fn block_not_found(id: BlockId) -> String {
    match id {
        BlockId::Height(h) => format!("Cant get block: {h}"),
        BlockId::Hash(h) => format!("Cant get block: <{h}>"),
    }
}

pub async fn block(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<BlockDetail>, ApiError> {
    let id = parse_block_id(&raw)?;
    Ok(ApiOk(build_block_detail(&state, id).await?))
}

/// Assemble one block's API representation.
///
/// Shared by `/api/block` and `/api/blocks/<start>/<end>`, because the element
/// type of the range response is exactly the single-block response.
async fn build_block_detail(state: &AppState, id: BlockId) -> Result<BlockDetail, ApiError> {
    let got = state
        .chain
        .block(id)
        .await
        .map_err(|e| on_chain_error(&e, &block_not_found(id)))?;

    let (fetched, _held) = state
        .chain
        .block_transactions(&got)
        .await
        .map_err(|e| on_chain_error(&e, &block_not_found(id)))?;

    // A cached block carries the depth it had when fetched; the answer counts
    // from the tip as it is now. See `RpcChainSource::depth_now`.
    let depth = state.chain.depth_now(&got.block_header).await;
    Ok(BlockDetail::build(
        &got.block_header,
        depth,
        &fetched.txs,
        BlockTree::of(&got).as_ref(),
    ))
}

// ---------------------------------------------------------------------------
// /api/rawblock/<height|hash> and /api/rawtransaction/<hash>
// ---------------------------------------------------------------------------

/// The block exactly as monerod decoded it.
///
/// `data` is `get_block`'s nested `json` string, reparsed and re-serialised.
/// monerod emits that document in *declaration* order (`major_version,
/// minor_version, timestamp, prev_id, nonce, miner_tx, tx_hashes`), and every
/// response here sorts its keys, so the string cannot be forwarded verbatim.
pub async fn raw_block(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<serde_json::Value>, ApiError> {
    let id = parse_block_id(&raw)?;

    let got = state
        .chain
        .block(id)
        .await
        .map_err(|e| on_chain_error(&e, &block_not_found(id)))?;

    let value: serde_json::Value = serde_json::from_str(&got.json)
        .map_err(|_| ApiError::daemon("Faild parsing raw blk data into json".to_owned()))?;
    Ok(ApiOk(value))
}

pub async fn raw_transaction(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<serde_json::Value>, ApiError> {
    let (_, entry) = fetch_tx(&state, &raw).await?;

    let value: serde_json::Value = serde_json::from_str(&entry.as_json)
        .map_err(|_| ApiError::daemon("Faild parsing raw tx data into json".to_owned()))?;
    Ok(ApiOk(value))
}

// ---------------------------------------------------------------------------
// /api/feeestimate
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeeData {
    fee: u64,
    /// The same number as `fee`. monerod returns a per-byte estimate, and
    /// this key kept its name from before the per-byte switch.
    fee_per_kb: u64,
    grace_blocks: u64,
}

#[derive(serde::Deserialize)]
pub struct GraceQuery {
    grace_blocks: Option<String>,
}

pub async fn fee_estimate(
    State(state): Shared,
    ApiQuery(q): ApiQuery<GraceQuery>,
) -> Result<ApiOk<FeeData>, ApiError> {
    // Absent, it is the window wallets use. A value that is not a number of
    // at most MAX_GRACE_BLOCKS is refused, as every argument here is.
    let most = monerod_rpc::types::MAX_GRACE_BLOCKS;
    let grace_blocks = match q.grace_blocks.as_deref() {
        None => wallet_grace_blocks(tip_hard_fork(&state).await),
        Some(text) => decimal(text).filter(|&g| g <= most).ok_or_else(|| {
            ApiError::bad_request(format!(
                "grace_blocks is not a number of at most {most}: {}",
                echo(text)
            ))
        })?,
    };

    let estimate = state
        .chain
        .fee_estimate(grace_blocks)
        .await
        .map_err(|_| ApiError::daemon("Cant get dynamic fee estimate".to_owned()))?;

    Ok(ApiOk(FeeData {
        fee: estimate.fee,
        fee_per_kb: estimate.fee,
        grace_blocks,
    }))
}

/// The tip's hard-fork version, or 0 if the daemon cannot say. The tip
/// block's `major_version` is the active version.
async fn tip_hard_fork(state: &AppState) -> u8 {
    state
        .chain
        .last_block_header()
        .await
        .map_or(0, |h| h.block_header.major_version)
}

// ---------------------------------------------------------------------------
// /api/transactions and /api/mempool
// ---------------------------------------------------------------------------

/// The largest `limit` `/api/transactions` will honour.
///
/// Every block in a page costs a network round trip to the daemon: one
/// `get_block` for each block that holds transactions, because headers carry
/// no `tx_hashes`, plus one `get_transactions` for the page. Without a cap a
/// single unauthenticated `?limit=200` took 19 seconds of daemon work and
/// returned 4 MB, and the header range cap of 1000 let one request reach a
/// thousand blocks. At this cap a page costs 52 calls on a full chain and 3 on
/// a quiet one, measured.
///
/// A larger `limit` is refused rather than clamped, so a caller never receives
/// a page it did not ask for.
pub const MAX_TRANSACTIONS_LIMIT: u64 = 50;

/// The largest `limit` `/api/mempool` will honour.
///
/// Bounded by the pool's own size in practice, so this is a ceiling on
/// response size rather than on daemon work.
pub const MAX_MEMPOOL_LIMIT: u64 = 500;

#[derive(serde::Deserialize)]
pub struct PageQuery {
    page: Option<String>,
    limit: Option<String>,
}

impl PageQuery {
    /// Read `page` and `limit`.
    ///
    /// A parameter that is present but is not a plain number is refused. The
    /// alternative is to answer a question the caller did not ask, which is
    /// worse than saying no.
    fn parse(&self, default_limit: u64, max_limit: u64) -> Result<(u64, u64), ApiError> {
        fn number(name: &str, given: Option<&String>) -> Result<Option<u64>, ApiError> {
            match given {
                None => Ok(None),
                Some(text) => decimal(text).map(Some).ok_or_else(|| {
                    ApiError::bad_request(format!("{name} is not a number: {}", echo(text)))
                }),
            }
        }

        let page = number("page", self.page.as_ref())?.unwrap_or(0);
        let limit = number("limit", self.limit.as_ref())?.unwrap_or(default_limit);
        if limit > max_limit {
            return Err(ApiError::bad_request(format!(
                "limit is at most {max_limit} on this endpoint: {limit}"
            )));
        }
        Ok((page, limit))
    }
}

#[derive(Serialize)]
pub struct BlockRow {
    age: String,
    hash: String,
    height: u64,
    /// A JSON **float** here, and an integer in `/api/block`. The two
    /// endpoints report one value in two types: on one block that is 95511.0
    /// against 95511.
    size: f64,
    timestamp: u64,
    timestamp_utc: String,
    txs: Vec<TxSummary>,
}

#[derive(Serialize)]
pub struct TransactionsData {
    blocks: Vec<BlockRow>,
    current_height: u64,
    limit: u64,
    page: u64,
    total_page_no: u64,
}

pub async fn transactions(
    State(state): Shared,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> Result<ApiOk<TransactionsData>, ApiError> {
    let (page, limit) = q.parse(25, MAX_TRANSACTIONS_LIMIT)?;

    let info = state
        .chain
        .info()
        .await
        .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;
    let height = info.height;

    // A large `page` wraps modulo 2^64 and lands back on recent blocks
    // instead of erroring. The wrap is written out, because this build keeps
    // overflow-checks on in release and would otherwise panic.
    let span = limit.wrapping_mul(page.wrapping_add(1));
    #[allow(
        clippy::cast_possible_wrap,
        reason = "the wrap is deliberate, see above"
    )]
    let start_signed = (height.wrapping_sub(span)) as i64;
    #[allow(clippy::cast_sign_loss, reason = "max(0) has already removed the sign")]
    let start = start_signed.max(0) as u64;
    // The page is `limit` blocks up from its clamped start, which is how
    // xmrblocks pages: the last page, whose start clamps to 0, repeats blocks
    // the page before it listed, and pages past it list those same blocks.
    // Kept, because clients page this endpoint by that arithmetic.
    let end = start.saturating_add(limit).min(height).saturating_sub(1);

    let mut blocks = Vec::new();
    if start < height && limit > 0 {
        // One fan-out for the whole page rather than two calls per block. The
        // partially-built array still travels with the error. It is empty
        // here, since a batch either arrives or does not.
        let fetched = state
            .chain
            .blocks_in_range(start, end, false)
            .await
            .map_err(|e| {
                let partial = serde_json::json!({ "blocks": [] });
                match e {
                    _ if e.is_not_found() => {
                        ApiError::not_found(format!("Cant get block: {start}"))
                    }
                    ChainError::RangeTooLarge { .. } | ChainError::Busy(_) => {
                        on_chain_error(&e, "")
                    }
                    _ => {
                        tracing::warn!("blocks {start} to {end}: {e}");
                        ApiError::daemon(format!("Cant get transactions in block: {start}"))
                    }
                }
                .with_partial(partial)
            })?;

        // Newest first, which is the order a page of recent blocks is read in.
        for block in fetched.iter().rev() {
            let header = &block.header;
            blocks.push(BlockRow {
                age: explorer_core::fmt::age(explorer_core::fmt::now(), header.timestamp),
                hash: normalise_hash(&header.hash),
                height: header.height,
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "this endpoint reports the value as a float and \
                              /api/block reports it as an integer, and block \
                              weights are far below 2^53 in any case"
                )]
                size: header.block_size as f64,
                timestamp: header.timestamp,
                timestamp_utc: timestamp_utc(header.timestamp),
                txs: block
                    .txs
                    .iter()
                    .filter_map(|e| e.parse_json().ok().map(|tx| TxSummary::build(e, &tx)))
                    .collect(),
            });
        }
    }

    Ok(ApiOk(TransactionsData {
        blocks,
        current_height: height,
        limit,
        page,
        // Ceiling division. Flooring would leave the final partial page
        // uncounted, and a client that trusts the number then stops one page
        // early and never sees the oldest blocks. Guards a zero limit.
        total_page_no: if limit == 0 {
            0
        } else {
            height.div_ceil(limit)
        },
    }))
}

#[derive(Serialize)]
pub struct MempoolData {
    limit: u64,
    page: u64,
    total_page_no: u64,
    txs: Vec<serde_json::Value>,
    txs_no: u64,
}

pub async fn mempool(
    State(state): Shared,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> Result<ApiOk<MempoolData>, ApiError> {
    // Capped by default rather than only when asked, for the reason on
    // MAX_MEMPOOL_LIMIT.
    let (page, limit) = q.parse(MAX_MEMPOOL_LIMIT, MAX_MEMPOOL_LIMIT)?;

    let pool = state.chain.mempool().await.map_err(|e| {
        tracing::warn!("mempool: {e}");
        ApiError::daemon(e.public_message())
    })?;

    let txs_no = pool.transactions.len() as u64;
    let skip = page.saturating_mul(limit);

    let mut txs = Vec::new();
    for info in pool
        .transactions
        .iter()
        // try_from rather than `as`: on a 32-bit target a u64 beyond
        // usize::MAX would truncate to a small number and silently skip the
        // wrong rows. Saturating is the honest reading of "past the end".
        .skip(usize::try_from(skip).unwrap_or(usize::MAX))
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
    {
        let Ok(tx) = info.parse_json() else { continue };
        // A pool transaction has no block, so its size is the pool entry's own
        // blob size rather than a reassembled hex blob.
        let mut value = match serde_json::to_value(TxSummary::build_pool(info, &tx)) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(map) = value.as_object_mut() {
            map.insert("timestamp".to_owned(), serde_json::json!(info.receive_time));
            map.insert(
                "timestamp_utc".to_owned(),
                serde_json::json!(timestamp_utc(info.receive_time)),
            );
        }
        txs.push(value);
    }

    Ok(ApiOk(MempoolData {
        limit,
        page,
        total_page_no: if limit == 0 {
            0
        } else {
            txs_no.div_ceil(limit)
        },
        txs,
        txs_no,
    }))
}

// ---------------------------------------------------------------------------
// /api/search/<height|hash>
// ---------------------------------------------------------------------------

/// Search dispatches on the *shape* of the argument: a short decimal string is
/// a height, a 64-character hex string is tried as a block hash and then as a
/// transaction hash.
///
/// The result is the matching block or transaction object with a `title`
/// naming which it is, so a client can tell them apart without re-inspecting
/// the fields.
///
/// Monero has no address index, so an address is not searchable here and
/// never can be without one. Saying so is more useful than a bare failure.
pub async fn search(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<serde_json::Value>, ApiError> {
    let shown = echo(&raw);

    match BlockId::parse(&raw) {
        Ok(BlockId::Height(height)) => {
            let block = block(State(state), ApiPath(height.to_string())).await?;
            return Ok(ApiOk(titled(block.0, "block")));
        }
        // A block hash and a transaction hash are the same shape, so the only
        // way to tell them apart is to try one and then the other.
        //
        // Only a not-found answer moves on to the next try. A daemon that
        // failed any other way has not said the hash is not a block, so its
        // error is the answer, rather than a 404 that says nothing matched.
        Ok(BlockId::Hash(_)) => {
            match block(State(Arc::clone(&state)), ApiPath(raw.clone())).await {
                Ok(found) => return Ok(ApiOk(titled(found.0, "block"))),
                Err(e) if e.status != StatusCode::NOT_FOUND => return Err(e),
                Err(_) => {}
            }
            match transaction(State(state), ApiPath(raw.clone())).await {
                Ok(found) => return Ok(ApiOk(titled(found.0, "tx"))),
                Err(e) if e.status != StatusCode::NOT_FOUND => return Err(e),
                Err(_) => {}
            }
            return Err(ApiError::not_found(format!(
                "Cant find blk or tx using search string: {shown}"
            )));
        }
        Err(_) => {}
    }

    // A mainnet address is 95 characters, so an argument this long is most
    // likely one, and saying why it cannot work beats a bare refusal.
    if raw.chars().count() > HASH_TEXT_LEN {
        return Err(ApiError::bad_request(format!(
            "Cant find blk or tx using search string: {shown}. Monero has no \
             address index, so addresses are not searchable"
        )));
    }

    Err(ApiError::bad_request(format!(
        "Cant find blk or tx using search string: {shown}"
    )))
}

fn titled<T: Serialize>(payload: T, title: &str) -> serde_json::Value {
    let mut value = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    if let Some(map) = value.as_object_mut() {
        map.insert("title".to_owned(), serde_json::json!(title));
    }
    value
}

// ---------------------------------------------------------------------------
// /api/networkinfo
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct NetworkInfoData {
    alt_blocks_count: u64,
    block_size_limit: u64,
    block_size_median: u64,
    /// A JSON **string**, not a number. A 128-bit difficulty does not fit a
    /// double, so a parser backed by doubles would lose it.
    cumulative_difficulty: String,
    current: bool,
    current_hf_version: u8,
    difficulty: String,
    fee_estimate: u64,
    fee_estimate_grace_blocks: u64,
    fee_per_kb: u64,
    grey_peerlist_size: u64,
    hash_rate: u64,
    height: u64,
    incoming_connections_count: u64,
    outgoing_connections_count: u64,
    stagenet: bool,
    start_time: u64,
    /// A boolean field of `data`, distinct from the envelope's `"status":
    /// "success"` string. Do not conflate them.
    status: bool,
    target: u64,
    target_height: u64,
    testnet: bool,
    top_block_hash: String,
    tx_count: u64,
    tx_pool_size: u64,
    tx_pool_size_kbytes: u64,
    white_peerlist_size: u64,
}

pub async fn network_info(State(state): Shared) -> Result<ApiOk<NetworkInfoData>, ApiError> {
    let info = state
        .chain
        .info()
        .await
        .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;

    let hf = tip_hard_fork(&state).await;
    let grace_blocks = wallet_grace_blocks(hf);
    let fee = state.chain.fee_estimate(grace_blocks).await.ok();

    // Despite the name, this field carries **bytes**. The name is part of the
    // JSON API, so dividing by 1024 to honour it would hand every existing
    // consumer a number 1024 times too small.
    //
    // Taken from `get_transaction_pool_stats`, which is the same total without
    // the pool attached to it. Unavailable on a restricted daemon, in which
    // case report zero rather than failing the whole page.
    let pool_bytes = state
        .chain
        .pool_stats()
        .await
        .ok()
        .map(|p| p.pool_stats.bytes_total);

    Ok(ApiOk(NetworkInfoData {
        alt_blocks_count: info.alt_blocks_count,
        block_size_limit: info.block_size_limit,
        block_size_median: info.block_size_median,
        cumulative_difficulty: info.cumulative_difficulty().to_string(),
        current: true,
        current_hf_version: hf,
        difficulty: info.difficulty().to_string(),
        // The real estimate, with the grace window beside it. Both are
        // reported, because a field that is always zero tells a client
        // nothing.
        fee_estimate: fee.as_ref().map_or(0, |f| f.fee),
        fee_estimate_grace_blocks: grace_blocks,
        fee_per_kb: fee.as_ref().map_or(0, |f| f.fee),
        grey_peerlist_size: info.grey_peerlist_size,
        // Network hash rate is difficulty spread over the target block time.
        hash_rate: if info.target == 0 {
            0
        } else {
            // Reassembled difficulty, not the low word: correct today because
            // mainnet's top64 is still zero, and correct later when it is not.
            u64::try_from(info.difficulty() / u128::from(info.target)).unwrap_or(u64::MAX)
        },
        height: info.height,
        incoming_connections_count: info.incoming_connections_count,
        outgoing_connections_count: info.outgoing_connections_count,
        stagenet: info.stagenet,
        start_time: info.start_time,
        status: true,
        target: info.target,
        target_height: info.target_height,
        testnet: info.testnet,
        top_block_hash: normalise_hash(&info.top_block_hash),
        tx_count: info.tx_count,
        tx_pool_size: info.tx_pool_size,
        tx_pool_size_kbytes: pool_bytes.unwrap_or(0),
        white_peerlist_size: info.white_peerlist_size,
    }))
}

// ---------------------------------------------------------------------------
// /api/transaction/private/<postfix>   — k-anonymous transaction lookup
// ---------------------------------------------------------------------------

/// The fewest transactions a postfix must be *expected* to match before the
/// lookup is worth serving.
///
/// Each further hex character divides the expected set by sixteen, so this is
/// what decides how long a postfix a given chain will accept. It has to be
/// well clear of one rather than merely above it: how many transactions
/// actually share a postfix is Poisson around the expected number, so at an
/// expected 2 a request has roughly a 40% chance of returning one transaction
/// or none — which is no anonymity at all. At 20 that is about 4 in 100
/// million.
///
/// On mainnet this permits 5 characters and refuses 6, so the smallest set
/// served is around 40 transactions.
pub const MIN_ANONYMITY_SET: u64 = 20;

/// Refuses the k-anonymous lookup on a daemon that has no `get_txids_loose`.
fn no_txids_loose() -> ApiError {
    ApiError::unsupported(
        "This daemon does not provide get_txids_loose, which the k-anonymous \
         lookup needs. Run a daemon that has the call to serve this endpoint.",
    )
}

/// The most matches this explorer will expand before refusing.
///
/// Checked twice, against two different numbers. [`check_postfix`] refuses a
/// postfix whose *expected* set is already larger than this, before the daemon
/// is asked anything; the handler refuses again on the count that actually came
/// back, because how many transactions share a postfix is Poisson around the
/// expectation rather than equal to it.
///
/// The first check is the one that matters for load. `get_txids_loose` walks
/// the whole transaction index, so a two-character postfix on mainnet is a
/// full-index scan answering with something like a quarter of a million hashes
/// -- ten megabytes off the daemon -- only for this explorer to then refuse to
/// serve them. Refusing on the arithmetic costs nothing and says the same
/// thing.
pub const MAX_PRIVATE_TX_MATCHES: u64 = 1000;

/// The two bounds have to leave a usable band between them on every chain
/// size, or the endpoint would refuse everything while reporting two different
/// reasons for it.
///
/// One extra character divides the expected set by sixteen, so consecutive
/// postfix lengths are a factor of sixteen apart: unless the band is at least
/// that wide, a chain can fall between two adjacent lengths and accept no
/// postfix at all. Asserted at compile time rather than in a test, because a
/// runtime check on two constants can only ever pass.
const _: () = assert!(
    MAX_PRIVATE_TX_MATCHES / MIN_ANONYMITY_SET >= 16,
    "the anonymity floor and the serving ceiling are less than one postfix \
     character apart, so some chain sizes would accept no postfix at all"
);

/// Every transaction on the chain, coinbase included.
///
/// `get_info.tx_count` counts only **non-coinbase** transactions, which on a
/// quiet chain is a tiny fraction of the total: the local testnet reports 14
/// against a real 134,875. The anonymity rule divides by this number, so
/// using the RPC field directly would refuse postfixes that are perfectly
/// anonymous.
///
/// Each block carries exactly one coinbase transaction, so the total is the
/// non-coinbase count plus the height: 14 + 134,861 = 134,875 on that chain.
fn total_transactions(info: &monerod_rpc::types::GetInfo) -> u64 {
    info.tx_count.saturating_add(info.height)
}

/// Why a postfix cannot be served.
enum PostfixRefusal {
    Length,
    NotHex,
    TooLongToBeAnonymous { tx_count: u64 },
    TooShortToServe { expected: u64 },
}

/// Validate a postfix against the anonymity rule and against what this
/// explorer will serve.
///
/// Separated from the handler so both rules can be tested without a daemon:
/// the first is the whole privacy property, and "it looked right" is not
/// evidence.
///
/// The accepted band is expressed entirely in expected matches — at least
/// [`MIN_ANONYMITY_SET`], at most [`MAX_PRIVATE_TX_MATCHES`] — so it scales
/// with the chain rather than hard-coding a length. On mainnet today that
/// admits five characters and no others; on the local testnet it is two or
/// three. Which lengths qualify moves as the chain grows, which is the point
/// of stating the rule in matches.
fn check_postfix(postfix: &str, tx_count: u64, limits: Limits) -> Result<(), PostfixRefusal> {
    if postfix.len() < limits.postfix_min || postfix.len() > limits.postfix_max {
        return Err(PostfixRefusal::Length);
    }
    if !postfix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PostfixRefusal::NotHex);
    }
    // Each hex character is four bits, so each one divides the expected set by
    // sixteen.
    let shift = u32::try_from(postfix.len() * 4).unwrap_or(u32::MAX);
    let expected = tx_count.checked_shr(shift).unwrap_or(0);
    // Too long: the chain is not expected to hold `MIN_ANONYMITY_SET` matches,
    // so the postfix identifies its transaction rather than hiding it, which is
    // the opposite of the point.
    if expected < MIN_ANONYMITY_SET {
        return Err(PostfixRefusal::TooLongToBeAnonymous { tx_count });
    }
    // Too short: the set is bigger than this explorer will expand, so the
    // request ends in a refusal either way. Reaching that conclusion here
    // rather than after the daemon has scanned its whole transaction index is
    // the difference between a rejected request and an amplified one.
    if expected > MAX_PRIVATE_TX_MATCHES {
        return Err(PostfixRefusal::TooShortToServe { expected });
    }
    Ok(())
}

/// Which postfix lengths this chain currently accepts.
///
/// Asks [`check_postfix`] rather than repeating its arithmetic, so the
/// documentation page cannot describe a rule the endpoint does not enforce.
/// Which lengths qualify moves as the chain grows, which is why the rule is
/// stated in expected matches and this is computed rather than written down.
#[must_use]
pub fn acceptable_postfix_lengths(
    info: &monerod_rpc::types::GetInfo,
    limits: Limits,
) -> Vec<usize> {
    postfix_lengths_for(total_transactions(info), limits)
}

fn postfix_lengths_for(tx_count: u64, limits: Limits) -> Vec<usize> {
    (limits.postfix_min..=limits.postfix_max)
        .filter(|n| check_postfix(&"a".repeat(*n), tx_count, limits).is_ok())
        .collect()
}

/// Narrow a hex postfix to a whole number of bytes, keeping the **trailing**
/// characters.
///
/// monerod matches on bits but parses a hash template, so only whole bytes can
/// be expressed; an odd-length postfix has to search one character narrower and
/// filter afterwards. Because it is a suffix, the character dropped is the
/// leading one: `"abc"` searches `"bc"`. Taking the front instead returns
/// nothing at all, and silently — the request succeeds with an empty set.
fn whole_byte_suffix(postfix: &str) -> &str {
    let keep = postfix.len() - postfix.len() % 2;
    postfix.get(postfix.len() - keep..).unwrap_or_default()
}

#[derive(Serialize)]
pub struct PrivateTxData {
    missed_txs: Vec<String>,
    txs: Vec<TxDetail>,
}

/// What a private lookup of `matches` transactions holds of the range
/// budget: [`PRIVATE_KIB_PER_MATCH`] each, and never more than the widest
/// range of blocks.
fn private_hold_kib(matches: usize) -> u64 {
    (matches as u64)
        .saturating_mul(PRIVATE_KIB_PER_MATCH)
        .min(explorer_core::rpc_source::MAX_RANGE_KIB)
}

/// A fetched transaction's share of the range budget, in KiB: twice what an
/// FCMP++ spend with two inputs takes, its hex and its decoded JSON.
const PRIVATE_KIB_PER_MATCH: u64 = 64;

pub async fn transaction_private(
    State(state): Shared,
    ApiPath(raw): ApiPath<String>,
) -> Result<ApiOk<PrivateTxData>, ApiError> {
    // Hex is case insensitive and transaction hashes are rendered lowercase,
    // so the case is folded before matching. Nothing else about the argument
    // is changed: a character that is not hex is refused below, not dropped.
    let postfix = raw.to_ascii_lowercase();

    let info = state
        .chain
        .info()
        .await
        .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;

    if let Err(why) = check_postfix(&postfix, total_transactions(&info), state.limits) {
        return Err(ApiError::bad_request(match why {
            PostfixRefusal::Length => format!(
                "Tx hash postfix not between {} and {} characters in length: {}",
                state.limits.postfix_min,
                state.limits.postfix_max,
                echo(&postfix)
            ),
            PostfixRefusal::NotHex => {
                format!("Tx hash postfix is not hex: {}", echo(&postfix))
            }
            PostfixRefusal::TooLongToBeAnonymous { tx_count } => format!(
                "Tx hash postfix {postfix} is too long to be anonymous on a chain \
                 of {tx_count} transactions"
            ),
            PostfixRefusal::TooShortToServe { expected } => format!(
                "About {expected} transactions are expected to end with {postfix}, \
                 and this explorer serves at most {MAX_PRIVATE_TX_MATCHES}. \
                 Please use a longer postfix."
            ),
        }));
    }

    // monerod matches on bits, but the template it parses is a hash, so only
    // whole bytes can be expressed. An odd-length postfix searches one
    // character narrower and the surplus is filtered below.
    //
    // It is a *suffix*, so the narrower search drops the leading character and
    // keeps the trailing ones: "abc" searches "bc", not "ab". Taking the front
    // instead returns nothing at all, because no hash ends with "ab" by
    // coincidence of starting with it.
    let searched = whole_byte_suffix(&postfix);
    let request = GetTxidsLooseRequest::from_hex_suffix(searched)
        .ok_or_else(|| ApiError::bad_request(format!("Tx hash postfix is not hex: {postfix}")))?;

    let Some(found) = state
        .chain
        .txids_loose(&request)
        .await
        .map_err(|e| on_chain_error(&e, "Cant search for matching transactions"))?
    else {
        return Err(no_txids_loose());
    };

    // Filter the surplus an odd-length postfix pulled in, then cap.
    let matching: Vec<Hash32> = found
        .txids
        .iter()
        .filter(|t| t.ends_with(&postfix))
        .filter_map(|t| t.parse::<Hash32>().ok())
        .collect();

    if matching.len() as u64 > MAX_PRIVATE_TX_MATCHES {
        return Err(ApiError::bad_request(format!(
            "More than {MAX_PRIVATE_TX_MATCHES} transactions end with {postfix}. \
             Please use a longer postfix."
        )));
    }

    // The matches are fetched whole, so they wait for their share of the
    // budget ranges of blocks share.
    let _held = state
        .chain
        .hold_kib(private_hold_kib(matching.len()))
        .await
        .map_err(|e| on_chain_error(&e, "Cant get matching transactions"))?;
    let fetched = state
        .chain
        .transactions(&matching)
        .await
        .map_err(|e| on_chain_error(&e, "Cant get matching transactions"))?;

    let mut txs = Vec::with_capacity(fetched.txs.len());
    for entry in &fetched.txs {
        let Ok(tx) = entry.parse_json() else { continue };
        // Rings are deliberately NOT expanded here. Expanding every ring of a
        // 500-transaction anonymity set would be thousands of RPC calls for a
        // caller who wants exactly one of them; the caller re-requests the one
        // it wanted through /api/transaction. The inputs are still listed --
        // they cost nothing and omitting them would report a spend as having
        // spent nothing.
        let inputs = unexpanded_inputs(&tx);
        let current = entry.block_height.saturating_add(entry.confirmations);
        txs.push(TxDetail::build(entry, &tx, &inputs, current));
    }

    Ok(ApiOk(PrivateTxData {
        missed_txs: fetched.missed,
        txs,
    }))
}

// ---------------------------------------------------------------------------
// /api/blocks/<start>/<end>   — k-anonymous block lookup
// ---------------------------------------------------------------------------

/// The widest block range this explorer will serve.
///
/// Bounded for the same reason the `limit` cap exists. Every block costs the
/// operator's daemon a call, so an
/// uncapped `/api/blocks/0/3000000` would be three million of them from one
/// unauthenticated request -- and a response to match, which has to be held in
/// memory to be sent.
///
/// 100 blocks is far wider than the anonymity set anyone needs — the point of
/// the endpoint is to hide *which* block was wanted, and a hundred candidates
/// does that — while bounding the cost at one header range, one `get_block`
/// per block that holds transactions, and one `get_transactions`. On a chain
/// where every block holds transactions that is 102 calls, plus one more
/// `get_transactions` per 500 transactions past the first 500 (the batch
/// size, `MAX_TXS_PER_CALL`): about 121 for a hundred mainnet blocks of ten
/// thousand transactions, and more on a full stressnet. On a quiet chain
/// before the FCMP++ fork it is two. From the fork on every block's body is
/// fetched, because the response carries each block's curve tree, which is in
/// the body; bodies come from cache by hash, or by height once buried, so a
/// range served before costs little more than its header call and its
/// transactions.
///
/// The bytes ranges hold together are bounded by `RANGE_KIB` in
/// explorer-core; see `deploy/oxblocks.service`.
pub async fn blocks_range(
    State(state): Shared,
    ApiPath((start_raw, end_raw)): ApiPath<(String, String)>,
) -> Result<ApiOk<Vec<BlockDetail>>, ApiError> {
    let start = decimal(&start_raw).ok_or_else(|| {
        ApiError::bad_request(format!("Cant parse block number: {}", echo(&start_raw)))
    })?;
    let end = decimal(&end_raw).ok_or_else(|| {
        ApiError::bad_request(format!("Cant parse block number: {}", echo(&end_raw)))
    })?;

    if start > end {
        return Err(ApiError::bad_request(
            "Invalid input: start height should be less than or equal to end height.".to_owned(),
        ));
    }

    // Before the daemon is asked anything: the span is arithmetic on the two
    // arguments, so a range too wide to serve costs no round trip to refuse.
    let span = end.saturating_sub(start).saturating_add(1);
    if span > state.limits.block_range {
        return Err(ApiError::bad_request(format!(
            "Requested {span} blocks; this explorer serves at most {} \
             per request because each one costs a call to the daemon.",
            state.limits.block_range
        )));
    }

    let mut info = state
        .chain
        .info()
        .await
        .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;

    // `height` counts blocks, so the tip is `height - 1`. The cached info can
    // trail a block that was just mined, so check a fresh one before refusing
    // the block after the tip.
    if end == info.height {
        info = state
            .chain
            .fresh_info()
            .await
            .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;
    }
    if end >= info.height {
        return Err(ApiError::not_found(format!(
            "Requested end height is higher than blockchain: {end}, {}",
            info.height
        )));
    }

    let blocks = state
        .chain
        .blocks_in_range(start, end, true)
        .await
        .map_err(|e| on_chain_error(&e, &format!("Cant get blocks: {start} to {end}")))?;

    Ok(ApiOk(
        blocks
            .iter()
            // A range's headers are fetched fresh, so their depth is current.
            .map(|b| BlockDetail::build(&b.header, b.header.depth, &b.txs, b.tree.as_ref()))
            .collect(),
    ))
}

/// Append a batch of transactions with their rings left unexpanded.
///
/// `/api/transactions/recent` answers with a *set* rather than a page, so
/// expanding every ring of it would be thousands of calls for a caller who
/// wants one of them and can re-request that one through `/api/transaction`.
/// Every transaction in the window shares one `current_height`, the pool ones
/// included.
fn push_unexpanded(txs: &mut Vec<TxDetail>, entries: &[TxEntry], current_height: u64) {
    for entry in entries {
        let Ok(tx) = entry.parse_json() else { continue };
        let inputs = unexpanded_inputs(&tx);
        txs.push(TxDetail::build(entry, &tx, &inputs, current_height));
    }
}

// ---------------------------------------------------------------------------
// /api/transactions/recent
// ---------------------------------------------------------------------------

/// The block range `/api/transactions/recent` covers, given the tip.
///
/// Inclusive at both ends and counted back from the newest *mined* block, so a
/// window of one is that block alone.
fn recent_window(height: u64, blocks: u64) -> (u64, u64) {
    let to = height.saturating_sub(1);
    (to.saturating_sub(blocks.saturating_sub(1)), to)
}

#[derive(Serialize)]
pub struct RecentData {
    current_height: u64,
    from_height: u64,
    mempool_txs_no: u64,
    to_height: u64,
    txs: Vec<TxDetail>,
}

/// The mempool, and the last `--recent-blocks` blocks.
///
/// The endpoint exists so that a caller who wants a *recent* transaction can
/// take a window rather than name one. If everyone asks for the same window,
/// asking reveals nothing.
///
/// **The window is bounded; the pool beside it is not.** Every unconfirmed
/// transaction is listed, because counting them in `mempool_txs_no` and then
/// withholding them was a real bug here. During a mempool flood this is the
/// most expensive endpoint here; see
/// `deploy/oxblocks.service`, which sizes `MemoryMax` against
/// `--max-concurrent` for exactly this family of requests.
pub async fn transactions_recent(
    State(state): Shared,
) -> Result<axum::response::Response, ApiError> {
    let tip_and_pool = async || {
        let info = state
            .chain
            .info()
            .await
            .map_err(|e| on_chain_error(&e, "Cant get daemon info"))?;
        let pool = state
            .chain
            .mempool()
            .await
            .map_err(|e| on_chain_error(&e, "Cant get the mempool"))?;
        Ok::<_, ApiError>((info, pool))
    };

    let (info, pool) = tip_and_pool().await?;
    if let Some(answer) = state.recent.get(&info.top_block_hash, &pool_key(&pool)) {
        return Ok(super::envelope::ok_response(answer));
    }
    let before = state.recent.built();
    let _turn = state.recent.turn.lock().await;
    if let Some(answer) = state.recent.since(before) {
        return Ok(super::envelope::ok_response(answer));
    }
    let (info, pool) = tip_and_pool().await?;
    let key = pool_key(&pool);
    if let Some(answer) = state.recent.get(&info.top_block_hash, &key) {
        return Ok(super::envelope::ok_response(answer));
    }

    let (from_height, to_height) = recent_window(info.height, state.limits.recent_blocks);
    // Blocks too large to fetch together cost the window its oldest, rather
    // than the answer: a caller cannot ask for a narrower one.
    let window = state
        .chain
        .newest_in_range(from_height, to_height, false)
        .await
        .map_err(|e| on_chain_error(&e, "Cant get recent blocks"))?;
    let from_height = window.first().map_or(from_height, |b| b.header.height);

    // The pool is listed first: those are more recent than any mined
    // transaction, and a caller reaching for this endpoint is reaching for a
    // recent one. Counting them in `mempool_txs_no` while leaving them out of
    // `txs` would name a set and then withhold it.
    let mut txs = Vec::new();
    let mut mempool_txs_no = 0;
    for entry in &pool.transactions {
        let Ok(tx) = entry.parse_json() else { continue };
        let inputs = unexpanded_inputs(&tx);
        txs.push(TxDetail::build_pool(entry, &tx, &inputs, info.height));
        mempool_txs_no += 1;
    }

    for block in &window {
        push_unexpanded(&mut txs, &block.txs, info.height);
    }

    let body = super::envelope::ok_body(&RecentData {
        current_height: info.height,
        from_height,
        mempool_txs_no,
        to_height,
        txs,
    })?;
    state
        .recent
        .keep(info.top_block_hash.clone(), key, body.clone());
    Ok(super::envelope::ok_response(body))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]

    use super::*;

    // Both bugs below were found by comparing live output on a real chain,
    // not by reading the code.

    /// A transaction still in the pool has no block, so no block timestamp --
    /// monerod puts the time it arrived in `received_timestamp` instead.
    /// Reading `block_timestamp` regardless dated every unconfirmed
    /// transaction 1970-01-01, which only showed up on a chain with a
    /// non-empty pool.
    #[test]
    fn a_pool_transaction_is_dated_by_when_it_arrived() {
        let entry: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": "37".repeat(32),
            "in_pool": true,
            "received_timestamp": 1_789_838_436u64,
            "block_timestamp": 0,
            "block_height": 0,
        }))
        .expect("a pool tx entry");
        let tx: monerod_rpc::types::TxJson = serde_json::from_value(serde_json::json!({
            "version": 2, "unlock_time": 0, "vin": [], "vout": [], "extra": [],
        }))
        .expect("a transaction");

        let detail = TxDetail::build(&entry, &tx, &[], 137_082);
        let rendered = serde_json::to_value(&detail).expect("serialises");
        assert_eq!(rendered["timestamp"], 1_789_838_436u64);
        assert_eq!(rendered["timestamp_utc"], "2026-09-19 17:20:36");
        assert_eq!(
            rendered["confirmations"], 0,
            "the pool has no confirmations"
        );
    }

    /// An odd-length postfix must narrow to its TRAILING bytes. Taking the
    /// leading ones returned an empty set while still reporting success:
    /// 0 matches for "abc" where the chain held 37.
    #[test]
    fn an_odd_postfix_narrows_to_its_trailing_bytes() {
        assert_eq!(whole_byte_suffix("abc"), "bc");
        assert_eq!(whole_byte_suffix("abcde"), "bcde");
        // Even lengths are already whole bytes and are untouched.
        assert_eq!(whole_byte_suffix("ab"), "ab");
        assert_eq!(whole_byte_suffix("abcd"), "abcd");
        assert_eq!(whole_byte_suffix(""), "");
    }

    /// The anonymity rule, which is the entire privacy property of the
    /// endpoint. The numbers are measured on the chains named below.
    #[test]
    fn the_anonymity_rule_holds_at_both_scales() {
        // The local testnet: 134,875 transactions.
        const CHAIN: u64 = 134_875;
        assert!(check_postfix("00", CHAIN, Limits::default()).is_ok());
        assert!(check_postfix("abc", CHAIN, Limits::default()).is_ok());
        // 134875 >> 16 == 2, below the floor of 20, so four characters would
        // identify the transaction rather than hide it.
        assert!(matches!(
            check_postfix("abcd", CHAIN, Limits::default()),
            Err(PostfixRefusal::TooLongToBeAnonymous { .. })
        ));

        // Mainnet-scale: 5 characters qualify and 6 do not.
        const MAINNET: u64 = 67_000_000;
        assert!(check_postfix("abcde", MAINNET, Limits::default()).is_ok());
        assert!(matches!(
            check_postfix("abcdef", MAINNET, Limits::default()),
            Err(PostfixRefusal::TooLongToBeAnonymous { .. })
        ));
    }

    #[test]
    fn postfix_length_and_alphabet_are_enforced() {
        const CHAIN: u64 = 134_875;
        assert!(matches!(
            check_postfix("0", CHAIN, Limits::default()),
            Err(PostfixRefusal::Length)
        ));
        assert!(matches!(
            check_postfix(&"0".repeat(13), CHAIN, Limits::default()),
            Err(PostfixRefusal::Length)
        ));
        assert!(matches!(
            check_postfix("zz", CHAIN, Limits::default()),
            Err(PostfixRefusal::NotHex)
        ));
    }

    /// The shift is bounded by the postfix ceiling, so it can never reach the
    /// width of the integer -- 12 characters is 48 bits. On an absurdly large
    /// chain the arithmetic must reach an answer rather than panicking on the
    /// way, and the answer is that even the longest postfix this explorer
    /// accepts still names 65,535 expected transactions there, which is more
    /// than it will expand.
    #[test]
    fn the_arithmetic_survives_an_enormous_chain() {
        assert!(u32::try_from(Limits::default().postfix_max * 4).is_ok_and(|b| b < 64));
        assert!(matches!(
            check_postfix(&"a".repeat(Limits::default().postfix_max), u64::MAX, Limits::default()),
            Err(PostfixRefusal::TooShortToServe { expected }) if expected == u64::MAX >> 48
        ));
    }

    /// The answer to a request this deployment's daemon cannot serve.
    ///
    /// Nothing announces the call in advance any more, so this message is
    /// where a caller finds out. It has to name the method, and it is the
    /// deployment's shortcoming rather than the caller's, so it is a 503 and
    /// not a 400.
    #[test]
    fn a_daemon_without_the_call_says_which_call_it_lacks() {
        let refused = no_txids_loose();
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            refused.message.contains("get_txids_loose"),
            "the answer does not name the missing call: {}",
            refused.message
        );
    }

    /// The guard that keeps a cheap request from becoming an expensive scan.
    ///
    /// `get_txids_loose` walks the whole transaction index. A two-character
    /// postfix on mainnet matches about a quarter of a million transactions --
    /// far more than this explorer will expand -- so the request is refused
    /// either way. Refusing on the arithmetic means the daemon is never asked.
    #[test]
    fn a_postfix_whose_set_is_too_large_to_serve_is_refused_before_the_daemon() {
        const MAINNET: u64 = 67_000_000;
        assert!(matches!(
            check_postfix("ab", MAINNET, Limits::default()),
            Err(PostfixRefusal::TooShortToServe { expected }) if expected == MAINNET >> 8
        ));
        assert!(matches!(
            check_postfix("abcd", MAINNET, Limits::default()),
            Err(PostfixRefusal::TooShortToServe { .. })
        ));
        // And the band is not empty: exactly one length fits mainnet.
        assert!(check_postfix("abcde", MAINNET, Limits::default()).is_ok());
    }

    /// The postfix bounds are the configured ones, not the built-in ones.
    #[test]
    fn the_postfix_band_follows_the_configured_bounds() {
        const CHAIN: u64 = 134_875;
        let wide = Limits {
            postfix_min: 1,
            postfix_max: 3,
            ..Limits::default()
        };

        // One character is refused by default and accepted here.
        assert!(matches!(
            check_postfix("0", CHAIN, Limits::default()),
            Err(PostfixRefusal::Length)
        ));
        assert!(matches!(
            check_postfix("0", CHAIN, wide),
            Err(PostfixRefusal::TooShortToServe { .. })
        ));

        // Four is accepted by default and refused here, on length rather than
        // on the match band.
        assert!(matches!(
            check_postfix("abcd", CHAIN, wide),
            Err(PostfixRefusal::Length)
        ));
    }

    /// The lengths the page advertises come from the same bounds the endpoint
    /// enforces, so narrowing the band narrows what is offered.
    #[test]
    fn the_advertised_lengths_follow_the_configured_bounds() {
        const MAINNET: u64 = 67_000_000;

        assert_eq!(postfix_lengths_for(MAINNET, Limits::default()), vec![5]);
        assert!(
            postfix_lengths_for(
                MAINNET,
                Limits {
                    postfix_min: 1,
                    postfix_max: 4,
                    ..Limits::default()
                }
            )
            .is_empty(),
            "a band that excludes the only workable length must advertise none"
        );

        // A band raised past the default ceiling, on a chain large enough that
        // a thirteen-character postfix still hides a transaction. Nothing
        // inside the default band qualifies here, so this can only pass if the
        // configured bounds are the ones being walked.
        const VAST: u64 = 1 << 57;
        assert_eq!(
            postfix_lengths_for(
                VAST,
                Limits {
                    postfix_min: 13,
                    postfix_max: 14,
                    ..Limits::default()
                }
            ),
            vec![13]
        );
    }

    /// The window is inclusive at both ends and counted back from the newest
    /// mined block, so a window of one block is that block alone.
    #[test]
    fn the_recent_window_is_as_wide_as_it_is_configured_to_be() {
        assert_eq!(recent_window(1000, 30), (970, 999));
        assert_eq!(recent_window(1000, 1), (999, 999));
        assert_eq!(recent_window(1000, 100), (900, 999));
        // A chain shorter than the window gives what there is, not an underflow.
        assert_eq!(recent_window(5, 30), (0, 4));
        assert_eq!(recent_window(0, 30), (0, 0));
    }

    /// An empty chain must refuse everything rather than divide its way into
    /// permitting a postfix that identifies the only transaction there is.
    #[test]
    fn an_empty_chain_refuses_every_postfix() {
        for len in Limits::default().postfix_min..=Limits::default().postfix_max {
            assert!(matches!(
                check_postfix(&"a".repeat(len), 0, Limits::default()),
                Err(PostfixRefusal::TooLongToBeAnonymous { .. })
            ));
        }
    }

    /// A daemon at hard fork `hf`, for the fee estimate and network info.
    fn fee_daemon(hf: u8) -> explorer_core::fake_daemon::FakeDaemon {
        explorer_core::fake_daemon::FakeDaemon::start(move |what, _| {
            let result = match what {
                "get_last_block_header" => serde_json::json!({"block_header": {
                    "major_version": hf, "minor_version": hf, "timestamp": 0, "prev_hash": "",
                    "nonce": 0, "orphan_status": false, "height": 9, "depth": 0, "hash": "",
                    "difficulty": 1, "difficulty_top64": 0, "wide_difficulty": "0x1",
                    "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                    "wide_cumulative_difficulty": "0x1", "reward": 1, "block_size": 1,
                    "num_txes": 0, "pow_hash": "", "miner_tx_hash": "",
                }, "status": "OK"}),
                "get_fee_estimate" => serde_json::json!({"fee": 20_000, "status": "OK"}),
                "get_info" => serde_json::json!({
                    "height": 10, "target_height": 0, "difficulty": 1, "difficulty_top64": 0,
                    "target": 120, "tx_count": 0, "tx_pool_size": 0, "alt_blocks_count": 0,
                    "outgoing_connections_count": 0, "incoming_connections_count": 0,
                    "white_peerlist_size": 0, "grey_peerlist_size": 0, "testnet": false,
                    "stagenet": false, "nettype": "regtest", "top_block_hash": "",
                    "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                    "block_size_limit": 0, "block_size_median": 0, "start_time": 0,
                    "version": "test", "restricted": false, "status": "OK",
                }),
                _ => serde_json::json!({"status": "Failed"}),
            };
            serde_json::json!({"jsonrpc": "2.0", "id": "0", "result": result})
        })
    }

    /// A daemon whose chain is block 0 alone, a coinbase, `size` bytes, with
    /// the tip hash `tip` holds, and an empty pool, or one it fails to send.
    fn recent_daemon(
        tip: Arc<std::sync::atomic::AtomicU64>,
        pool: bool,
        size: u64,
    ) -> explorer_core::fake_daemon::FakeDaemon {
        let coinbase = "aa".repeat(32);
        explorer_core::fake_daemon::FakeDaemon::start(move |what, _| {
            let tip = tip.load(std::sync::atomic::Ordering::SeqCst);
            let header = serde_json::json!({
                "major_version": 16, "minor_version": 16, "timestamp": 0, "prev_hash": "",
                "nonce": 0, "orphan_status": false, "height": 0, "depth": 0,
                "hash": format!("{tip:064x}"), "difficulty": 1, "difficulty_top64": 0,
                "wide_difficulty": "0x1", "cumulative_difficulty": 1,
                "cumulative_difficulty_top64": 0, "wide_cumulative_difficulty": "0x1",
                "reward": 1, "block_size": size, "num_txes": 0, "pow_hash": "",
                "miner_tx_hash": coinbase,
            });
            let ok = |r: serde_json::Value| serde_json::json!({"jsonrpc": "2.0", "id": "0", "result": r});
            match what {
                "get_info" => ok(serde_json::json!({
                    "height": 1, "target_height": 0, "difficulty": 1, "difficulty_top64": 0,
                    "target": 120, "tx_count": 1, "tx_pool_size": 0, "alt_blocks_count": 0,
                    "outgoing_connections_count": 0, "incoming_connections_count": 0,
                    "white_peerlist_size": 0, "grey_peerlist_size": 0, "testnet": false,
                    "stagenet": false, "nettype": "regtest", "top_block_hash": format!("{tip:064x}"),
                    "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                    "block_size_limit": 0, "block_size_median": 0, "start_time": 0,
                    "version": "test", "restricted": false, "status": "OK",
                })),
                "get_block_headers_range" => {
                    ok(serde_json::json!({"headers": [header], "status": "OK"}))
                }
                "get_transactions" => serde_json::json!({"txs": [{
                    "tx_hash": coinbase, "as_hex": "",
                    "as_json": r#"{"version":2,"unlock_time":60,"vin":[{"gen":{"height":0}}],"vout":[],"extra":[],"rct_signatures":{"type":0}}"#,
                    "block_height": 0, "block_timestamp": 0, "confirmations": 1, "in_pool": false,
                    "double_spend_seen": false, "output_indices": [],
                }], "status": "OK"}),
                "get_transaction_pool_hashes" if pool => {
                    serde_json::json!({"tx_hashes": [], "status": "OK"})
                }
                _ => serde_json::json!({"status": "Failed"}),
            }
        })
    }

    async fn body_of(response: axum::response::Response) -> axum::body::Bytes {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
    }

    /// Every caller gets the one answer, built once while the tip and the
    /// pool stay the same, and built again once the tip moves.
    #[tokio::test]
    async fn the_recent_answer_is_built_once_per_tip_and_pool() {
        let tip = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let daemon = recent_daemon(Arc::clone(&tip), true, 1);
        let state = state_on(&daemon);
        let together = tokio::join!(
            transactions_recent(state.clone()),
            transactions_recent(state.clone()),
            transactions_recent(state.clone()),
            transactions_recent(state.clone()),
        );
        assert!(
            together.0.is_ok() && together.1.is_ok() && together.2.is_ok() && together.3.is_ok()
        );
        assert_eq!(
            daemon.count("get_block_headers_range"),
            1,
            "built once for all four"
        );
        let first = body_of(transactions_recent(state.clone()).await.unwrap()).await;
        assert!(String::from_utf8_lossy(&first).contains(&"aa".repeat(32)));
        let calls = state.chain.rpc_calls();
        for _ in 0..3 {
            let again = body_of(transactions_recent(state.clone()).await.unwrap()).await;
            assert_eq!(again, first);
        }
        assert_eq!(
            state.chain.rpc_calls(),
            calls,
            "no daemon call for the same answer"
        );

        tip.store(2, std::sync::atomic::Ordering::SeqCst);
        state.chain.fresh_info().await.unwrap();
        let moved = body_of(transactions_recent(state.clone()).await.unwrap()).await;
        assert!(
            state.chain.rpc_calls() > calls + 1,
            "built again under the new tip"
        );
        assert_eq!(
            moved, first,
            "the same chain under a new tip hash reads the same"
        );
    }

    /// A range too large is the caller's to narrow, a full budget is ours
    /// for a moment, and a daemon without the call is this deployment's.
    #[test]
    fn chain_failures_are_answered_by_whose_they_are() {
        let status = |e: ChainError| on_chain_error(&e, "x").status;
        let large = ChainError::RangeTooLarge {
            start: 1,
            end: 2,
            kib: 3,
        };
        assert_eq!(status(large), StatusCode::BAD_REQUEST);
        assert_eq!(
            status(ChainError::Busy("ranges")),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status(ChainError::NeedsUnrestricted("the mempool")),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status(ChainError::Unavailable("down".to_owned())),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status(ChainError::BlockNotFound(BlockId::Height(9))),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            on_chain_error(&ChainError::Busy("ranges"), "x").outcome,
            super::super::envelope::Outcome::Error
        );
    }

    /// A pool that cannot be had fails the answer rather than reading as
    /// empty.
    #[tokio::test]
    async fn the_recent_answer_needs_the_pool() {
        let tip = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let daemon = recent_daemon(tip, false, 1);
        let err = transactions_recent(state_on(&daemon)).await.err().unwrap();
        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(daemon.count("get_block_headers_range"), 0);
    }

    /// A window too large to fetch together is served from its newest block.
    #[tokio::test]
    async fn a_recent_window_too_large_is_served_from_its_newest() {
        let tip = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let huge = (explorer_core::rpc_source::MAX_RANGE_KIB + 1) << 10;
        let daemon = recent_daemon(tip, true, huge);
        let answer = transactions_recent(state_on(&daemon)).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_of(answer).await).unwrap();
        assert_eq!(body["data"]["from_height"], 0);
        assert_eq!(body["data"]["txs"].as_array().unwrap().len(), 1);
    }

    /// A caller that waited while another built takes that answer rather
    /// than build again.
    #[tokio::test]
    async fn a_caller_that_waited_takes_the_answer_built_meanwhile() {
        let tip = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let daemon = recent_daemon(tip, true, 1);
        let state = state_on(&daemon);
        let turn = state.recent.turn.lock().await;
        let waiting = tokio::spawn(transactions_recent(state.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        state.recent.keep(
            "another tip".to_owned(),
            Vec::new(),
            axum::body::Bytes::from_static(b"built meanwhile"),
        );
        drop(turn);
        let answer = body_of(waiting.await.unwrap().unwrap()).await;
        assert_eq!(&answer[..], b"built meanwhile");
        assert_eq!(daemon.count("get_block_headers_range"), 0);
    }

    /// What a recent answer reads of the pool: each hash and arrival, in
    /// order.
    #[test]
    fn a_pool_is_named_by_its_hashes_and_arrivals() {
        let tx = |h: &str, t: u64| {
            serde_json::json!({
                "id_hash": h, "blob_size": 1, "fee": 1, "max_used_block_id_hash": "",
                "max_used_block_height": 0, "kept_by_block": false, "last_failed_height": 0,
                "last_failed_id_hash": "", "receive_time": t, "relayed": true,
                "last_relayed_time": 0, "do_not_relay": false, "double_spend_seen": false,
                "tx_blob": "",
            })
        };
        let pool = explorer_core::rpc_source::Mempool {
            transactions: [tx("a", 5), tx("b", 7)]
                .into_iter()
                .map(|t| Arc::new(serde_json::from_value(t).unwrap()))
                .collect(),
        };
        assert_eq!(pool_key(&pool), [("a".to_owned(), 5), ("b".to_owned(), 7)]);
    }

    /// A kept answer is for its own tip and for a pool holding the same
    /// transactions, arrived at the same times, in the same order; and one
    /// built since a caller arrived is that caller's.
    #[test]
    fn a_kept_recent_answer_is_for_its_own_tip_and_pool() {
        let tx = |h: &str, t: u64| (h.to_owned(), t);
        let recent = RecentAnswer::default();
        assert_eq!(recent.built(), 0);
        recent.keep(
            "t".to_owned(),
            vec![tx("a", 1), tx("b", 2)],
            axum::body::Bytes::from_static(b"x"),
        );
        assert!(recent.get("t", &[tx("a", 1), tx("b", 2)]).is_some());
        assert!(recent.get("t", &[tx("b", 2), tx("a", 1)]).is_none());
        assert!(recent.get("t", &[tx("a", 1), tx("b", 3)]).is_none());
        assert!(recent.get("t", &[tx("a", 1)]).is_none());
        assert!(recent.get("u", &[tx("a", 1), tx("b", 2)]).is_none());

        let before = recent.built();
        assert!(recent.since(before).is_none());
        recent.keep("u".to_owned(), vec![], axum::body::Bytes::from_static(b"y"));
        assert_eq!(recent.since(before).as_deref(), Some(&b"y"[..]));
        assert!(recent.since(recent.built()).is_none());
    }

    /// A private lookup holds the range budget in proportion to what it
    /// fetches, so a few lookups at once cannot stall every range.
    #[test]
    fn a_private_lookup_holds_what_its_matches_take() {
        assert_eq!(private_hold_kib(64), 64 * PRIVATE_KIB_PER_MATCH);
        assert!(private_hold_kib(64) * 5 < explorer_core::rpc_source::MAX_RANGE_KIB);
        assert_eq!(
            private_hold_kib(MAX_PRIVATE_TX_MATCHES as usize),
            explorer_core::rpc_source::MAX_RANGE_KIB
        );
    }

    /// The paths answer is written straight from its structs, so they have to
    /// be in byte order, as `ok_body` checks.
    #[test]
    fn the_paths_answer_is_in_byte_order() {
        let leaf = LeafData {
            commitment: "c".to_owned(),
            kind: "carrot",
            output_key: "k".to_owned(),
            unified_id: 7,
        };
        let group = |leaves: Vec<LeafData>, members: Vec<String>| GroupData {
            curve: explorer_core::curve_tree::Curve::Selene,
            layer: 0,
            layer_size: 38,
            leaves,
            members,
            offset: 1,
            start: 0,
        };
        let data = PathsData {
            as_of_block: 10,
            n_layers: 2,
            n_leaf_tuples: 38,
            outputs: vec![OutputPathData {
                check: Some("holds"),
                groups: vec![
                    group(vec![leaf], Vec::new()),
                    group(Vec::new(), vec!["m".to_owned()]),
                ],
                index: 0,
                last_locked_block: 9,
                leaf_idx: Some(1),
                unified_id: 7,
            }],
            root: Some("r".to_owned()),
            root_block: Some(2),
            root_check: "matches",
            tx_hash: "t".to_owned(),
        };
        assert!(super::super::envelope::ok_body(&data).is_ok());
    }

    fn state_on(daemon: &explorer_core::fake_daemon::FakeDaemon) -> Shared {
        State(Arc::new(AppState {
            chain: daemon.source(),
            limits: Limits::default(),
            paths: crate::tree_paths::PathCache::default(),
            recent: Default::default(),
            rows: Default::default(),
        }))
    }

    /// The grace window the daemon was asked for, in order.
    fn graces(daemon: &explorer_core::fake_daemon::FakeDaemon) -> Vec<u64> {
        daemon
            .bodies("get_fee_estimate")
            .iter()
            .map(|b| b["params"]["grace_blocks"].as_u64().unwrap())
            .collect()
    }

    /// monerod loops once per grace block holding its chain lock, so a
    /// window past MAX_GRACE_BLOCKS never reaches it, and one not asked for
    /// is the window wallets use, which the 2026 fee scaling widened.
    #[tokio::test]
    async fn the_fee_estimate_asks_the_daemon_for_the_window_wallets_use() {
        let asking = |g: &str| {
            ApiQuery(GraceQuery {
                grace_blocks: Some(g.to_owned()),
            })
        };
        let daemon = fee_daemon(17);
        for g in ["18446744073709551615", "1001", "", "x", "-1", "+7"] {
            let err = fee_estimate(state_on(&daemon), asking(g))
                .await
                .err()
                .unwrap();
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "{g:?}");
        }
        let ApiOk(fee) = fee_estimate(state_on(&daemon), asking("1000"))
            .await
            .unwrap();
        assert_eq!((fee.fee, fee.grace_blocks), (20_000, 1000));
        let ApiOk(fee) = fee_estimate(state_on(&daemon), asking("7")).await.unwrap();
        assert_eq!(fee.grace_blocks, 7);
        let q = ApiQuery(GraceQuery { grace_blocks: None });
        let ApiOk(fee) = fee_estimate(state_on(&daemon), q).await.unwrap();
        assert_eq!(fee.grace_blocks, 1000);
        assert_eq!(graces(&daemon), [1000, 7, 1000]);

        let before = fee_daemon(16);
        let q = ApiQuery(GraceQuery { grace_blocks: None });
        let ApiOk(fee) = fee_estimate(state_on(&before), q).await.unwrap();
        assert_eq!(fee.grace_blocks, 10);
        assert_eq!(graces(&before), [10]);

        for (hf, grace) in [(16, 10), (17, 1000)] {
            let daemon = fee_daemon(hf);
            let ApiOk(info) = network_info(state_on(&daemon)).await.unwrap();
            let info = serde_json::to_value(&info).unwrap();
            assert_eq!(info["fee_estimate_grace_blocks"], grace);
            assert_eq!(info["fee_estimate"], 20_000);
            assert_eq!(info["current_hf_version"], hf);
            assert_eq!(graces(&daemon), [grace]);
        }
    }
}
