//! The one thing that answers questions about the chain, over monerod's RPC.
//!
//! There is no trait here and no second implementation to abstract over. The
//! vocabulary those questions are asked in lives in [`crate::chain`].

use monerod_rpc::types::error_code;
use monerod_rpc::types::{
    FeeEstimate, GetAlternateChains, GetBlock, GetBlockHeader, GetBlockHeadersRange,
    GetBlockHeadersRangeRequest, GetBlockRequest, GetFeeEstimateRequest, GetInfo, GetOutsRequest,
    GetTransactionPool, GetTransactionPoolStats, GetTransactionsRequest, GetTxidsLooseRequest,
    GetTxidsLooseResponse, OutKey, OutKeyRequest, PathQuery, TreePaths, TreeSizeQuery, TxEntry,
    TxInToKey, TxJson,
};
use monerod_rpc::{Client, RpcError};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::cache::{Cache, REORG_WINDOW, safe_to_cache_by_height};
use crate::chain::{BlockId, ChainError, ResolvedInput, RingMember};
use crate::hash::Hash32;

/// What a batch fetch actually yielded.
///
/// monerod reports a transaction it does not have in `missed_tx`, not through
/// `status`, and omits the field entirely when nothing was missed -- so a
/// caller that only looks at `txs` cannot tell "not found" from "found
/// nothing". Keeping the two together makes that distinction hard to drop.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FetchedTxs {
    pub txs: Vec<TxEntry>,
    /// Hashes monerod does not have, as it returned them.
    pub missed: Vec<String>,
}

/// Put a fetched batch back into the order it was asked for.
///
/// Cache hits and freshly fetched transactions arrive from two different
/// places, and a block's order carries meaning: it lists its transactions in a
/// fixed order with the coinbase first. Answering in the order the two sources
/// happened to produce would be right on a cold server and wrong on a warm
/// one, which is the worst shape a bug can take.
fn in_requested_order(hashes: &[Hash32], mut found: HashMap<Hash32, TxEntry>) -> Vec<TxEntry> {
    hashes.iter().filter_map(|h| found.remove(h)).collect()
}

pub struct RpcChainSource {
    client: Client,
    /// Blocks keyed by hash. A hash names one block forever, but not where it
    /// stands: a reorg can orphan a recent block, or put an orphan on the main
    /// chain, and the cached header would go on saying otherwise. So entries
    /// expire after a block's time; a block buried past the reorg window is
    /// kept in `blocks_by_height` as well, without expiry.
    blocks_by_hash: Cache<Hash32, GetBlock>,
    /// Blocks keyed by height, populated **only** for heights buried deeper
    /// than [`REORG_WINDOW`]. A reorg reassigns a height to a different block,
    /// so caching a recent height would serve a block that no longer exists.
    blocks_by_height: Cache<u64, GetBlock>,
    /// Confirmed transactions, keyed by hash and cached only once buried.
    txs: Cache<Hash32, TxEntry>,
    /// Ring members, keyed by amount and index, cached only once buried: a
    /// reorg can give a recent index to a different output.
    outs: Cache<(u64, u64), OutKey>,
    /// The chain tip. Short-lived by nature, so it expires rather than being
    /// invalidated.
    info: Cache<(), GetInfo>,
    /// Curve-tree sizes keyed by the block they were taken at, cached only once
    /// that block is buried past [`REORG_WINDOW`]: a reorg gives a height a
    /// different block, and with it a different tree.
    tree_sizes: Cache<u64, u64>,
    /// Bounds how many RPC calls can be in flight against the daemon at once.
    ///
    /// The single choke point protecting the operator's node. Per-request
    /// limits bound how much work *one* request can ask for, but they multiply
    /// by however many requests arrive at once; this bounds the product,
    /// whatever any future endpoint does. A request that cannot get a permit
    /// waits, and the inbound request timeout eventually sheds it -- queueing
    /// in front of the daemon rather than stampeding it.
    rpc_permits: Arc<Semaphore>,
    /// The chain bytes that ranges of blocks may hold at once, in KiB. See
    /// [`RANGE_KIB`].
    range_kib: Arc<Semaphore>,
    /// Outbound calls made since start.
    ///
    /// The number that matters for load on the operator's node, and not the
    /// same as cache misses -- one `/get_transactions` carrying forty hashes
    /// is forty misses and one call. Counting misses would overstate
    /// amplification by an order of magnitude.
    rpc_calls: Arc<AtomicU64>,
}

/// Turn a `get_block` error code into something the web layer can act on.
///
/// Only the not-found codes mean "no such block": a daemon that is merely
/// busy must not tell the reader their block does not exist. The codes below
/// are what monerod returns, measured against a live node:
///
/// | ask | code | meaning |
/// | --- | --- | --- |
/// | height past the tip | -2 | not found |
/// | hash it does not hold | -5 | not found |
/// | unparseable hex | -1 | not found |
/// | busy | -9 | try again |
/// | method gated off | -32601 | unavailable by configuration |
///
/// `-5` is `INTERNAL`, a generic code, but for a `get_block` *by hash* it is
/// how monerod says it has no such block ("Internal error: can't get block by
/// hash"). That reading is specific to this call and does not generalise.
///
/// Anything unrecognised is reported as unavailable rather than as missing:
/// claiming a block does not exist is a stronger statement than we can make
/// about an error we do not understand.
fn classify_block_error(code: i64, id: BlockId, detail: String) -> ChainError {
    use monerod_rpc::types::error_code as ec;

    match code {
        ec::WRONG_PARAM | ec::TOO_BIG_HEIGHT | ec::INTERNAL => ChainError::BlockNotFound(id),
        ec::CORE_BUSY => ChainError::Unavailable(detail),
        ec::METHOD_NOT_FOUND | ec::RESTRICTED => ChainError::NeedsUnrestricted("block lookup"),
        _ => ChainError::Unavailable(detail),
    }
}

/// Transaction hashes per `/get_transactions` call.
///
/// The call accepts any number, and asking for a hundred blocks' transactions
/// in one request instead of a hundred is the whole point of batching -- but
/// the response carries every blob, so an unbounded batch is an unbounded
/// allocation, which is the failure mode this explorer exists to avoid. A few
/// large calls rather than one enormous one; they are issued together, so the
/// split costs no extra round trip.
const MAX_TXS_PER_CALL: usize = 500;

/// The chain bytes, in KiB, that every range of blocks held at once may add
/// up to: 48 MiB.
///
/// A range holds each of its transactions as hex and as JSON, several times
/// its size on the chain, from the fetch until the caller lets the range go.
/// The number of blocks in a range bounds none of that when blocks are as
/// large as the chain allows, and concurrent ranges multiply it. So a range
/// takes its blocks' sizes, as their headers give them, from this budget
/// before fetching anything, and waits while the budget is spent, for
/// [`RANGE_WAIT`] at most. A range wider than [`MAX_RANGE_KIB`] is refused.
pub const RANGE_KIB: u32 = 48 * 1024;

/// The most chain bytes, in KiB, one range may hold: half of [`RANGE_KIB`].
/// A wider range is refused rather than let through alone, since alone it
/// could still hold more than the process may.
pub const MAX_RANGE_KIB: u64 = RANGE_KIB as u64 / 2;

/// How long a range waits for its share of [`RANGE_KIB`] before it gives
/// up: long enough to wait out a range or two, short enough to leave the
/// request time to fetch once it has its share.
pub const RANGE_WAIT: Duration = Duration::from_secs(5);

/// How many blocks sit on block `height`, in a chain of `chain_height`.
const fn depth(chain_height: u64, height: u64) -> u64 {
    chain_height.saturating_sub(height.saturating_add(1))
}

/// A range of blocks with their transactions, holding its share of
/// [`RANGE_KIB`] until it is dropped.
pub struct BlockRange {
    blocks: Vec<BlockWithTxs>,
    _held: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl std::ops::Deref for BlockRange {
    type Target = [BlockWithTxs];
    fn deref(&self) -> &[BlockWithTxs] {
        &self.blocks
    }
}

impl<'a> IntoIterator for &'a BlockRange {
    type Item = &'a BlockWithTxs;
    type IntoIter = std::slice::Iter<'a, BlockWithTxs>;
    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter()
    }
}

/// One block's header and every transaction in it, coinbase first.
pub struct BlockWithTxs {
    pub header: monerod_rpc::types::BlockHeader,
    pub txs: Vec<TxEntry>,
    /// The curve tree the block commits to, from its own JSON. `None` below
    /// the FCMP++ fork, and when that JSON did not decode.
    pub tree: Option<BlockTree>,
}

/// The curve tree a block commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTree {
    pub root: String,
    pub n_layers: u8,
}

impl BlockTree {
    /// Read from a fetched block. Both fields or neither: a root without its
    /// layer count describes no tree anyone could check a proof against. The
    /// root must be 64 hex characters.
    ///
    /// A block below the fork is answered from its header alone, without
    /// parsing its JSON, which is every block of a chain that has not forked.
    /// A post-fork block without a well-formed tree is logged, since the
    /// daemon's block format should always carry one.
    #[must_use]
    pub fn of(block: &GetBlock) -> Option<Self> {
        let header = &block.block_header;
        if header.major_version < monerod_rpc::types::HF_VERSION_FCMP_PLUS_PLUS {
            return None;
        }
        let tree = block
            .parse_tree()
            .map_err(|e| tracing::warn!("block {}'s tree did not parse: {e}", header.height))
            .ok()?;
        let root = tree
            .fcmp_pp_tree_root
            .as_deref()
            .and_then(|r| monerod_rpc::types::hex_of_len(r, 64));
        let (Some(root), Some(n_layers)) = (root, tree.fcmp_pp_n_tree_layers) else {
            tracing::warn!("block {} carries no well-formed curve tree", header.height);
            return None;
        };
        Some(Self {
            root: root.to_ascii_lowercase(),
            n_layers,
        })
    }
}

/// Concurrent RPC calls allowed against the daemon.
///
/// monerod answers RPC on a bounded thread pool, so flooding it degrades the
/// node itself -- including its peer-to-peer duties. Kept well under what a
/// daemon will happily serve.
pub const DEFAULT_MAX_INFLIGHT_RPC: usize = 24;

/// Roughly the bytes a cached block holds: its strings, which the daemon
/// sizes, and a word for everything else.
fn block_bytes(b: &GetBlock) -> usize {
    let h = &b.block_header;
    b.blob.len()
        + b.json.len()
        + b.miner_tx_hash.len()
        + b.status.len()
        + b.tx_hashes.iter().map(String::len).sum::<usize>()
        + h.hash.len()
        + h.prev_hash.len()
        + h.wide_difficulty.len()
        + h.wide_cumulative_difficulty.len()
        + h.pow_hash.len()
        + std::mem::size_of::<GetBlock>()
}

/// Roughly the bytes a cached transaction holds. See [`block_bytes`].
fn tx_bytes(t: &TxEntry) -> usize {
    t.tx_hash.len()
        + t.as_hex.len()
        + t.pruned_as_hex.len()
        + t.prunable_as_hex.len()
        + t.prunable_hash.len()
        + t.as_json.len()
        + 8 * (t.output_indices.len() + t.unified_ids.len())
        + std::mem::size_of::<TxEntry>()
}

/// Roughly the bytes a cached ring member holds. See [`block_bytes`].
fn out_bytes(o: &OutKey) -> usize {
    o.key.len() + o.mask.len() + o.txid.len() + std::mem::size_of::<OutKey>()
}

impl RpcChainSource {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self {
            client,
            // Sized for a working set of a few thousand objects: enough that
            // paging through recent history is warm, small enough that the
            // process footprint stays predictable.
            //
            // What the daemon sends is sized by the daemon, so the caches
            // holding its strings are also held to a byte budget: about 200
            // MiB in all, inside the 512 MiB `deploy/oxblocks.service` allows.
            blocks_by_hash: Cache::expiring(512, Duration::from_secs(120))
                .within_bytes(32 << 20, block_bytes),
            blocks_by_height: Cache::permanent(2048).within_bytes(64 << 20, block_bytes),
            txs: Cache::permanent(8192).within_bytes(96 << 20, tx_bytes),
            outs: Cache::permanent(65_536).within_bytes(16 << 20, out_bytes),
            // Long enough to collapse the several calls a single page makes,
            // short enough that the height on screen is never visibly stale.
            info: Cache::expiring(1, Duration::from_secs(5)),
            tree_sizes: Cache::permanent(4096),
            rpc_permits: Arc::new(Semaphore::new(DEFAULT_MAX_INFLIGHT_RPC)),
            range_kib: Arc::new(Semaphore::new(RANGE_KIB as usize)),
            rpc_calls: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Outbound RPC calls made since start.
    #[must_use]
    pub fn rpc_calls(&self) -> u64 {
        self.rpc_calls.load(Ordering::Relaxed)
    }

    /// Override the in-flight RPC ceiling. See [`DEFAULT_MAX_INFLIGHT_RPC`].
    #[must_use]
    pub fn with_max_inflight_rpc(mut self, permits: usize) -> Self {
        self.rpc_permits = Arc::new(Semaphore::new(permits.max(1)));
        self
    }

    /// Call a JSON-RPC method, holding a permit for the duration.
    ///
    /// Together with [`Self::bare`] and [`Self::binary`] this is the **only**
    /// path to the daemon:
    /// `client` is private and has no accessor, so a new call site cannot
    /// forget the permit.
    async fn rpc<P, R>(&self, method: &'static str, params: Option<P>) -> Result<R, RpcError>
    where
        P: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let _permit = self.permit().await;
        self.rpc_calls.fetch_add(1, Ordering::Relaxed);
        self.client.json_rpc(method, params).await
    }

    /// Call a bare (non-JSON-RPC) endpoint, holding a permit for the duration.
    async fn bare<B, R>(&self, endpoint: &'static str, body: &B) -> Result<R, RpcError>
    where
        B: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let _permit = self.permit().await;
        self.rpc_calls.fetch_add(1, Ordering::Relaxed);
        self.client.endpoint(endpoint, body).await
    }

    /// Call a binary endpoint, holding a permit for the duration.
    async fn binary(
        &self,
        endpoint: &'static str,
        fields: &[(&str, monerod_rpc::epee::Field<'_>)],
        wanted: &[&str],
        max_bytes: u64,
    ) -> Result<monerod_rpc::epee::Root, RpcError> {
        let _permit = self.permit().await;
        self.rpc_calls.fetch_add(1, Ordering::Relaxed);
        self.client
            .binary(endpoint, fields, wanted, max_bytes)
            .await
    }

    /// Acquire a permit for one call against the daemon.
    ///
    /// Returns `None` only if the semaphore has been closed, which this code
    /// never does; callers treat that as "proceed" rather than failing a page
    /// over a condition that cannot arise.
    async fn permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.rpc_permits).acquire_owned().await.ok()
    }

    /// Cache occupancy and hit counts, for `/health` and for tests.
    pub fn cache_stats(&self) -> [(&'static str, crate::cache::Stats); 6] {
        [
            ("blocks_by_hash", self.blocks_by_hash.stats()),
            ("blocks_by_height", self.blocks_by_height.stats()),
            ("txs", self.txs.stats()),
            ("outs", self.outs.stats()),
            ("info", self.info.stats()),
            ("tree_sizes", self.tree_sizes.stats()),
        ]
    }

    /// How many outputs an FCMP++ transaction's inputs could each be spending:
    /// the curve tree's size as of its reference block.
    ///
    /// `None` for a ring spend, for a transaction still in the pool (it has no
    /// unified ids to probe with; see [`TreeSizeQuery`]), for one whose
    /// reference block pruning took, and whenever the daemon cannot answer --
    /// a daemon from before FCMP++ has no such endpoint. None of those is a
    /// page failure, so none of them is an error.
    ///
    /// `chain_height` is the tip's height plus one, as `get_info` reports it,
    /// and decides whether the answer is buried deep enough to keep.
    pub async fn anonymity_set(
        &self,
        tx: &TxJson,
        entry: &TxEntry,
        chain_height: u64,
    ) -> Option<u64> {
        let reference = tx.reference_block()?;
        if entry.in_pool {
            return None;
        }
        if let Some(hit) = self.tree_sizes.get(&reference) {
            return Some(*hit);
        }
        let probe = *entry.unified_ids.first()?;
        let query = TreeSizeQuery::as_of_block(reference, probe)?;
        let root = self
            .binary(
                TreeSizeQuery::ENDPOINT,
                &query.fields(),
                TreeSizeQuery::WANTED,
                TreeSizeQuery::MAX_ANSWER_BYTES,
            )
            .await
            .map_err(|e| tracing::warn!("tree size as of block {reference}: {e}"))
            .ok()?;
        let size = TreeSizeQuery::answer(&root)?;
        if safe_to_cache_by_height(depth(chain_height, reference)) {
            self.tree_sizes.insert(reference, size);
        }
        Some(size)
    }

    /// The paths through the curve tree of the outputs `unified_ids`, as of
    /// block `as_of_block`: one per id, in order, `None` for an output not in
    /// the tree as of that block. See [`PathQuery`].
    ///
    /// Not cached here: a path as of the tip changes with every block, and
    /// whether an answer is worth keeping is known only once it is placed
    /// and checked, which is [`crate::curve_tree::place_all`].
    pub async fn tree_paths(
        &self,
        as_of_block: u64,
        unified_ids: &[u64],
    ) -> Result<TreePaths, ChainError> {
        let bad = |detail: String| ChainError::BadAnswer {
            what: PathQuery::ENDPOINT,
            detail,
        };
        let query = PathQuery::as_of_block(as_of_block, unified_ids).ok_or_else(|| {
            bad(format!(
                "{} ids as of block {as_of_block} cannot be asked about in one call",
                unified_ids.len()
            ))
        })?;
        let root = self
            .binary(
                PathQuery::ENDPOINT,
                &query.fields(),
                PathQuery::WANTED,
                PathQuery::MAX_ANSWER_BYTES,
            )
            .await?;
        query.answer(&root).map_err(|e| bad(e.to_string()))
    }

    pub async fn info(&self) -> Result<Arc<GetInfo>, ChainError> {
        if let Some(hit) = self.info.get(&()) {
            return Ok(hit);
        }
        let fresh: GetInfo = self.rpc("get_info", None::<()>).await?;
        Ok(self.info.insert((), fresh))
    }

    /// The chain's info, asked of the daemon now rather than read from the
    /// cache.
    ///
    /// For a caller whose answer turns on the newest block, which the cached
    /// info can be up to five seconds behind. The answer replaces the cached
    /// one. It costs one daemon call, as looking up an unknown hash does.
    pub async fn fresh_info(&self) -> Result<Arc<GetInfo>, ChainError> {
        let fresh: GetInfo = self.rpc("get_info", None::<()>).await?;
        Ok(self.info.insert((), fresh))
    }

    pub async fn block(&self, id: BlockId) -> Result<Arc<GetBlock>, ChainError> {
        match id {
            BlockId::Hash(h) => {
                if let Some(hit) = self.blocks_by_hash.get(&h) {
                    return Ok(hit);
                }
            }
            BlockId::Height(h) => {
                if let Some(hit) = self.blocks_by_height.get(&h) {
                    return Ok(hit);
                }
            }
        }

        let request = match id {
            BlockId::Height(h) => GetBlockRequest::by_height(h),
            BlockId::Hash(h) => GetBlockRequest::by_hash(h.to_hex()),
        };

        let fresh: GetBlock = self
            .rpc("get_block", Some(request))
            .await
            .map_err(|e| match &e {
                RpcError::JsonRpc { code, .. } => classify_block_error(*code, id, e.to_string()),
                _ => ChainError::from(e),
            })?;

        // The block asked for, or none: a block the daemon sends in its place
        // must not be shown, nor cached under a name it does not have.
        let answered = fresh.block_header.hash.parse::<Hash32>().ok();
        let matches = match id {
            BlockId::Hash(h) => answered == Some(h),
            BlockId::Height(h) => fresh.block_header.height == h,
        };
        if !matches {
            return Err(ChainError::BadAnswer {
                what: "get_block",
                detail: format!("asked for block {id}, sent {}", fresh.block_header.height),
            });
        }

        if let Some(h) = answered {
            self.blocks_by_hash.insert(h, fresh.clone());
        }

        // Keyed by height: only once buried past the reorg window, because a
        // reorg reassigns a height to a different block. `depth` is the
        // daemon's own count of how far down the chain this block sits.
        //
        // And never for an orphan. monerod serves an alternative chain's block
        // by hash, with a depth counted from the main tip like any other, so
        // one looked up once buried would otherwise take the main chain's
        // place at its height for every later lookup by height.
        //
        // The daemon's depth is checked against the tip rather than taken on
        // its word alone.
        let buried = safe_to_cache_by_height(fresh.block_header.depth)
            && self.info().await.is_ok_and(|info| {
                safe_to_cache_by_height(depth(info.height, fresh.block_header.height))
            });
        if buried && !fresh.block_header.orphan_status {
            return Ok(self
                .blocks_by_height
                .insert(fresh.block_header.height, fresh));
        }

        Ok(Arc::new(fresh))
    }

    /// The body of the block `header` names, from whichever cache holds it.
    ///
    /// By hash, which names one block forever, so the body cache serves it at
    /// any depth and a reorg since `header` was fetched cannot substitute a
    /// different block. A block buried past the reorg window may sit in the
    /// larger height cache instead, and is taken from there when its hash
    /// matches: a scan of deep ranges wider than the hash cache would
    /// otherwise miss on every block.
    async fn body_for(
        &self,
        header: &monerod_rpc::types::BlockHeader,
    ) -> Result<Arc<GetBlock>, ChainError> {
        if safe_to_cache_by_height(header.depth)
            && let Some(hit) = self.blocks_by_height.get(&header.height)
            && hit.block_header.hash.eq_ignore_ascii_case(&header.hash)
        {
            return Ok(hit);
        }
        let id = header
            .hash
            .parse::<Hash32>()
            .map_or(BlockId::Height(header.height), BlockId::Hash);
        self.block(id).await
    }

    /// The block at `height`, without re-fetching a recent block's body on
    /// every call.
    ///
    /// [`Self::block`] by height caches only blocks buried past the reorg
    /// window, so a recent height costs a whole body each time. This asks for
    /// the header instead, which is small, and takes the body by the hash it
    /// names, which the hash cache holds after the first time.
    pub async fn block_at(&self, height: u64) -> Result<Arc<GetBlock>, ChainError> {
        if let Some(hit) = self.blocks_by_height.get(&height) {
            return Ok(hit);
        }
        let range = self.headers_range(height, height).await?;
        let Some(header) = range.headers.first() else {
            return Err(ChainError::BlockNotFound(BlockId::Height(height)));
        };
        self.body_for(header).await
    }

    /// The block carrying the root an FCMP++ proof naming `reference_block`
    /// was checked against, with that root: `reference_block - 8`, once it is
    /// known to carry one.
    ///
    /// Arithmetic alone names a block from before the fork for the first
    /// reference blocks after it, which carries no root, so the block is
    /// fetched and asked. `None` for such a block, below height 8, and when
    /// the block cannot be had.
    pub async fn proof_root(&self, reference_block: u64) -> Option<(u64, String)> {
        let height = monerod_rpc::types::tree_root_block(reference_block)?;
        let block = self.block_at(height).await.ok()?;
        BlockTree::of(&block).map(|t| (height, t.root))
    }

    /// How deep `header`'s block sits below the tip now.
    ///
    /// `depth` is counted from the tip at the moment the daemon answered, and a
    /// cached block keeps the count it had then: a block cached as the tip
    /// reads as the tip for as long as it stays cached. Anything shown to a
    /// reader is recounted from the current tip. When the tip cannot be had,
    /// the stored count is the best there is.
    ///
    /// 0 for an orphan: it is on no chain the tip is on, so no block buries
    /// it, although monerod counts its depth from the main tip like any other.
    pub async fn depth_now(&self, header: &monerod_rpc::types::BlockHeader) -> u64 {
        if header.orphan_status {
            return 0;
        }
        match self.info().await {
            Ok(info) => depth(info.height, header.height),
            Err(_) => header.depth,
        }
    }

    pub async fn transactions(&self, hashes: &[Hash32]) -> Result<FetchedTxs, ChainError> {
        // Asking monerod for nothing is not a useful round trip, and the empty
        // wire envelope would have to claim a status it was never given.
        if hashes.is_empty() {
            return Ok(FetchedTxs::default());
        }

        // Answer whatever is already cached and ask only for the rest. A block
        // page re-requests the same transactions every time it is reloaded,
        // and a reader paging back and forth revisits the same ones.
        let mut found: HashMap<Hash32, TxEntry> = HashMap::new();
        let mut want: Vec<String> = Vec::new();
        for h in hashes {
            match self.txs.get(h) {
                Some(hit) => {
                    found.insert(*h, (*hit).clone());
                }
                None => want.push(h.to_hex()),
            }
        }

        // A cached entry keeps the confirmation count it had when fetched, so
        // it is recounted from the current tip, the same count monerod gives:
        // the chain's height less the block's. When the tip cannot be had,
        // the stored count is the best there is.
        if !found.is_empty()
            && let Ok(info) = self.info().await
        {
            for entry in found.values_mut() {
                entry.confirmations = info
                    .height
                    .saturating_sub(entry.block_height)
                    .max(entry.confirmations);
            }
        }

        // What was asked for, so that only that is cached, and the chain's
        // height, so that "buried" is not the daemon's word alone.
        let asked: std::collections::HashSet<&Hash32> = hashes.iter().collect();
        // Asked for only when an answer might be cached.
        let mut tip_height: Option<Option<u64>> = None;
        let mut missed = Vec::new();
        for response in futures_util::future::join_all(want.chunks(MAX_TXS_PER_CALL).map(|chunk| {
            let request = GetTransactionsRequest::decoded(chunk.to_vec());
            async move {
                self.bare::<_, monerod_rpc::types::GetTransactionsResponse>(
                    "get_transactions",
                    &request,
                )
                .await
            }
        }))
        .await
        {
            let response = response?;
            for entry in response.txs {
                let Ok(h) = entry.tx_hash.parse::<Hash32>() else {
                    continue;
                };
                // A transaction not asked for is dropped, not cached under a
                // name the daemon chose.
                if !asked.contains(&h) {
                    continue;
                }
                // Only confirmed and buried transactions. A pool transaction
                // will gain a block, and a freshly confirmed one can still be
                // reorged back out -- either would be cached as a lie.
                let candidate = !entry.in_pool && entry.confirmations >= REORG_WINDOW;
                if candidate && tip_height.is_none() {
                    tip_height = Some(self.info().await.ok().map(|i| i.height));
                }
                let buried = candidate
                    && tip_height
                        .flatten()
                        .is_some_and(|tip| safe_to_cache_by_height(depth(tip, entry.block_height)));
                if buried {
                    self.txs.insert(h, entry.clone());
                }
                found.insert(h, entry);
            }
            missed.extend(response.missed_tx);
        }

        Ok(FetchedTxs {
            txs: in_requested_order(hashes, found),
            missed,
        })
    }

    /// Block headers for a height range, inclusive at both ends.
    ///
    /// monerod caps the span at 1000 under a restricted daemon. We require an
    /// unrestricted one, but the cap is cheap to respect and keeps a single
    /// oversized request from being rejected wholesale.
    pub async fn headers_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<GetBlockHeadersRange, ChainError> {
        const MAX_SPAN: u64 = 1000;
        let end = end.min(start.saturating_add(MAX_SPAN - 1));
        let request = GetBlockHeadersRangeRequest {
            start_height: start,
            end_height: end,
            fill_pow_hash: false,
        };
        Ok(self.rpc("get_block_headers_range", Some(request)).await?)
    }

    /// Every block in a height range, with its transactions.
    ///
    /// The obvious shape -- `get_block` then `get_transactions`, per block,
    /// each awaited before the next begins -- is 2N round trips in single
    /// file. This is three things instead:
    ///
    /// * one `get_block_headers_range` for the whole span, which already
    ///   carries every field a block listing shows;
    /// * `get_block` only for the blocks that hold user transactions, because
    ///   the header names the coinbase and counts the rest -- and all of them
    ///   at once rather than one after another;
    /// * one `get_transactions` for every hash in the range together.
    ///
    /// So 2N becomes 2 + however many blocks hold anything, and the round
    /// trips overlap. On a busy chain that is about half the calls; on a quiet
    /// one, where most blocks are nothing but their coinbase, it is two.
    ///
    /// `with_tree` asks for each block's curve tree as well. From the FCMP++
    /// fork on the tree is in the block's body, so that fetches the body of
    /// every post-fork block, coinbase-only ones included: N + 2 calls. Only
    /// a caller that shows the tree should ask for it.
    ///
    /// The headers are not cached, so a range that was served before now costs
    /// one call rather than none. That is the trade for the cold path costing
    /// two instead of two hundred.
    ///
    /// The range waits for its blocks' sizes' worth of [`RANGE_KIB`] before
    /// fetching them, and holds it for as long as the [`BlockRange`] lives.
    /// It is refused when its blocks hold more than [`MAX_RANGE_KIB`], and
    /// when it waits longer than [`RANGE_WAIT`].
    pub async fn blocks_in_range(
        &self,
        start: u64,
        end: u64,
        with_tree: bool,
    ) -> Result<BlockRange, ChainError> {
        let headers = self.headers_range(start, end).await?.headers;

        // The range's share of what ranges may hold at once, taken before any
        // body or transaction is fetched. See [`RANGE_KIB`].
        let kib = headers
            .iter()
            .map(|h| h.block_size.div_ceil(1024))
            .fold(0u64, u64::saturating_add);
        if kib > MAX_RANGE_KIB {
            return Err(ChainError::RangeTooLarge { start, end, kib });
        }
        let share = u32::try_from(kib).unwrap_or(u32::MAX).clamp(1, RANGE_KIB);
        let held = tokio::time::timeout(
            RANGE_WAIT,
            Arc::clone(&self.range_kib).acquire_many_owned(share),
        )
        .await
        .map_err(|_| ChainError::Busy("other ranges of blocks"))?
        .ok();

        // A block's body is fetched when it holds transactions, whose hashes
        // only the body lists -- the range cannot be answered without it --
        // and when the caller wants a post-fork block's curve tree, which is
        // in the body too but is optional: a block whose body could not be had
        // for its tree alone reports no tree rather than failing the range.
        //
        // Through `body_for`, which fetches by the hash each header carries:
        // see there for why, and for which cache serves it.
        let wanted_bodies: Vec<(&monerod_rpc::types::BlockHeader, bool)> = headers
            .iter()
            .filter_map(|h| {
                let needed = h.num_txes > 0;
                let for_tree =
                    with_tree && h.major_version >= monerod_rpc::types::HF_VERSION_FCMP_PLUS_PLUS;
                (needed || for_tree).then_some((h, needed))
            })
            .collect();
        let bodies =
            futures_util::future::join_all(wanted_bodies.iter().map(|(h, _)| self.body_for(h)))
                .await;

        let mut extra: HashMap<u64, Arc<GetBlock>> = HashMap::with_capacity(wanted_bodies.len());
        // Trees left out are reported as none, which the API documents as
        // "none reported" rather than "none exists", and logged once per
        // range, at warn, so an operator can tell a busy daemon from a
        // pre-fork block without a line per block.
        let mut trees_missed: Vec<(u64, ChainError)> = Vec::new();
        for ((header, needed), body) in wanted_bodies.iter().zip(bodies) {
            match body {
                Ok(body) => drop(extra.insert(header.height, body)),
                Err(e) if !needed => trees_missed.push((header.height, e)),
                Err(e) => return Err(e),
            }
        }
        if let Some((first, e)) = trees_missed.first() {
            tracing::warn!(
                "{} curve trees left out of blocks {start} to {end}, first at block {first}: {e}",
                trees_missed.len()
            );
        }

        // Every hash in the range, in the order its block lists them.
        let wanted: Vec<Vec<Hash32>> = headers
            .iter()
            .map(|h| {
                let mut hashes: Vec<Hash32> = Vec::new();
                hashes.extend(h.miner_tx_hash.parse::<Hash32>());
                if let Some(body) = extra.get(&h.height) {
                    hashes.extend(
                        body.tx_hashes
                            .iter()
                            .filter_map(|t| t.parse::<Hash32>().ok()),
                    );
                }
                hashes
            })
            .collect();

        let flat: Vec<Hash32> = wanted.iter().flatten().copied().collect();
        let mut fetched: HashMap<Hash32, TxEntry> = self
            .transactions(&flat)
            .await?
            .txs
            .into_iter()
            .filter_map(|e| e.tx_hash.parse::<Hash32>().ok().map(|h| (h, e)))
            .collect();

        let blocks = headers
            .into_iter()
            .zip(wanted)
            .map(|(header, hashes)| BlockWithTxs {
                tree: if with_tree {
                    extra.get(&header.height).and_then(|b| BlockTree::of(b))
                } else {
                    None
                },
                header,
                txs: hashes.iter().filter_map(|h| fetched.remove(h)).collect(),
            })
            .collect();
        Ok(BlockRange {
            blocks,
            _held: held,
        })
    }

    /// The tip block's header.
    ///
    /// Its `major_version` is the active hard-fork version, which is why
    /// `/api/networkinfo` needs it.
    pub async fn last_block_header(&self) -> Result<GetBlockHeader, ChainError> {
        Ok(self.rpc("get_last_block_header", None::<()>).await?)
    }

    pub async fn fee_estimate(&self, grace_blocks: u64) -> Result<FeeEstimate, ChainError> {
        let request = GetFeeEstimateRequest { grace_blocks };
        Ok(self.rpc("get_fee_estimate", Some(request)).await?)
    }

    /// Transaction ids whose low bits match a template.
    ///
    /// The daemon side of the k-anonymous lookup: the caller names a suffix
    /// rather than a transaction, and everything matching comes back, so the
    /// explorer never learns which one was wanted.
    ///
    /// `Ok(None)` means the daemon does not have the method -- it is in
    /// monerod `master` and `release-v0.19` but in no release, and v0.18.5.1
    /// answers `Method not found`. That is a deployment fact rather than a
    /// failure, so it is a distinct outcome from an error.
    pub async fn txids_loose(
        &self,
        request: &GetTxidsLooseRequest,
    ) -> Result<Option<GetTxidsLooseResponse>, ChainError> {
        match self
            .rpc::<_, GetTxidsLooseResponse>("get_txids_loose", Some(request))
            .await
        {
            Ok(r) => Ok(Some(r)),
            Err(RpcError::JsonRpc { code, .. }) if code == error_code::METHOD_NOT_FOUND => Ok(None),
            Err(e) => Err(ChainError::from(e)),
        }
    }

    /// Alternative chains this node is tracking.
    ///
    /// Blocked under `--restricted-rpc`, like the mempool.
    pub async fn alt_chains(&self) -> Result<GetAlternateChains, ChainError> {
        self.rpc("get_alternate_chains", None::<()>)
            .await
            .map_err(|e| match &e {
                RpcError::JsonRpc { code, .. } if *code == error_code::METHOD_NOT_FOUND => {
                    ChainError::NeedsUnrestricted("alternative chains")
                }
                _ => ChainError::from(e),
            })
    }

    /// The mempool.
    ///
    /// Blocked under `--restricted-rpc`, so a restricted daemon surfaces as
    /// [`ChainError::NeedsUnrestricted`] rather than as a generic failure --
    /// the page is unavailable by configuration, not broken.
    pub async fn mempool(&self) -> Result<GetTransactionPool, ChainError> {
        let mut pool: GetTransactionPool = self
            .bare("get_transaction_pool", &serde_json::json!({}))
            .await
            .map_err(|e| match &e {
                RpcError::Http { status: 404, .. } => ChainError::NeedsUnrestricted("the mempool"),
                _ => ChainError::from(e),
            })?;

        newest_first(&mut pool.transactions);
        Ok(pool)
    }

    /// The pool's aggregate figures, without the pool.
    ///
    /// `/api/networkinfo` wants one number out of the mempool, its size in
    /// bytes. Summing it from [`Self::mempool`] means the daemon serialises
    /// every pool transaction -- 187 kB against 868 on a 12-transaction
    /// testnet pool -- for a page that is otherwise the cheapest one here.
    pub async fn pool_stats(&self) -> Result<GetTransactionPoolStats, ChainError> {
        self.bare("get_transaction_pool_stats", &serde_json::json!({}))
            .await
            .map_err(|e| match &e {
                RpcError::Http { status: 404, .. } => ChainError::NeedsUnrestricted("the mempool"),
                _ => ChainError::from(e),
            })
    }

    /// Resolve one input's ring, in a call of its own.
    ///
    /// **The fallback path.** [`Self::resolve_rings`] asks for a whole
    /// transaction's rings at once and drops to this when the daemon refuses:
    /// monerod fails the *entire* `/get_outs` request if any single
    /// `(amount, index)` pair is out of range — measured, mixing one bad index
    /// with one good one returns `status: "Failed"` and no `outs` key at all —
    /// so a batch cannot say which input was the bad one. One call per input
    /// can, which is how one unresolvable input avoids blanking every ring on
    /// the page. The offending input is dropped and the rest are rendered.
    ///
    /// Never returns `Err` for an unresolvable ring: that is a per-input
    /// display state, not a page failure.
    pub async fn resolve_ring(&self, input: &TxInToKey) -> ResolvedInput {
        let key_image = input.k_image.parse::<Hash32>().unwrap_or(Hash32::ZERO);

        let unresolved = |unavailable: bool| ResolvedInput {
            amount: input.amount,
            key_image,
            ring: Vec::new(),
            ring_unavailable: unavailable,
        };

        // `ring_members` carries this input's own amount through with each
        // index. For a pre-RingCT input the index means nothing without it:
        // the cumulative offset sum addresses that denomination's output set,
        // not the global one.
        let Some(requests) = input.ring_members() else {
            // A hostile offset list that overflows u64 on summation.
            return unresolved(true);
        };
        if requests.is_empty() {
            return unresolved(false);
        }

        let wanted = requests.len();

        // Ring members repeat heavily: popular outputs are chosen as decoys
        // again and again, and reloading a page re-requests the same ring. If
        // every member is already known, the daemon is not asked at all.
        let cached: Vec<Option<Arc<OutKey>>> = requests
            .iter()
            .map(|r| self.outs.get(&(r.amount(), r.index())))
            .collect();
        if cached.iter().all(Option::is_some) {
            return ResolvedInput {
                amount: input.amount,
                key_image,
                ring: requests
                    .iter()
                    .zip(cached.iter())
                    .filter_map(|(req, hit)| {
                        let out = hit.as_ref()?;
                        Some(RingMember {
                            index: req.index(),
                            block_height: out.height,
                            public_key: out.key.parse().unwrap_or(Hash32::ZERO),
                            tx_hash: out.txid.parse().unwrap_or(Hash32::ZERO),
                        })
                    })
                    .collect(),
                ring_unavailable: false,
            };
        }

        let request = GetOutsRequest::new(requests.clone(), true);
        let Ok(response) = self
            .bare::<_, monerod_rpc::types::GetOutsResponse>("get_outs", &request)
            .await
        else {
            return unresolved(true);
        };

        // A short `outs` array cannot be zipped positionally against the
        // requests: we would silently attribute one offset's output to another.
        if response.outs.len() != wanted {
            return unresolved(true);
        }

        let tip = self.info().await.ok().map(|i| i.height);
        for (req, out) in requests.iter().zip(response.outs.iter()) {
            self.keep_out((req.amount(), req.index()), out.clone(), tip);
        }

        let ring = requests
            .iter()
            .zip(response.outs.iter())
            .map(|(req, out)| RingMember {
                index: req.index(),
                block_height: out.height,
                public_key: out.key.parse().unwrap_or(Hash32::ZERO),
                tx_hash: out.txid.parse().unwrap_or(Hash32::ZERO),
            })
            .collect();

        ResolvedInput {
            amount: input.amount,
            key_image,
            ring,
            ring_unavailable: false,
        }
    }

    /// Resolve every input of a transaction, one request per input.
    ///
    /// The requests are issued **concurrently**, not in sequence. They stay
    /// one-per-input for the correctness reason on [`Self::resolve_ring`] --
    /// monerod fails a whole batch if any index is out of range -- but nothing
    /// requires waiting for each before starting the next.
    ///
    /// This matters on real data: mainnet transaction bf1b4e2b…c193 has 195
    /// inputs, and resolving them in sequence took 6.1 seconds. The semaphore
    /// still bounds how many actually reach the daemon at once, so this
    /// shortens the request rather than deepening the load.
    ///
    /// `join_all` preserves order, which ring display depends on: ring `n`
    /// must belong to input `n`.
    pub async fn resolve_rings(&self, tx: &TxJson) -> Vec<ResolvedInput> {
        // An FCMP++ input has no ring to fetch, and nothing was refused.
        if tx.is_fcmp_pp() {
            return unexpanded_inputs(tx);
        }

        let inputs: Vec<&TxInToKey> = tx
            .vin
            .iter()
            .filter_map(|input| match input {
                monerod_rpc::types::TxIn::Key(k) => Some(k),
                _ => None,
            })
            .collect();

        // One call for the whole transaction when the daemon will allow it.
        // A transaction's inputs are independent only in the failure case, so
        // paying a round trip each is paying for a case that almost never
        // happens: mainnet bf1b4e2b..c193 has 195 inputs and cost 195 calls.
        if inputs.len() > 1
            && let Some(resolved) = self.resolve_rings_together(&inputs).await
        {
            return resolved;
        }

        futures_util::future::join_all(inputs.iter().map(|k| self.resolve_ring(k))).await
    }

    /// A ring member, cached when its block is buried past the reorg window
    /// below `tip`, the chain's height, and returned either way.
    fn keep_out(&self, key: (u64, u64), out: OutKey, tip: Option<u64>) -> Arc<OutKey> {
        let buried = tip.is_some_and(|tip| safe_to_cache_by_height(depth(tip, out.height)));
        if buried {
            self.outs.insert(key, out)
        } else {
            Arc::new(out)
        }
    }

    /// Every ring of one transaction in a single `get_outs`.
    ///
    /// `None` means the batch is not usable and the caller must fall back to
    /// one call per input: monerod fails the *whole* request if any single
    /// index is out of range, so a batch cannot report which input was the bad
    /// one, and the per-input path exists precisely so that one unresolvable
    /// input does not blank every ring on the page.
    ///
    /// Nothing here reads a ring member back out of the cache after writing
    /// it. The cache is a bounded LRU shared with every other request, so an
    /// entry written at the top of this function can be evicted before the
    /// bottom of it, and a ring assembled from what survived would be reported
    /// as partly unavailable when it was in fact complete.
    async fn resolve_rings_together(&self, inputs: &[&TxInToKey]) -> Option<Vec<ResolvedInput>> {
        let rings: Vec<Vec<OutKeyRequest>> = inputs
            .iter()
            .map(|k| k.ring_members())
            .collect::<Option<_>>()?;
        if rings.iter().any(Vec::is_empty) {
            return None;
        }

        // Ask only for what is not already known, and only once for a decoy
        // that two inputs happen to share -- which they may, decoys being
        // drawn independently per input.
        let mut known: HashMap<(u64, u64), Arc<OutKey>> = HashMap::new();
        let mut wanted: Vec<OutKeyRequest> = Vec::new();
        // A set rather than a linear scan of `wanted`: mainnet bf1b4e2b..c193
        // has 195 inputs, so its rings hold 3,120 members and a scan-per-member
        // is about five million comparisons before a single byte is asked for.
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        for member in rings.iter().flatten() {
            let key = (member.amount(), member.index());
            if !seen.insert(key) {
                continue;
            }
            match self.outs.get(&key) {
                Some(hit) => drop(known.insert(key, hit)),
                None => wanted.push(*member),
            }
        }

        if !wanted.is_empty() {
            let request = GetOutsRequest::new(wanted.clone(), true);
            let response: monerod_rpc::types::GetOutsResponse =
                self.bare("get_outs", &request).await.ok()?;

            // A short array cannot be zipped positionally against the
            // requests: we would attribute one offset's output to another.
            if response.outs.len() != wanted.len() {
                return None;
            }
            let tip = self.info().await.ok().map(|i| i.height);
            for (req, out) in wanted.iter().zip(response.outs) {
                let key = (req.amount(), req.index());
                known.insert(key, self.keep_out(key, out, tip));
            }
        }

        Some(
            inputs
                .iter()
                .zip(rings)
                .map(|(input, members)| {
                    let ring: Vec<RingMember> = members
                        .iter()
                        .filter_map(|m| {
                            let out = known.get(&(m.amount(), m.index()))?;
                            Some(RingMember {
                                index: m.index(),
                                block_height: out.height,
                                public_key: out.key.parse().unwrap_or(Hash32::ZERO),
                                tx_hash: out.txid.parse().unwrap_or(Hash32::ZERO),
                            })
                        })
                        .collect();
                    let whole = ring.len() == members.len();
                    ResolvedInput {
                        amount: input.amount,
                        key_image: input.k_image.parse().unwrap_or(Hash32::ZERO),
                        ring: if whole { ring } else { Vec::new() },
                        ring_unavailable: !whole,
                    }
                })
                .collect(),
        )
    }
}

/// Order pool transactions by arrival, newest first.
///
/// monerod returns the pool in its own internal order, which is neither
/// arrival order nor stable between calls. Newest first is the only order a
/// pool listing means anything in, so the pool is sorted here.
fn newest_first(txs: &mut [monerod_rpc::types::PoolTxInfo]) {
    txs.sort_by_key(|t| std::cmp::Reverse(t.receive_time));
}

/// A transaction's inputs, listed but not expanded.
///
/// Only the ring members cost a lookup; the amount and key image are in the
/// transaction itself. An endpoint that deliberately skips the lookup -- the
/// k-anonymous one expands nothing, because expanding every ring of a
/// thousand-transaction anonymity set is thousands of calls for a caller who
/// wants one of them -- still has to say the inputs are there. Answering
/// `"inputs": []` for a transaction that spends something is not an
/// abbreviation of the truth, it is a different claim, and it contradicts the
/// `"coinbase": false` sitting beside it.
///
/// An FCMP++ transaction is the exception: its inputs have no ring to
/// withhold, so they are reported as complete and empty rather than as
/// unavailable.
#[must_use]
pub fn unexpanded_inputs(tx: &TxJson) -> Vec<ResolvedInput> {
    let withheld = !tx.is_fcmp_pp();
    tx.vin
        .iter()
        .filter_map(|input| match input {
            monerod_rpc::types::TxIn::Key(k) => Some(ResolvedInput {
                amount: k.amount,
                key_image: k.k_image.parse().unwrap_or(Hash32::ZERO),
                ring: Vec::new(),
                ring_unavailable: withheld,
            }),
            _ => None,
        })
        .collect()
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

    fn source() -> RpcChainSource {
        RpcChainSource::new(Client::new("http://127.0.0.1:1").expect("valid url"))
    }

    fn hash(byte: u8) -> Hash32 {
        format!("{byte:02x}")
            .repeat(32)
            .parse()
            .expect("32 bytes of hex")
    }

    /// Every field but these two has a serde default, so this is the whole
    /// shape a confirmed transaction needs to stand in for one here.
    fn entry(h: Hash32) -> TxEntry {
        serde_json::from_value(serde_json::json!({
            "tx_hash": h.to_hex(),
            "in_pool": false,
        }))
        .expect("a minimal confirmed tx entry")
    }

    /// The order a block lists its transactions in is part of the answer, and
    /// the coinbase is first. Cache hits and fetched transactions arrive from
    /// two different places, so assembling them in arrival order gets this
    /// right only while the cache is empty: warming one transaction of a
    /// block by visiting its own page would move it to the front of that
    /// block's list.
    #[test]
    fn a_partly_cached_batch_keeps_the_order_it_was_asked_for() {
        let asked = [hash(0x11), hash(0x22), hash(0x33)];

        // Insert in an order unrelated to `asked`, as the two sources would:
        // the middle one was the cache hit, the others came back from the RPC.
        let mut found = HashMap::new();
        found.insert(asked[1], entry(asked[1]));
        found.insert(asked[2], entry(asked[2]));
        found.insert(asked[0], entry(asked[0]));

        let got = in_requested_order(&asked, found);
        let order: Vec<String> = got.iter().map(|e| e.tx_hash.clone()).collect();
        assert_eq!(
            order,
            asked.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
            "answered in its own order rather than the caller's"
        );
    }

    /// A transaction the daemon does not have is dropped, not substituted by
    /// its neighbour. monerod reports it in `missed_tx` and simply omits it
    /// from `txs`, so the batch comes back shorter than it was asked for.
    #[test]
    fn a_transaction_the_daemon_does_not_have_is_dropped_not_substituted() {
        let asked = [hash(0x11), hash(0x22), hash(0x33)];
        let mut found = HashMap::new();
        found.insert(asked[2], entry(asked[2]));
        found.insert(asked[0], entry(asked[0]));

        let got = in_requested_order(&asked, found);
        assert_eq!(got.len(), 2, "the absent one was filled in from somewhere");
        assert!(
            !got.iter().any(|e| e.tx_hash == asked[1].to_hex()),
            "the hash monerod did not answer for came back anyway"
        );
    }

    /// The invariant the batched ring lookup is most likely to break.
    ///
    /// monerod fails an entire `get_outs` if any one index is out of range, so
    /// asking for a whole transaction's rings at once means one bad input can
    /// take every other ring down with it. The fallback to one call per input
    /// exists so that one bad input costs only its own ring. Built from a real
    /// transaction, because a ring that resolves has to actually resolve for
    /// the test to mean anything.
    #[tokio::test]
    #[ignore = "needs the local testnet node on 127.0.0.1:28081"]
    async fn one_unresolvable_input_does_not_blank_the_rings_beside_it() {
        let source = RpcChainSource::new(Client::new("http://127.0.0.1:28081").expect("valid url"));

        // Block 134,721 holds one of the chain's original transactions.
        let block = source
            .block(BlockId::Height(134_721))
            .await
            .expect("the testnet node has block 134721");
        let hash: Hash32 = block.tx_hashes[0].parse().expect("a tx hash");
        let entry = source.transactions(&[hash]).await.expect("the tx");
        let tx = entry.txs[0].parse_json().expect("decoded json");

        let monerod_rpc::types::TxIn::Key(good) = tx.vin[0].clone() else {
            panic!("block 134721's transaction should spend a key input");
        };

        let mut mixed = tx.clone();
        mixed.vin = vec![
            monerod_rpc::types::TxIn::Key(good.clone()),
            monerod_rpc::types::TxIn::Key(TxInToKey {
                amount: good.amount,
                // Far past the end of any output set this chain has.
                key_offsets: vec![u64::MAX / 2],
                k_image: "cc".repeat(32),
            }),
        ];

        let resolved = source.resolve_rings(&mixed).await;
        assert_eq!(resolved.len(), 2);
        assert!(
            !resolved[0].ring.is_empty(),
            "the good ring was blanked by the bad input next to it"
        );
        assert!(!resolved[0].ring_unavailable);
        assert!(
            resolved[1].ring.is_empty() && resolved[1].ring_unavailable,
            "the out-of-range input should be the only one reported unavailable"
        );

        // And when every input resolves, the whole transaction costs one
        // call rather than one per input. Two inputs drawing the same ring
        // also exercise the dedup: a decoy two inputs share is asked for once.
        let mut both_good = tx.clone();
        both_good.vin = vec![
            monerod_rpc::types::TxIn::Key(good.clone()),
            monerod_rpc::types::TxIn::Key(good),
        ];

        let fresh = RpcChainSource::new(Client::new("http://127.0.0.1:28081").expect("valid url"));
        let resolved = fresh.resolve_rings(&both_good).await;
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|r| !r.ring.is_empty()));
        assert_eq!(
            fresh.rpc_calls(),
            1,
            "a transaction's rings should cost one call, not one per input"
        );
    }

    /// Newest first. monerod's own order is arbitrary, and a pool listing in
    /// arbitrary order is not a listing of anything; a reversed sort would
    /// show the oldest unconfirmed transaction as the newest.
    #[test]
    fn the_pool_is_ordered_by_arrival_newest_first() {
        let mut pool: Vec<monerod_rpc::types::PoolTxInfo> = [30u64, 10, 20]
            .into_iter()
            .map(|t| {
                serde_json::from_value(serde_json::json!({
                    "id_hash": format!("{t:02x}").repeat(32),
                    "receive_time": t,
                    "blob_size": 0,
                    "fee": 0,
                    "max_used_block_id_hash": "",
                    "max_used_block_height": 0,
                    "kept_by_block": false,
                    "last_failed_height": 0,
                    "last_failed_id_hash": "",
                    "relayed": true,
                    "last_relayed_time": 0,
                    "do_not_relay": false,
                    "double_spend_seen": false,
                    "tx_blob": "",
                }))
                .expect("a minimal pool entry")
            })
            .collect();

        newest_first(&mut pool);
        assert_eq!(
            pool.iter().map(|t| t.receive_time).collect::<Vec<_>>(),
            vec![30, 20, 10]
        );
    }

    /// Listing a transaction's inputs costs nothing -- the amount and key
    /// image are in the transaction itself -- so an endpoint that skips the
    /// ring lookup still has to report that the inputs exist. Answering
    /// `"inputs": []` next to `"coinbase": false` says the transaction spent
    /// nothing, which is a different claim from "the ring is not shown".
    #[test]
    fn an_unexpanded_input_is_listed_with_its_ring_withheld_not_dropped() {
        let tx: TxJson = serde_json::from_value(serde_json::json!({
            "version": 1,
            "unlock_time": 0,
            "vin": [{"key": {
                "amount": 10_000_000_000_000u64,
                "key_offsets": [3, 7, 11],
                "k_image": "87".repeat(32),
            }}],
            "vout": [],
            "extra": [],
        }))
        .expect("a one-input transaction");

        let inputs = unexpanded_inputs(&tx);
        assert_eq!(inputs.len(), 1, "the input was dropped rather than listed");
        assert_eq!(inputs[0].amount, 10_000_000_000_000);
        assert_eq!(inputs[0].key_image.to_hex(), "87".repeat(32));
        assert!(inputs[0].ring.is_empty());
        assert!(
            inputs[0].ring_unavailable,
            "an empty ring must render as withheld, not as a ring of zero members"
        );
    }

    /// A coinbase has a `gen` input, which is not a spend and carries no key
    /// image. No inputs are reported for one.
    #[test]
    fn a_coinbase_input_is_not_listed_as_a_spend() {
        let tx: TxJson = serde_json::from_value(serde_json::json!({
            "version": 2,
            "unlock_time": 0,
            "vin": [{"gen": {"height": 137_080}}],
            "vout": [],
            "extra": [],
        }))
        .expect("a coinbase transaction");
        assert!(unexpanded_inputs(&tx).is_empty());
    }

    /// The same guarantee through the public call, on the path that asks the
    /// daemon for no transaction. It asks for the tip, to recount the cached
    /// entries' confirmations, and answers without it when it cannot be had.
    #[tokio::test]
    async fn a_fully_cached_batch_is_answered_in_the_order_it_was_asked_for() {
        let source = source();
        let asked = [hash(0xaa), hash(0xbb), hash(0xcc)];
        // Cached in reverse, which is what a reader who arrived from the
        // newest transaction backwards would leave behind.
        for h in asked.iter().rev() {
            source.txs.insert(*h, entry(*h));
        }

        let got = source
            .transactions(&asked)
            .await
            .expect("a fully cached batch needs no transaction from the daemon");
        let order: Vec<String> = got.txs.iter().map(|e| e.tx_hash.clone()).collect();
        assert_eq!(order, asked.iter().map(|h| h.to_hex()).collect::<Vec<_>>());
        assert_eq!(source.rpc_calls(), 1, "only the tip was asked for");
    }

    /// A ring whose offsets overflow on summation must degrade to an
    /// unavailable ring, not panic and not reach the daemon.
    #[tokio::test]
    async fn an_overflowing_offset_list_never_reaches_the_daemon() {
        let input = TxInToKey {
            amount: 0,
            key_offsets: vec![u64::MAX, u64::MAX],
            k_image: "aa".repeat(32),
        };
        // The client points at a closed port; if this tried to call out it
        // would still return unavailable, so assert it did not even try by
        // checking it resolves instantly and reports the right shape.
        let resolved = source().resolve_ring(&input).await;
        assert!(resolved.ring.is_empty());
        assert!(resolved.ring_unavailable);
        assert_eq!(resolved.amount, 0);
    }

    /// An input with no offsets has an empty ring, but that is not a failure:
    /// nothing was unavailable, there was simply nothing to fetch.
    #[tokio::test]
    async fn an_empty_offset_list_is_empty_but_not_unavailable() {
        let input = TxInToKey {
            amount: 0,
            key_offsets: vec![],
            k_image: "bb".repeat(32),
        };
        let resolved = source().resolve_ring(&input).await;
        assert!(resolved.ring.is_empty());
        assert!(
            !resolved.ring_unavailable,
            "nothing was asked for, so nothing was refused"
        );
    }

    /// The bound that protects the operator's daemon. Without it, per-request
    /// limits still multiply by however many requests arrive at once.
    #[tokio::test]
    async fn no_more_than_the_permitted_number_of_calls_reach_the_daemon_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let source = Arc::new(
            RpcChainSource::new(Client::new("http://127.0.0.1:1").expect("valid url"))
                .with_max_inflight_rpc(3),
        );

        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..40 {
            let source = Arc::clone(&source);
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            tasks.push(tokio::spawn(async move {
                let _permit = source.permit().await;
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                live.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.expect("no task panicked");
        }

        let observed = peak.load(Ordering::SeqCst);
        assert!(
            observed <= 3,
            "{observed} calls were in flight at once against a ceiling of 3"
        );
        assert!(observed > 1, "the test did not actually run concurrently");
    }

    /// Resolving concurrently must not reorder the results: the page shows
    /// ring `n` under input `n`, so a reordering would attribute one input's
    /// decoys to another -- wrong, and wrong in a way that looks plausible.
    ///
    /// The daemon is unreachable here, so every ring comes back unavailable;
    /// what is under test is that the *order* survives the concurrency, which
    /// the distinct per-input amounts make observable.
    #[tokio::test]
    async fn concurrent_ring_resolution_preserves_input_order() {
        use monerod_rpc::types::{TxIn, TxInToKey};

        let source = RpcChainSource::new(Client::new("http://127.0.0.1:1").expect("valid url"));

        let tx = TxJson {
            version: 1,
            unlock_time: 0,
            vin: (0..25u64)
                .map(|i| {
                    TxIn::Key(TxInToKey {
                        // Distinct per input, so a reordering is visible.
                        amount: 1_000 + i,
                        key_offsets: vec![i + 1],
                        k_image: format!("{:02x}", i).repeat(32),
                    })
                })
                .collect(),
            vout: Vec::new(),
            extra: Vec::new(),
            signatures: None,
            rct_signatures: None,
            rctsig_prunable: None,
        };

        let resolved = source.resolve_rings(&tx).await;

        assert_eq!(resolved.len(), 25);
        for (i, r) in resolved.iter().enumerate() {
            assert_eq!(
                r.amount,
                1_000 + i as u64,
                "input {i} came back in position {i} with the wrong amount"
            );
        }
    }

    /// Only a not-found code reads as "no such block", so a busy daemon never
    /// tells the reader their block does not exist. The codes are monerod's,
    /// measured against a live node.
    #[test]
    fn block_errors_are_classified_by_what_monerod_actually_returns() {
        use monerod_rpc::types::error_code as ec;
        let id = BlockId::Height(999_999_999);

        // Asked for something that is not there, three ways.
        for code in [ec::WRONG_PARAM, ec::TOO_BIG_HEIGHT, ec::INTERNAL] {
            let e = classify_block_error(code, id, "x".to_owned());
            assert!(e.is_not_found(), "code {code} should read as not found");
            assert!(!e.is_transient());
        }

        // Busy is the one that was being reported as missing.
        let busy = classify_block_error(ec::CORE_BUSY, id, "busy".to_owned());
        assert!(!busy.is_not_found(), "a busy daemon has not lost the block");
        assert!(busy.is_transient(), "and retrying may work");

        // Gated off by configuration: neither missing nor worth retrying.
        let gated = classify_block_error(ec::METHOD_NOT_FOUND, id, "x".to_owned());
        assert!(!gated.is_not_found());
        assert!(!gated.is_transient());

        // An unrecognised code must not claim the block is absent: that is a
        // stronger statement than the evidence supports.
        let unknown = classify_block_error(-12345, id, "x".to_owned());
        assert!(!unknown.is_not_found());
    }

    /// A ceiling of zero would deadlock every request forever, which is a
    /// worse failure than an unbounded one because it looks like a hang.
    #[tokio::test]
    async fn a_zero_ceiling_is_raised_to_one_rather_than_deadlocking() {
        let source = RpcChainSource::new(Client::new("http://127.0.0.1:1").expect("valid url"))
            .with_max_inflight_rpc(0);
        let permit = source.permit().await;
        assert!(permit.is_some(), "a zero ceiling must still admit one call");
    }

    fn block_with(major_version: u8, json: &str) -> GetBlock {
        serde_json::from_value(serde_json::json!({
            "block_header": {
                "major_version": major_version, "minor_version": major_version,
                "timestamp": 0, "prev_hash": "", "nonce": 0, "orphan_status": false,
                "height": 1, "depth": 0, "hash": "", "difficulty": 1,
                "difficulty_top64": 0, "wide_difficulty": "0x1",
                "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                "wide_cumulative_difficulty": "0x1", "reward": 0, "block_size": 0,
                "num_txes": 0, "pow_hash": "", "miner_tx_hash": "",
            },
            "miner_tx_hash": "", "blob": "", "json": json,
        }))
        .expect("a block")
    }

    /// A block's version decides whether its JSON is read at all: below the
    /// fork there is no tree to find, so a pre-fork block costs no parse,
    /// whatever its JSON holds.
    #[test]
    fn only_a_post_fork_block_is_asked_for_its_tree() {
        let root = "AB".repeat(32);
        let json = format!(r#"{{"fcmp_pp_n_tree_layers":2,"fcmp_pp_tree_root":"{root}"}}"#);
        assert_eq!(BlockTree::of(&block_with(16, &json)), None);
        assert_eq!(
            BlockTree::of(&block_with(17, &json)),
            Some(BlockTree {
                root: "ab".repeat(32),
                n_layers: 2
            })
        );
        // A root that is not 64 hex characters is no root.
        for bad in ["AB", &"zz".repeat(32), &"ab".repeat(33)] {
            let json = format!(r#"{{"fcmp_pp_n_tree_layers":2,"fcmp_pp_tree_root":"{bad}"}}"#);
            assert_eq!(BlockTree::of(&block_with(17, &json)), None, "{bad}");
        }
        // Both fields or neither.
        let half = r#"{"fcmp_pp_tree_root":"ab"}"#;
        assert_eq!(BlockTree::of(&block_with(17, half)), None);
        assert_eq!(BlockTree::of(&block_with(17, "not json")), None);
    }

    fn fcmp_pp_tx() -> TxJson {
        serde_json::from_value(serde_json::json!({
            "version": 2, "unlock_time": 0,
            "vin": [
                {"key": {"amount": 0, "key_offsets": [], "k_image": "aa".repeat(32)}},
                {"key": {"amount": 0, "key_offsets": [], "k_image": "bb".repeat(32)}},
            ],
            "vout": [], "extra": [],
            "rct_signatures": {"type": 7, "txnFee": 1},
        }))
        .expect("an FCMP++ transaction")
    }

    /// An FCMP++ input has no ring, so resolving one must not reach the
    /// daemon, even with offsets a ring spend would carry. The source here
    /// points at a port nothing listens on: a call would come back
    /// unavailable, and the count would move.
    #[tokio::test]
    async fn an_fcmp_pp_transaction_resolves_without_asking_the_daemon() {
        let src = source();
        let mut tx = fcmp_pp_tx();
        for input in &mut tx.vin {
            if let monerod_rpc::types::TxIn::Key(k) = input {
                k.key_offsets = vec![5, 1];
            }
        }
        let resolved = src.resolve_rings(&tx).await;
        assert_eq!(resolved.len(), 2, "every input is still listed");
        for r in &resolved {
            assert!(r.ring.is_empty());
            assert!(!r.ring_unavailable, "nothing was refused");
        }
        assert_eq!(resolved[1].key_image, "bb".repeat(32).parse().unwrap());
        assert_eq!(src.rpc_calls(), 0);
    }

    /// The k-anonymous endpoint withholds rings, but an FCMP++ input has none
    /// to withhold. Reporting it unavailable would claim a lookup was skipped.
    #[test]
    fn an_unexpanded_fcmp_pp_input_is_complete_not_withheld() {
        let inputs = unexpanded_inputs(&fcmp_pp_tx());
        assert_eq!(inputs.len(), 2);
        assert!(inputs.iter().all(|i| !i.ring_unavailable));
    }

    /// The tree size is asked for only where it can be answered. A pool
    /// transaction has no unified id to probe with, a ring spend has no tree,
    /// and a pruned FCMP++ spend has no reference block; none of them may cost
    /// a daemon call.
    #[tokio::test]
    async fn the_tree_size_is_not_asked_for_where_it_cannot_be_answered() {
        let src = source();
        let fcmp = fcmp_pp_tx();
        let mut with_ref = fcmp.clone();
        with_ref.rctsig_prunable = Some(monerod_rpc::types::RctSigPrunable {
            reference_block: Some(120),
            n_tree_layers: Some(2),
            ..Default::default()
        });

        let mut pool = entry(hash(1));
        pool.in_pool = true;
        pool.unified_ids = vec![5];
        assert_eq!(src.anonymity_set(&with_ref, &pool, 200).await, None);

        // Pruned: FCMP++, but no reference block.
        let mut mined = entry(hash(2));
        mined.unified_ids = vec![5];
        assert_eq!(src.anonymity_set(&fcmp, &mined, 200).await, None);

        // A daemon that sent no unified ids.
        let bare = entry(hash(3));
        assert_eq!(src.anonymity_set(&with_ref, &bare, 200).await, None);

        assert_eq!(src.rpc_calls(), 0);

        // With everything in place the call is made, and an unreachable daemon
        // reads as unknown rather than as an error.
        assert_eq!(src.anonymity_set(&with_ref, &mined, 200).await, None);
        assert_eq!(src.rpc_calls(), 1);
    }

    // -----------------------------------------------------------------------
    // A stand-in daemon, for the paths whose behaviour is which calls they make
    // -----------------------------------------------------------------------

    /// A loopback HTTP server answering like monerod for the few calls the
    /// range and cache code makes, and recording each one. Bounded throughout:
    /// the listener polls, every read has a timeout, and dropping it stops and
    /// joins the thread, so a broken build fails instead of hanging.
    struct FakeDaemon {
        port: u16,
        calls: Arc<std::sync::Mutex<Vec<String>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    type Answer = dyn Fn(&str, &serde_json::Value) -> serde_json::Value + Send + Sync;

    impl FakeDaemon {
        /// `answer` gets the method (for `/json_rpc`) or the endpoint, and the
        /// request body, and returns the whole response body.
        fn start(
            answer: impl Fn(&str, &serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
        ) -> Self {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let answer: Arc<Answer> = Arc::new(answer);
            let (c, st) = (Arc::clone(&calls), Arc::clone(&stop));
            let handle = std::thread::spawn(move || {
                while !st.load(Ordering::Relaxed) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, length) = loop {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break (None, 0);
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (Some(i + 4), length);
                        }
                    };
                    let Some(start) = head_end else { continue };
                    while buf.len() < start + length {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request_line = String::from_utf8_lossy(&buf[..start]).to_string();
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .trim_start_matches('/')
                        .to_owned();
                    let body: serde_json::Value =
                        serde_json::from_slice(&buf[start..start + length]).unwrap_or_default();
                    let what = if path == "json_rpc" {
                        body["method"].as_str().unwrap_or("").to_owned()
                    } else {
                        path
                    };
                    c.lock().unwrap().push(what.clone());
                    let reply = answer(&what, &body).to_string();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                }
            });
            Self {
                port,
                calls,
                stop,
                handle: Some(handle),
            }
        }

        fn source(&self) -> RpcChainSource {
            RpcChainSource::new(Client::new(format!("http://127.0.0.1:{}", self.port)).unwrap())
        }

        fn count(&self, what: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| *c == what)
                .count()
        }
    }

    impl Drop for FakeDaemon {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// A small chain for the stand-in: block `h` has hash `hash_of(h)`, the
    /// tip is `tip`, and every block from `fork` on carries a curve tree.
    #[derive(Clone, Copy)]
    struct Chain {
        tip: u64,
        fork: u64,
    }

    fn hash_of(height: u64) -> String {
        format!("{:064x}", height + 1)
    }

    /// Blocks from this height on are a MiB each; those below, 100 bytes.
    const LARGE_FROM: u64 = 1000;

    impl Chain {
        fn header(self, height: u64, orphan: bool) -> serde_json::Value {
            let version = if height >= self.fork { 17 } else { 16 };
            serde_json::json!({
                "major_version": version, "minor_version": version, "timestamp": height,
                "prev_hash": hash_of(height.saturating_sub(1)), "nonce": 0,
                "orphan_status": orphan, "height": height,
                "depth": self.tip.saturating_sub(height),
                "hash": if orphan { format!("{:064x}", height + 1_000_000) } else { hash_of(height) },
                "difficulty": 1, "difficulty_top64": 0, "wide_difficulty": "0x1",
                "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                "wide_cumulative_difficulty": "0x1", "reward": 1,
                "block_size": if height >= LARGE_FROM { 1 << 20 } else { 100 },
                "num_txes": 0, "pow_hash": "", "miner_tx_hash": "",
            })
        }

        fn block(self, height: u64, orphan: bool) -> serde_json::Value {
            let tree = if height >= self.fork {
                format!(
                    r#","fcmp_pp_n_tree_layers":2,"fcmp_pp_tree_root":"{:064x}""#,
                    height + 500
                )
            } else {
                String::new()
            };
            let json = format!(
                r#"{{"major_version":17,"minor_version":17,"timestamp":0,"prev_id":"","nonce":0,"miner_tx":{{"version":2,"unlock_time":0,"vin":[],"vout":[],"extra":[]}},"tx_hashes":[]{tree}}}"#
            );
            serde_json::json!({
                "block_header": self.header(height, orphan),
                "miner_tx_hash": "", "blob": "", "json": json, "status": "OK",
            })
        }

        fn info(self) -> serde_json::Value {
            serde_json::json!({
                "height": self.tip + 1, "target_height": 0, "difficulty": 1, "difficulty_top64": 0,
                "target": 120, "tx_count": 0, "tx_pool_size": 0, "alt_blocks_count": 0,
                "outgoing_connections_count": 0, "incoming_connections_count": 0,
                "white_peerlist_size": 0, "grey_peerlist_size": 0, "testnet": true,
                "stagenet": false, "nettype": "testnet", "top_block_hash": hash_of(self.tip),
                "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
                "block_size_limit": 0, "block_size_median": 0, "start_time": 0,
                "version": "test", "restricted": false, "status": "OK",
            })
        }

        /// A daemon for this chain. `busy` names heights whose `get_block`
        /// answers BUSY; `orphan_at` makes a lookup by hash of an unknown hash
        /// answer an orphan at that height.
        fn daemon(self, busy: &'static [u64], orphan_at: Option<u64>) -> FakeDaemon {
            FakeDaemon::start(move |what, body| {
                let ok =
                    |r: serde_json::Value| serde_json::json!({"jsonrpc":"2.0","id":"0","result":r});
                match what {
                    "get_info" => ok(self.info()),
                    "get_block_headers_range" => {
                        let (a, b) = (
                            body["params"]["start_height"].as_u64().unwrap(),
                            body["params"]["end_height"].as_u64().unwrap(),
                        );
                        ok(serde_json::json!({
                            "headers": (a..=b).map(|h| self.header(h, false)).collect::<Vec<_>>(),
                            "status": "OK",
                        }))
                    }
                    "get_block" => {
                        let p = &body["params"];
                        let (height, orphan) = if let Some(h) = p["height"].as_u64() {
                            (h, false)
                        } else {
                            let hash = p["hash"].as_str().unwrap();
                            match (0..=self.tip).find(|h| hash_of(*h) == hash) {
                                Some(h) => (h, false),
                                None => (orphan_at.unwrap(), true),
                            }
                        };
                        if busy.contains(&height) {
                            return serde_json::json!({"jsonrpc":"2.0","id":"0",
                                "error":{"code":-9,"message":"Core is busy"}});
                        }
                        ok(self.block(height, orphan))
                    }
                    _ => serde_json::json!({"status": "OK"}),
                }
            })
        }
    }

    /// A post-fork block wanted only for its tree, whose body the daemon will
    /// not hand over, costs that block its tree and nothing else.
    #[tokio::test]
    async fn a_block_wanted_only_for_its_tree_does_not_fail_the_range() {
        let chain = Chain { tip: 9, fork: 0 };
        let daemon = chain.daemon(&[5], None);
        let blocks = daemon.source().blocks_in_range(0, 9, true).await.unwrap();
        assert_eq!(blocks.len(), 10);
        for b in &blocks {
            assert_eq!(
                b.tree.is_some(),
                b.header.height != 5,
                "block {}",
                b.header.height
            );
        }
        assert_eq!(daemon.count("get_block"), 10);
    }

    /// A block sent in place of the one asked for is refused, and is not
    /// cached under the name asked for or its own.
    #[tokio::test]
    async fn a_block_other_than_the_one_asked_for_is_refused() {
        let chain = Chain { tip: 9, fork: 0 };
        // Any unknown hash is answered with the orphan at height 3, whose own
        // hash is another.
        let daemon = chain.daemon(&[], Some(3));
        let source = daemon.source();
        let asked: Hash32 = format!("{:064x}", 0xdead).parse().unwrap();
        let err = source.block(BlockId::Hash(asked)).await.unwrap_err();
        assert!(matches!(err, ChainError::BadAnswer { .. }), "{err}");
        assert!(source.blocks_by_hash.get(&asked).is_none());
        let sent: Hash32 = format!("{:064x}", 3 + 1_000_000).parse().unwrap();
        assert!(source.blocks_by_hash.get(&sent).is_none());
    }

    /// A range holds its blocks' sizes of the budget ranges share for as
    /// long as it lives, and waits while the budget is spent.
    #[tokio::test]
    async fn a_range_holds_its_share_of_the_budget_and_waits_for_it() {
        let chain = Chain { tip: 9, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let source = daemon.source();
        let all = RANGE_KIB as usize;

        // Ten blocks of 100 bytes: a KiB each.
        let blocks = source.blocks_in_range(0, 9, false).await.unwrap();
        assert_eq!(blocks.len(), 10);
        assert_eq!(source.range_kib.available_permits(), all - 10);
        drop(blocks);
        assert_eq!(source.range_kib.available_permits(), all);

        // With the budget spent, a range waits rather than fetching.
        let spent = Arc::clone(&source.range_kib)
            .acquire_many_owned(RANGE_KIB)
            .await
            .unwrap();
        let waiting = tokio::time::timeout(
            Duration::from_millis(200),
            source.blocks_in_range(0, 9, false),
        )
        .await;
        assert!(waiting.is_err(), "the range ran with the budget spent");
        drop(spent);
        let blocks = source.blocks_in_range(0, 9, false).await.unwrap();
        assert_eq!(blocks.len(), 10);
    }

    /// A range holding more than one request may fetch is refused before
    /// anything is fetched, and one just under is served.
    #[tokio::test]
    async fn a_range_too_large_for_one_request_is_refused() {
        let chain = Chain {
            tip: LARGE_FROM + 100,
            fork: 0,
        };
        let daemon = chain.daemon(&[], None);
        let source = daemon.source();
        let most = MAX_RANGE_KIB / 1024;

        let err = source
            .blocks_in_range(LARGE_FROM, LARGE_FROM + most, false)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, ChainError::RangeTooLarge { .. }), "{err}");
        assert_eq!(daemon.count("get_block"), 0);
        assert_eq!(source.range_kib.available_permits(), RANGE_KIB as usize);

        let blocks = source
            .blocks_in_range(LARGE_FROM, LARGE_FROM + most - 1, false)
            .await
            .unwrap();
        assert_eq!(blocks.len() as u64, most);
    }

    /// Without the tree the same range fetches no bodies at all.
    #[tokio::test]
    async fn a_range_that_does_not_show_the_tree_does_not_pay_for_it() {
        let chain = Chain { tip: 9, fork: 0 };
        let daemon = chain.daemon(&[], None);
        daemon.source().blocks_in_range(0, 9, false).await.unwrap();
        assert_eq!(daemon.count("get_block"), 0);
    }

    /// Recent bodies are fetched by hash, so a repeated range is served from
    /// the hash cache although none of them is deep enough for the height one.
    #[tokio::test]
    async fn a_repeated_recent_range_is_served_from_the_hash_cache() {
        let chain = Chain { tip: 9, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        src.blocks_in_range(0, 9, true).await.unwrap();
        src.blocks_in_range(0, 9, true).await.unwrap();
        assert_eq!(
            daemon.count("get_block"),
            10,
            "the second pass fetched bodies again"
        );
        assert_eq!(daemon.count("get_block_headers_range"), 2);
    }

    /// A deep body already in the height cache is taken from there when its
    /// hash matches the header, and fetched by hash when it does not.
    #[tokio::test]
    async fn a_deep_range_uses_the_height_cache_when_the_hash_matches() {
        let chain = Chain { tip: 200, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        for h in 0..10 {
            let block: GetBlock = serde_json::from_value(chain.block(h, false)).unwrap();
            src.blocks_by_height.insert(h, block);
        }
        // A stale entry for height 3: a different block than the header names.
        let stale: GetBlock = serde_json::from_value(chain.block(3, true)).unwrap();
        src.blocks_by_height.insert(3, stale);

        let blocks = src.blocks_in_range(0, 9, true).await.unwrap();
        assert!(blocks.iter().all(|b| b.tree.is_some()));
        assert_eq!(
            daemon.count("get_block"),
            1,
            "only the mismatched block is fetched"
        );
    }

    /// An orphan looked up by hash once buried must not take the main chain's
    /// place at its height.
    #[tokio::test]
    async fn an_orphan_is_never_cached_by_height() {
        let chain = Chain { tip: 200, fork: 0 };
        let daemon = chain.daemon(&[], Some(5));
        let src = daemon.source();
        let alt: Hash32 = format!("{:064x}", 5 + 1_000_000).parse().unwrap();
        let orphan = src.block(BlockId::Hash(alt)).await.unwrap();
        assert!(orphan.block_header.orphan_status);

        let main = src.block(BlockId::Height(5)).await.unwrap();
        assert!(
            !main.block_header.orphan_status,
            "the orphan was served by height"
        );
        assert_eq!(main.block_header.hash, hash_of(5));
        assert_eq!(daemon.count("get_block"), 2);
    }

    /// `block_at` asks for a recent block's header each time but its body
    /// only once.
    #[tokio::test]
    async fn a_recent_block_by_height_costs_its_body_once() {
        let chain = Chain { tip: 9, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        src.block_at(5).await.unwrap();
        src.block_at(5).await.unwrap();
        assert_eq!(daemon.count("get_block"), 1);
        assert_eq!(daemon.count("get_block_headers_range"), 2);
    }

    /// The root link is fetched, not computed: for a reference block less than
    /// eight past the fork, block R - 8 is from before it and has no root.
    #[tokio::test]
    async fn a_proof_root_is_linked_only_where_a_block_carries_one() {
        let chain = Chain { tip: 40, fork: 20 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        assert_eq!(
            src.proof_root(25).await,
            None,
            "block 17 is before the fork"
        );
        assert_eq!(
            src.proof_root(30).await,
            Some((22, format!("{:064x}", 22 + 500)))
        );
        assert_eq!(src.proof_root(5).await, None, "block -3 does not exist");
    }

    /// A block's depth is counted from the tip as it is now, not as it was
    /// when the block was cached.
    #[tokio::test]
    async fn depth_is_counted_from_the_current_tip() {
        let chain = Chain { tip: 100, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        let mut header: monerod_rpc::types::BlockHeader =
            serde_json::from_value(chain.header(90, false)).unwrap();
        header.depth = 0; // as cached when block 90 was the tip
        assert_eq!(src.depth_now(&header).await, 10);

        // With no tip to count from, the stored count is all there is.
        assert_eq!(source().depth_now(&header).await, 0);

        // An orphan is buried by nothing, whatever depth monerod gives it.
        let orphan: monerod_rpc::types::BlockHeader =
            serde_json::from_value(chain.header(90, true)).unwrap();
        assert!(orphan.depth > 0);
        assert_eq!(src.depth_now(&orphan).await, 0);
    }

    /// A cached transaction's confirmations are counted from the tip as it is
    /// now, not as it was when the transaction was cached.
    #[tokio::test]
    async fn cached_confirmations_are_counted_from_the_current_tip() {
        let chain = Chain { tip: 100, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        let h = hash(0x44);
        let mut cached = entry(h);
        cached.block_height = 30;
        cached.confirmations = 60; // as cached when the tip was block 89
        src.txs.insert(h, cached);

        let got = src.transactions(&[h]).await.unwrap();
        assert_eq!(got.txs.first().map(|e| e.confirmations), Some(71));
    }

    /// A fresh lookup skips a stale cached tip, and its answer replaces it.
    #[tokio::test]
    async fn a_fresh_tip_lookup_replaces_the_cached_one() {
        let chain = Chain { tip: 100, fork: 0 };
        let daemon = chain.daemon(&[], None);
        let src = daemon.source();
        let mut stale = (*src.info().await.unwrap()).clone();
        stale.height = 90;
        src.info.insert((), stale);
        assert_eq!(src.info().await.unwrap().height, 90);
        assert_eq!(src.fresh_info().await.unwrap().height, 101);
        assert_eq!(src.info().await.unwrap().height, 101);
        assert_eq!(src.rpc_calls(), 2);
    }

    /// An unreachable daemon marks the ring unavailable rather than erroring
    /// the page or silently rendering an empty ring as though it were real.
    #[tokio::test]
    async fn an_unreachable_daemon_marks_the_ring_unavailable() {
        let input = TxInToKey {
            amount: 7_000_000_000_000,
            key_offsets: vec![4732, 5082],
            k_image: "cc".repeat(32),
        };
        let resolved = source().resolve_ring(&input).await;
        assert!(resolved.ring_unavailable);
        assert_eq!(
            resolved.amount, 7_000_000_000_000,
            "the denomination survives a failed lookup; it comes from the input"
        );
    }
}
