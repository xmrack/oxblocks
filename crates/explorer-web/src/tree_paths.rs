//! A transaction's outputs' paths through the curve tree, fetched, placed and
//! checked: what the paths page and `/api/transaction/<hash>/paths` show.

use std::ops::Range;
use std::sync::{Arc, LazyLock};

use explorer_core::curve_tree::{
    Group, Output, PathCheck, PlacedPath, place_all, visible_commitment,
};
use explorer_core::fmt::decimal;
use explorer_core::{Cache, ChainError, safe_to_cache_by_height};
use monerod_rpc::types::{PathLeaf, PathQuery, TxEntry, TxJson, last_locked_block};
use tokio::sync::Semaphore;

use crate::api::handlers::{AppState, echo};

/// The most outputs shown at once: the most one daemon call answers for.
pub const MAX_OUTPUTS: usize = PathQuery::MAX_IDS;

/// How many answers are checked at once, across every request.
///
/// Checking is CPU work on the blocking pool, and it runs to its end even
/// when the request that asked for it has timed out, so it gets its own
/// bound rather than only the daemon calls' one.
const CHECKS_AT_ONCE: usize = 4;

static CHECKS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(CHECKS_AT_ONCE)));

/// The most paths kept, and the bytes they may hold.
const PATHS_KEPT: usize = 4096;
const PATHS_KEPT_BYTES: usize = 16 * 1024 * 1024;

/// Checked paths as of blocks past the reorg window, by that block and the
/// output's unified id.
///
/// The tree as of a block is fixed once the block is, so an output's path as
/// of it is too. A path is kept only when its hashes hold and end at the root
/// the chain records, and only as of a block no reorganisation reaches: a
/// later view of it then needs neither a daemon call nor the hashing. A path
/// that fails is not kept, so it is asked for again next time.
///
/// A path as of a block the reorg window still reaches is kept as well, for
/// as long as the tip it was checked under: the tip's hash fixes the chain,
/// and with it the tree as of every block below.
pub struct PathCache {
    buried: Cache<(u64, u64), Checked>,
    recent: Cache<(u64, u64, String), Checked>,
}

struct Checked {
    n_leaf_tuples: u64,
    placed: PlacedPath,
}

impl Default for PathCache {
    fn default() -> Self {
        Self {
            buried: Cache::permanent(PATHS_KEPT).within_bytes(PATHS_KEPT_BYTES, checked_bytes),
            // The keys of a replaced tip are never asked for again.
            recent: Cache::expiring(PATHS_KEPT / 4, std::time::Duration::from_secs(600))
                .within_bytes(PATHS_KEPT_BYTES / 4, checked_bytes),
        }
    }
}

impl PathCache {
    #[must_use]
    pub fn stats(&self) -> explorer_core::cache::Stats {
        self.buried.stats()
    }

    #[must_use]
    pub fn recent_stats(&self) -> explorer_core::cache::Stats {
        self.recent.stats()
    }

    /// `output`'s path as of `as_of_block`, if one was kept, under `tip` for a
    /// block not yet buried, and it climbs from `output` as its transaction
    /// records it now.
    fn get(&self, as_of_block: u64, tip: Option<&str>, output: &Output) -> Option<Arc<Checked>> {
        match tip {
            None => self.buried.get(&(as_of_block, output.unified_id)),
            Some(t) => self
                .recent
                .get(&(as_of_block, output.unified_id, t.to_owned())),
        }
        .filter(|c| c.placed.leaf().is_some_and(|l| output.is(l)))
    }

    /// Keep `placed`, as of `as_of_block`, under `tip` for a block not yet
    /// buried, if it leads to `root`.
    fn keep(
        &self,
        as_of_block: u64,
        tip: Option<&str>,
        n_leaf_tuples: u64,
        placed: &PlacedPath,
        root: Option<&str>,
    ) {
        if root.is_some_and(|r| leads_to(placed, r)) {
            let checked = Checked {
                n_leaf_tuples,
                placed: placed.clone(),
            };
            match tip {
                None => drop(
                    self.buried
                        .insert((as_of_block, placed.unified_id), checked),
                ),
                Some(t) => drop(
                    self.recent
                        .insert((as_of_block, placed.unified_id, t.to_owned()), checked),
                ),
            }
        }
    }
}

/// Roughly the bytes a kept path holds.
fn checked_bytes(c: &Checked) -> usize {
    let p = &c.placed;
    p.path.leaves.len() * size_of::<PathLeaf>()
        + p.path
            .layers
            .iter()
            .map(|l| l.len() * 32 + size_of::<Vec<[u8; 32]>>())
            .sum::<usize>()
        + p.groups.len() * size_of::<Group>()
        + size_of::<Checked>()
}

/// Whether `p`'s hashes hold and end at `root`, written out in hex.
fn leads_to(p: &PlacedPath, root: &str) -> bool {
    p.check == PathCheck::Holds
        && p.root()
            .is_some_and(|r| explorer_core::hex::encode(r).eq_ignore_ascii_case(root))
}

/// The query string of the paths page and its API twin, as given.
#[derive(serde::Deserialize, Default)]
pub struct PathsParams {
    output: Option<String>,
    block: Option<String>,
    from: Option<String>,
}

/// [`PathsParams`], read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wanted {
    /// One output, counted from 1 as the transaction page lists them.
    pub output: Option<usize>,
    /// The block to take the tree as of; the tip when absent.
    pub block: Option<u64>,
    /// The first output of a window, counted from 0.
    pub from: usize,
}

impl PathsParams {
    /// Each parameter is a plain number or absent. An empty one, which the
    /// page's form sends when its box is left blank, is absent.
    pub fn read(&self) -> Result<Wanted, String> {
        fn number(name: &str, given: Option<&str>) -> Result<Option<u64>, String> {
            match given {
                None | Some("") => Ok(None),
                Some(text) => decimal(text)
                    .map(Some)
                    .ok_or_else(|| format!("{name} is not a number: {}", echo(text))),
            }
        }
        let index = |name: &str, given: Option<&str>| -> Result<Option<usize>, String> {
            number(name, given)?
                .map(|n| usize::try_from(n).map_err(|_| format!("{name} is too large: {n}")))
                .transpose()
        };
        Ok(Wanted {
            output: index("output", self.output.as_deref())?,
            block: number("block", self.block.as_deref())?,
            from: index("from", self.from.as_deref())?.unwrap_or(0),
        })
    }
}

impl Wanted {
    /// The outputs asked for, counted from 0, of a transaction with `total`:
    /// `output` alone, or up to [`MAX_OUTPUTS`] from `from`.
    pub fn outputs(&self, total: usize) -> Result<Range<usize>, PathsError> {
        match self.output {
            Some(k) if k == 0 || k > total => Err(PathsError::NoSuchOutput { asked: k, total }),
            Some(k) => Ok((k - 1)..k),
            None if self.from >= total => Err(PathsError::NoSuchOutputs {
                from: self.from,
                total,
            }),
            None => Ok(self.from..self.from.saturating_add(MAX_OUTPUTS).min(total)),
        }
    }
}

/// Paths as of one block, for some of one transaction's outputs.
pub struct TxPaths {
    pub as_of_block: u64,
    /// The block the transaction is in.
    pub mined_in: u64,
    /// The chain's tip when asked, the newest block a path can be taken as of.
    pub tip: u64,
    pub n_leaf_tuples: u64,
    /// The block carrying the root of the tree as of `as_of_block`, eight
    /// blocks below it, with that root, where the block carries one.
    pub root_block: Option<(u64, String)>,
    pub outputs: Vec<OutputPath>,
}

pub struct OutputPath {
    /// Counted from 0, as the transaction lists its outputs.
    pub index: usize,
    pub unified_id: u64,
    /// The block the output joins the tree at: the tree as of this block and
    /// every later one holds it, and `placed` is `None` as of any before it.
    pub last_locked_block: u64,
    /// `None` when the output is not in the tree as of the block asked about.
    pub placed: Option<PlacedPath>,
}

/// What every path found says about the root, against the block's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCheck {
    /// Every output in the tree as of the block, and at least one is, has a
    /// path ending at the root the block records. The paths, the outputs and
    /// the root all come from the one daemon, so this says they agree with
    /// each other, not that the daemon is honest.
    Matches,
    /// Some output's path is missing, does not hold, or ends at another root.
    Fails,
    /// No block carries the root to compare with, or no output is in the
    /// tree yet.
    Unchecked,
}

impl RootCheck {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::Fails => "fails",
            Self::Unchecked => "unchecked",
        }
    }
}

/// Where one output's path stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Not in the tree as of the block asked about.
    Waiting,
    /// In the tree as of it, by its lock, but the daemon sent no path.
    Missing,
    /// The path's hashes do not hold.
    Fails(PathCheck),
    /// The hashes hold and end at a root other than the block's.
    OtherRoot,
    /// The hashes hold and end at the block's root.
    Reaches,
    /// The hashes hold, and no block carries a root to compare with.
    Holds,
}

impl TxPaths {
    #[must_use]
    pub fn standing(&self, o: &OutputPath) -> Standing {
        let Some(p) = &o.placed else {
            return if o.last_locked_block > self.as_of_block {
                Standing::Waiting
            } else {
                Standing::Missing
            };
        };
        match (p.check, &self.root_block) {
            (PathCheck::Holds, None) => Standing::Holds,
            (PathCheck::Holds, Some((_, root))) if leads_to(p, root) => Standing::Reaches,
            (PathCheck::Holds, Some(_)) => Standing::OtherRoot,
            (check, _) => Standing::Fails(check),
        }
    }

    #[must_use]
    pub fn root_check(&self) -> RootCheck {
        let standings: Vec<Standing> = self.outputs.iter().map(|o| self.standing(o)).collect();
        if standings.iter().any(|s| {
            matches!(
                s,
                Standing::Missing | Standing::Fails(_) | Standing::OtherRoot
            )
        }) {
            RootCheck::Fails
        } else if standings.contains(&Standing::Reaches) {
            RootCheck::Matches
        } else {
            RootCheck::Unchecked
        }
    }
}

/// Why there are no paths to show.
pub enum PathsError {
    /// The transaction is in the pool: its outputs have no place in the
    /// chain's order of outputs yet, so none in the tree.
    InPool,
    /// The daemon gives the transaction's outputs no unified ids: it is from
    /// before FCMP++.
    NoIds,
    /// The block asked about is past the tip.
    Ahead {
        asked: u64,
        tip: u64,
    },
    /// The output asked for, counted from 1, is not one of the
    /// transaction's.
    NoSuchOutput {
        asked: usize,
        total: usize,
    },
    /// The window asked for starts past the transaction's last output.
    NoSuchOutputs {
        from: usize,
        total: usize,
    },
    Chain(ChainError),
}

/// The paths of `tx`'s outputs in `which`, as of `as_of` or the tip.
///
/// `which` is clamped to the outputs the transaction has and to
/// [`MAX_OUTPUTS`] of them, and must start at one of them.
pub async fn gather(
    state: &AppState,
    entry: &TxEntry,
    tx: &TxJson,
    as_of: Option<u64>,
    which: Range<usize>,
) -> Result<TxPaths, PathsError> {
    if entry.in_pool {
        return Err(PathsError::InPool);
    }
    let ids = entry
        .unified_ids_per_output(tx.vout.len())
        .ok_or(PathsError::NoIds)?;
    let mut info = state.chain.info().await.map_err(PathsError::Chain)?;
    // The cached info can trail a block that was just mined.
    if as_of == Some(info.height) {
        info = state.chain.fresh_info().await.map_err(PathsError::Chain)?;
    }
    let tip = info.height.saturating_sub(1);
    let as_of_block = as_of.unwrap_or(tip);
    if as_of_block > tip {
        return Err(PathsError::Ahead {
            asked: as_of_block,
            tip,
        });
    }
    let start = which.start;
    let end = which
        .end
        .min(ids.len())
        .min(start.saturating_add(MAX_OUTPUTS));
    let wanted = match ids.get(start..end) {
        Some(w) if !w.is_empty() => outputs(tx, start, w),
        _ => {
            return Err(PathsError::NoSuchOutputs {
                from: start,
                total: ids.len(),
            });
        }
    };

    // A path checked before is kept: for good as of a block past the reorg
    // window, and under the tip's hash as of one it still reaches.
    let buried = safe_to_cache_by_height(tip.saturating_sub(as_of_block));
    let kept_under = (!buried).then_some(info.top_block_hash.as_str());
    let known: Vec<Option<Arc<Checked>>> = wanted
        .iter()
        .map(|o| state.paths.get(as_of_block, kept_under, o))
        .collect();
    let missing: Vec<Output> = wanted
        .iter()
        .zip(&known)
        .filter(|(_, k)| k.is_none())
        .map(|(o, _)| *o)
        .collect();

    let fetch = async {
        if missing.is_empty() {
            return Ok(None);
        }
        let ids: Vec<u64> = missing.iter().map(|o| o.unified_id).collect();
        state.chain.tree_paths(as_of_block, &ids).await.map(Some)
    };
    let (answer, root_block) = tokio::join!(fetch, state.chain.proof_root(as_of_block));
    let answer = answer.map_err(PathsError::Chain)?;
    let n_leaf_tuples = match &answer {
        Some(a) => a.n_leaf_tuples,
        None => known.iter().flatten().next().map_or(0, |k| k.n_leaf_tuples),
    };

    let fresh = match answer {
        None => Vec::new(),
        Some(answer) => check(missing, answer.paths, n_leaf_tuples).await?,
    };
    let root = root_block.as_ref().map(|(_, r)| r.as_str());
    for p in fresh.iter().flatten() {
        state
            .paths
            .keep(as_of_block, kept_under, n_leaf_tuples, p, root);
    }
    let mut fresh = fresh.into_iter();
    let placed = known.into_iter().map(|k| match k {
        Some(k) => Some(k.placed.clone()),
        None => fresh.next().flatten(),
    });

    let locked = last_locked_block(tx.unlock_time, entry.block_height);
    let outputs = placed
        .zip(wanted)
        .enumerate()
        .map(|(k, (placed, output))| OutputPath {
            index: start + k,
            unified_id: output.unified_id,
            last_locked_block: locked,
            placed,
        })
        .collect();
    Ok(TxPaths {
        as_of_block,
        mined_in: entry.block_height,
        tip,
        n_leaf_tuples,
        root_block,
        outputs,
    })
}

/// The outputs `start..` of `tx`, with `unified_ids`, as `tx` records them.
fn outputs(tx: &TxJson, start: usize, unified_ids: &[u64]) -> Vec<Output> {
    fn bytes(hex: &str) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        explorer_core::hex::decode_to_slice(hex, &mut out).ok()?;
        Some(out)
    }
    // A RingCT output's commitment is on the chain, one an output. A
    // coinbase's and a pre-RingCT output's amount is in the clear, and the
    // tree commits to it with a mask of 1.
    let visible = tx.is_coinbase() || tx.is_v1();
    let commitments = tx
        .rct_signatures
        .as_ref()
        .and_then(|r| r.out_pk.as_deref())
        .filter(|pk| pk.len() == tx.vout.len());
    unified_ids
        .iter()
        .enumerate()
        .map(|(k, &unified_id)| {
            let i = start.saturating_add(k);
            Output {
                unified_id,
                key: tx
                    .vout
                    .get(i)
                    .and_then(|o| o.target.public_key())
                    .and_then(bytes),
                commitment: if visible {
                    tx.vout.get(i).map(|o| visible_commitment(o.amount))
                } else {
                    commitments.and_then(|c| c.get(i)).and_then(|c| bytes(c))
                },
            }
        })
        .collect()
}

/// Place and check `paths`, the paths of `outputs`.
///
/// Checking a path is CPU work, a few milliseconds a group of leaves, so it
/// is kept off the threads serving other requests. The permit travels with
/// the work and is given back when the work ends, not when a timed-out
/// request stops waiting for it.
async fn check(
    outputs: Vec<Output>,
    paths: Vec<Option<monerod_rpc::types::TreePath>>,
    n_leaf_tuples: u64,
) -> Result<Vec<Option<PlacedPath>>, PathsError> {
    let stopped = |detail: String| {
        PathsError::Chain(ChainError::BadAnswer {
            what: PathQuery::ENDPOINT,
            detail,
        })
    };
    let permit = Arc::clone(&CHECKS)
        .acquire_owned()
        .await
        .map_err(|e| stopped(format!("no checking slot: {e}")))?;
    tokio::task::spawn_blocking(move || {
        let placed = place_all(&outputs, paths, n_leaf_tuples);
        drop(permit);
        placed
    })
    .await
    .map_err(|e| stopped(format!("checking the paths stopped: {e}")))
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn params(output: Option<&str>, block: Option<&str>, from: Option<&str>) -> PathsParams {
        PathsParams {
            output: output.map(str::to_owned),
            block: block.map(str::to_owned),
            from: from.map(str::to_owned),
        }
    }

    /// The captured transaction's outputs, as [`gather`] reads them.
    pub(crate) fn captured_outputs() -> Vec<Output> {
        let raw = include_str!("../../../fixtures/fcmp/paths/get_transactions.json");
        let answer: monerod_rpc::types::GetTransactionsResponse =
            serde_json::from_str(raw).unwrap();
        let entry = &answer.txs[0];
        let tx = entry.parse_json().unwrap();
        outputs(&tx, 0, entry.unified_ids_per_output(tx.vout.len()).unwrap())
    }

    /// The captured transaction's paths as of block 814, placed, with the
    /// root block 806 records.
    fn captured() -> (u64, Vec<PlacedPath>, &'static str) {
        const IDS: [u64; 4] = [802, 803, 804, 805];
        let bin = include_bytes!("../../../fixtures/fcmp/paths/get_path_by_unified_id_later.bin");
        let answer = PathQuery::as_of_block(814, &IDS)
            .unwrap()
            .answer(&monerod_rpc::epee::read_root(bin, PathQuery::WANTED).unwrap())
            .unwrap();
        let n = answer.n_leaf_tuples;
        let placed = place_all(&captured_outputs(), answer.paths, n)
            .into_iter()
            .flatten()
            .collect();
        (
            n,
            placed,
            "e71da88f93a4ded7a2de6217859985fb5349d597e38232572e8d02d8a21e51ce",
        )
    }

    #[test]
    fn only_a_path_that_leads_to_its_blocks_root_is_kept() {
        let (n, placed, root) = captured();
        let outputs = captured_outputs();
        let cache = PathCache::default();
        assert!(placed.iter().all(|p| p.check == PathCheck::Holds));

        cache.keep(814, None, n, &placed[0], Some(root));
        let kept = cache.get(814, None, &outputs[0]).unwrap();
        assert_eq!((kept.n_leaf_tuples, &kept.placed), (n, &placed[0]));
        // Kept as of that block only.
        assert!(cache.get(815, None, &outputs[0]).is_none());
        // And given only for the output it climbs from.
        let other_key = Output {
            key: outputs[1].key,
            ..outputs[0]
        };
        assert!(cache.get(814, None, &other_key).is_none());

        // Not without a root to compare with, nor with another root.
        cache.keep(814, None, n, &placed[1], None);
        cache.keep(814, None, n, &placed[2], Some(&"00".repeat(32)));
        // Nor when its hashes do not hold.
        let mut broken = placed[3].clone();
        broken.check = PathCheck::Broken { layer: 0 };
        cache.keep(814, None, n, &broken, Some(root));
        for o in &outputs[1..] {
            assert!(cache.get(814, None, o).is_none());
        }
        assert_eq!(cache.stats().len, 1);

        // Kept under a tip, a path is given under that tip only, and apart
        // from those kept for good.
        cache.keep(814, Some("t"), n, &placed[1], Some(root));
        assert!(cache.get(814, Some("t"), &outputs[1]).is_some());
        assert!(cache.get(814, Some("u"), &outputs[1]).is_none());
        assert!(cache.get(814, None, &outputs[1]).is_none());
        assert!(cache.get(814, Some("t"), &outputs[0]).is_none());
    }

    /// The page and the API take the same outputs for the same query.
    #[test]
    fn the_outputs_asked_for_are_one_alone_or_a_window() {
        let wanted = |output: Option<&str>, from: Option<&str>| {
            params(output, None, from).read().unwrap().outputs(60)
        };
        assert_eq!(wanted(Some("2"), None).ok(), Some(1..2));
        assert_eq!(wanted(None, Some("7")).ok(), Some(7..57));
        assert_eq!(wanted(None, Some("30")).ok(), Some(30..60));
        assert!(matches!(
            wanted(Some("0"), None),
            Err(PathsError::NoSuchOutput {
                asked: 0,
                total: 60
            })
        ));
        assert!(matches!(
            wanted(Some("61"), None),
            Err(PathsError::NoSuchOutput { asked: 61, .. })
        ));
        assert!(matches!(
            wanted(None, Some("60")),
            Err(PathsError::NoSuchOutputs { from: 60, .. })
        ));
    }

    #[test]
    fn an_empty_parameter_is_absent_and_a_bad_one_is_refused() {
        assert_eq!(
            params(Some("2"), Some(""), None).read(),
            Ok(Wanted {
                output: Some(2),
                block: None,
                from: 0
            })
        );
        assert!(params(None, None, Some("x")).read().is_err());
        assert!(
            params(Some("99999999999999999999"), None, None)
                .read()
                .is_err()
        );
    }

    /// The captured transaction as `gather` is handed it: mined in block
    /// 801, its outputs joining the tree at 810.
    fn captured_tx() -> (TxEntry, TxJson) {
        let raw = include_str!("../../../fixtures/fcmp/paths/get_transactions.json");
        let answer: monerod_rpc::types::GetTransactionsResponse =
            serde_json::from_str(raw).unwrap();
        let entry = answer.txs.into_iter().next().unwrap();
        let tx = entry.parse_json().unwrap();
        (entry, tx)
    }

    /// The daemon's paths as of block 814 for the captured outputs `which`,
    /// cut from its answer for all four.
    fn paths_of(which: Range<usize>) -> Vec<u8> {
        use monerod_rpc::epee::{Root, Value, encode_root, read_root};
        let bin = include_bytes!("../../../fixtures/fcmp/paths/get_path_by_unified_id_later.bin");
        let root = read_root(bin, &["n_leaf_tuples", "paths", "status"]).unwrap();
        let entries = root
            .entries()
            .iter()
            .map(|(k, v)| match v {
                Value::Array(paths) if k == "paths" => {
                    (k.clone(), Value::Array(paths[which.clone()].to_vec()))
                }
                _ => (k.clone(), v.clone()),
            })
            .collect();
        encode_root(&Root::new(entries)).unwrap()
    }

    /// A daemon on the captured chain with its tip at `tip`, answering for
    /// the paths of the captured outputs `which`, and with block 806, which
    /// carries the root of the tree as of 814.
    fn daemon(
        tip: Arc<std::sync::atomic::AtomicU64>,
        which: Range<usize>,
    ) -> explorer_core::fake_daemon::FakeDaemon {
        let block = include_str!("../../../fixtures/fcmp/paths/get_block_root_later.json");
        let paths = paths_of(which);
        explorer_core::fake_daemon::FakeDaemon::start_raw(move |what, _| match what {
            "get_info" => {
                let height = tip.load(std::sync::atomic::Ordering::SeqCst) + 1;
                let info = serde_json::json!({"jsonrpc": "2.0", "id": "0", "result": {
                    "height": height, "target_height": 0, "difficulty": 1,
                    "difficulty_top64": 0, "target": 120, "tx_count": 0, "tx_pool_size": 0,
                    "alt_blocks_count": 0, "outgoing_connections_count": 0,
                    "incoming_connections_count": 0, "white_peerlist_size": 0,
                    "grey_peerlist_size": 0, "testnet": false, "stagenet": false,
                    "nettype": "regtest", "top_block_hash": format!("{height:064x}"), "cumulative_difficulty": 1,
                    "cumulative_difficulty_top64": 0, "block_size_limit": 0,
                    "block_size_median": 0, "start_time": 0, "version": "test",
                    "restricted": false, "status": "OK",
                }});
                (200, info.to_string().into_bytes())
            }
            "get_block" => (200, block.as_bytes().to_vec()),
            "get_block_headers_range" => {
                let block: serde_json::Value = serde_json::from_str(block).unwrap();
                let range = serde_json::json!({"jsonrpc": "2.0", "id": "0", "result": {
                    "headers": [block["result"]["block_header"]], "status": "OK",
                }});
                (200, range.to_string().into_bytes())
            }
            PathQuery::ENDPOINT => (200, paths.clone()),
            _ => (404, Vec::new()),
        })
    }

    fn state_on(daemon: &explorer_core::fake_daemon::FakeDaemon) -> AppState {
        AppState {
            chain: daemon.source(),
            limits: crate::config::Limits::default(),
            paths: PathCache::default(),
            recent: Default::default(),
            rows: Default::default(),
        }
    }

    fn tip_at(height: u64) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::new(std::sync::atomic::AtomicU64::new(height))
    }

    fn standings(paths: &TxPaths) -> Vec<Standing> {
        paths.outputs.iter().map(|o| paths.standing(o)).collect()
    }

    /// As of the tip, every path is fetched and checked, and kept for as long
    /// as that tip is: once a block arrives, the reorg window still reaches
    /// the tree as of it, so it is fetched and checked again.
    #[tokio::test]
    async fn the_paths_as_of_the_tip_are_kept_while_the_tip_stays() {
        let (entry, tx) = captured_tx();
        let tip = tip_at(814);
        let d = daemon(Arc::clone(&tip), 0..4);
        let state = state_on(&d);
        for _ in 0..3 {
            assert!(gather(&state, &entry, &tx, Some(814), 0..4).await.is_ok());
        }
        assert_eq!(d.count(PathQuery::ENDPOINT), 1);
        assert_eq!(state.paths.recent_stats().len, 4);
        assert_eq!(state.paths.stats().len, 0, "not kept for good");

        tip.store(815, std::sync::atomic::Ordering::SeqCst);
        state.chain.fresh_info().await.unwrap();
        assert!(gather(&state, &entry, &tx, Some(814), 0..4).await.is_ok());
        assert_eq!(
            d.count(PathQuery::ENDPOINT),
            2,
            "asked again under the new tip"
        );
    }

    /// Every view as of the tip is checked; only the first under a tip asks.
    #[tokio::test]
    async fn the_paths_as_of_the_tip_are_checked() {
        let (entry, tx) = captured_tx();
        let d = daemon(tip_at(814), 0..4);
        let state = state_on(&d);
        for _ in 1..=2 {
            let Ok(paths) = gather(&state, &entry, &tx, None, 0..4).await else {
                panic!("paths")
            };
            assert_eq!(
                (paths.as_of_block, paths.tip, paths.mined_in),
                (814, 814, 801)
            );
            assert_eq!(paths.root_block, Some((806, captured().2.to_owned())));
            let ids: Vec<_> = paths
                .outputs
                .iter()
                .map(|o| (o.index, o.unified_id))
                .collect();
            assert_eq!(ids, [(0, 802), (1, 803), (2, 804), (3, 805)]);
            assert!(paths.outputs.iter().all(|o| o.last_locked_block == 810));
            assert_eq!(standings(&paths), [Standing::Reaches; 4]);
            assert_eq!(paths.root_check(), RootCheck::Matches);
            assert_eq!(state.paths.stats().len, 0);
            assert_eq!(d.count(PathQuery::ENDPOINT), 1);
        }
    }

    /// As of a block the reorg window no longer reaches, a path that leads
    /// to the root is kept, and shown again without asking the daemon.
    #[tokio::test]
    async fn the_paths_as_of_a_buried_block_are_kept() {
        let (entry, tx) = captured_tx();
        let d = daemon(tip_at(814 + explorer_core::REORG_WINDOW), 0..4);
        let state = state_on(&d);
        for _ in 0..2 {
            let Ok(paths) = gather(&state, &entry, &tx, Some(814), 0..4).await else {
                panic!("paths")
            };
            assert_eq!(standings(&paths), [Standing::Reaches; 4]);
            assert_eq!(paths.n_leaf_tuples, captured().0);
        }
        assert_eq!(state.paths.stats().len, 4);
        assert_eq!(d.count(PathQuery::ENDPOINT), 1);
    }

    /// A window past the first output numbers its outputs from where it
    /// starts, and matches each path to its own output.
    #[tokio::test]
    async fn a_window_matches_each_path_to_its_own_output() {
        let (entry, tx) = captured_tx();
        let d = daemon(tip_at(814), 2..4);
        let Ok(paths) = gather(&state_on(&d), &entry, &tx, None, 2..4).await else {
            panic!("paths")
        };
        let ids: Vec<_> = paths
            .outputs
            .iter()
            .map(|o| (o.index, o.unified_id))
            .collect();
        assert_eq!(ids, [(2, 804), (3, 805)]);
        assert_eq!(standings(&paths), [Standing::Reaches; 2]);
    }

    /// A block mined since the cached info was taken is not past the tip.
    #[tokio::test]
    async fn a_block_just_mined_is_asked_about_not_refused() {
        let (entry, tx) = captured_tx();
        let tip = tip_at(813);
        let d = daemon(Arc::clone(&tip), 0..4);
        let state = state_on(&d);
        assert!(gather(&state, &entry, &tx, Some(813), 0..4).await.is_ok());
        tip.store(814, std::sync::atomic::Ordering::SeqCst);
        let Ok(paths) = gather(&state, &entry, &tx, Some(814), 0..4).await else {
            panic!("the new tip")
        };
        assert_eq!(paths.tip, 814);
        assert!(matches!(
            gather(&state, &entry, &tx, Some(816), 0..4).await,
            Err(PathsError::Ahead {
                asked: 816,
                tip: 814
            })
        ));
    }

    /// The tree commits to an amount in the clear with a mask of 1, and to
    /// a hidden one with the commitment the transaction records; each
    /// output of a window is read from its own place.
    #[test]
    fn each_output_is_read_with_the_commitment_the_tree_holds() {
        let raw = include_str!("../../../fixtures/fcmp/get_transactions_coinbase.json");
        let answer: monerod_rpc::types::GetTransactionsResponse =
            serde_json::from_str(raw).unwrap();
        let coinbase = answer.txs[0].parse_json().unwrap();
        assert!(coinbase.is_coinbase() && !coinbase.vout.is_empty());
        let read = outputs(&coinbase, 0, &vec![7; coinbase.vout.len()]);
        for (o, v) in read.iter().zip(&coinbase.vout) {
            assert_eq!(o.commitment, Some(visible_commitment(v.amount)));
        }

        let v1: TxJson = serde_json::from_value(serde_json::json!({
            "version": 1, "unlock_time": 0, "extra": [],
            "vin": [{"key": {"amount": 5, "key_offsets": [1], "k_image": "11".repeat(32)}}],
            "vout": [{"amount": 5, "target": {"key": "22".repeat(32)}}],
        }))
        .unwrap();
        assert!(v1.is_v1() && !v1.is_coinbase());
        assert_eq!(
            outputs(&v1, 0, &[7])[0].commitment,
            Some(visible_commitment(5))
        );

        let (_, tx) = captured_tx();
        let pk = tx.rct_signatures.as_ref().unwrap().out_pk.as_ref().unwrap();
        let window = outputs(&tx, 2, &[804, 805]);
        for (o, i) in window.iter().zip(2..) {
            let mut key = [0u8; 32];
            explorer_core::hex::decode_to_slice(tx.vout[i].target.public_key().unwrap(), &mut key)
                .unwrap();
            let mut commitment = [0u8; 32];
            explorer_core::hex::decode_to_slice(&pk[i], &mut commitment).unwrap();
            assert_eq!(
                (o.key, o.commitment),
                (Some(key), Some(commitment)),
                "output {i}"
            );
        }
    }
}
