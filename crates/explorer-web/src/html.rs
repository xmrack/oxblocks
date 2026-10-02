//! The HTML interface.
//!
//! Templates are compiled by askama, which escapes every interpolation by
//! default. Markup assembled by string concatenation hides a missed escape.
//! Here an unescaped value requires writing `|safe`, which greps.
//!
//! No JavaScript, no cookies, no images, no external requests. The
//! Content-Security-Policy is `default-src 'none'; style-src 'self'`, so the
//! browser enforces that independently of what these templates emit.

use std::sync::OnceLock;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use explorer_core::fmt::{age, decimal, now, timestamp_utc};
use explorer_core::{Amount, BlockId, BlockTree, ChainError, Hash32, TxFacts};
use monerod_rpc::types::{PoolTxInfo, TREE_ROOT_LAG, TxEntry, TxJson};
use std::collections::HashMap;

use crate::api::handlers::{AppState, Shared, echo};
use crate::config::Theme;

mod leaf_grid;
mod map_labels;
mod paths;
mod tree_field;
pub use paths::tree_paths;

/// The chain summary strip shown on every page.
pub struct ChainStatus {
    pub height: u64,
    pub nettype: String,
    pub difficulty: String,
    pub pool: u64,
    pub target: u64,
    pub syncing: bool,
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    blocks: Vec<BlockRow>,
    page: u64,
    /// The next page back, while there are older blocks.
    older: Option<u64>,
}

struct BlockRow {
    height: u64,
    age: String,
    size: u64,
    /// Every transaction in the block, coinbase included, matching the block
    /// page's own count and the number of rows in its table. `num_txes`
    /// counts non-coinbase transactions only; see `total_tx_count`.
    tx_count: u64,
    reward: String,
    hash: String,
}

#[derive(Template)]
#[template(path = "block.html")]
struct BlockPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    height: u64,
    depth: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    timestamp_utc: String,
    age: String,
    size: u64,
    weight: u64,
    /// Every transaction in the block, coinbase included: the rows below and
    /// the unreadable ones. Agrees with the index row's
    /// `total_tx_count(num_txes)` because every valid block carries exactly
    /// one coinbase.
    tx_count: usize,
    /// Transactions the daemon sent that did not decode, so have no row.
    unreadable: usize,
    /// Not on the main chain: reached by its hash, an alternative block.
    orphan: bool,
    reward: String,
    difficulty: String,
    nonce: u32,
    major_version: u8,
    minor_version: u8,
    /// The curve tree this block commits to, from hard fork 17. Both `None`
    /// below the fork, and when the block's own JSON did not decode.
    tree_root: Option<String>,
    tree_layers: Option<u8>,
    /// The outputs in the tree whose root this block carries, and how many
    /// more than in the previous block's.
    tree_growth: Option<(String, String)>,
    fee_sort: ColumnSort,
    size_sort: ColumnSort,
    txs: Vec<BlockTxRow>,
}

struct BlockTxRow {
    hash: String,
    coinbase: bool,
    p2pool: bool,
    /// Its spends: a coinbase's one input creates coins, and is shown as
    /// none.
    inputs: usize,
    outputs: usize,
    fee: String,
    fee_atomic: u64,
    ring: usize,
    /// An FCMP++ spend, whose ring column names the curve tree rather than a
    /// 0 that would say it has no anonymity set.
    full_chain: bool,
    /// Its reference block, and the tree's size as of it when known.
    reference: Option<u64>,
    tree: Option<String>,
    size: u64,
}

#[derive(Template)]
#[template(path = "tx.html")]
struct TxPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    hash: String,
    coinbase: bool,
    p2pool: bool,
    in_pool: bool,
    pruned: bool,
    block_height: u64,
    confirmations: u64,
    timestamp: u64,
    timestamp_utc: String,
    age: String,
    fee: String,
    size: u64,
    version_no: u64,
    rct_type: u8,
    ring_size: usize,
    /// The inputs prove membership in the curve tree, so there is
    /// no ring to show.
    fcmp_pp: bool,
    /// The height whose curve tree the FCMP++ proof was built against, and
    /// the tree's layer count then. `None` on a ring spend, and on an FCMP++
    /// spend whose prunable half this node no longer holds.
    reference_block: Option<u64>,
    n_tree_layers: Option<u8>,
    /// The block that carries the root the proof was checked
    /// against, eight below the reference block (see
    /// [`monerod_rpc::types::TREE_ROOT_LAG`]), and that root. `None` when that
    /// block carries no tree, which is so for the first reference blocks after
    /// the fork, and when it could not be fetched.
    root_block: Option<(u64, String)>,
    /// The curve tree's size as of the reference block, digits grouped. `None`
    /// wherever the API's `anonymity_set` is `null`.
    anonymity_set: Option<String>,
    /// That tree, drawn. Present exactly when `anonymity_set` is.
    tree: Option<[TreeFunnel; 2]>,
    /// The FCMP++ proof's length in bytes.
    proof_size: Option<String>,
    /// Any output is a Carrot output, which carries a three-byte view tag and
    /// an encrypted Janus anchor.
    carrot: bool,
    unlock_time: u64,
    payment_id: String,
    payment_id8: String,
    inputs: Vec<InputView>,
    outputs: Vec<OutputView>,
    has_view_tags: bool,
    /// Every output has a unified id, which a pool transaction does not.
    has_unified_ids: bool,
    extra: String,
    extra_fields: Vec<ExtraField>,
    extra_undecoded: bool,
}

struct InputView {
    key_image: String,
    amount: Option<String>,
    unavailable: bool,
    ring: Vec<RingView>,
    ages: AgeStrip,
}

struct RingView {
    height: u64,
    public_key: String,
    tx_hash: String,
}

/// An input's ring laid out along a time axis.
struct AgeStrip {
    marks: Vec<AgeMark>,
    ticks: Vec<AgeTick>,
}

/// One ring member's place on the strip: a hairline at its own age, under a
/// wide translucent halo. Halos of members close in age overlap into a darker
/// band, which is what makes the clustering visible at a glance.
struct AgeMark {
    /// Left edges, in the strip's own coordinate space. Computed here because
    /// the Content-Security-Policy forbids inline styles, so the SVG carries
    /// presentation attributes rather than a `style=`.
    halo: u32,
    stem: u32,
    /// The age this mark stands for, e.g. "4 h".
    label: String,
}

/// One labelled point on the strip's time axis.
struct AgeTick {
    x: u32,
    label: String,
}

/// A transaction's inputs that spend an output: all of them but a coinbase's
/// one, which creates coins instead.
fn spends(tx: &TxJson) -> usize {
    tx.vin.iter().filter(|v| v.as_key().is_some()).count()
}

/// Whether a coinbase was paid out by p2pool.
///
/// Two marks together, both on the chain and free to read. A coinbase with
/// more than one output paid its miners directly, which is what a
/// decentralised pool does and what a solo miner or a custodial pool never
/// needs to do. A merge-mining tag beside it is the commitment p2pool writes
/// to tie the block to its sidechain.
///
/// Measured over 300 consecutive mainnet blocks: 21 coinbases paid more than
/// one output and all 21 carried the tag, in the same order every time. Of
/// the 279 single-output coinbases, 142 carried a merge-mining tag on its own
/// and none paid a second address, so neither mark identifies a payout by
/// itself.
///
/// This reads the payout, not the software. Another decentralised pool that
/// paid on chain and committed to a sidechain the same way would read the
/// same, and which miner received which output is not on the Monero chain at
/// all.
fn is_p2pool(coinbase: bool, outputs: usize, merge_mined: bool) -> bool {
    coinbase && outputs > 1 && merge_mined
}

/// Blocks per hour and per day at Monero's two-minute target.
const BLOCKS_PER_HOUR: u64 = 30;
const BLOCKS_PER_DAY: u64 = 720;

/// The strip's coordinate space, in the pixels it occupies at full size. The
/// stylesheet lets it shrink with a narrow window but never enlarges it, so
/// the axis labels stay the size they were drawn at.
const STRIP_WIDTH: u32 = 760;
const STRIP_BAND: u32 = 26;
const STRIP_HEIGHT: u32 = 44;
const HALO_WIDTH: u32 = 26;
const STEM_WIDTH: u32 = 2;
/// Baseline for the axis labels: below the band, with room for descenders.
const TICK_BASELINE: u32 = STRIP_HEIGHT - 5;

/// Axis labels, spaced widely enough on a log scale that two never collide.
const AGE_TICKS: [(u64, &str); 7] = [
    (BLOCKS_PER_HOUR, "1h"),
    (6 * BLOCKS_PER_HOUR, "6h"),
    (BLOCKS_PER_DAY, "1d"),
    (7 * BLOCKS_PER_DAY, "1w"),
    (30 * BLOCKS_PER_DAY, "1mo"),
    (365 * BLOCKS_PER_DAY, "1y"),
    (1825 * BLOCKS_PER_DAY, "5y"),
];

/// The axis every strip on a transaction shares: the oldest age any of its
/// inputs reaches. Drawn to its own scale, each input would put the same
/// cluster in a different place, and the strips could not be compared.
fn axis_span(heights: impl Iterator<Item = u64>, spent_at: u64) -> u64 {
    heights
        .map(|h| spent_at.saturating_sub(h))
        .max()
        .unwrap_or(0)
}

/// Lays a ring out on a time axis running from `oldest` at the left to the
/// spend itself at the right.
///
/// `spent_at` is the height of the block holding the spending transaction, or
/// the current tip for one still in the pool. A member mined *after* that --
/// which the daemon should never return -- reads as brand new rather than
/// wrapping.
///
/// `oldest` is the axis, in blocks, and is the oldest age reached by any of
/// the transaction's inputs rather than by this one alone.
fn age_strip(ring: &[RingView], spent_at: u64, oldest: u64) -> AgeStrip {
    let ages = ring.iter().map(|m| spent_at.saturating_sub(m.height));

    AgeStrip {
        marks: ages
            .map(|age| {
                let x = strip_x(age, oldest);
                AgeMark {
                    halo: centred(x, HALO_WIDTH),
                    stem: centred(x, STEM_WIDTH),
                    label: age_label(age),
                }
            })
            .collect(),
        // Only the range the ring covers: a label with nothing under it
        // invites the reader to look for members that are not there.
        ticks: AGE_TICKS
            .iter()
            .filter(|&&(age, _)| age <= oldest)
            .map(|&(age, label)| AgeTick {
                x: strip_x(age, oldest),
                label: label.to_owned(),
            })
            .collect(),
    }
}

/// Left edge of a mark of `width` centred on `x`, held inside the strip so a
/// member at either extreme is drawn whole rather than half outside the band.
fn centred(x: u32, width: u32) -> u32 {
    x.saturating_sub(width / 2).min(STRIP_WIDTH - width)
}

/// Where an age sits along the strip: 0 is the oldest member, `STRIP_WIDTH`
/// the moment of the spend.
///
/// Logarithmic, because decoys are drawn from a gamma distribution that
/// strongly favours recent outputs. On a linear axis nearly every member of a
/// healthy ring lands within a unit or two of the right edge, and the shape
/// worth looking at is the one that disappears.
fn strip_x(age: u64, oldest: u64) -> u32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a chart coordinate, not chain arithmetic"
    )]
    let (age, oldest) = (age as f64, oldest as f64);

    let span = (oldest + 1.0).ln();
    if span <= 0.0 {
        // No member is older than the spend, so there is no axis to spread
        // them along; they all belong at the spend end.
        return STRIP_WIDTH;
    }

    let from_left = f64::from(STRIP_WIDTH) * (1.0 - (age + 1.0).ln() / span);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to the strip before the cast"
    )]
    let x = from_left.clamp(0.0, f64::from(STRIP_WIDTH)).round() as u32;
    x
}

/// An age written the way a reader would say it.
fn age_label(blocks: u64) -> String {
    let minutes = blocks.saturating_mul(2);
    match minutes {
        0..60 => format!("{minutes} min"),
        60..1440 => format!("{} h", minutes / 60),
        1440..43200 => format!("{} d", minutes / 1440),
        _ => format!("{} mo", minutes / 43200),
    }
}

/// The curve tree an FCMP++ spend proved against, drawn as a funnel: one bar
/// per layer, the root at the top and the outputs at the bottom. Below the
/// root, every bar is split into the root's children's subtrees, one column
/// for each, joined by its own band to the column above.
struct TreeFunnel {
    class: &'static str,
    width: u32,
    height: u32,
    rows: Vec<FunnelRow>,
    /// The bands joining each bar's blocks to the ones below them, as
    /// polygon points.
    webs: Vec<String>,
    /// The root the proof was checked against, abbreviated.
    root: Option<String>,
    root_x: u32,
    root_y: u32,
    /// Where each row's count sits: at the right beside the bars, or over the
    /// middle of its bar when the label is above it.
    count_x: u32,
    count_anchor: &'static str,
    leaves: String,
    layers: usize,
}

struct FunnelRow {
    name: String,
    curve: Option<&'static str>,
    /// `None` on the root when its hash is shown: there is always one.
    count: Option<String>,
    class: &'static str,
    x: u32,
    y: u32,
    label_y: u32,
    width: u32,
    /// The bar's part of each of the root's children's subtrees, left to
    /// right; the root's bar is one block.
    blocks: Vec<FunnelBlock>,
}

struct FunnelBlock {
    x: String,
    width: String,
    /// How many of the layer's nodes the block holds.
    nodes: u64,
}

impl FunnelRow {
    /// A block's tooltip: what it holds.
    fn holds(&self, b: &FunnelBlock) -> String {
        let (one, many) = match self.class {
            "leaf" => ("output", "outputs"),
            _ => ("node", "nodes"),
        };
        format!(
            "{} {}",
            grouped(b.nodes),
            if b.nodes == 1 { one } else { many }
        )
    }
}

/// Labels take the left of the strip's width and counts the right.
const FUNNEL_LEFT: u32 = 150;
const FUNNEL_RIGHT: u32 = 110;
const FUNNEL_TOP: u32 = 14;
const FUNNEL_ROW: u32 = 30;
const FUNNEL_BAR: u32 = 14;
const FUNNEL_MIN_BAR: u32 = 10;
/// The space between two blocks of a bar, at most, and at most this share of
/// the bar in all.
const FUNNEL_GAP: f64 = 3.0;
const FUNNEL_GAP_SHARE: f64 = 0.25;

/// Where a funnel's labels, counts and bars go.
struct FunnelLayout {
    class: &'static str,
    width: u32,
    left: u32,
    right: u32,
    top: u32,
    row: u32,
    /// Labels sit on the bar's line, or above it. Above, the count goes over
    /// the middle of the bar.
    above: bool,
}

/// Labels beside the bars.
const WIDE_FUNNEL: FunnelLayout = FunnelLayout {
    class: "wide",
    width: STRIP_WIDTH,
    left: FUNNEL_LEFT,
    right: FUNNEL_RIGHT,
    top: FUNNEL_TOP,
    row: FUNNEL_ROW,
    above: false,
};

/// Labels above the bars, for a phone: the whole tree fits its width.
const NARROW_FUNNEL: FunnelLayout = FunnelLayout {
    class: "narrow",
    width: 320,
    left: 0,
    right: 0,
    top: 30,
    row: 44,
    above: true,
};

/// The tree holding `leaves` outputs, laid out wide and narrow. `None` for an
/// empty tree.
fn tree_picture(leaves: u64, root: Option<&str>) -> Option<[TreeFunnel; 2]> {
    Some([
        tree_funnel(leaves, root, &WIDE_FUNNEL)?,
        tree_funnel(leaves, root, &NARROW_FUNNEL)?,
    ])
}

/// Lays out the tree holding `leaves` outputs. `None` for an empty tree.
///
/// The shape follows from the size alone, so nothing here depends on, or
/// could hint at, which output an input spent.
fn tree_funnel(leaves: u64, root: Option<&str>, layout: &FunnelLayout) -> Option<TreeFunnel> {
    let layers = monerod_rpc::types::tree_layers(leaves);
    let depth = layers.len();
    if depth == 0 {
        return None;
    }
    let counts = layers.iter().rev().copied().chain([leaves]);
    let span = layout.width - layout.left - layout.right;
    let centre = layout.left + span / 2;

    // Nodes of each row under one child of the root: 1 in the root's
    // children's own row, and each row below holds its group width times the
    // row above.
    let branches = layers.iter().rev().nth(1).copied().unwrap_or(leaves);
    let mut per_branch = 0u64;

    let rows: Vec<FunnelRow> = counts
        .zip(0u32..)
        .map(|(count, i)| {
            let width = funnel_width(count, leaves, span);
            let x = centre - width / 2;
            let y = layout.top + i * layout.row;
            let layer = depth - i as usize;
            let curve =
                (layer > 0).then(|| explorer_core::curve_tree::Curve::of_layer(layer).name());
            let (name, class) = match i {
                0 => ("Root".to_owned(), "root"),
                _ if layer == 0 => ("Outputs".to_owned(), "leaf"),
                _ => (format!("Layer {layer}"), "node"),
            };
            per_branch = match i {
                0 => 0,
                1 => 1,
                _ => per_branch.saturating_mul(explorer_core::curve_tree::group_width(layer)),
            };
            let blocks = if i == 0 {
                vec![FunnelBlock {
                    x: x.to_string(),
                    width: width.to_string(),
                    nodes: count,
                }]
            } else {
                funnel_blocks(count, branches, per_branch, x, width)
            };
            FunnelRow {
                name,
                curve,
                count: (i > 0 || root.is_none()).then(|| grouped(count)),
                class,
                x,
                y,
                label_y: if layout.above { y - 8 } else { y + 12 },
                width,
                blocks,
            }
        })
        .collect();

    // The root's band fans out to the whole bar below it; each band below
    // that joins a branch's block to the same branch's block beneath.
    let webs = rows
        .windows(2)
        .flat_map(|w| match w {
            [a, b] if a.blocks.len() == 1 => vec![format!(
                "{},{top} {},{top} {},{} {},{}",
                a.x,
                a.x + a.width,
                b.x + b.width,
                b.y,
                b.x,
                b.y,
                top = a.y + FUNNEL_BAR,
            )],
            [a, b] => a
                .blocks
                .iter()
                .zip(&b.blocks)
                .map(|(p, q)| {
                    format!(
                        "{},{top} {},{top} {},{} {},{}",
                        p.x,
                        block_end(p),
                        block_end(q),
                        b.y,
                        q.x,
                        b.y,
                        top = a.y + FUNNEL_BAR,
                    )
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect();

    Some(TreeFunnel {
        class: layout.class,
        width: layout.width,
        height: rows.last().map_or(0, |r| r.y) + FUNNEL_BAR + 6,
        root_x: centre,
        root_y: rows.first().map_or(0, |r| r.label_y.min(r.y - 3)),
        count_x: if layout.above { centre } else { layout.width },
        count_anchor: if layout.above { "middle" } else { "end" },
        rows,
        webs,
        root: root.and_then(|r| r.get(..16)).map(|r| format!("{r}…")),
        leaves: grouped(leaves),
        layers: depth,
    })
}

/// A bar of `count` nodes, `width` wide from `x`, split into `branches`
/// blocks of `per_branch` nodes each but the last, which holds the rest.
#[allow(
    clippy::cast_precision_loss,
    reason = "a chart coordinate, not chain arithmetic"
)]
fn funnel_blocks(
    count: u64,
    branches: u64,
    per_branch: u64,
    x: u32,
    width: u32,
) -> Vec<FunnelBlock> {
    let w = f64::from(width);
    let gap = if branches > 1 {
        FUNNEL_GAP.min(FUNNEL_GAP_SHARE * w / (branches - 1) as f64)
    } else {
        0.0
    };
    let room = w - gap * branches.saturating_sub(1) as f64;
    let mut at = f64::from(x);
    (0..branches)
        .map(|j| {
            let nodes = count
                .saturating_sub(j.saturating_mul(per_branch))
                .min(per_branch);
            let bw = room * nodes as f64 / count.max(1) as f64;
            let block = FunnelBlock {
                x: coord(at),
                width: coord(bw.max(1.0)),
                nodes,
            };
            at += bw + gap;
            block
        })
        .collect()
}

fn block_end(b: &FunnelBlock) -> String {
    let (x, w) = (b.x.parse().unwrap_or(0.0), b.width.parse().unwrap_or(0.0));
    coord(x + w)
}

/// A drawing coordinate to a tenth of a pixel, written short.
fn coord(v: f64) -> String {
    let s = format!("{v:.1}");
    s.strip_suffix(".0").map_or(s.clone(), str::to_owned)
}

/// A bar's width: the log of its node count against the log of the outputs',
/// so the outputs span the full width and the root takes the minimum.
fn funnel_width(count: u64, leaves: u64, span: u32) -> u32 {
    if leaves <= 1 {
        return FUNNEL_MIN_BAR;
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "a chart coordinate, not chain arithmetic"
    )]
    let share = (count as f64).ln() / (leaves as f64).ln();
    let room = f64::from(span - FUNNEL_MIN_BAR);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to the span before the cast"
    )]
    let extra = (room * share).clamp(0.0, room).round() as u32;
    FUNNEL_MIN_BAR + extra
}

struct OutputView {
    public_key: String,
    amount: Option<String>,
    view_tag: String,
    /// The encrypted Janus anchor of a Carrot output, or empty.
    anchor: String,
    unified_id: Option<u64>,
}

/// A count with its thousands separated, for a number a reader has to take in
/// at a glance. The API publishes the bare integer.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

struct ExtraField {
    name: String,
    value: String,
}

#[derive(Template)]
#[template(path = "mempool.html")]
struct MempoolPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    waiting_sort: ColumnSort,
    fee_sort: ColumnSort,
    size_sort: ColumnSort,
    /// Every transaction in the pool, of which `txs` are the first.
    total: usize,
    /// Whether the pool is longer than the page shows.
    cut: bool,
    txs: Vec<PoolRow>,
}

impl MempoolPage {
    /// Whether any row is an FCMP++ spend, whose column holds a tree's size
    /// rather than a ring's.
    fn anon_set(&self) -> bool {
        self.txs.iter().any(|t| t.full_chain)
    }
}

impl BlockPage {
    /// As [`MempoolPage::anon_set`].
    fn anon_set(&self) -> bool {
        self.txs.iter().any(|t| t.full_chain)
    }
}

/// The most rows the mempool page shows: as many as `/api/mempool` sends at
/// once.
#[allow(clippy::cast_possible_truncation, reason = "500 fits any usize")]
const MEMPOOL_ROWS: usize = crate::api::handlers::MAX_MEMPOOL_LIMIT as usize;

struct PoolRow {
    hash: String,
    age: String,
    /// The outputs it spends.
    inputs: usize,
    outputs: usize,
    fee: String,
    ring: usize,
    full_chain: bool,
    reference: Option<u64>,
    tree: Option<String>,
    size: u64,
}

/// Which table column a page was sorted by, if any.
///
/// Only the columns backed by a plain number are sortable. `Hash` has no
/// useful order and `Ring` was not asked for. `Waiting` exists only on the
/// mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Waiting,
    Fee,
    Size,
}

impl SortKey {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "waiting" => Some(Self::Waiting),
            "fee" => Some(Self::Fee),
            "size" => Some(Self::Size),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Fee => "fee",
            Self::Size => "size",
        }
    }

    /// What a pool transaction sorts by, as the daemon states it: the same
    /// numbers its row shows.
    fn of(self, t: &PoolTxInfo, asked_at: u64) -> u64 {
        match self {
            Self::Waiting => waiting_secs(asked_at, t.receive_time),
            Self::Fee => t.fee,
            Self::Size => t.blob_size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "asc" => Some(Self::Asc),
            "desc" => Some(Self::Desc),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    fn flipped(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

/// A column header's link: where clicking it goes, and whether it is sorted
/// now, `asc`, `desc` or `none`, as the class its mark is drawn with.
///
/// No JavaScript runs on this page, so "clicking a header to sort" has to be
/// an ordinary link to a URL that already carries the answer.
struct ColumnSort {
    href: String,
    state: &'static str,
}

/// The header link for `key`, given the sort currently in effect (if any).
///
/// A column not currently sorted links to itself descending, largest or
/// longest-waiting first, which is normally the more interesting read. The
/// active column instead links to its own reverse, so a second click flips
/// it.
///
/// Every sortable column carries a mark. The active one points the way it is
/// sorted now, and the rest show both ways, because a header that looks like
/// every other header does not say that it can be clicked. The mark is drawn
/// in SVG: every arrow character has an emoji form on some phone.
fn column_sort(page: &str, key: SortKey, active: Option<(SortKey, SortDir)>) -> ColumnSort {
    let dir = match active {
        Some((k, d)) if k == key => d.flipped(),
        _ => SortDir::Desc,
    };
    let state = match active {
        Some((k, d)) if k == key => d.as_str(),
        _ => "none",
    };
    ColumnSort {
        href: format!("{page}?sort={}&dir={}", key.as_str(), dir.as_str()),
        state,
    }
}

/// How long a pool transaction has been waiting, in seconds.
fn waiting_secs(asked_at: u64, receive_time: u64) -> u64 {
    asked_at.abs_diff(receive_time)
}

/// Orders rows by `value`, stably: rows equal under it keep the order the
/// daemon returned them in, whichever direction is asked for.
fn sort_rows<T>(rows: &mut [T], dir: SortDir, value: impl Fn(&T) -> u64) {
    rows.sort_by(|a, b| {
        let ord = value(a).cmp(&value(b));
        if dir == SortDir::Desc {
            ord.reverse()
        } else {
            ord
        }
    });
}

/// The mempool page's rows: the pool sorted as asked, and cut to
/// [`MEMPOOL_ROWS`] before any transaction is decoded, so a pool of
/// thousands costs the rows shown. A transaction that does not decode has no
/// row.
/// What a table row shows of a transaction. Its hash fixes all of it, so
/// it is worked out once rather than parsed again on every view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowFacts {
    coinbase: bool,
    p2pool: bool,
    inputs: usize,
    outputs: usize,
    fee: u64,
    ring: usize,
    full_chain: bool,
    reference: Option<u64>,
    size: u64,
}

impl RowFacts {
    fn of(tx: &TxJson, f: &TxFacts) -> Self {
        Self {
            coinbase: f.coinbase,
            p2pool: is_p2pool(
                f.coinbase,
                tx.vout.len(),
                f.extra.merge_mining_tag().is_some(),
            ),
            inputs: spends(tx),
            outputs: tx.vout.len(),
            fee: f.fee,
            ring: f.ring_size,
            full_chain: f.fcmp_pp.is_some(),
            reference: tx.reference_block(),
            size: f.size,
        }
    }
}

/// [`RowFacts`] by transaction hash, and whether they are a pool row's: the
/// pool states a transaction's size and fee itself, a block row measures and
/// derives them.
pub struct RowCache(explorer_core::cache::Cache<(String, bool), RowFacts>);

impl Default for RowCache {
    fn default() -> Self {
        Self(explorer_core::cache::Cache::permanent(16_384))
    }
}

impl RowCache {
    #[must_use]
    pub fn stats(&self) -> explorer_core::cache::Stats {
        self.0.stats()
    }

    fn of_block_tx(&self, e: &TxEntry) -> Option<RowFacts> {
        let key = (e.tx_hash.to_lowercase(), false);
        if let Some(hit) = self.0.get(&key) {
            return Some(*hit);
        }
        let tx = e.parse_json().ok()?;
        let facts = RowFacts::of(&tx, &TxFacts::from_entry(e, &tx));
        // A pruned entry measures short; it is shown as it is, not kept.
        if !e.prunable_missing(&tx) {
            self.0.insert(key, facts);
        }
        Some(facts)
    }

    fn of_pool_tx(&self, t: &PoolTxInfo) -> Option<RowFacts> {
        let key = (t.id_hash.to_lowercase(), true);
        if let Some(hit) = self.0.get(&key) {
            return Some(*hit);
        }
        let tx = t.parse_json().ok()?;
        let facts = RowFacts::of(&tx, &TxFacts::from_pool(t, &tx));
        self.0.insert(key, facts);
        Some(facts)
    }
}

fn pool_rows(
    rows: &RowCache,
    pool: &[PoolTxInfo],
    active: Option<(SortKey, SortDir)>,
    asked_at: u64,
) -> Vec<PoolRow> {
    let mut listed: Vec<&PoolTxInfo> = pool.iter().collect();
    if let Some((key, dir)) = active {
        sort_rows(&mut listed, dir, |t| key.of(t, asked_at));
    }
    listed
        .into_iter()
        .take(MEMPOOL_ROWS)
        .filter_map(|t| {
            let f = rows.of_pool_tx(t)?;
            Some(PoolRow {
                hash: t.id_hash.to_lowercase(),
                age: age(asked_at, t.receive_time),
                inputs: f.inputs,
                outputs: f.outputs,
                fee: xmr_aligned(f.fee),
                ring: f.ring,
                full_chain: f.full_chain,
                reference: f.reference,
                tree: None,
                size: f.size,
            })
        })
        .collect()
}

/// The outputs in the tree as of a row's reference block, from `sizes`.
fn tree_of(reference: Option<u64>, sizes: &HashMap<u64, u64>) -> Option<String> {
    sizes
        .get(&reference?)
        .filter(|n| **n > 0)
        .map(|n| grouped(*n))
}

/// The size of the tree whose root block `height` carries, and how many
/// outputs it gained over the previous block's: both are as of
/// `TREE_ROOT_LAG` blocks on.
fn tree_growth(height: u64, sizes: &HashMap<u64, u64>) -> Option<(String, String)> {
    let at = height.checked_add(TREE_ROOT_LAG)?;
    let now = *sizes.get(&at)?;
    let before = *sizes.get(&(at - 1))?;
    Some((grouped(now), grouped(now.saturating_sub(before))))
}

/// Orders a block's rows. A block has no `Waiting` column, so that key is
/// refused before it gets here.
fn sort_block_rows(rows: &mut [BlockTxRow], key: SortKey, dir: SortDir) {
    let value: fn(&BlockTxRow) -> u64 = if key == SortKey::Size {
        |r| r.size
    } else {
        |r| r.fee_atomic
    };
    sort_rows(rows, dir, value);
}

#[derive(Template)]
#[template(path = "altblocks.html")]
struct AltBlocksPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    chains: Vec<AltChainRow>,
}

struct AltChainRow {
    /// The height of the chain's first block, where it diverged.
    diverged: u64,
    length: u64,
    tip: u64,
    block_hash: String,
    difficulty: String,
    parent: String,
}

/// An alternative chain as the page shows it. monerod's `height` is the
/// tip's, and the chain runs `length` blocks down to where it diverged.
fn alt_chain_row(c: &monerod_rpc::types::ChainInfo) -> AltChainRow {
    AltChainRow {
        diverged: c.height.saturating_add(1).saturating_sub(c.length),
        length: c.length,
        tip: c.height,
        block_hash: c.block_hash.to_lowercase(),
        difficulty: c.cumulative_difficulty().to_string(),
        parent: c.main_chain_parent_block.to_lowercase(),
    }
}

/// The JSON API's own documentation.
///
/// Every limit on this page is interpolated from what the handler actually
/// enforces -- a constant, or the deployment's configured
/// [`Limits`](crate::config::Limits) -- and the accepted postfix lengths are
/// computed by asking the validator. Documentation that restates a number is
/// documentation that will one day be wrong; documentation that reads it
/// cannot be.
#[derive(Template)]
#[template(path = "api.html")]
struct ApiPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    /// Real heights, so the example links are clickable rather than
    /// illustrative.
    sample_height: u64,
    sample_range_start: u64,
    /// "5 characters", or "2 or 3 characters" on a smaller chain.
    postfix_lengths: String,
    max_transactions_limit: u64,
    max_mempool_limit: u64,
    max_block_range: u64,
    min_postfix_len: usize,
    max_postfix_len: usize,
    min_anonymity_set: u64,
    max_private_tx_matches: u64,
    recent_blocks: u64,
    /// Recorded response bodies, shown collapsed under each endpoint. See
    /// [`example`]: these are answers the chain really gave, not fabrications,
    /// and they cost no daemon call to render.
    example_version: &'static str,
    example_network_info: &'static str,
    example_block: &'static str,
    example_blocks_range: &'static str,
    example_transaction: &'static str,
    example_transaction_private: &'static str,
    example_transactions: &'static str,
    example_mempool: &'static str,
    example_transactions_recent: &'static str,
    example_search_block: &'static str,
    example_search_tx: &'static str,
    example_feeestimate: &'static str,
    example_health: &'static str,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    title: String,
    detail: String,
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The stylesheet's bytes, embedded at compile time.
///
/// In three parts because the colours are settled at startup: the rules name
/// every colour through a variable, and a palette defines them.
const STYLESHEET: &str = include_str!("../static/style.css");
const LIGHT_PALETTE: &str = include_str!("../static/light.css");
const DARK_PALETTE: &str = include_str!("../static/dark.css");

/// The stylesheet as served: a palette, then the rules.
struct Sheet {
    body: String,
    version: u64,
}

impl Sheet {
    fn new(theme: Theme) -> Self {
        // dark.css is one `:root` rule and nothing else, so deferring it to
        // the reader's system preference is a matter of nesting it.
        let body = match theme {
            Theme::Auto => format!(
                "{LIGHT_PALETTE}\n@media (prefers-color-scheme: dark) {{\n{DARK_PALETTE}}}\n{STYLESHEET}"
            ),
            Theme::Light => format!("{LIGHT_PALETTE}{STYLESHEET}"),
            Theme::Dark => format!("{DARK_PALETTE}{STYLESHEET}"),
        };
        Self {
            version: fnv1a(body.as_bytes()),
            body,
        }
    }
}

static SHEET: OnceLock<Sheet> = OnceLock::new();

/// Fix the colour scheme for the life of the process.
///
/// Called by `main` from the command line before the first request is served.
/// There is no per-reader toggle to change it later: that would need a cookie
/// or a script, and this explorer serves neither.
pub fn set_theme(theme: Theme) {
    let _ = SHEET.set(Sheet::new(theme));
}

fn sheet() -> &'static Sheet {
    SHEET.get_or_init(|| Sheet::new(Theme::default()))
}

/// A cache key derived from the served stylesheet's own contents.
///
/// The stylesheet is served with a day-long `max-age` and carries no `ETag`,
/// so a returning browser reuses whatever it already has. At a fixed URL that
/// means a CSS change is invisible for a day: the page renders new markup
/// against an old stylesheet, which is how a `<details>` hint came out as a
/// bare disclosure triangle and a black blob. Changing the *URL* whenever the
/// bytes change makes the long cache lifetime correct instead of harmful.
/// The palette is part of those bytes, so restarting under another `--theme`
/// moves the URL too.
///
/// FNV-1a, and deliberately not a cryptographic hash: this is a cache key, not
/// a signature, and nothing is trusted on the strength of it.
pub fn stylesheet_version() -> u64 {
    sheet().version
}

const fn fnv1a(mut bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    // Walked by slice pattern rather than by index: the workspace denies
    // `indexing_slicing`, and this needs no bounds check to begin with.
    while let [first, rest @ ..] = bytes {
        hash ^= *first as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        bytes = rest;
    }
    hash
}

/// A rendered page, or a rendered explanation of why there is not one.
pub struct Page(StatusCode, String);

impl IntoResponse for Page {
    /// `no-cache` lets a browser keep the page but makes it ask before showing
    /// it again. Without it a phone showed a copy from before a change, and
    /// the chain it describes moves every two minutes anyway.
    fn into_response(self) -> Response {
        (self.0, [(header::CACHE_CONTROL, "no-cache")], Html(self.1)).into_response()
    }
}

fn render<T: Template>(status: StatusCode, page: &T) -> Page {
    match page.render() {
        Ok(body) => Page(status, body),
        // A template failure is ours, not the caller's, and must not leak the
        // internals of why.
        Err(e) => {
            tracing::error!("template render failed: {e}");
            Page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "<h1>oxblocks</h1><p>Could not render this page.</p>".to_owned(),
            )
        }
    }
}

fn error_page(chain: Option<ChainStatus>, status: StatusCode, title: &str, detail: &str) -> Page {
    error_page_for(chain, status, title, detail, None)
}

/// As [`error_page`], but keeps the user's search term in the box so they can
/// correct it rather than retype it.
///
/// This is the one place arbitrary user text reaches a template. askama escapes
/// every interpolation, so it is safe by construction rather than by the caller
/// remembering -- `a_hostile_search_term_is_escaped_in_the_page` proves it.
fn error_page_for(
    chain: Option<ChainStatus>,
    status: StatusCode,
    title: &str,
    detail: &str,
    query: Option<String>,
) -> Page {
    render(
        status,
        &ErrorPage {
            version: VERSION,
            query,
            chain,
            title: title.to_owned(),
            detail: detail.to_owned(),
        },
    )
}

/// The status strip. Failure to fetch it must not fail the page around it, so
/// this returns `None` rather than an error.
async fn status_of(state: &AppState) -> Option<ChainStatus> {
    let info = state.chain.info().await.ok()?;
    Some(ChainStatus {
        height: info.height,
        nettype: info.nettype.clone(),
        difficulty: info.difficulty().to_string(),
        pool: info.tx_pool_size,
        target: info.target_height,
        syncing: info.target_height > info.height,
    })
}

fn xmr(atomic: u64) -> String {
    Amount::from_atomic(atomic).to_trimmed_xmr_string()
}

/// XMR with every decimal place shown.
///
/// `xmr` trims for a value read on its own; a table column is read against
/// its neighbours, and a fee of `0.6` above one of `0.00003064` does not
/// align on the decimal point unless both carry the same number of places.
fn xmr_aligned(atomic: u64) -> String {
    Amount::from_atomic(atomic).to_xmr_string()
}

/// The XMR value of an input or output, when there is one to show.
///
/// A RingCT amount is committed, not published: the cleartext field is zero
/// and means "hidden", not "nothing". `None` is that state, so the templates
/// cannot render it as a number.
///
/// This was a string comparison against `"0"` in two places. The output path
/// built that sentinel and matched; the input path formatted through `xmr`,
/// which yields `"0.0"`, so its guard never fired and every RingCT input was
/// labelled `0.0 XMR`. One function, no sentinel, no second copy to drift.
fn visible_amount(atomic: u64) -> Option<String> {
    (atomic != 0).then(|| xmr(atomic))
}

/// The index shows this so it agrees with the block page's own count.
///
/// `BlockHeader::num_txes` counts non-coinbase transactions only, and every
/// valid block carries exactly one coinbase besides those, a consensus rule
/// this crate does not itself enforce but can rely on. The block page counts
/// every row it renders instead of applying this arithmetic a second time, so
/// the two derivations cannot silently drift apart the way `num_txes` alone
/// once did: the index showed 16, the block page showed 17.
fn total_tx_count(num_txes: u64) -> u64 {
    num_txes.saturating_add(1)
}

/// The block page's half of the same total: every row it renders, coinbase
/// included. Named so a test can call the block handler's own arithmetic
/// directly, rather than recomputing `txs.len()` a second time and only
/// proving the two copies agree with each other.
fn table_tx_count(txs: &[BlockTxRow]) -> usize {
    txs.len()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn index(state: Shared) -> Page {
    render_page(state, 0).await
}

/// Takes the page number as a string and parses it here.
///
/// Declaring it `Path<u64>` hands rejection to axum, which answers with its
/// own `text/plain` 400 quoting the input back -- the only route that did not
/// render this explorer's own error page. Harmless as an injection (the type
/// is `text/plain`, `nosniff` is set and the policy is `default-src 'none'`),
/// but it reflected raw input and read like a different piece of software.
pub async fn page_at(state: Shared, Path(raw): Path<String>) -> Page {
    let Some(page) = decimal(&raw) else {
        return error_page(
            status_of(&state).await,
            StatusCode::NOT_FOUND,
            "No such page",
            "A page number is a whole number, counting back from the newest block.",
        );
    };
    render_page(state, page).await
}

async fn render_page(State(state): Shared, page: u64) -> Page {
    const PER_PAGE: u64 = 25;

    let chain = status_of(&state).await;
    let Some(height) = chain.as_ref().map(|c| c.height) else {
        return error_page(
            None,
            StatusCode::BAD_GATEWAY,
            "monerod is unavailable",
            "The explorer could not reach its daemon. This is usually temporary.",
        );
    };

    let top = height.saturating_sub(1);
    // Past the genesis block there is nothing to list. Refused here rather
    // than rendered as a repeat of the oldest page, which also keeps the
    // pager's next number from overflowing.
    if page > top / PER_PAGE {
        return error_page(
            chain,
            StatusCode::NOT_FOUND,
            "No such page",
            &format!("The chain has {} pages of blocks.", top / PER_PAGE + 1),
        );
    }
    let start = top.saturating_sub(page.saturating_mul(PER_PAGE));
    let end = start;
    let begin = start.saturating_sub(PER_PAGE.saturating_sub(1));

    let headers = match state.chain.headers_range(begin, end).await {
        Ok(h) => h.headers,
        Err(e) => {
            tracing::warn!("index: {e}");
            return error_page(
                chain,
                StatusCode::BAD_GATEWAY,
                "Could not load blocks",
                &e.public_message(),
            );
        }
    };

    let blocks = headers
        .iter()
        .rev()
        .map(|h| BlockRow {
            height: h.height,
            age: age(now(), h.timestamp),
            size: h.block_size,
            tx_count: total_tx_count(h.num_txes),
            // The reward, not the fee total. Fees are the reward less the base
            // emission, and no header field carries the base, so this column
            // cannot be a fee column without inventing the number. It was
            // headed "Fees" and showed this value, which read as a plausible
            // fee and was not one.
            reward: xmr_aligned(h.reward),
            hash: h.hash.to_lowercase(),
        })
        .collect();

    render(
        StatusCode::OK,
        &IndexPage {
            version: VERSION,
            query: None,
            chain,
            blocks,
            page,
            older: (begin > 0).then_some(page + 1),
        },
    )
}

pub async fn block(
    State(state): Shared,
    Path(raw): Path<String>,
    Query(q): Query<SortQuery>,
) -> Page {
    let chain = status_of(&state).await;
    let active = active_sort(q.sort.as_deref(), q.dir.as_deref())
        .filter(|(key, _)| *key != SortKey::Waiting);

    let Ok(id) = BlockId::parse(&raw) else {
        return error_page(
            chain,
            StatusCode::NOT_FOUND,
            "No such block",
            &format!("{} is not a block height or a block hash.", echo(&raw)),
        );
    };

    let got = match state.chain.block(id).await {
        Ok(b) => b,
        Err(e) => return chain_error_page(chain, &e, &format!("No block {id}")),
    };

    let header = got.block_header.clone();
    let (fetched, _held) = match state.chain.block_transactions(&got).await {
        Ok(f) => f,
        // Rendering the header on its own would show a block that holds
        // transactions as though it were empty -- a wrong page rather than a
        // partial one.
        Err(e) => return chain_error_page(chain, &e, "Could not load this block's transactions"),
    };
    let mut txs = fetched
        .txs
        .iter()
        .filter_map(|e| {
            let f = state.rows.of_block_tx(e)?;
            Some(BlockTxRow {
                hash: e.tx_hash.to_lowercase(),
                coinbase: f.coinbase,
                p2pool: f.p2pool,
                inputs: f.inputs,
                outputs: f.outputs,
                fee: xmr_aligned(f.fee),
                fee_atomic: f.fee,
                ring: f.ring,
                full_chain: f.full_chain,
                reference: f.reference,
                tree: None,
                size: f.size,
            })
        })
        .collect::<Vec<_>>();
    let unreadable = fetched.txs.len().saturating_sub(txs.len());
    let tx_count = table_tx_count(&txs) + unreadable;
    if let Some((key, dir)) = active {
        sort_block_rows(&mut txs, key, dir);
    }
    let page = block_link(&header);

    // The tree fields are in the block's own JSON, not in its header. A
    // document that does not decode costs this one row and nothing else:
    // everything above it came from the header.
    let tree = BlockTree::of(&got);
    let depth = state.chain.depth_now(&header).await;

    // The coinbase's output is newer than every tree asked about here. An
    // orphan's sizes would be the main chain's, so it is asked nothing.
    let probe = fetched
        .txs
        .first()
        .and_then(|e| e.unified_ids.first().copied())
        .filter(|_| !header.orphan_status);
    let sizes = match probe {
        Some(probe) => {
            let grew = tree
                .is_some()
                .then(|| header.height.checked_add(TREE_ROOT_LAG))
                .flatten();
            let heights = txs
                .iter()
                .filter_map(|r| r.reference)
                .chain(grew.into_iter().flat_map(|h| [h - 1, h]));
            let chain_height = header.height.saturating_add(depth).saturating_add(1);
            state.chain.tree_sizes(heights, probe, chain_height).await
        }
        None => HashMap::new(),
    };
    for r in &mut txs {
        r.tree = tree_of(r.reference, &sizes);
    }

    render(
        StatusCode::OK,
        &BlockPage {
            version: VERSION,
            query: None,
            chain,
            height: header.height,
            depth,
            hash: header.hash.to_lowercase(),
            prev_hash: header.prev_hash.to_lowercase(),
            timestamp: header.timestamp,
            timestamp_utc: timestamp_utc(header.timestamp),
            age: age(now(), header.timestamp),
            size: header.block_size,
            weight: header.block_weight,
            tx_count,
            unreadable,
            orphan: header.orphan_status,
            reward: xmr(header.reward),
            difficulty: header.difficulty().to_string(),
            nonce: header.nonce,
            major_version: header.major_version,
            minor_version: header.minor_version,
            tree_growth: tree
                .as_ref()
                .and_then(|_| tree_growth(header.height, &sizes)),
            tree_layers: tree.as_ref().map(|t| t.n_layers),
            tree_root: tree.map(|t| t.root),
            fee_sort: column_sort(&page, SortKey::Fee, active),
            size_sort: column_sort(&page, SortKey::Size, active),
            txs,
        },
    )
}

/// The block page's own address, for its sort links. By height rather than
/// by whatever the request named, so a sorted link from a page reached by
/// hash still lands on this block; but an orphan's height names the main
/// chain's block, so it goes by its hash.
fn block_link(header: &monerod_rpc::types::BlockHeader) -> String {
    if header.orphan_status {
        format!("/block/{}", header.hash.to_lowercase())
    } else {
        format!("/block/{}", header.height)
    }
}

fn chain_error_page(chain: Option<ChainStatus>, e: &ChainError, title: &str) -> Page {
    if !e.is_not_found() {
        tracing::warn!("{title}: {e}");
    }
    if e.is_not_found() {
        error_page(chain, StatusCode::NOT_FOUND, title, &e.public_message())
    } else if e.is_transient() {
        error_page(
            chain,
            StatusCode::SERVICE_UNAVAILABLE,
            "monerod is busy",
            "The daemon is syncing or overloaded. This is usually temporary.",
        )
    } else {
        error_page(chain, StatusCode::BAD_GATEWAY, title, &e.public_message())
    }
}

/// The transaction a page is about, decoded, or the error page to show
/// instead. `chain` is moved into that page.
async fn fetch_tx(
    state: &AppState,
    chain: &mut Option<ChainStatus>,
    raw: &str,
) -> Result<(TxEntry, TxJson), Page> {
    let Ok(hash) = raw.parse::<Hash32>() else {
        return Err(error_page(
            chain.take(),
            StatusCode::NOT_FOUND,
            "No such transaction",
            &format!("{} is not a transaction hash.", echo(raw)),
        ));
    };

    let fetched = match state.chain.transactions(std::slice::from_ref(&hash)).await {
        Ok(f) => f,
        Err(e) => {
            return Err(chain_error_page(
                chain.take(),
                &e,
                &format!("No transaction {hash}"),
            ));
        }
    };

    let Some(entry) = fetched.txs.into_iter().next() else {
        return Err(error_page(
            chain.take(),
            StatusCode::NOT_FOUND,
            "No such transaction",
            &format!("The daemon does not have transaction {hash}."),
        ));
    };

    let Ok(tx) = entry.parse_json() else {
        return Err(error_page(
            chain.take(),
            StatusCode::BAD_GATEWAY,
            "Could not decode this transaction",
            "The daemon returned a transaction this explorer could not read.",
        ));
    };
    Ok((entry, tx))
}

/// The size of the curve tree an FCMP++ spend proved against, and the block
/// carrying the root it was checked against with that root. Independent, so
/// asked for together. See `RpcChainSource::proof_root` for why the root block
/// is fetched rather than computed.
async fn tree_facts(
    state: &AppState,
    tx: &TxJson,
    entry: &TxEntry,
    reference: Option<u64>,
) -> (Option<u64>, Option<(u64, String)>) {
    tokio::join!(
        state.chain.anonymity_set(
            tx,
            entry,
            entry.block_height.saturating_add(entry.confirmations),
        ),
        async {
            match reference {
                Some(r) => state.chain.proof_root(r).await,
                None => None,
            }
        },
    )
}

pub async fn transaction(State(state): Shared, Path(raw): Path<String>) -> Page {
    let mut chain = status_of(&state).await;
    let (entry, tx) = match fetch_tx(&state, &mut chain, &raw).await {
        Ok(found) => found,
        Err(page) => return page,
    };
    let entry = &entry;

    let f = TxFacts::from_entry(entry, &tx);
    let rings = state.chain.resolve_rings(&tx).await;
    let reference = f.fcmp_pp.and_then(|x| x.reference_block);
    let (anonymity_set, root_block) = tree_facts(&state, &tx, entry, reference).await;

    // A transaction in the pool is in no block, so the time it carries is the
    // time it arrived: `block_timestamp` is 0 there and renders as 1970. The
    // JSON API draws the same distinction in `Placement`.
    let when = if entry.in_pool {
        entry.received_timestamp
    } else {
        entry.block_timestamp
    };

    // Ring ages are measured against the block that spent them, or the tip
    // for a transaction still in the pool.
    let spent_at = if entry.in_pool {
        chain.as_ref().map_or(0, |c| c.height)
    } else {
        entry.block_height
    };

    let oldest = axis_span(
        rings.iter().flat_map(|r| &r.ring).map(|m| m.block_height),
        spent_at,
    );

    let inputs: Vec<InputView> = rings
        .iter()
        .map(|r| {
            let ring: Vec<RingView> = r
                .ring
                .iter()
                .map(|m| RingView {
                    height: m.block_height,
                    public_key: m.public_key.to_hex(),
                    tx_hash: m.tx_hash.to_hex(),
                })
                .collect();
            InputView {
                key_image: r.key_image.to_hex(),
                amount: visible_amount(r.amount),
                unavailable: r.ring_unavailable,
                ages: age_strip(&ring, spent_at, oldest),
                ring,
            }
        })
        .collect();

    let mut has_view_tags = false;
    let unified_ids = entry.unified_ids_per_output(tx.vout.len());
    // A pool transaction's outputs have no place in the tree yet.
    let has_unified_ids = unified_ids.is_some() && !entry.in_pool;
    let outputs = tx
        .vout
        .iter()
        .enumerate()
        .map(|(i, o)| {
            // The key and the tag through the target's own accessors, the same
            // ones the API uses, so a new output type is taught in one place.
            let view_tag = o.target.view_tag().unwrap_or_default().to_owned();
            has_view_tags |= !view_tag.is_empty();
            let anchor = o
                .target
                .encrypted_janus_anchor()
                .unwrap_or_default()
                .to_owned();
            OutputView {
                public_key: o.target.public_key().unwrap_or_default().to_owned(),
                amount: visible_amount(o.amount),
                view_tag,
                anchor,
                unified_id: unified_ids.and_then(|ids| ids.get(i)).copied(),
            }
        })
        .collect();

    let parsed = &f.extra;
    let mut extra_fields = Vec::new();
    // Carrot keeps the tags but changes what they hold: the key under 0x01
    // (and each one under 0x04) is the sender's ephemeral X25519 key, not an
    // Ed25519 transaction key. Same 32 bytes, different curve, so the label
    // says which.
    let (pub_key_name, additional_name) = if f.carrot {
        ("Ephemeral public key (X25519)", "Additional ephemeral key")
    } else {
        ("Transaction public key", "Additional public key")
    };
    if let Some(k) = parsed.tx_pub_key_explorer_compat() {
        extra_fields.push(ExtraField {
            name: pub_key_name.to_owned(),
            value: k.to_hex(),
        });
    }
    for (i, k) in parsed.additional_pub_keys().iter().enumerate() {
        extra_fields.push(ExtraField {
            name: format!("{additional_name} {}", i + 1),
            value: k.to_hex(),
        });
    }
    if let Some((depth, root)) = parsed.merge_mining_tag() {
        extra_fields.push(ExtraField {
            name: format!("Merge mining tag (depth {depth})"),
            value: root.to_hex(),
        });
    }

    render(
        StatusCode::OK,
        &TxPage {
            version: VERSION,
            query: None,
            chain,
            hash: entry.tx_hash.to_lowercase(),
            coinbase: f.coinbase,
            p2pool: is_p2pool(
                f.coinbase,
                tx.vout.len(),
                f.extra.merge_mining_tag().is_some(),
            ),
            in_pool: entry.in_pool,
            pruned: entry.prunable_missing(&tx),
            block_height: entry.block_height,
            confirmations: entry.confirmations,
            timestamp: when,
            timestamp_utc: timestamp_utc(when),
            // The clock, not an extrapolation from the confirmation count: at
            // a flat 120 seconds a block this reported a block mined seconds
            // ago as two minutes old, and disagreed with the block page beside
            // it, which has always used the clock.
            age: age(now(), when),
            fee: xmr(f.fee),
            size: f.size,
            version_no: f.version,
            rct_type: f.rct_type,
            ring_size: f.ring_size,
            fcmp_pp: f.fcmp_pp.is_some(),
            reference_block: f.fcmp_pp.and_then(|x| x.reference_block),
            n_tree_layers: f.fcmp_pp.and_then(|x| x.n_tree_layers),
            tree: anonymity_set
                .and_then(|n| tree_picture(n, root_block.as_ref().map(|(_, root)| root.as_str()))),
            root_block,
            anonymity_set: anonymity_set.map(grouped),
            proof_size: f.fcmp_pp.and_then(|x| x.proof_size).map(grouped),
            carrot: f.carrot,
            unlock_time: f.unlock_time,
            payment_id: f.payment_id_hex(),
            payment_id8: f.payment_id8_hex(),
            inputs,
            outputs,
            has_view_tags,
            has_unified_ids,
            extra: f.extra_hex(),
            extra_fields,
            extra_undecoded: !parsed.is_complete(),
        },
    )
}

/// The walkthrough's steps, in order.
const FCMP_STEPS: [&str; 7] = [
    "The tree",
    "Disguise the output",
    "Prove the right to spend",
    "Prove it is in the tree",
    "Tie it to the chain",
    "Balance the amounts",
    "What anyone can tell",
];

/// A walk through an FCMP++ transaction's proof, one step at a time.
///
/// Steps switch by anchor and `:target`, as the Content-Security-Policy
/// allows no script.
#[derive(Template)]
#[template(path = "fcmp.html")]
struct FcmpPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    hash: String,
    steps: Vec<StepLink>,
    in_pool: bool,
    /// Bytes, grouped. `None` where this node no longer holds the proof.
    proof_size: Option<String>,
    anonymity_set: Option<String>,
    reference_block: Option<u64>,
    n_tree_layers: Option<u8>,
    /// The block carrying the root the proof was checked against, and that
    /// root.
    root_block: Option<(u64, String)>,
    inputs: Vec<FcmpInputView>,
    /// The membership proof's bytes, grouped, and its share of the proof in
    /// whole percent.
    membership: Option<(String, u64)>,
    tuple_len: usize,
    sal_len: usize,
    root_pok_len: usize,
    fee: String,
    outputs: usize,
    range_proofs: usize,
    /// The two circuit proofs' rows, shown only where they account for the
    /// membership proof's actual length.
    shape: Option<ShapeView>,
    /// The curve the root is on: Selene for an odd layer count.
    root_curve: Option<&'static str>,
    /// The proof drawn to scale, one segment per part.
    map: Vec<ProofSegment>,
    map_labels: Option<map_labels::MapLabels>,
    tree: Option<[tree_field::TreeField; 2]>,
    /// How the tree's size gives each layer's, from the leaves up. Empty
    /// where the size is not known.
    layer_sums: Vec<LayerSum>,
}

/// One layer of a curve tree as a division: `children` members, `width` to
/// a parent, make `nodes` nodes on `curve`.
struct LayerSum {
    children: String,
    width: u64,
    nodes: String,
    curve: &'static str,
}

/// The layers of a tree of `leaves` outputs as `LayerSum`s.
fn layer_sums(leaves: u64) -> Vec<LayerSum> {
    use explorer_core::curve_tree::{Curve, group_width};

    let mut children = leaves;
    monerod_rpc::types::tree_layers(leaves)
        .into_iter()
        .enumerate()
        .map(|(below, nodes)| {
            let sum = LayerSum {
                children: grouped(children),
                width: group_width(below),
                nodes: grouped(nodes),
                curve: Curve::of_layer(below + 1).name(),
            };
            children = nodes;
            sum
        })
        .collect()
}

struct ShapeView {
    selene_rows: usize,
    selene_rounds: u32,
    helios_rows: usize,
    helios_rounds: u32,
}

/// One part of the proof along the walkthrough's bar.
struct ProofSegment {
    /// Left and width in thousandths of the bar.
    x: u32,
    width: u32,
    class: &'static str,
    /// The step that explains this part.
    step: usize,
    bytes: usize,
    label: String,
}

impl ProofSegment {
    fn x_pct(&self) -> String {
        format!("{}%", f64::from(self.x) / 10.0)
    }

    fn width_pct(&self) -> String {
        format!("{}%", f64::from(self.width) / 10.0)
    }
}

/// The bar's coordinate space, and the narrowest a part is drawn so it can
/// still be seen and clicked.
const MAP_WIDTH: u32 = 1000;
const MAP_MIN_SEGMENT: f64 = 14.0;

/// Lays the proof's parts along the bar, each as wide as its share of the
/// bytes but never narrower than [`MAP_MIN_SEGMENT`].
fn proof_map(inputs: usize, membership_len: usize) -> Vec<ProofSegment> {
    use monerod_rpc::types::{FCMP_PP_ROOT_POK_LEN, FCMP_PP_SAL_LEN, FCMP_PP_TUPLE_LEN};

    let mut parts: Vec<(usize, &'static str, usize, String)> = (1..=inputs)
        .flat_map(|i| {
            [
                (
                    FCMP_PP_TUPLE_LEN,
                    "tuple",
                    2,
                    format!("Input {i}'s disguised output, {FCMP_PP_TUPLE_LEN} bytes"),
                ),
                (
                    FCMP_PP_SAL_LEN,
                    "sal",
                    3,
                    format!("Input {i}'s signature, {FCMP_PP_SAL_LEN} bytes"),
                ),
            ]
        })
        .collect();
    let body = membership_len.saturating_sub(FCMP_PP_ROOT_POK_LEN);
    parts.push((
        body,
        "member",
        4,
        format!("The membership proof, {} bytes", grouped(body as u64)),
    ));
    parts.push((
        FCMP_PP_ROOT_POK_LEN,
        "anchor",
        5,
        format!("The root anchor, {FCMP_PP_ROOT_POK_LEN} bytes"),
    ));

    #[allow(
        clippy::cast_precision_loss,
        reason = "a chart coordinate, not chain arithmetic"
    )]
    let total = parts.iter().map(|p| p.0).sum::<usize>().max(1) as f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "a chart coordinate, not chain arithmetic"
    )]
    let drawn: Vec<f64> = parts
        .iter()
        .map(|p| (p.0 as f64 / total * f64::from(MAP_WIDTH)).max(MAP_MIN_SEGMENT))
        .collect();
    let scale = f64::from(MAP_WIDTH) / drawn.iter().sum::<f64>();

    let mut at = 0.0;
    parts
        .into_iter()
        .zip(drawn)
        .map(|((bytes, class, step, label), w)| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "within the bar's width by construction"
            )]
            let (x, end) = (
                (at * scale).round() as u32,
                ((at + w) * scale).round() as u32,
            );
            at += w;
            // A pixel of space either side, so neighbours read as separate.
            ProofSegment {
                x: x + 1,
                width: (end - x).saturating_sub(2),
                class,
                step,
                bytes,
                label,
            }
        })
        .collect()
}

struct StepLink {
    n: usize,
    title: &'static str,
}

struct FcmpInputView {
    key_image: String,
    pseudo_out: Option<String>,
    /// `None` where the proof is not held.
    disguise: Option<Disguise>,
}

/// An input's re-randomized output: O~, I~ and R.
struct Disguise {
    o_tilde: String,
    i_tilde: String,
    r: String,
}

pub async fn fcmp_proof(State(state): Shared, Path(raw): Path<String>) -> Page {
    let mut chain = status_of(&state).await;
    let (entry, tx) = match fetch_tx(&state, &mut chain, &raw).await {
        Ok(found) => found,
        Err(page) => return page,
    };
    if !tx.is_fcmp_pp() {
        return error_page(
            chain,
            StatusCode::NOT_FOUND,
            "Not an FCMP++ transaction",
            &format!(
                "Transaction {} has no FCMP++ proof to walk through.",
                entry.tx_hash.to_lowercase()
            ),
        );
    }
    let (anonymity_set, root_block) = tree_facts(&state, &tx, &entry, tx.reference_block()).await;
    render(
        StatusCode::OK,
        &fcmp_page(chain, &entry, &tx, anonymity_set, root_block),
    )
}

fn fcmp_page(
    chain: Option<ChainStatus>,
    entry: &TxEntry,
    tx: &TxJson,
    anonymity_set: Option<u64>,
    root_block: Option<(u64, String)>,
) -> FcmpPage {
    use monerod_rpc::types::{FCMP_PP_ROOT_POK_LEN, FCMP_PP_SAL_LEN, FCMP_PP_TUPLE_LEN};

    let f = TxFacts::from_entry(entry, tx);
    let prunable = tx.rctsig_prunable.as_ref();
    let proof_len = prunable.and_then(|p| p.fcmp_pp_len());
    let parts = prunable.and_then(|p| p.fcmp_pp_parts(tx.vin.len()));
    let pseudo_outs = tx.pseudo_outs();
    let disguises = parts
        .as_ref()
        .map(|p| p.inputs.as_slice())
        .unwrap_or_default();

    let inputs = tx
        .vin
        .iter()
        .filter_map(|v| v.as_key())
        .enumerate()
        .map(|(i, k)| FcmpInputView {
            key_image: k.k_image.clone(),
            pseudo_out: pseudo_outs.get(i).cloned(),
            disguise: disguises.get(i).map(|d| Disguise {
                o_tilde: d.o_tilde.to_owned(),
                i_tilde: d.i_tilde.to_owned(),
                r: d.r.to_owned(),
            }),
        })
        .collect();

    let layers = tx.n_tree_layers();
    let shape = parts
        .as_ref()
        .zip(layers.and_then(|l| explorer_core::fcmp::MembershipShape::of(tx.vin.len(), l)))
        .filter(|(p, s)| p.membership_len == s.len)
        .map(|(_, s)| ShapeView {
            selene_rows: s.selene_rows,
            selene_rounds: s.selene_rows.trailing_zeros(),
            helios_rows: s.helios_rows,
            helios_rounds: s.helios_rows.trailing_zeros(),
        });
    let map = parts
        .as_ref()
        .map(|p| proof_map(p.inputs.len(), p.membership_len))
        .unwrap_or_default();
    let tree = anonymity_set.and_then(|n| {
        tree_field::tree_field(
            n,
            root_block.as_ref().map(|(_, root)| root.as_str()),
            tx.reference_block(),
            root_block.as_ref().map(|(b, _)| *b),
        )
    });

    // Without the root anchor, which step 5 counts, as the bar does.
    let membership = parts.as_ref().zip(proof_len).map(|(p, total)| {
        let body = p.membership_len.saturating_sub(FCMP_PP_ROOT_POK_LEN);
        (grouped(body as u64), (body * 100 / total.max(1)) as u64)
    });

    FcmpPage {
        version: VERSION,
        query: None,
        chain,
        hash: entry.tx_hash.to_lowercase(),
        steps: FCMP_STEPS
            .iter()
            .enumerate()
            .map(|(i, &title)| StepLink { n: i + 1, title })
            .collect(),
        in_pool: entry.in_pool,
        proof_size: proof_len.map(|n| grouped(n as u64)),
        anonymity_set: anonymity_set.map(grouped),
        reference_block: tx.reference_block(),
        n_tree_layers: tx.n_tree_layers(),
        root_block,
        inputs,
        membership,
        tuple_len: FCMP_PP_TUPLE_LEN,
        sal_len: FCMP_PP_SAL_LEN,
        root_pok_len: FCMP_PP_ROOT_POK_LEN,
        fee: xmr(f.fee),
        outputs: tx.vout.len(),
        range_proofs: prunable.and_then(|p| p.bpp.as_ref()).map_or(0, Vec::len),
        shape,
        root_curve: layers
            .map(|l| explorer_core::curve_tree::Curve::of_layer(usize::from(l)).name()),
        map_labels: map_labels::map_labels(&map),
        map,
        tree,
        layer_sums: anonymity_set.map(layer_sums).unwrap_or_default(),
    }
}

#[derive(serde::Deserialize)]
pub struct SortQuery {
    sort: Option<String>,
    dir: Option<String>,
}

/// The sort a request asked for, from its query string.
///
/// An unrecognised `sort` or `dir` -- a stale link, a typo -- is treated as
/// unsorted rather than failing the page. A `dir` with no `sort` names
/// nothing to reverse and is ignored.
fn active_sort(sort: Option<&str>, dir: Option<&str>) -> Option<(SortKey, SortDir)> {
    let key = SortKey::parse(sort?)?;
    Some((key, dir.and_then(SortDir::parse).unwrap_or(SortDir::Desc)))
}

pub async fn mempool(State(state): Shared, Query(q): Query<SortQuery>) -> Page {
    let chain = status_of(&state).await;
    let active = active_sort(q.sort.as_deref(), q.dir.as_deref());

    let pool = match state.chain.mempool().await {
        Ok(p) => p,
        Err(ChainError::NeedsUnrestricted(what)) => {
            return error_page(
                chain,
                StatusCode::NOT_IMPLEMENTED,
                "The mempool is unavailable",
                &format!(
                    "Showing {what} needs an unrestricted daemon. This one runs with \
                     --restricted-rpc, which blocks /get_transaction_pool."
                ),
            );
        }
        Err(e) => return chain_error_page(chain, &e, "Could not load the mempool"),
    };

    // Measured against the clock rather than against the newest entry in the
    // pool: the latter always shows the newest transaction as having waited no
    // time at all, even on a pool nothing has arrived in for an hour.
    let asked_at = now();
    let mut txs = pool_rows(&state.rows, &pool.transactions, active, asked_at);
    if txs.iter().any(|r| r.reference.is_some())
        && let (Some(probe), Ok(info)) = (state.chain.tip_probe().await, state.chain.info().await)
    {
        let heights = txs.iter().filter_map(|r| r.reference);
        let sizes = state.chain.tree_sizes(heights, probe, info.height).await;
        for r in &mut txs {
            r.tree = tree_of(r.reference, &sizes);
        }
    }

    render(
        StatusCode::OK,
        &MempoolPage {
            version: VERSION,
            query: None,
            chain,
            waiting_sort: column_sort("/mempool", SortKey::Waiting, active),
            fee_sort: column_sort("/mempool", SortKey::Fee, active),
            size_sort: column_sort("/mempool", SortKey::Size, active),
            total: pool.transactions.len(),
            cut: pool.transactions.len() > MEMPOOL_ROWS,
            txs,
        },
    )
}

pub async fn alt_blocks(State(state): Shared) -> Page {
    let chain = status_of(&state).await;

    let alt = match state.chain.alt_chains().await {
        Ok(a) => a,
        Err(ChainError::NeedsUnrestricted(what)) => {
            return error_page(
                chain,
                StatusCode::NOT_IMPLEMENTED,
                "Alternative chains are unavailable",
                &format!(
                    "Showing {what} needs an unrestricted daemon. This one runs with \
                     --restricted-rpc, which blocks get_alternate_chains."
                ),
            );
        }
        Err(e) => return chain_error_page(chain, &e, "Could not load alternative chains"),
    };

    let chains = alt.chains.iter().map(alt_chain_row).collect();

    render(
        StatusCode::OK,
        &AltBlocksPage {
            version: VERSION,
            query: None,
            chain,
            chains,
        },
    )
}

#[derive(serde::Deserialize)]
pub struct SearchQuery {
    q: Option<String>,
}

/// Search dispatches on shape and then *redirects*, so the address bar ends up
/// on the canonical page rather than on a query string.
pub async fn search(State(state): Shared, Query(q): Query<SearchQuery>) -> Response {
    let raw = q.q.unwrap_or_default();
    let cleaned = raw.trim();

    if cleaned.is_empty() {
        return axum::response::Redirect::to("/").into_response();
    }

    match BlockId::parse(cleaned) {
        Ok(BlockId::Height(_)) => {
            return axum::response::Redirect::to(&format!("/block/{cleaned}")).into_response();
        }
        Ok(BlockId::Hash(hash)) => {
            // A block hash and a transaction hash are the same shape, so the
            // only way to tell them apart is to look one up. Only a not-found
            // answer means it is not a block: a daemon that failed any other
            // way sends the reader to the block page, which reports the
            // failure, rather than to a transaction page that says "not found".
            let target = match state.chain.block(BlockId::Hash(hash)).await {
                Err(e) if e.is_not_found() => "tx",
                _ => "block",
            };
            return axum::response::Redirect::to(&format!("/{target}/{cleaned}")).into_response();
        }
        Err(_) => {}
    }

    let chain = status_of(&state).await;
    error_page_for(
        chain,
        StatusCode::NOT_FOUND,
        "Nothing found",
        "Enter a block height, a block hash, or a transaction hash. Monero has \
         no address index, so addresses cannot be searched.",
        Some(raw),
    )
    .into_response()
}

/// The stylesheet, compiled into the binary.
///
/// Embedded rather than read from disk so the binary is self-contained: there
/// is no asset directory to deploy, and no path for a misconfigured server to
/// expose.
pub async fn stylesheet() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        sheet().body.as_str(),
    )
        .into_response()
}

/// Render a list of accepted lengths as English: "5 characters",
/// "2 or 3 characters", "2, 3 or 4 characters".
fn describe_lengths(lengths: &[usize]) -> String {
    let names: Vec<String> = lengths.iter().map(ToString::to_string).collect();
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => format!("{last} characters"),
        Some((last, rest)) => format!("{} or {last} characters", rest.join(", ")),
    }
}

/// The example responses shown on the documentation page.
///
/// Recorded from a synced explorer rather than invented, so every hash,
/// amount and height a reader sees is one the chain really holds. Refresh
/// them with `tools/capture-api-examples.py` when a response shape changes.
///
/// Two are shortened by that tool rather than reproduced whole, because the
/// endpoints answer with as much as the chain has: `/api/transactions/recent`
/// carries the entire pool, and the recording keeps one transaction from it
/// and one from the block, with the pool count corrected to match.
mod example {
    macro_rules! recorded {
        ($name:ident, $file:literal) => {
            pub const $name: &str =
                include_str!(concat!("../../../fixtures/api-examples/", $file, ".json"));
        };
    }

    recorded!(VERSION, "version");
    recorded!(NETWORK_INFO, "networkinfo");
    recorded!(BLOCK, "block");
    recorded!(BLOCKS_RANGE, "blocks_range");
    recorded!(TRANSACTION, "transaction");
    recorded!(TRANSACTION_PRIVATE, "transaction_private");
    recorded!(TRANSACTIONS, "transactions");
    recorded!(MEMPOOL, "mempool");
    recorded!(TRANSACTIONS_RECENT, "transactions_recent");
    recorded!(SEARCH_BLOCK, "search_block");
    recorded!(SEARCH_TX, "search_tx");
    recorded!(FEE_ESTIMATE, "feeestimate");
    recorded!(HEALTH, "health");

    /// Every recording, for the tests that read all of them.
    #[cfg(test)]
    pub const ALL: [(&str, &str); 13] = [
        ("version", VERSION),
        ("networkinfo", NETWORK_INFO),
        ("block", BLOCK),
        ("blocks_range", BLOCKS_RANGE),
        ("transaction", TRANSACTION),
        ("transaction_private", TRANSACTION_PRIVATE),
        ("transactions", TRANSACTIONS),
        ("mempool", MEMPOOL),
        ("transactions_recent", TRANSACTIONS_RECENT),
        ("search_block", SEARCH_BLOCK),
        ("search_tx", SEARCH_TX),
        ("feeestimate", FEE_ESTIMATE),
        ("health", HEALTH),
    ];
}

/// The API documentation, which is what the `API` link in the header points
/// at: a reader looking for documentation gets a page, not raw JSON.
pub async fn api_docs(State(state): Shared) -> Page {
    let chain = status_of(&state).await;

    // Already fetched by `status_of` a moment ago, so this is a cache hit
    // rather than a second round trip.
    let info = state.chain.info().await.ok();
    let height = info.as_ref().map_or(0, |i| i.height);
    let sample_height = height.saturating_sub(1);

    let lengths = info
        .as_ref()
        .map(|i| crate::api::handlers::acceptable_postfix_lengths(i, state.limits))
        .unwrap_or_default();

    render(
        StatusCode::OK,
        &ApiPage {
            version: VERSION,
            query: None,
            chain,
            sample_height,
            sample_range_start: sample_height.saturating_sub(9),
            postfix_lengths: describe_lengths(&lengths),
            max_transactions_limit: crate::api::handlers::MAX_TRANSACTIONS_LIMIT,
            max_mempool_limit: crate::api::handlers::MAX_MEMPOOL_LIMIT,
            max_block_range: state.limits.block_range,
            min_postfix_len: state.limits.postfix_min,
            max_postfix_len: state.limits.postfix_max,
            min_anonymity_set: crate::api::handlers::MIN_ANONYMITY_SET,
            max_private_tx_matches: crate::api::handlers::MAX_PRIVATE_TX_MATCHES,
            recent_blocks: state.limits.recent_blocks,
            example_version: example::VERSION,
            example_network_info: example::NETWORK_INFO,
            example_block: example::BLOCK,
            example_blocks_range: example::BLOCKS_RANGE,
            example_transaction: example::TRANSACTION,
            example_transaction_private: example::TRANSACTION_PRIVATE,
            example_transactions: example::TRANSACTIONS,
            example_mempool: example::MEMPOOL,
            example_transactions_recent: example::TRANSACTIONS_RECENT,
            example_search_block: example::SEARCH_BLOCK,
            example_search_tx: example::SEARCH_TX,
            example_feeestimate: example::FEE_ESTIMATE,
            example_health: example::HEALTH,
        },
    )
}

pub async fn not_found(State(state): Shared) -> Page {
    let chain = status_of(&state).await;
    error_page(
        chain,
        StatusCode::NOT_FOUND,
        "Page not found",
        "There is no such page.",
    )
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

    use std::collections::BTreeSet;

    use super::*;

    const FUNNEL_SPAN: u32 = STRIP_WIDTH - FUNNEL_LEFT - FUNNEL_RIGHT;
    const FUNNEL_CENTRE: u32 = FUNNEL_LEFT + FUNNEL_SPAN / 2;

    fn status() -> Option<ChainStatus> {
        Some(ChainStatus {
            height: 3_185_431,
            nettype: "mainnet".to_owned(),
            difficulty: "691253322598".to_owned(),
            pool: 7,
            target: 0,
            syncing: false,
        })
    }

    /// The defence the whole HTML layer rests on. Escaping is the default,
    /// and opting out requires `|safe`.
    #[test]
    fn a_hostile_search_term_is_escaped_in_the_page() {
        let page = ErrorPage {
            version: VERSION,
            query: Some(r#"<script>alert(1)</script>"#.to_owned()),
            chain: status(),
            title: "Nothing found".to_owned(),
            detail: r#"also "quoted" & <dangerous>"#.to_owned(),
        };
        let html = page.render().expect("renders");

        assert!(
            !html.contains("<script>"),
            "a raw script tag reached the page"
        );
        assert!(!html.contains("alert(1)</script>"));
        assert!(html.contains("&#60;script&#62;"), "escaped form is present");
        // The detail text is escaped too, including the quote that would
        // otherwise break out of an attribute.
        assert!(!html.contains(r#""quoted""#));
    }

    /// No script element, no inline handler, no external origin: the page must
    /// satisfy `default-src 'none'; style-src 'self'` on its own, not merely be
    /// protected by the header.
    #[test]
    fn rendered_pages_contain_no_script_and_no_external_reference() {
        let page = ErrorPage {
            version: VERSION,
            query: None,
            chain: status(),
            title: "Page not found".to_owned(),
            detail: "There is no such page.".to_owned(),
        };
        let html = page.render().expect("renders").to_lowercase();

        assert!(!html.contains("<script"));
        assert!(!html.contains("javascript:"));
        assert!(!html.contains(" onclick"));
        assert!(!html.contains(" onload"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("<img"));
        // The only asset is our own stylesheet, served from this binary.
        assert_eq!(html.matches("/static/style.css").count(), 1);
    }

    #[test]
    fn the_chain_strip_renders_its_values() {
        let page = ErrorPage {
            version: VERSION,
            query: None,
            chain: status(),
            title: "t".to_owned(),
            detail: "d".to_owned(),
        };
        let html = page.render().expect("renders");
        assert!(html.contains("3185431"));
        assert!(html.contains("mainnet"));
        assert!(html.contains("691253322598"));
    }

    fn api_page() -> ApiPage {
        api_page_with(crate::config::Limits::default())
    }

    fn api_page_with(limits: crate::config::Limits) -> ApiPage {
        use crate::api::handlers as h;
        ApiPage {
            version: VERSION,
            query: None,
            chain: status(),
            sample_height: 3_185_430,
            sample_range_start: 3_185_421,
            postfix_lengths: describe_lengths(&[5]),
            max_transactions_limit: h::MAX_TRANSACTIONS_LIMIT,
            max_mempool_limit: h::MAX_MEMPOOL_LIMIT,
            max_block_range: limits.block_range,
            min_postfix_len: limits.postfix_min,
            max_postfix_len: limits.postfix_max,
            min_anonymity_set: h::MIN_ANONYMITY_SET,
            max_private_tx_matches: h::MAX_PRIVATE_TX_MATCHES,
            recent_blocks: limits.recent_blocks,
            example_version: example::VERSION,
            example_network_info: example::NETWORK_INFO,
            example_block: example::BLOCK,
            example_blocks_range: example::BLOCKS_RANGE,
            example_transaction: example::TRANSACTION,
            example_transaction_private: example::TRANSACTION_PRIVATE,
            example_transactions: example::TRANSACTIONS,
            example_mempool: example::MEMPOOL,
            example_transactions_recent: example::TRANSACTIONS_RECENT,
            example_search_block: example::SEARCH_BLOCK,
            example_search_tx: example::SEARCH_TX,
            example_feeestimate: example::FEE_ESTIMATE,
            example_health: example::HEALTH,
        }
    }

    /// Every `/api/*` route the router registers must be documented.
    ///
    /// Read out of `main.rs`'s own source, so adding a route and forgetting to
    /// write it up fails the build rather than shipping a documentation page
    /// that quietly omits an endpoint. Compared on the part of the pattern
    /// before its first `{placeholder}`, because the page spells arguments
    /// `<hash>` where axum spells them `{hash}`.
    #[test]
    fn every_api_route_appears_in_the_documentation() {
        let router_source = include_str!("main.rs");
        // The route table only. The tests below it name `/api` paths that are
        // arguments rather than routes.
        let router_source = router_source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(router_source);
        let page = api_page().render().expect("renders");

        let mut routes: Vec<&str> = Vec::new();
        for (at, _) in router_source.match_indices("\"/api") {
            let rest = router_source.get(at + 1..).unwrap_or_default();
            if let Some(end) = rest.find('"')
                && let Some(pattern) = rest.get(..end)
            {
                routes.push(pattern);
            }
        }
        routes.sort_unstable();
        routes.dedup();

        assert!(
            routes.len() >= 13,
            "only found {} routes in the router source, so this test is not \
             actually reading the route table: {routes:?}",
            routes.len()
        );

        for route in routes {
            let stem = route.split('{').next().unwrap_or(route);
            assert!(
                page.contains(stem),
                "{route} is routed but {stem} appears nowhere in the API \
                 documentation page"
            );
        }
    }

    /// Every status code the API can answer with has to be on the page. A
    /// client that reads the documentation and then meets an undocumented code
    /// treats a plain refusal as a transport failure.
    #[test]
    fn the_documented_status_codes_are_the_ones_the_api_answers_with() {
        use crate::api::envelope::ApiError;

        let page = api_page().render().expect("renders");
        let codes = [
            StatusCode::OK,
            ApiError::bad_request("x").status,
            ApiError::not_found("x").status,
            ApiError::internal("x").status,
            ApiError::daemon("x").status,
            ApiError::unsupported("x").status,
        ];
        for code in codes {
            assert!(
                page.contains(code.as_str()),
                "the page never mentions {code}"
            );
        }
    }

    /// The limits on the page are the constants the handlers enforce, not
    /// numbers typed into the template beside them. Changing a cap without
    /// touching the template fails here.
    #[test]
    fn the_documented_limits_are_the_enforced_ones() {
        use crate::api::handlers as h;
        let page = api_page().render().expect("renders");

        let limits = crate::config::Limits::default();
        for value in [
            h::MAX_TRANSACTIONS_LIMIT,
            h::MAX_MEMPOOL_LIMIT,
            limits.block_range,
            limits.recent_blocks,
        ] {
            assert!(
                page.contains(&format!("<td class=\"num\">{value}</td>")),
                "{value} is enforced but the limits table does not list it"
            );
        }

        // A band is one cell holding both of its ends.
        for (what, low, high) in [
            (
                "anonymity",
                h::MIN_ANONYMITY_SET.to_string(),
                h::MAX_PRIVATE_TX_MATCHES.to_string(),
            ),
            (
                "postfix length",
                limits.postfix_min.to_string(),
                limits.postfix_max.to_string(),
            ),
        ] {
            assert!(
                page.contains(&format!("<td class=\"num\">{low}&ndash;{high}</td>")),
                "the limits table does not state the accepted {what} band"
            );
        }
    }

    /// Every documented endpoint carries a runnable example, and the example
    /// points at the endpoint it is filed under.
    ///
    /// The second half is the part worth checking: a copied section whose
    /// `curl` line still names the endpoint above it is the likely mistake,
    /// and it reads as correct.
    #[test]
    fn every_documented_endpoint_shows_a_curl_example_for_itself() {
        let page = api_page().render().expect("renders");
        let mut checked = 0;

        for (at, _) in page.match_indices(r#"<section class="endpoint" id=""#) {
            let rest = page.get(at..).unwrap_or_default();
            let Some(body_end) = rest.find("</section>") else {
                panic!("unterminated endpoint section")
            };
            let section = rest.get(..body_end).unwrap_or_default();

            // The shared response shapes are not endpoints and take no request.
            let id_at = r#"<section class="endpoint" id=""#.len();
            let id = section
                .get(id_at..)
                .and_then(|r| r.split('"').next())
                .unwrap_or_default();
            if id.starts_with("shape-") {
                continue;
            }

            // The route as the heading states it, up to its first argument.
            let route = section
                .split_once(r#"<h3>"#)
                .and_then(|(_, r)| r.split_once("</h3>"))
                .and_then(|(h, _)| h.rsplit_once(r#"<code class="lit">"#))
                .and_then(|(_, c)| c.split_once("</code>"))
                .map(|(path, _)| path)
                .unwrap_or_default();
            let stem = route
                .split(['?'])
                .next()
                .unwrap_or_default()
                .split("&lt;")
                .next()
                .unwrap_or_default()
                .trim_end_matches('/');
            assert!(
                stem.starts_with('/'),
                "section {id} has no route in its heading, found {route:?}"
            );

            let example = section
                .split_once(r#"<pre class="blob">curl "#)
                .map(|(_, rest)| rest.split_once("</pre>").unwrap_or((rest, "")).0)
                .unwrap_or_else(|| panic!("section {id} documents no curl example"));
            assert!(
                example.contains(stem),
                "the example under {id} does not call {stem}: {example}"
            );
            checked += 1;
        }

        assert!(
            checked >= 13,
            "only {checked} endpoint sections were examined, so this test is \
             not reading the page"
        );
    }

    /// Every example response is valid JSON, and every one starts collapsed.
    ///
    /// A native `<details>` with no `open` attribute renders closed without
    /// any script, which is what "default minimized" means here.
    #[test]
    fn every_example_response_is_valid_json_and_starts_collapsed() {
        let page = api_page().render().expect("renders");
        let mut checked = 0;

        for (at, _) in page.match_indices(r#"<details class="response">"#) {
            let rest = page.get(at..).unwrap_or_default();
            let tag_end = rest.find('>').unwrap_or(0);
            assert!(
                !rest.get(..tag_end).unwrap_or_default().contains("open"),
                "an example response is expanded by default at byte {at}"
            );

            let body_end = rest.find("</details>").unwrap_or_else(|| {
                panic!("unterminated <details class=\"response\"> at byte {at}")
            });
            let block = rest.get(..body_end).unwrap_or_default();
            let json = block
                .split_once(r#"<pre class="blob">"#)
                .and_then(|(_, r)| r.split_once("</pre>"))
                .map(|(json, _)| json)
                .unwrap_or_else(|| panic!("example response at byte {at} holds no <pre>"));

            // Escaped by askama like any other interpolated value; undo that
            // before parsing, the same four entities `render()` can produce.
            let unescaped = json
                .replace("&quot;", "\"")
                .replace("&#34;", "\"")
                .replace("&#39;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");
            serde_json::from_str::<serde_json::Value>(&unescaped).unwrap_or_else(|e| {
                panic!("example response at byte {at} is not JSON: {e}\n{unescaped}")
            });
            checked += 1;
        }

        assert_eq!(
            checked, 13,
            "expected 13 example responses (one per endpoint, two for \
             /api/search), found {checked}"
        );
    }

    /// The examples are recordings, so their hashes are the chain's own.
    ///
    /// They were invented once, and a reader met
    /// `a1a1a1a1a1a1...` where a hash belonged. A repeated two-character
    /// pattern is what that mistake looks like, and no real hash carries one
    /// across all 64 characters.
    #[test]
    fn the_examples_carry_real_hashes() {
        let mut hashes = 0;
        for (name, body) in example::ALL {
            for hash in hex_runs_of_64(body) {
                hashes += 1;
                let pair = hash.get(..2).unwrap_or_default();
                assert!(
                    !hash.chars().eq(pair.chars().cycle().take(64)),
                    "{name} carries an invented hash: {hash}"
                );
            }
        }
        // A floor, not a count: it proves the loop above read the recordings.
        // The recordings are FCMP++ transactions, whose inputs name no ring
        // members, and hold 45.
        assert!(
            hashes > 30,
            "only {hashes} hashes were examined, so this test is not reading \
             the recordings"
        );
    }

    /// Every 64-character hex run in a body, which is every hash in it.
    fn hex_runs_of_64(body: &str) -> Vec<String> {
        body.split(|c: char| !c.is_ascii_hexdigit())
            .filter(|run| run.len() == 64)
            .map(ToOwned::to_owned)
            .collect()
    }

    fn ring_at(heights: &[u64]) -> Vec<RingView> {
        heights
            .iter()
            .map(|&h| RingView {
                height: h,
                public_key: "2".repeat(64),
                tx_hash: "3".repeat(64),
            })
            .collect()
    }

    /// The strip runs oldest-left, spend-right.
    #[test]
    fn the_oldest_member_anchors_the_left_edge_and_the_newest_the_spend() {
        let spent_at = 3_000_000;
        let axis = 40 * BLOCKS_PER_DAY;
        let strip = age_strip(&ring_at(&[spent_at, spent_at - axis]), spent_at, axis);

        assert_eq!(
            strip.marks.first().map(|m| m.stem),
            Some(STRIP_WIDTH - STEM_WIDTH),
            "a member as new as the spend sits at the right edge"
        );
        assert_eq!(
            strip.marks.last().map(|m| m.stem),
            Some(0),
            "and the oldest at the left"
        );
    }

    /// Older is always further left. Nothing else on the strip means anything
    /// if this does not hold.
    #[test]
    fn marks_run_in_age_order_along_the_strip() {
        let spent_at = 3_000_000;
        let heights: Vec<u64> = [0, BLOCKS_PER_HOUR, BLOCKS_PER_DAY, 30 * BLOCKS_PER_DAY]
            .iter()
            .map(|age| spent_at - age)
            .collect();
        let strip = age_strip(&ring_at(&heights), spent_at, 30 * BLOCKS_PER_DAY);

        let mut checked = 0;
        for pair in strip.marks.windows(2) {
            if let [newer, older] = pair {
                assert!(
                    older.stem < newer.stem,
                    "an older member drawn at {} is not left of a newer one at {}",
                    older.stem,
                    newer.stem
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 3, "every neighbouring pair was compared");
    }

    /// The point of the log axis: a real ring clusters in the last day while
    /// one member may be a year old. A linear axis would put those two recent
    /// members less than a unit apart.
    #[test]
    fn a_recent_cluster_stays_legible_beside_a_year_old_member() {
        let spent_at = 3_000_000;
        let strip = age_strip(
            &ring_at(&[
                spent_at - BLOCKS_PER_HOUR,
                spent_at - 6 * BLOCKS_PER_HOUR,
                spent_at - 365 * BLOCKS_PER_DAY,
            ]),
            spent_at,
            365 * BLOCKS_PER_DAY,
        );

        let (one_hour, six_hours) = (
            strip.marks.first().map_or(0, |m| m.stem),
            strip.marks.get(1).map_or(0, |m| m.stem),
        );
        assert!(
            one_hour.abs_diff(six_hours) > HALO_WIDTH,
            "one hour and six hours are {} apart, so their halos merge into one",
            one_hour.abs_diff(six_hours)
        );
    }

    /// The halo stands for its member's age, so it has to sit around that age
    /// rather than beside it: offset by half a halo, every cluster on the
    /// strip is drawn newer than the ring it came from.
    #[test]
    fn a_halo_is_centred_on_the_member_it_belongs_to() {
        let spent_at = 3_000_000;
        let strip = age_strip(
            &ring_at(&[spent_at - BLOCKS_PER_DAY, spent_at - 365 * BLOCKS_PER_DAY]),
            spent_at,
            365 * BLOCKS_PER_DAY,
        );

        let mark = strip.marks.first().expect("the day-old member");
        assert_eq!(mark.halo + HALO_WIDTH / 2, mark.stem + STEM_WIDTH / 2);
    }

    /// A strip two days wide must not carry a "1y" label with nothing under it.
    #[test]
    fn the_axis_is_labelled_only_across_the_range_it_covers() {
        let spent_at = 3_000_000;
        let strip = age_strip(
            &ring_at(&[spent_at, spent_at - 2 * BLOCKS_PER_DAY]),
            spent_at,
            2 * BLOCKS_PER_DAY,
        );

        let labels: Vec<&str> = strip.ticks.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels, ["1h", "6h", "1d"]);
        assert!(
            strip.ticks.iter().all(|t| t.x <= STRIP_WIDTH),
            "a tick fell outside the strip it labels"
        );
    }

    #[test]
    fn the_axis_reaches_the_oldest_member_of_any_input() {
        let spent_at = 3_000_000;
        assert_eq!(
            axis_span(
                [spent_at - 10, spent_at - 4000, spent_at - 700].into_iter(),
                spent_at
            ),
            4000
        );
        assert_eq!(
            axis_span([spent_at + 50].into_iter(), spent_at),
            0,
            "a member newer than the spend does not stretch the axis backwards"
        );
        assert_eq!(axis_span([].into_iter(), spent_at), 0);
    }

    /// Every input of a transaction is drawn against the same axis, so the
    /// same cluster sits in the same place on each. An input whose ring is
    /// younger than the widest one therefore stops short of the left edge.
    #[test]
    fn an_input_is_drawn_against_the_transactions_axis_not_its_own() {
        let spent_at = 3_000_000;
        let ring = ring_at(&[spent_at, spent_at - BLOCKS_PER_DAY]);

        let alone = age_strip(&ring, spent_at, BLOCKS_PER_DAY);
        let beside_an_older_input = age_strip(&ring, spent_at, 365 * BLOCKS_PER_DAY);

        assert_eq!(alone.marks.last().map(|m| m.stem), Some(0));
        assert!(
            beside_an_older_input.marks.last().map_or(0, |m| m.stem) > HALO_WIDTH,
            "a day-old member is drawn as though it were the oldest on the page"
        );
    }

    #[test]
    fn an_age_is_labelled_in_the_unit_a_reader_would_use() {
        assert_eq!(age_label(0), "0 min");
        assert_eq!(age_label(5), "10 min");
        assert_eq!(age_label(BLOCKS_PER_HOUR), "1 h");
        assert_eq!(age_label(BLOCKS_PER_DAY), "1 d");
        assert_eq!(age_label(29 * BLOCKS_PER_DAY), "29 d");
        assert_eq!(age_label(45 * BLOCKS_PER_DAY), "1 mo");
    }

    /// A ring member mined after the spending block would underflow an
    /// unchecked subtraction. The daemon should never return one; the page
    /// must not render a wrong chart if it does.
    #[test]
    fn a_ring_member_newer_than_the_spend_does_not_wrap() {
        let strip = age_strip(&ring_at(&[3_000_100]), 3_000_000, 0);

        assert_eq!(
            strip.marks.first().map(|m| m.stem),
            Some(STRIP_WIDTH - STEM_WIDTH),
            "it reads as brand new rather than as ancient"
        );
        assert_eq!(strip.marks.len(), 1);
        assert!(strip.ticks.is_empty(), "there is no age range to label");
    }

    /// The info icon in the caption is an `<svg>` inside `.ring-ages` as well,
    /// so a rule meant for the strip has to name the strip. Written as
    /// `.ring-ages svg`, it stretched a 13px icon to the width of the page.
    #[test]
    fn the_strip_is_styled_by_its_own_class_rather_than_by_being_an_svg() {
        let html = tx_page().render().expect("renders");
        assert!(
            html.contains(r#"<svg class="strip""#),
            "the strip does not carry the class its rules are written for"
        );
        assert!(
            !STYLESHEET.contains(".ring-ages svg"),
            "a rule for every svg under .ring-ages also sizes the caption icon"
        );
    }

    /// The tag states what was inferred, not the output count.
    ///
    /// It first read "51 recipients", which the Outputs column beside it
    /// already said -- a tag that repeats an adjacent cell costs a reader
    /// attention and tells them nothing.
    #[test]
    fn the_p2pool_tag_says_more_than_the_output_count_does() {
        let html = block_page().render().expect("renders");
        assert!(
            html.contains(r#"<span class="tag coinbase">p2pool</span>"#),
            "the inference is not stated:\n{html}"
        );

        let outputs = block_tx(true).outputs;
        assert!(
            !html.contains(&format!(r#"<span class="tag coinbase">{outputs}"#)),
            "the tag opens by restating the output count"
        );

        let mut tx = tx_page();
        tx.coinbase = true;
        tx.p2pool = true;
        let tx_html = tx.render().expect("renders");
        assert!(tx_html.contains(r#"<span class="tag coinbase">p2pool</span>"#));
        assert!(
            !tx_html.contains("recipients</span>"),
            "the transaction heading still counts recipients in its tag"
        );
    }

    /// Both marks are needed, because each one alone is common on mainnet:
    /// 142 of 279 single-output coinbases in one 300-block sample carried a
    /// merge-mining tag, and the tag says nothing about who was paid.
    #[test]
    fn a_p2pool_payout_pays_many_outputs_and_commits_to_a_sidechain() {
        assert!(is_p2pool(true, 51, true), "p2pool pays its miners on chain");
        assert!(
            !is_p2pool(true, 1, true),
            "a merge-mined solo or custodial coinbase pays one address"
        );
        assert!(
            !is_p2pool(true, 51, false),
            "many outputs without a sidechain commitment is not p2pool"
        );
        assert!(
            !is_p2pool(false, 51, true),
            "an ordinary transaction with many outputs is not a payout"
        );
        assert!(!is_p2pool(false, 2, false));
    }

    /// The hints are plain markup: no script, no external reference, and they
    /// work with JavaScript off, which is the only way they can work here.
    #[test]
    fn the_transaction_page_hints_need_no_script() {
        let mut page = tx_page();
        page.payment_id8 = "1234567890abcdef".to_owned();
        let html = page.render().expect("renders");

        assert!(
            html.matches("<details class=\"hint\">").count() >= 6,
            "the explanatory hints are missing:\n{html}"
        );
        // An icon, not a bare "?" character: the glyph relied on the reader
        // guessing, and rendered at the mercy of whatever font was in use.
        assert!(
            !html.contains("<summary>?</summary>"),
            "the hint affordance is a bare question mark again"
        );
        assert_eq!(
            html.matches(r#"<svg class="icon""#).count(),
            html.matches("<details class=\"hint\">").count(),
            "every hint should carry the icon"
        );
        assert!(!html.to_lowercase().contains("<script"));
        assert!(!html.contains("onclick"));
        // The key image was an unlabelled hash next to the ring member count,
        // which is what made it read as an output key.
        assert!(html.contains("Key image"), "the key image is unlabelled");
        assert!(
            html.contains("Tx_Extra"),
            "the heading does not name the field"
        );
    }

    /// The block header's Version field is two numbers with no context; a
    /// reader has no way to tell a hard fork from a signalling bit without
    /// this.
    #[test]
    fn the_block_version_is_explained() {
        let html = block_page().render().expect("renders");

        assert_eq!(
            html.matches("<details class=\"hint\">").count(),
            1,
            "the version field carries no explanatory hint:\n{html}"
        );
        assert_eq!(
            html.matches(r#"<svg class="icon""#).count(),
            1,
            "the hint carries no icon"
        );
        assert!(
            html.contains("network upgrade"),
            "the hint does not say what a major version is"
        );
        assert!(
            html.contains("signals"),
            "the hint does not say what a minor version is"
        );
        // Forks follow no fixed schedule, and a page that dates itself is
        // worse than one that does not.
        assert!(
            !html.contains("every six months"),
            "the hint is claiming a fork schedule again"
        );
    }

    /// The text of the first hint panel that opens after `marker`.
    fn hint_after<'a>(html: &'a str, marker: &str) -> &'a str {
        let rest = &html[html.find(marker).expect("the marker is on the page")..];
        let open = rest.find("<p>").expect("the hint has a panel");
        let close = rest.find("</p>").expect("the panel closes");
        &rest[open + 3..close]
    }

    /// The Version field is two numbers side by side and the hint described
    /// only the second, which left a reader no way to tell what the first one
    /// counts.
    #[test]
    fn the_transaction_version_explains_both_of_its_numbers() {
        let html = tx_page().render().expect("renders");
        let panel = hint_after(&html, "<dt>Version</dt>");

        assert!(
            panel.contains("format"),
            "the hint does not say what the first number is:\n{panel}"
        );
        assert!(
            panel.contains("scheme"),
            "the hint does not say what the second number is:\n{panel}"
        );
        assert!(
            panel.find("format") < panel.find("scheme"),
            "the hint explains the numbers in the opposite order to the page"
        );
    }

    /// A hint opens next to the value, never inside the label.
    ///
    /// `dl.kv` sizes its label column to fit the widest `<dt>`, so a panel
    /// opened there pushed every value on the page far to the right, and a
    /// `<th>` sizes its column the same way.
    #[test]
    fn a_hint_opens_beside_a_value_and_not_inside_a_label() {
        for (name, html) in [
            ("index", index_page().render().expect("renders")),
            ("block", block_page().render().expect("renders")),
            ("tx", tx_page().render().expect("renders")),
            ("api", api_page().render().expect("renders")),
            (
                "mempool",
                mempool_page(Some((SortKey::Size, SortDir::Desc)))
                    .render()
                    .expect("renders"),
            ),
        ] {
            for label in ["th", "dt"] {
                for (at, _) in html.match_indices(&format!("<{label}")) {
                    let rest = &html[at..];
                    let end = rest.find(&format!("</{label}>")).expect("the label closes");
                    assert!(
                        !rest[..end].contains(r#"<details class="hint">"#),
                        "{name} opens a hint inside a <{label}>, which widens its column"
                    );
                }
            }
        }
    }

    /// The panel is prose wherever it opens.
    ///
    /// The ring age caption uppercases and letter-spaces its text, so the
    /// explanation nested in it came out shouting.
    #[test]
    fn a_hint_panel_reads_as_prose_wherever_it_opens() {
        let (_, rest) = STYLESHEET
            .split_once("details.hint > p {")
            .expect("the hint panel has rules");
        let rule = rest.split_once('}').expect("the rules close").0;

        for property in [
            "text-transform: none",
            "letter-spacing: normal",
            "white-space: normal",
        ] {
            assert!(
                rule.contains(property),
                "a panel inside a caption or a header inherits its {property}"
            );
        }
    }

    /// A heading counts what follows it, so it has to agree with it. Written
    /// as a fixed plural it read "1 inputs" on the transactions that carry
    /// one.
    #[test]
    fn the_input_and_output_headings_count_in_english() {
        let many = tx_page().render().expect("renders");
        assert!(many.contains("<h2>2 Inputs</h2>"), "{many}");
        assert!(many.contains("<h2>2 Outputs</h2>"), "{many}");

        let mut page = tx_page();
        page.inputs.truncate(1);
        page.outputs.truncate(1);
        let one = page.render().expect("renders");
        assert!(one.contains("<h2>1 Input</h2>"), "{one}");
        assert!(one.contains("<h2>1 Output</h2>"), "{one}");

        let mut page = tx_page();
        page.coinbase = true;
        let coinbase = page.render().expect("renders");
        assert!(
            coinbase.contains("<h2>Inputs</h2>"),
            "a coinbase counts inputs it does not have:\n{coinbase}"
        );
    }

    /// The right edge of the age axis is the moment of this transaction.
    ///
    /// It was labelled "spent", which reads as a claim about the member
    /// nearest to it rather than as the origin of the axis.
    #[test]
    fn the_age_axis_names_its_right_edge_after_this_transaction() {
        let html = tx_page().render().expect("renders");

        assert!(
            html.contains(">this tx</text>"),
            "the axis does not say what its right edge is:\n{html}"
        );
        assert!(
            !html.contains(">spent</text>"),
            "the right edge is labelled as a spent member again"
        );
        assert!(
            html.contains("this transaction at the right"),
            "the chart describes itself to a screen reader in the old terms"
        );
    }

    /// No page may carry a `style=` attribute.
    ///
    /// The policy is `style-src 'self'` with no `'unsafe-inline'`, so a
    /// browser drops inline styles silently -- the markup looks right, the
    /// rule never applies, and nothing reports it. Three had accumulated this
    /// way before this test existed.
    #[test]
    fn no_page_styles_itself_inline() {
        let mut tx = tx_page();
        tx.p2pool = true;
        tx.pruned = true;
        tx.extra_fields = vec![ExtraField {
            name: "Transaction public key".to_owned(),
            value: "a".repeat(64),
        }];
        tx.inputs.iter_mut().for_each(|i| i.unavailable = true);

        for (name, html) in [
            ("index", index_page().render().expect("renders")),
            ("block", block_page().render().expect("renders")),
            ("tx", tx.render().expect("renders")),
            ("api", api_page().render().expect("renders")),
            (
                "mempool",
                mempool_page(Some((SortKey::Size, SortDir::Desc)))
                    .render()
                    .expect("renders"),
            ),
        ] {
            assert!(
                !html.contains("style=\""),
                "{name} carries an inline style, which the policy discards:\n{html}"
            );
        }
    }

    /// Every `<table>` must scroll on its own rather than widen the page.
    ///
    /// `td`/`th` are `white-space: nowrap` so numeric columns line up, which
    /// means a table with a long text column pushes the whole page wider than
    /// a narrow screen unless it sits inside `<div class="scroll">`. The API
    /// page's status code table shipped without that wrapper once, while
    /// every other table on the site already had it.
    #[test]
    fn every_table_scrolls_on_its_own() {
        for (name, html) in [
            ("index", index_page().render().expect("renders")),
            ("block", block_page().render().expect("renders")),
            ("tx", tx_page().render().expect("renders")),
            ("api", api_page().render().expect("renders")),
            (
                "mempool",
                mempool_page(Some((SortKey::Size, SortDir::Desc)))
                    .render()
                    .expect("renders"),
            ),
        ] {
            for (at, _) in html.match_indices("<table>") {
                let before = html.get(..at).unwrap_or_default().trim_end();
                assert!(
                    before.ends_with(r#"<div class="scroll">"#),
                    "{name} has a <table> not wrapped in <div class=\"scroll\">"
                );
            }
        }
    }

    /// Every colour name the rules use has to exist in whichever palette is
    /// served with them, or that theme renders a page of `initial` colours --
    /// black text on transparent, with no error anywhere.
    #[test]
    fn every_colour_the_rules_name_is_defined_by_both_palettes() {
        let used = variables_used(STYLESHEET);
        assert!(used.len() > 5, "the rules no longer name their colours");

        // The rules define a couple of their own, which no palette repeats.
        let own = variables_declared(STYLESHEET);
        for (name, palette) in [("light", LIGHT_PALETTE), ("dark", DARK_PALETTE)] {
            let declared: BTreeSet<String> =
                variables_declared(palette).union(&own).cloned().collect();
            let missing: Vec<&String> = used.difference(&declared).collect();
            assert!(
                missing.is_empty(),
                "the {name} palette defines no {missing:?}"
            );
        }
    }

    /// A pinned theme is pinned: the reader's system setting must not reach it.
    #[test]
    fn a_pinned_theme_serves_its_own_palette_and_no_other() {
        for (name, theme, mine, theirs) in [
            ("light", Theme::Light, "#fbfbfa", "#17181a"),
            ("dark", Theme::Dark, "#17181a", "#fbfbfa"),
        ] {
            let body = rules_only(&Sheet::new(theme).body);
            assert!(body.contains(mine), "--theme {name} serves no palette");
            assert!(
                !body.contains(theirs),
                "--theme {name} serves both palettes"
            );
            assert!(
                !body.contains("prefers-color-scheme"),
                "--theme {name} still defers to the browser"
            );
            assert!(
                body.contains("box-sizing"),
                "--theme {name} serves no rules"
            );
        }
    }

    #[test]
    fn following_the_system_preference_puts_only_the_dark_palette_behind_the_query() {
        let body = rules_only(&Sheet::new(Theme::Auto).body);
        let query = body
            .find("@media (prefers-color-scheme: dark)")
            .expect("the dark palette is not conditional");
        let light = body.find("#fbfbfa").expect("no light palette");
        let dark = body.find("#17181a").expect("no dark palette");
        assert!(
            light < query,
            "the light palette is not the unconditional one"
        );
        assert!(dark > query, "the dark palette is not behind the query");

        // The wrap is hand-written, so the brace it opens has to close.
        let depth = body.chars().fold(0_i32, |d, c| match c {
            '{' => d + 1,
            '}' => d - 1,
            _ => d,
        });
        assert_eq!(depth, 0, "wrapping the palette left an unbalanced brace");
    }

    /// Restarting under a different `--theme` changes the bytes at a URL a
    /// browser holds for a day, so it has to change the URL as well.
    #[test]
    fn the_cache_key_tells_the_palettes_apart() {
        let keys = [Theme::Auto, Theme::Light, Theme::Dark].map(|t| Sheet::new(t).version);
        let distinct: BTreeSet<u64> = keys.iter().copied().collect();
        assert_eq!(distinct.len(), keys.len(), "two themes share a cache key");
    }

    /// The stylesheet with its comments removed, so that a comment quoting a
    /// rule is not mistaken for the rule.
    fn rules_only(css: &str) -> String {
        let mut out = String::new();
        let mut rest = css;
        while let Some((before, after)) = rest.split_once("/*") {
            out.push_str(before);
            rest = after.split_once("*/").map_or("", |(_, tail)| tail);
        }
        out.push_str(rest);
        out
    }

    /// Names in `var(--name)`, fallback syntax included.
    fn variables_used(css: &str) -> BTreeSet<String> {
        css.split("var(")
            .skip(1)
            .filter_map(|rest| rest.split([',', ')']).next())
            .map(str::to_owned)
            .collect()
    }

    /// Names on the left of a `--name: value` declaration.
    fn variables_declared(css: &str) -> BTreeSet<String> {
        css.lines()
            .filter_map(|line| line.trim().strip_prefix("--"))
            .filter_map(|decl| decl.split(':').next())
            .map(|name| format!("--{name}"))
            .collect()
    }

    /// The stylesheet link carries a key derived from the stylesheet itself.
    ///
    /// Without it, the day-long `max-age` means a returning browser renders
    /// new markup against an old stylesheet. That is not hypothetical: it is
    /// how the `<details>` hints first appeared, as a bare disclosure triangle
    /// beside a solid black circle, because the cached CSS predated the rules
    /// that style them.
    #[test]
    fn the_stylesheet_url_changes_when_the_stylesheet_does() {
        // The published FNV-1a 64-bit vectors. Pinned because the doc comment
        // claims this *is* FNV-1a, and the first version of it was not: the
        // multiplier was written 0x1000_0000_01b3, one digit longer than the
        // real prime, which still hashed but was not the named algorithm.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);

        // The key tracks content: two different stylesheets cannot share one.
        assert_ne!(fnv1a(b"a { color: red }"), fnv1a(b"a { color: blue }"));
        assert_ne!(fnv1a(b""), fnv1a(b" "));
        assert_eq!(fnv1a(b"same"), fnv1a(b"same"));
        assert_ne!(stylesheet_version(), 0);

        let expected = format!("/static/style.css?v={}", stylesheet_version());
        for (name, html) in [
            ("index", index_page().render().expect("renders")),
            ("block", block_page().render().expect("renders")),
            ("tx", tx_page().render().expect("renders")),
            ("api", api_page().render().expect("renders")),
        ] {
            assert!(
                html.contains(&expected),
                "{name} links the stylesheet without a cache key"
            );
        }
    }

    /// The documentation page is subject to the same rule as every other page:
    /// nothing external, no script, one stylesheet. Example requests are shown
    /// as paths rather than absolute URLs partly for this reason -- a page read
    /// over Tor should not carry a hostname somebody might click.
    #[test]
    fn the_api_page_references_nothing_external() {
        let html = api_page().render().expect("renders").to_lowercase();
        assert!(!html.contains("<script"));
        assert!(!html.contains("javascript:"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("<img"));
        assert_eq!(html.matches("/static/style.css").count(), 1);
    }

    /// The page documents the endpoint, not the daemon behind it.
    ///
    /// It carries no notice about whether the daemon has `get_txids_loose`.
    /// A daemon that lacks the call says so in the answer to the request that
    /// needed it, which is where a caller is looking.
    #[test]
    fn the_page_does_not_report_on_the_daemon_behind_it() {
        let html = api_page().render().expect("renders");
        assert!(
            !html.contains("Unavailable on this deployment"),
            "the page is probing the daemon again:\n{html}"
        );
    }

    #[test]
    fn accepted_postfix_lengths_read_as_english() {
        assert_eq!(describe_lengths(&[]), "");
        assert_eq!(describe_lengths(&[5]), "5 characters");
        assert_eq!(describe_lengths(&[2, 3]), "2 or 3 characters");
        assert_eq!(describe_lengths(&[2, 3, 4]), "2, 3 or 4 characters");
    }

    // -----------------------------------------------------------------------
    // The three pages a reader actually spends time on.
    //
    // Every compatibility test in this repository compares `/api/*` output, so
    // nothing above this line ever rendered an index, block or transaction
    // page. Three wrong figures shipped behind that gap: a column headed
    // "Fees" that held the block reward, a block page that counted its own
    // coinbase and so read one higher than the index row linking to it, and a
    // `0.0 XMR` label on every RingCT input. All three are template-and-
    // mapping bugs, invisible to a JSON differential by construction.
    // -----------------------------------------------------------------------

    fn index_page() -> IndexPage {
        IndexPage {
            version: VERSION,
            query: None,
            chain: status(),
            blocks: vec![BlockRow {
                height: 3_185_430,
                age: "00:01:12".to_owned(),
                size: 40_490,
                tx_count: 16,
                reward: "0.60160672".to_owned(),
                hash: "a".repeat(64),
            }],
            page: 0,
            older: Some(1),
        }
    }

    /// With no older page, the pager's link to one is dead.
    #[test]
    fn the_last_page_links_to_no_older_one() {
        let mut page = index_page();
        page.older = None;
        let html = page.render().expect("renders");
        assert!(html.contains("<span>Older &rarr;</span>"));
        assert!(
            index_page()
                .render()
                .expect("renders")
                .contains(r#"<a href="/page/1">Older"#)
        );
    }

    fn block_tx(coinbase: bool) -> BlockTxRow {
        BlockTxRow {
            hash: if coinbase { "c" } else { "d" }.repeat(64),
            coinbase,
            p2pool: is_p2pool(coinbase, 2, coinbase),
            inputs: if coinbase { 0 } else { 3 },
            outputs: 2,
            fee: if coinbase { "0.0" } else { "0.00071136" }.to_owned(),
            fee_atomic: if coinbase { 0 } else { 711_360_000 },
            ring: if coinbase { 0 } else { 16 },
            full_chain: false,
            reference: None,
            tree: None,
            size: 2_223,
        }
    }

    fn block_page() -> BlockPage {
        let txs = vec![block_tx(true), block_tx(false), block_tx(false)];
        BlockPage {
            version: VERSION,
            query: None,
            chain: status(),
            height: 3_185_430,
            depth: 1,
            hash: "a".repeat(64),
            prev_hash: "b".repeat(64),
            timestamp: 1_790_038_920,
            timestamp_utc: "2026-09-22 01:02:00".to_owned(),
            age: "00:01:12".to_owned(),
            size: 40_490,
            weight: 40_490,
            tx_count: table_tx_count(&txs),
            unreadable: 0,
            orphan: false,
            reward: "0.60160672".to_owned(),
            difficulty: "691253322598".to_owned(),
            nonce: 7,
            major_version: 16,
            minor_version: 16,
            tree_root: None,
            tree_layers: None,
            tree_growth: None,
            fee_sort: column_sort("/block/3185430", SortKey::Fee, None),
            size_sort: column_sort("/block/3185430", SortKey::Size, None),
            txs,
        }
    }

    fn pool_row(size: u64) -> PoolRow {
        PoolRow {
            hash: "e".repeat(64),
            age: "00:00:00".to_owned(),
            inputs: 2,
            outputs: 3,
            fee: "0.0".to_owned(),
            ring: 16,
            full_chain: false,
            reference: None,
            tree: None,
            size,
        }
    }

    fn mempool_page(active: Option<(SortKey, SortDir)>) -> MempoolPage {
        let txs = vec![pool_row(2_000), pool_row(1_000), pool_row(3_000)];
        MempoolPage {
            version: VERSION,
            query: None,
            chain: status(),
            waiting_sort: column_sort("/mempool", SortKey::Waiting, active),
            fee_sort: column_sort("/mempool", SortKey::Fee, active),
            size_sort: column_sort("/mempool", SortKey::Size, active),
            total: txs.len(),
            cut: false,
            txs,
        }
    }

    #[test]
    fn waiting_time_is_the_gap_since_the_transaction_was_received() {
        assert_eq!(waiting_secs(1_000, 400), 600);
        assert_eq!(
            waiting_secs(400, 1_000),
            600,
            "the same gap either way round"
        );
        assert_eq!(waiting_secs(500, 500), 0);
    }

    #[test]
    fn the_query_string_is_parsed_into_a_sort_that_defaults_to_descending() {
        assert_eq!(
            active_sort(Some("fee"), Some("asc")),
            Some((SortKey::Fee, SortDir::Asc))
        );
        assert_eq!(
            active_sort(Some("fee"), None),
            Some((SortKey::Fee, SortDir::Desc)),
            "no dir defaults to descending"
        );
        assert_eq!(
            active_sort(Some("fee"), Some("sideways")),
            Some((SortKey::Fee, SortDir::Desc)),
            "a bad dir falls back to descending rather than failing the page"
        );
        assert_eq!(
            active_sort(Some("hash"), Some("asc")),
            None,
            "hash has no useful order to sort by"
        );
        assert_eq!(
            active_sort(None, Some("asc")),
            None,
            "a dir with no sort names nothing to reverse"
        );
    }

    #[test]
    fn sort_key_and_dir_round_trip_through_their_query_strings() {
        for k in [SortKey::Waiting, SortKey::Fee, SortKey::Size] {
            assert_eq!(SortKey::parse(k.as_str()), Some(k));
        }
        assert_eq!(SortKey::parse("hash"), None, "hash has no useful order");
        assert_eq!(
            SortKey::parse("ring"),
            None,
            "sorting by ring was not asked for"
        );

        for d in [SortDir::Asc, SortDir::Desc] {
            assert_eq!(SortDir::parse(d.as_str()), Some(d));
        }
        assert_eq!(SortDir::parse("sideways"), None);
    }

    /// An unsorted column links to itself descending -- largest, or
    /// longest-waiting, first -- and says it can be sorted at all.
    #[test]
    fn an_unsorted_column_links_to_itself_descending_and_offers_both_directions() {
        let c = column_sort("/mempool", SortKey::Fee, None);
        assert_eq!(c.href, "/mempool?sort=fee&dir=desc");
        assert_eq!(c.state, "none", "the column does not say it sorts");

        let c = column_sort(
            "/mempool",
            SortKey::Size,
            Some((SortKey::Fee, SortDir::Asc)),
        );
        assert_eq!(
            c.href, "/mempool?sort=size&dir=desc",
            "a column sorted by something else is still unsorted itself"
        );
        assert_eq!(c.state, "none");
    }

    /// The active column links to its own reverse, so a second click flips
    /// it, and its arrow names the direction it is sorted in right now.
    #[test]
    fn the_active_column_links_to_its_reverse_and_names_its_direction() {
        let desc = column_sort(
            "/mempool",
            SortKey::Waiting,
            Some((SortKey::Waiting, SortDir::Desc)),
        );
        assert_eq!(desc.href, "/mempool?sort=waiting&dir=asc");
        assert_eq!(desc.state, "desc");

        let asc = column_sort(
            "/mempool",
            SortKey::Waiting,
            Some((SortKey::Waiting, SortDir::Asc)),
        );
        assert_eq!(asc.href, "/mempool?sort=waiting&dir=desc");
        assert_eq!(asc.state, "asc");
    }

    /// A pool transaction as the daemon lists it, received at `received`,
    /// paying `fee` and `size` bytes long.
    fn pool_tx(received: u64, fee: u64, size: u64) -> PoolTxInfo {
        let tx = serde_json::json!({
            "version": 2, "unlock_time": 0, "extra": [], "vout": [],
            "vin": [{"key": {"amount": 0, "key_offsets": vec![1; 16], "k_image": "ab".repeat(32)}}],
        });
        serde_json::from_value(serde_json::json!({
            "id_hash": format!("{fee:064x}"), "tx_json": tx.to_string(), "blob_size": size,
            "fee": fee, "max_used_block_id_hash": "", "max_used_block_height": 0,
            "kept_by_block": false, "last_failed_height": 0, "last_failed_id_hash": "",
            "receive_time": received, "relayed": true, "last_relayed_time": 0,
            "do_not_relay": false, "double_spend_seen": false, "tx_blob": "",
        }))
        .expect("a pool transaction")
    }

    /// Each row's fee, which `pool_tx` writes into its hash.
    fn fees(rows: &[PoolRow]) -> Vec<u64> {
        rows.iter()
            .map(|r| u64::from_str_radix(&r.hash, 16).expect("a fee"))
            .collect()
    }

    #[test]
    fn rows_sort_by_the_requested_column_in_the_requested_direction() {
        let pool = [
            pool_tx(990, 300, 2_000),
            pool_tx(970, 100, 1_000),
            pool_tx(980, 200, 3_000),
        ];
        let rows = |key, dir| pool_rows(&RowCache::default(), &pool, Some((key, dir)), 1_000);

        assert_eq!(fees(&rows(SortKey::Fee, SortDir::Asc)), [100, 200, 300]);
        // Waiting 30, 20 and 10 seconds.
        assert_eq!(
            fees(&rows(SortKey::Waiting, SortDir::Desc)),
            [100, 200, 300]
        );
        assert_eq!(fees(&rows(SortKey::Waiting, SortDir::Asc)), [300, 200, 100]);
        let sizes: Vec<u64> = rows(SortKey::Size, SortDir::Asc)
            .iter()
            .map(|r| r.size)
            .collect();
        assert_eq!(sizes, [1_000, 2_000, 3_000]);
        assert!(
            rows(SortKey::Fee, SortDir::Asc)
                .iter()
                .all(|r| r.ring == 16)
        );
    }

    /// A row's figures are worked out once per transaction: a second view
    /// takes them from the cache, not from parsing the transaction again;
    /// and a pool row's are kept apart from the same transaction's block row.
    #[test]
    fn a_rows_figures_are_worked_out_once() {
        let rows = RowCache::default();
        let mut tx = pool_tx(0, 7, 900);
        let first = rows.of_pool_tx(&tx).expect("figures");
        assert_eq!((first.size, first.fee, first.ring), (900, 7, 16));
        tx.tx_json = "not json".to_owned();
        assert_eq!(rows.of_pool_tx(&tx), Some(first), "not parsed again");

        let mined: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": format!("{:064x}", 7), "as_hex": "00".repeat(50),
            "as_json": r#"{"version":2,"unlock_time":0,"extra":[],"vout":[],"vin":[{"gen":{"height":5}}]}"#,
            "block_height": 5, "block_timestamp": 0, "confirmations": 1, "in_pool": false,
            "double_spend_seen": false, "output_indices": [],
        }))
        .expect("a mined entry");
        let block = rows.of_block_tx(&mined).expect("figures");
        assert!(block.coinbase && block.size == 50, "{block:?}");

        // A pruned entry is shown as it is, and not kept.
        let mut pruned: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": format!("{:064x}", 8), "as_hex": "", "pruned_as_hex": "00".repeat(40),
            "prunable_as_hex": "",
            "as_json": r#"{"version":2,"unlock_time":0,"extra":[],"vout":[],"vin":[{"key":{"amount":0,"key_offsets":[1],"k_image":"ab"}}]}"#,
            "block_height": 5, "block_timestamp": 0, "confirmations": 1, "in_pool": false,
            "double_spend_seen": false, "output_indices": [],
        }))
        .expect("a pruned entry");
        assert!(rows.of_block_tx(&pruned).is_some());
        pruned.as_json = "not json".to_owned();
        assert_eq!(rows.of_block_tx(&pruned), None, "parsed again");
    }

    /// Each pool row counts the outputs its transaction spends and makes,
    /// from the transaction itself.
    #[test]
    fn the_mempool_table_counts_each_transactions_inputs_and_outputs() {
        let mut tx = pool_tx(0, 1, 1);
        tx.tx_json = serde_json::json!({
            "version": 2, "unlock_time": 0, "extra": [],
            "vin": (0..3).map(|_| serde_json::json!({"key": {
                "amount": 0, "key_offsets": [1], "k_image": "ab".repeat(32),
            }})).collect::<Vec<_>>(),
            "vout": (0..5).map(|_| serde_json::json!({
                "amount": 0, "target": {"key": "cd".repeat(32)},
            })).collect::<Vec<_>>(),
        })
        .to_string();
        let rows = pool_rows(&RowCache::default(), &[tx], None, 0);
        assert_eq!((rows[0].inputs, rows[0].outputs), (3, 5));

        let html = mempool_page(None).render().expect("renders");
        assert!(html.contains(
            r#"<th class="num">Inputs</th>
      <th class="num">Outputs</th>"#
        ));
        assert_eq!(
            html.matches(
                r#"<td class="num">2</td>
      <td class="num">3</td>"#
            )
            .count(),
            3
        );
    }

    /// A pool longer than the page is sorted whole and cut after, so the
    /// rows shown are the top of the whole pool, and says so.
    #[test]
    fn a_long_pool_shows_the_top_of_its_sorted_whole() {
        let pool: Vec<PoolTxInfo> = (1..=MEMPOOL_ROWS as u64 + 20)
            .map(|fee| pool_tx(0, fee, 1))
            .collect();
        let rows = pool_rows(
            &RowCache::default(),
            &pool,
            Some((SortKey::Fee, SortDir::Desc)),
            0,
        );
        assert_eq!(rows.len(), MEMPOOL_ROWS);
        let fees = fees(&rows);
        assert_eq!(fees.first(), Some(&(MEMPOOL_ROWS as u64 + 20)));
        assert_eq!(fees.last(), Some(&21));
        let unsorted = pool_rows(&RowCache::default(), &pool, None, 0);
        assert_eq!(
            unsorted[0].hash,
            format!("{:064x}", 1),
            "the daemon's order"
        );

        let mut page = mempool_page(None);
        assert!(
            !page
                .render()
                .expect("renders")
                .contains("Showing the first")
        );
        page.total = pool.len();
        page.cut = true;
        let html = page.render().expect("renders");
        assert!(html.contains(&format!("{} transactions", MEMPOOL_ROWS + 20)));
        assert!(html.contains(&format!("Showing the first {MEMPOOL_ROWS}, in the")));
    }

    #[test]
    fn a_page_is_checked_with_the_server_before_it_is_shown_again() {
        for status in [StatusCode::OK, StatusCode::NOT_FOUND] {
            let r = Page(status, String::new()).into_response();
            assert_eq!(r.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");
        }
    }

    /// A block's table sorts by fee and by size, and its headers link back to
    /// the block by height.
    #[test]
    fn a_block_sorts_its_transactions_by_fee_or_size() {
        let row = |fee_atomic, size| BlockTxRow {
            fee_atomic,
            size,
            ..block_tx(false)
        };
        let mut rows = vec![row(300, 2_000), row(100, 1_000), row(200, 3_000)];

        sort_block_rows(&mut rows, SortKey::Fee, SortDir::Desc);
        assert_eq!(
            rows.iter().map(|r| r.fee_atomic).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );
        sort_block_rows(&mut rows, SortKey::Size, SortDir::Asc);
        assert_eq!(
            rows.iter().map(|r| r.size).collect::<Vec<_>>(),
            vec![1_000, 2_000, 3_000]
        );

        let mut page = block_page();
        let active = Some((SortKey::Fee, SortDir::Asc));
        page.fee_sort = column_sort("/block/3185430", SortKey::Fee, active);
        page.size_sort = column_sort("/block/3185430", SortKey::Size, active);
        let html = page.render().expect("renders");
        assert!(
            html.contains(
                r#"href="/block/3185430?sort=fee&#38;dir=desc">Fee<svg class="sort-mark asc""#
            ),
            "the active column does not flip:\n{html}"
        );
        assert!(
            html.contains(
                r#"href="/block/3185430?sort=size&#38;dir=desc">Size<svg class="sort-mark none""#
            ),
            "the size column does not offer to sort:\n{html}"
        );
        assert!(!html.contains("Ring<svg"), "ring is not sortable");
    }

    /// A transaction page marks what it is about: its own hash and the key
    /// images its inputs spend. Other hashes on it stay plain.
    #[test]
    fn a_transaction_marks_its_hash_and_key_images() {
        let html = tx_page().render().expect("renders");
        assert!(html.contains(&format!(r#"<p class="hash mark">{}</p>"#, "e".repeat(64))));
        assert_eq!(
            html.matches(r#"Key image <span class="hash mark">"#)
                .count(),
            2,
            "every key image should be marked:\n{html}"
        );
        assert_eq!(
            html.matches(r#"class="hash mark""#).count(),
            3,
            "something other than the hash and key images is marked"
        );
        assert!(STYLESHEET.contains(".hash.mark { color: var(--accent); }"));
    }

    /// A stable sort: rows tied on the sort key keep the daemon's own order,
    /// whichever direction was asked for, rather than flipping arbitrarily.
    #[test]
    fn rows_tied_on_the_sort_key_keep_their_original_order() {
        let pool = [pool_tx(5, 100, 1), pool_tx(5, 200, 2), pool_tx(5, 300, 3)];
        for dir in [SortDir::Desc, SortDir::Asc] {
            let rows = pool_rows(
                &RowCache::default(),
                &pool,
                Some((SortKey::Waiting, dir)),
                10,
            );
            assert_eq!(fees(&rows), [100, 200, 300]);
        }
    }

    #[test]
    fn the_mempool_headers_link_to_the_sort_state_they_were_given() {
        let html = mempool_page(Some((SortKey::Fee, SortDir::Asc)))
            .render()
            .expect("renders");
        assert!(
            html.contains(r#"href="/mempool?sort=fee&#38;dir=desc""#),
            "the active column should link to its own reverse:\n{html}"
        );
        assert!(
            html.contains(r#">Fee<svg class="sort-mark asc""#),
            "the active column should show which way it is sorted:\n{html}"
        );
        assert!(
            html.contains(r#"href="/mempool?sort=waiting&#38;dir=desc""#),
            "an inactive column should default to descending:\n{html}"
        );
        assert!(
            html.contains(r#">Waiting [h:m:s]<svg class="sort-mark none""#),
            "an inactive column must not claim a direction:\n{html}"
        );
        assert_eq!(
            html.matches(r#"<svg class="sort-mark none""#).count(),
            2,
            "every sortable column but the active one should offer both \
             directions:\n{html}"
        );
        assert!(
            !html.contains("Ring<svg") && !html.contains("Hash<svg"),
            "a column that cannot be sorted must not offer to:\n{html}"
        );
        // A typed arrow is what a phone turned into an emoji.
        for glyph in ['\u{2195}', '\u{21c5}', '\u{25b2}', '\u{25bc}'] {
            assert!(!html.contains(glyph), "a sort arrow is typed again");
        }
    }

    /// One RingCT input and output, one pre-RingCT input and output. Both
    /// states have to be present or the distinction is unobservable.
    fn tx_page() -> TxPage {
        TxPage {
            version: VERSION,
            query: None,
            chain: status(),
            hash: "e".repeat(64),
            coinbase: false,
            p2pool: false,
            in_pool: false,
            pruned: false,
            block_height: 3_185_430,
            confirmations: 1,
            timestamp: 1_790_038_920,
            timestamp_utc: "2026-09-22 01:02:00".to_owned(),
            age: "00:01:12".to_owned(),
            fee: "0.00071136".to_owned(),
            size: 2_223,
            version_no: 2,
            rct_type: 6,
            ring_size: 16,
            fcmp_pp: false,
            reference_block: None,
            n_tree_layers: None,
            root_block: None,
            anonymity_set: None,
            tree: None,
            proof_size: None,
            carrot: false,
            unlock_time: 0,
            payment_id: String::new(),
            payment_id8: String::new(),
            inputs: vec![
                InputView {
                    key_image: "1".repeat(64),
                    amount: visible_amount(0),
                    unavailable: false,
                    ring: vec![RingView {
                        height: 3_100_000,
                        public_key: "2".repeat(64),
                        tx_hash: "3".repeat(64),
                    }],
                    ages: age_strip(&[], 0, 0),
                },
                InputView {
                    key_image: "4".repeat(64),
                    amount: visible_amount(2_000_000_000_000),
                    unavailable: false,
                    ring: Vec::new(),
                    ages: age_strip(&[], 0, 0),
                },
            ],
            outputs: vec![
                OutputView {
                    public_key: "5".repeat(64),
                    amount: visible_amount(0),
                    view_tag: "94".to_owned(),
                    anchor: String::new(),
                    unified_id: None,
                },
                OutputView {
                    public_key: "6".repeat(64),
                    amount: visible_amount(3_000_000_000_000),
                    view_tag: "d6".to_owned(),
                    anchor: String::new(),
                    unified_id: None,
                },
            ],
            has_view_tags: true,
            has_unified_ids: false,
            extra: "01aa".to_owned(),
            extra_fields: Vec::new(),
            extra_undecoded: false,
        }
    }

    /// The same page for an FCMP++ spend with Carrot outputs, as it would be
    /// built from a type 7 transaction.
    fn fcmp_tx_page() -> TxPage {
        let mut page = tx_page();
        page.rct_type = 7;
        page.ring_size = 0;
        page.fcmp_pp = true;
        page.reference_block = Some(3_012_345);
        page.n_tree_layers = Some(6);
        page.carrot = true;
        for i in &mut page.inputs {
            i.amount = None;
            i.ring = Vec::new();
        }
        for o in &mut page.outputs {
            o.amount = None;
            o.view_tag = "a1b2c3".to_owned();
            o.anchor = "7".repeat(32);
        }
        page
    }

    /// An FCMP++ input has no ring, and the page must say what it has instead
    /// rather than print "0 ring members", which reads as no privacy at all.
    #[test]
    fn an_fcmp_pp_spend_shows_the_curve_tree_as_its_anonymity_set() {
        let html = fcmp_tx_page().render().expect("renders");
        assert!(html.contains("Every output in the curve tree"), "{html}");
        assert!(
            html.contains(r#"as of block <a href="/block/3012345">3012345</a>"#),
            "the reference block links to its block:
{html}"
        );
        assert!(html.contains("6 tree layers"));
        assert!(!html.contains("ring members"), "{html}");
        assert!(
            !html.contains("Ring member ages"),
            "no strip without a ring"
        );
        assert!(!html.contains("<dt>Ring size</dt>"));
        assert!(!html.contains("refused this ring lookup"));
        assert_eq!(
            html.matches(r#"<span class="tag">FCMP++</span>"#).count(),
            2
        );
        assert!(html.contains("FCMP++ (type 7)"));
        assert!(!html.contains("RingCT type 7"));
    }

    /// With the tree's size known, the row gives the count; the proof size and
    /// each output's unified id have rows and a column of their own.
    #[test]
    fn a_known_tree_size_is_the_anonymity_set_and_the_proof_has_a_size() {
        let mut page = fcmp_tx_page();
        page.anonymity_set = Some(grouped(1_234_567));
        page.proof_size = Some(grouped(6_528));
        page.has_unified_ids = true;
        for (i, o) in page.outputs.iter_mut().enumerate() {
            o.unified_id = Some(900 + i as u64);
        }
        let html = page.render().expect("renders");
        assert!(
            html.contains(r#"1,234,567 outputs, as of block <a href="/block/3012345">"#),
            "{html}"
        );
        assert!(!html.contains("Every output in the curve tree"));
        assert!(html.contains("<dt>FCMP++ proof</dt><dd>6,528 bytes"));
        assert!(html.contains(r#"<th class="num">Unified ID</th>"#));
        // Each unified id links to its output's path, and the section to all
        // of them.
        let paths = format!("/tx/{}/paths", page.hash);
        assert!(html.contains(&format!(r#"<a href="{paths}?output=1" title="This output's path through the curve tree">900</a>"#)));
        assert!(html.contains(&format!(r#"<a href="{paths}?output=2" title="This output's path through the curve tree">901</a>"#)));
        assert!(html.contains(&format!(r#"<a class="walk" href="{paths}">"#)));
        // Without them, none of it appears.
        let bare = fcmp_tx_page().render().expect("renders");
        assert!(bare.contains("Every output in the curve tree"));
        assert!(!bare.contains("FCMP++ proof"));
        assert!(!bare.contains("Unified ID"));
    }

    #[test]
    fn the_funnel_runs_from_the_root_down_with_the_curves_alternating() {
        let t = tree_funnel(152_000_000, None, &WIDE_FUNNEL).expect("a tree");
        let rows: Vec<_> = t
            .rows
            .iter()
            .map(|r| (r.name.as_str(), r.curve, r.count.as_deref(), r.width))
            .collect();
        assert_eq!(
            rows,
            [
                ("Root", Some("Helios"), Some("1"), FUNNEL_MIN_BAR),
                ("Layer 5", Some("Selene"), Some("9"), 67),
                ("Layer 4", Some("Helios"), Some("325"), 160),
                ("Layer 3", Some("Selene"), Some("5,848"), 236),
                ("Layer 2", Some("Helios"), Some("222,223"), 330),
                ("Layer 1", Some("Selene"), Some("4,000,000"), 405),
                ("Outputs", None, Some("152,000,000"), FUNNEL_SPAN),
            ]
        );
        assert_eq!(t.layers, 6);
        for (i, r) in t.rows.iter().enumerate() {
            assert_eq!(r.x + r.width / 2, FUNNEL_CENTRE, "row {i} is centred");
            assert_eq!(r.y, FUNNEL_TOP + FUNNEL_ROW * i as u32);
        }
        // Below the root, a column for each of its nine children: all but
        // the last full, so 38 of layer 4's nodes each, 38 × 18 of layer
        // 3's, and the rest in the last.
        let nodes = |i: usize| -> Vec<u64> { t.rows[i].blocks.iter().map(|b| b.nodes).collect() };
        assert_eq!(nodes(0), [1]);
        assert_eq!(nodes(1), [1; 9]);
        assert_eq!(nodes(2), [38, 38, 38, 38, 38, 38, 38, 38, 21]);
        assert_eq!(&nodes(3)[..2], [684, 684]);
        assert_eq!(nodes(3)[8], 5_848 - 8 * 684);
        for (i, r) in t.rows.iter().enumerate().skip(1) {
            assert_eq!(
                nodes(i).iter().sum::<u64>(),
                r.count
                    .as_deref()
                    .map_or(0, |c| c.replace(',', "").parse().unwrap())
            );
            let first = r.blocks.first().expect("a block");
            let last = r.blocks.last().expect("a block");
            assert_eq!(first.x, r.x.to_string(), "row {i} starts at its bar");
            assert_eq!(
                block_end(last),
                (r.x + r.width).to_string(),
                "and ends there"
            );
        }
        // One band from the root to layer 5, then one for each column.
        assert_eq!(t.webs.len(), 1 + 5 * 9);
    }

    /// A tree small enough for one Selene root, as on a young chain.
    #[test]
    fn a_one_layer_tree_shows_every_output() {
        let root = "2348cda97f56d37466e0216de7454db6478b51d180ef8ca457f901eca2ce30a9";
        let t = tree_funnel(22, Some(root), &WIDE_FUNNEL).expect("a tree");
        assert_eq!(t.layers, 1);
        assert_eq!(t.rows[0].curve, Some("Selene"));
        let leaves = &t.rows[1];
        assert_eq!((leaves.x, leaves.width), (150, 500));
        // The outputs are the root's children: a block each, 3 apart.
        assert_eq!(leaves.blocks.len(), 22);
        assert!(
            leaves
                .blocks
                .iter()
                .all(|b| b.nodes == 1 && b.width == "19.9")
        );
        assert_eq!(leaves.blocks[1].x, "172.9");
        assert_eq!(t.webs, ["395,28 405,28 650,44 150,44"]);
        assert_eq!(t.height, 64);
        assert_eq!(t.root.as_deref(), Some("2348cda97f56d374…"));

        // 200 outputs: 6 Selene nodes under the root, 38 outputs each but
        // the last 10.
        let t = tree_funnel(200, None, &WIDE_FUNNEL).expect("a tree");
        let outputs: Vec<u64> = t.rows[2].blocks.iter().map(|b| b.nodes).collect();
        assert_eq!(outputs, [38, 38, 38, 38, 38, 10]);
        assert!(
            tree_funnel(22, None, &WIDE_FUNNEL)
                .expect("a tree")
                .root
                .is_none()
        );
        assert!(tree_funnel(0, None, &WIDE_FUNNEL).is_none());
    }

    /// For a phone the labels go above the bars, so the whole tree fits the
    /// narrow drawing's width.
    #[test]
    fn the_narrow_funnel_puts_each_label_above_its_bar() {
        let t = tree_funnel(22, Some(&"ab".repeat(32)), &NARROW_FUNNEL).expect("a tree");
        let rows: Vec<_> = t
            .rows
            .iter()
            .map(|r| (r.name.as_str(), r.x, r.y, r.label_y, r.width))
            .collect();
        assert_eq!(
            rows,
            [("Root", 155, 30, 22, 10), ("Outputs", 0, 74, 66, 320)]
        );
        assert_eq!(
            (t.class, t.width, t.count_x, t.height, t.root_y),
            ("narrow", 320, 160, 94, 22)
        );
        assert_eq!(t.webs, ["155,44 165,44 320,74 0,74"]);
        assert_eq!(
            (t.count_x, t.count_anchor, t.root_x),
            (160, "middle", 160),
            "the counts go over the bars, and the root's hash takes the root's"
        );
        assert_eq!(t.rows[0].count, None, "the hash stands in for the root's 1");
        assert_eq!(t.rows[1].blocks[0].x, "0");

        let wide = tree_funnel(22, None, &WIDE_FUNNEL).expect("a tree");
        assert_eq!(
            (wide.class, wide.width, wide.root_x, wide.root_y),
            ("wide", 760, 400, 11)
        );
        assert_eq!((wide.count_x, wide.count_anchor), (760, "end"));
        assert_eq!(
            wide.rows[0].count.as_deref(),
            Some("1"),
            "without a hash, the root is counted"
        );
        assert_eq!(wide.rows[0].label_y, 26);
    }

    /// Drawn once for the transaction, above its inputs, from presentation
    /// attributes only.
    #[test]
    fn a_known_tree_size_draws_the_tree() {
        let mut page = fcmp_tx_page();
        page.tree = tree_picture(22, Some(&"ab".repeat(32)));
        let html = page.render().expect("renders");
        assert_eq!(html.matches(r#"<figure class="curve-tree">"#).count(), 1);
        assert_eq!(
            html.matches(r#"<svg class="funnel wide" viewBox="0 0 760 64""#)
                .count(),
            1
        );
        assert_eq!(
            html.matches(r#"<svg class="funnel narrow" viewBox="0 0 320 94""#)
                .count(),
            1
        );
        assert!(
            html.contains(r#"aria-label="Curve tree of 22 outputs in 1 layer, the root"#),
            "{html}"
        );
        assert!(html.contains(
            r#"<text class="label" x="0" y="26">Root<tspan class="curve"> · Selene</tspan>"#
        ));
        assert!(html.contains(r#"text-anchor="end">22</text>"#));
        assert!(html.contains(">abababababababab…</text>"));
        assert!(
            html.find("curve-tree") < html.find("input-card"),
            "above the inputs"
        );
        assert!(!html.contains(" style="), "the CSP drops inline styles");

        assert!(
            !fcmp_tx_page()
                .render()
                .expect("renders")
                .contains("curve-tree")
        );
        assert!(!tx_page().render().expect("renders").contains("curve-tree"));
    }

    /// However many outputs, a bar is split only into the root's children's
    /// branches, so a mainnet-sized tree draws as few blocks as a small one
    /// with as many branches, and every gap stays visible on a phone.
    #[test]
    fn a_mainnet_sized_tree_draws_only_its_branches() {
        let [wide, narrow] = tree_picture(152_318_407, None).expect("a tree");
        for t in [&wide, &narrow] {
            assert_eq!(t.rows.len(), 7, "six layers and the outputs");
            let blocks: Vec<_> = t.rows.iter().map(|r| r.blocks.len()).collect();
            assert_eq!(blocks, [1, 9, 9, 9, 9, 9, 9]);
            for r in &t.rows[1..] {
                let ends: Vec<f64> = r
                    .blocks
                    .iter()
                    .flat_map(|b| [b.x.parse::<f64>().unwrap(), block_end(b).parse().unwrap()])
                    .collect();
                assert!(
                    ends.windows(2)
                        .skip(1)
                        .step_by(2)
                        .all(|w| w[1] - w[0] >= 0.9),
                    "{} {}: blocks stay apart",
                    t.class,
                    r.name
                );
            }
        }

        let mut page = fcmp_tx_page();
        page.tree = Some([wide, narrow]);
        let html = page.render().expect("renders");
        assert_eq!(html.matches(r#"<rect class="bar"#).count(), 2 * (1 + 6 * 9));
        assert!(!html.contains("<pattern") && !html.contains(r#"class="cut""#));
        assert!(html.contains("<title>38 nodes</title>"));
        assert!(html.contains("<title>1 node</title>"));
    }

    /// The walkthrough is linked under the inputs' heading, above the tree
    /// when there is one.
    #[test]
    fn the_walkthrough_is_linked_from_the_tree() {
        let link = r#"<a class="walk" href="/tx/abc/fcmp">How this spend stays private &rarr;</a>"#;
        let mut page = fcmp_tx_page();
        page.hash = "abc".to_owned();
        page.tree = tree_picture(22, None);
        let html = page.render().expect("renders");
        assert_eq!(html.matches(link).count(), 1);
        let at = html.find(link);
        let heading = html.find(" Input").expect("the inputs' heading");
        assert!(at > Some(heading), "under the heading");
        assert!(
            at < html.find(r#"<figure class="curve-tree">"#),
            "above the tree"
        );
        assert!(!html.contains("how it works"));

        page.tree = None;
        let html = page.render().expect("renders");
        assert_eq!(html.matches(link).count(), 1);
        assert!(
            html.find(link) < html.find("input-card"),
            "above the inputs"
        );

        let mut ring = tx_page();
        ring.hash = "abc".to_owned();
        assert!(!ring.render().expect("renders").contains("/fcmp"));
    }

    fn fcmp_fixture(file: &str) -> Vec<(TxEntry, TxJson)> {
        let json = match file {
            "full" => include_str!("../../../fixtures/fcmp/get_transactions_fcmp.json"),
            _ => include_str!("../../../fixtures/fcmp/get_transactions_fcmp_pruned.json"),
        };
        let resp: monerod_rpc::types::GetTransactionsResponse =
            serde_json::from_str(json).expect("a fixture");
        assert!(!resp.txs.is_empty());
        resp.txs
            .into_iter()
            .map(|e| {
                let tx = e.parse_json().expect("decodes");
                (e, tx)
            })
            .collect()
    }

    /// Each input's own bytes are read from its place in the proof, and the
    /// shared membership proof is what is left.
    #[test]
    fn the_walkthrough_shows_each_inputs_own_part_of_the_proof() {
        for (entry, tx) in fcmp_fixture("full") {
            let proof = tx
                .rctsig_prunable
                .as_ref()
                .and_then(|p| p.fcmp_pp.clone())
                .expect("a proof");
            let n = tx.vin.len();
            let page = fcmp_page(None, &entry, &tx, Some(62), Some((112, "9".repeat(64))));

            assert_eq!(page.inputs.len(), n);
            for (i, input) in page.inputs.iter().enumerate() {
                let at = i * 960;
                let d = input.disguise.as_ref().expect("the proof is held");
                assert_eq!(d.o_tilde, proof[at..at + 64]);
                assert_eq!(d.i_tilde, proof[at + 64..at + 128]);
                assert_eq!(d.r, proof[at + 128..at + 192]);
                assert_eq!(
                    input.key_image,
                    tx.vin[i].as_key().expect("a key input").k_image
                );
                assert_eq!(
                    input.pseudo_out.as_deref(),
                    Some(tx.pseudo_outs()[i].as_str())
                );
            }
            let total = proof.len() / 2;
            // What is left after the tuples and signatures, less the anchor.
            let membership = total - n * 480 - 64;
            assert_eq!(
                page.membership,
                Some((
                    grouped(membership as u64),
                    (membership * 100 / total) as u64
                ))
            );
            assert_eq!(page.proof_size, Some(grouped(total as u64)));
            assert_eq!(page.reference_block, Some(120));
            assert_eq!(page.range_proofs, 1);

            let html = page.render().expect("renders");
            assert!(html.contains(
                "As of block 120, the one this proof was built against, the tree held 62 outputs."
            ));
            assert!(html.contains("Block 112 already carries that tree's root:"));
            // Step 7 counts the inputs: each spent its own output.
            assert!(n > 1, "the captured transactions spend two outputs each");
            assert!(html.contains(&format!(
                "That each of its {n} inputs spent a different one of 62 outputs,\nby someone entitled to spend it, and only once. Not which ones."
            )));
            assert!(html.contains("<dt>Each input could be spending</dt>"));
            let mut single = fcmp_page(None, &entry, &tx, Some(62), Some((112, "9".repeat(64))));
            single.inputs.truncate(1);
            let single = single.render().expect("renders");
            assert!(single.contains(
                "That one of 62 outputs\nwas spent, by someone entitled to spend it, and only once. Not which one."
            ));
            assert!(single.contains("<dt>Could be spending</dt>"));
            assert!(html.contains("<dd>1 Bulletproofs+ proof over the outputs</dd>"));
            let first = page
                .inputs
                .first()
                .and_then(|i| i.disguise.as_ref())
                .expect("one");
            assert!(html.contains(&format!(r#"<dd class="hash">{}</dd>"#, first.o_tilde)));
            assert!(html.contains(
                r##"<a class="btn next" href="#s2">Next: Disguise the output &rarr;</a>"##
            ));
            assert_eq!(
                html.matches("&larr; Back").count(),
                6,
                "every step but the first"
            );
            let last = html.find(r#"id="s7""#).expect("step 7");
            assert_eq!(html.matches("Start again").count(), 1);
            let again = html.find("Start again");
            assert!(
                again > Some(last) && again < html.find(r#"id="s1""#),
                "on step 7"
            );
            assert!(html.contains(&format!("Its {}-byte FCMP++ proof", grouped(total as u64))));
            for input in &page.inputs {
                assert!(html.contains(&format!(
                    r#"<dd class="hash mark">{}</dd>"#,
                    input.key_image
                )));
            }
            assert!(
                html.rfind(r#"id="s1""#) > html.rfind(r#"id="s7""#),
                "step 1 comes last, for the stylesheet's `~`"
            );
            assert!(!html.contains(" style="), "the CSP drops inline styles");
        }
    }

    #[test]
    fn the_walkthrough_counts_this_transactions_amounts() {
        let (entry, tx) = fcmp_fixture("full").remove(1);
        let html = fcmp_page(None, &entry, &tx, None, None)
            .render()
            .expect("renders");
        assert!(html.contains("<dd>2 disguised amounts</dd>"));
        assert!(html.contains("<dd>4 hidden amounts</dd>"));
        assert!(
            html.contains("<dd>0.0113292 XMR, the only amount in the clear</dd>"),
            "{html}"
        );
        assert!(html.contains("all 2 inputs at once"));
    }

    /// Parts in the proof's own order, each linked to its step, edge to edge
    /// with a pixel either side, filling the bar.
    #[test]
    fn the_proof_bar_lays_each_part_out_in_order() {
        let map = proof_map(2, 5_568);
        let order: Vec<_> = map.iter().map(|g| (g.class, g.step)).collect();
        assert_eq!(
            order,
            [
                ("tuple", 2),
                ("sal", 3),
                ("tuple", 2),
                ("sal", 3),
                ("member", 4),
                ("anchor", 5)
            ]
        );
        assert_eq!(map.first().map(|g| g.x), Some(1));
        let last = map.last().expect("an anchor");
        assert_eq!(last.x + last.width + 1, MAP_WIDTH);
        for w in map.windows(2) {
            assert_eq!(w[1].x, w[0].x + w[0].width + 2);
        }
        // To scale: 5,504 of 6,528 bytes, less what the narrow parts borrow.
        let member = &map[4];
        assert!((800..840).contains(&member.width), "{}", member.width);
        assert!(
            map[0].width < map[1].width,
            "a tuple is a quarter of a signature"
        );
        assert_eq!(map[4].label, "The membership proof, 5,504 bytes");
        assert_eq!(map[0].label, "Input 1's disguised output, 96 bytes");
        assert_eq!(map[3].label, "Input 2's signature, 384 bytes");

        // Every part of a 128-input proof still gets a visible sliver.
        let wide = proof_map(128, 200_000);
        assert_eq!(wide.len(), 258);
        assert!(wide.iter().all(|g| g.width >= 1), "no part vanishes");
        let end = wide.last().expect("an anchor");
        assert_eq!(end.x + end.width + 1, MAP_WIDTH);
    }

    /// The proof's shape, the tree, the root's curve and the bar all come
    /// from this transaction, and every step's math starts closed.
    #[test]
    fn the_walkthrough_draws_this_proof_and_hides_the_math() {
        let (entry, mut tx) = fcmp_fixture("full").remove(0);
        let page = fcmp_page(None, &entry, &tx, Some(62), Some((112, "9".repeat(64))));
        let s = page
            .shape
            .as_ref()
            .expect("the shape accounts for the proof");
        assert_eq!(
            (
                s.selene_rows,
                s.selene_rounds,
                s.helios_rows,
                s.helios_rounds
            ),
            (256, 8, 128, 7)
        );
        assert_eq!(page.root_curve, Some("Helios"));
        let html = page.render().expect("renders");
        assert!(html.contains(
            "Here the Selene proof has\n256 rows, folded in 8 rounds, and the Helios\nproof 128 rows in 7 rounds."
        ), "{html}");
        assert!(html.contains("<dt>Root is on</dt><dd>Helios</dd>"));
        assert!(html.contains(r#"aria-label="Curve tree of 62 outputs in 2 layers"#));
        assert!(html.contains(
            "&lceil;62 &divide; 38&rceil; = 2 Selene nodes<br>&lceil;2 &divide; 18&rceil; = 1 Helios node, the root"
        ));
        assert!(html.contains("one line for each of its 2\nlayers."));
        // Step 1 keeps its picture beside the words, the tree among them.
        let first = &html[html.find(r#"id="s1""#).expect("step 1")..];
        let tree = first
            .find(r#"<figure class="curve-tree tree-field">"#)
            .expect("the tree");
        let pic = first.find(r#"<svg class="pic""#).expect("the picture");
        assert!(tree < first.find("Show me the math").expect("math") && tree < pic);
        assert!(!html.contains(" style="), "the CSP drops inline styles");
        assert!(!html.contains(r#"class="maths" open"#));
        assert_eq!(html.matches(r#"aria-current="step""#).count(), 7);
        // Step 2 lights both inputs' tuples, step 4 the membership proof,
        // step 5 the anchor, and nothing else is ever lit.
        assert_eq!(html.matches(r#"class="seg tuple on""#).count(), 2);
        assert_eq!(html.matches(r#"class="seg sal on""#).count(), 2);
        assert_eq!(html.matches(r#"class="seg member on""#).count(), 1);
        assert_eq!(html.matches(r#"class="seg anchor on""#).count(), 1);
        assert_eq!(html.matches(r#"<svg class="proof-map""#).count(), 4);

        // A layer count the proof's length does not fit leaves the shape out
        // rather than print rows that describe some other proof.
        tx.rctsig_prunable.as_mut().expect("prunable").n_tree_layers = Some(1);
        let odd = fcmp_page(None, &entry, &tx, None, None);
        assert!(odd.shape.is_none());
        assert_eq!(odd.root_curve, Some("Selene"));
        assert!(odd.tree.is_none());
        let html = odd.render().expect("renders");
        assert!(!html.contains("rows, folded in"));
        assert!(
            !html.contains("&lceil;"),
            "no sums for a tree of unknown size"
        );
        assert!(
            html.contains(r#"<path class="web" d="M96 38H104"#),
            "the drawing is there without the tree"
        );
    }

    /// A pruned node has none of the proof, and says so rather than showing
    /// empty rows.
    #[test]
    fn a_pruned_proof_is_explained_without_its_bytes() {
        for (entry, tx) in fcmp_fixture("pruned") {
            let page = fcmp_page(None, &entry, &tx, None, None);
            assert!(
                page.inputs
                    .iter()
                    .all(|i| i.disguise.is_none() && i.pseudo_out.is_none())
            );
            assert_eq!(page.proof_size, None);
            assert_eq!(page.membership, None);
            let html = page.render().expect("renders");
            assert!(html.contains("no longer holds this transaction's proof"));
            assert!(!html.contains("&Otilde;</dt>"));
            assert!(html.contains("Its FCMP++ proof is what makes that possible."));
            assert!(
                !html.contains("known once this transaction is mined"),
                "it was"
            );
        }
    }

    /// A pool transaction's tree size cannot be asked for yet.
    #[test]
    fn a_pool_spend_says_its_tree_size_waits_for_a_block() {
        let (mut entry, tx) = fcmp_fixture("full").remove(0);
        entry.in_pool = true;
        let html = fcmp_page(None, &entry, &tx, None, None)
            .render()
            .expect("renders");
        assert!(html.contains("The tree's size is known once this transaction is mined."));
        assert!(html.contains("The pool accepted its key images as new."));
        assert!(html.contains("any output in the tree"));
        assert!(!html.contains("outputs in the tree</dt>"));
    }

    #[test]
    fn counts_group_their_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(150_123_456), "150,123,456");
        assert_eq!(grouped(u64::MAX), "18,446,744,073,709,551,615");
    }

    /// The root a proof was checked against is in a different block from the
    /// one it names, and the page links both.
    #[test]
    fn the_reference_block_and_the_root_block_are_both_linked() {
        let mut page = fcmp_tx_page();
        page.root_block =
            monerod_rpc::types::tree_root_block(3_012_345).map(|h| (h, "9".repeat(64)));
        let html = page.render().expect("renders");
        assert!(html.contains(r#"as of block <a href="/block/3012345">3012345</a>"#));
        assert!(
            html.contains(r#"root in block <a href="/block/3012337">3012337</a>"#),
            "{html}"
        );
        assert!(html.contains("FCMP++ (type 7)"));
        assert!(html.contains(&format!(r#"title="Tree root {}""#, "9".repeat(64))));

        // A root block from before the fork carries no tree, so there is no
        // link to make.
        let bare = fcmp_tx_page().render().expect("renders");
        assert!(!bare.contains("root in block"));
    }

    /// A pruned node knows the transaction is FCMP++ but not which tree it
    /// named. The row stays; the claim about the block goes.
    #[test]
    fn a_pruned_fcmp_pp_spend_names_no_reference_block() {
        let mut page = fcmp_tx_page();
        page.pruned = true;
        page.reference_block = None;
        page.n_tree_layers = None;
        let html = page.render().expect("renders");
        assert!(html.contains("Every output in the curve tree"));
        assert!(!html.contains("as of block"));
        assert!(html.contains("the FCMP++ proof and the block it"));
        assert!(!html.contains("Ring members are still resolved"));
    }

    /// Carrot outputs carry a three-byte view tag and an encrypted anchor, and
    /// the hint describes the three-byte tag, not the one-byte one.
    #[test]
    fn carrot_outputs_show_their_anchor_and_describe_their_view_tag() {
        let html = fcmp_tx_page().render().expect("renders");
        assert!(html.contains("<th>Janus anchor</th>"));
        assert_eq!(html.matches(&"7".repeat(32)).count(), 2);
        assert!(html.contains("<code>a1b2c3</code>"));
        assert!(html.contains("Three bytes that make scanning cheaper"));
        assert!(!html.contains("One byte that makes scanning cheaper"));

        let legacy = tx_page().render().expect("renders");
        assert!(!legacy.contains("Janus anchor"));
        assert!(legacy.contains("One byte that makes scanning cheaper"));
        assert!(legacy.contains("<dt>Ring size</dt>"));
    }

    /// The tree row appears from the fork on and not before it.
    #[test]
    fn a_block_shows_its_curve_tree_only_when_it_has_one() {
        let before = block_page().render().expect("renders");
        assert!(!before.contains("Curve tree"));

        let mut page = block_page();
        page.major_version = 17;
        page.minor_version = 17;
        page.tree_root = Some("9".repeat(64));
        page.tree_layers = Some(5);
        let after = page.render().expect("renders");
        assert!(after.contains("<dt>Curve tree</dt>"));
        assert!(after.contains(&"9".repeat(64)));
        assert!(after.contains("5 layers"));
    }

    /// Each row counts its inputs, and a coinbase, which spends nothing,
    /// shows a dash as it does for its ring.
    #[test]
    fn the_block_table_counts_each_transactions_inputs() {
        let html = block_page().render().expect("renders");
        assert!(html.contains(
            r#"<th class="num">Inputs</th>
      <th class="num">Outputs</th>"#
        ));
        assert_eq!(html.matches(r#"<td class="num">3</td>"#).count(), 2);
        let coinbase = &html[..html.find("d".repeat(64).as_str()).expect("a spend")];
        assert!(
            coinbase.contains(
                r#"<td class="num">&mdash;</td>
      <td class="num">2</td>"#
            ),
            "{html}"
        );

        let (_, tx) = fcmp_fixture("full").remove(0);
        assert_eq!(spends(&tx), 2);
        let coinbase: TxJson = serde_json::from_str(
            r#"{"version":2,"unlock_time":60,"vin":[{"gen":{"height":5}}],"vout":[],"extra":[],"rct_signatures":{"type":0}}"#,
        )
        .expect("a coinbase");
        assert_eq!(spends(&coinbase), 0);
    }

    /// An FCMP++ row's column holds its tree's size when that is known, never
    /// the 0 its ring size is, and a table with one heads it "Anon set".
    #[test]
    fn an_fcmp_pp_row_names_its_tree_in_the_ring_column() {
        let fcmp = || BlockTxRow {
            ring: 0,
            full_chain: true,
            reference: Some(300),
            ..block_tx(false)
        };
        let ring_only = block_page().render().expect("renders");
        assert!(ring_only.contains(r#"<th class="num">Ring</th>"#));
        assert!(!ring_only.contains("Anon set"));
        let ring_pool = mempool_page(None).render().expect("renders");
        assert!(ring_pool.contains(r#"<th class="num">Ring</th>"#));

        let mut page = block_page();
        page.txs.push(BlockTxRow {
            tree: Some("6,213".to_owned()),
            ..fcmp()
        });
        page.txs.push(fcmp());
        let html = page.render().expect("renders");
        assert_eq!(html.matches(">6,213</span>").count(), 1, "{html}");
        assert!(html.contains(r#"<th class="num">Anon set</th>"#), "{html}");
        assert!(html.contains("one of the 6,213 outputs in the curve tree"));
        assert_eq!(html.matches(">whole tree</span>").count(), 1, "{html}");
        assert!(!html.contains(">0</td>"), "{html}");

        let mut pool = mempool_page(None);
        pool.txs.push(PoolRow {
            ring: 0,
            full_chain: true,
            tree: Some("7,001".to_owned()),
            ..pool_row(5)
        });
        let html = pool.render().expect("renders");
        assert!(html.contains(">7,001</span>"), "{html}");
        assert!(html.contains(r#"<th class="num">Anon set</th>"#), "{html}");
    }

    /// A row's tree is the one as of its own reference block, and an empty
    /// tree, which no proof was built against, is not a size to show.
    #[test]
    fn a_rows_tree_is_the_one_as_of_its_reference_block() {
        let sizes = HashMap::from([(300, 6_213), (301, 6_250), (302, 0)]);
        assert_eq!(tree_of(Some(301), &sizes).as_deref(), Some("6,250"));
        assert_eq!(tree_of(Some(300), &sizes).as_deref(), Some("6,213"));
        assert_eq!(tree_of(Some(302), &sizes), None);
        assert_eq!(tree_of(Some(303), &sizes), None);
        assert_eq!(tree_of(None, &sizes), None);
    }

    /// A block's root is the tree as of eight blocks on, so its growth is
    /// that tree's size against the one a block before it.
    #[test]
    fn a_blocks_growth_is_its_roots_tree_against_the_previous_one() {
        let sizes = HashMap::from([(366, 6_970), (367, 6_988), (359, 6_800)]);
        assert_eq!(
            tree_growth(359, &sizes),
            Some(("6,988".to_owned(), "18".to_owned()))
        );
        assert_eq!(tree_growth(358, &sizes), None, "no size as of 367 - 1");
        let first = HashMap::from([(107, 0), (108, 38)]);
        assert_eq!(
            tree_growth(100, &first),
            Some(("38".to_owned(), "38".to_owned())),
            "an empty tree before it is a real 0"
        );
    }

    #[test]
    fn a_block_shows_its_trees_growth_only_when_known() {
        let mut page = block_page();
        page.tree_root = Some("9".repeat(64));
        page.tree_layers = Some(3);
        assert!(!page.render().expect("renders").contains("Tree size"));
        page.tree_growth = Some(("6,988".to_owned(), "18".to_owned()));
        let html = page.render().expect("renders");
        assert!(
            html.contains("<dd>6,988 outputs, 18 more than the block before"),
            "{html}"
        );
        page.tree_growth = Some(("0".to_owned(), "0".to_owned()));
        let html = page.render().expect("renders");
        assert!(html.contains("<dd>No outputs yet"), "{html}");
    }

    /// A RingCT amount is hidden, not zero, and the two must not render alike.
    ///
    /// The whole rule lives here because it used to live in two places written
    /// two different ways: the output path compared against a `"0"` sentinel it
    /// built itself, the input path compared against `"0"` but formatted
    /// through `xmr`, which never produces `"0"` -- it produces `"0.0"`.
    #[test]
    fn a_hidden_amount_has_no_string_form() {
        assert_eq!(visible_amount(0), None);
        assert_eq!(
            visible_amount(2_000_000_000_000),
            Some("2.0".to_owned()),
            "a pre-RingCT amount is public and must still be shown"
        );
        assert_eq!(visible_amount(1), Some("0.000000000001".to_owned()));
        // The trap: the formatter's rendering of zero is not the digit zero.
        assert_eq!(xmr(0), "0.0");
    }

    /// A fee column mixes tiny fees and large ones; trimmed, `xmr` gives them
    /// different numbers of decimal places and a right-aligned column stops
    /// lining up on the decimal point. `xmr_aligned` always shows all twelve.
    #[test]
    fn a_column_amount_keeps_every_decimal_place_so_the_column_aligns() {
        assert_eq!(xmr_aligned(0), "0.000000000000");
        assert_eq!(xmr_aligned(600_000_000_000), "0.600000000000");
        assert_eq!(
            xmr_aligned(30_600),
            "0.000000030600",
            "trimmed, this would be shorter than the row above and misalign"
        );
    }

    /// Bulletproofs hide the amount; the page must not print a figure for it.
    #[test]
    fn a_ringct_input_or_output_shows_no_number() {
        let html = tx_page().render().expect("renders");

        assert!(
            !html.contains("0.0 XMR"),
            "a RingCT input was labelled with an amount:\n{html}"
        );
        assert!(
            html.contains("2.0 XMR"),
            "the pre-RingCT input's visible amount was dropped"
        );
        // The output column says so in words rather than printing a zero.
        assert_eq!(
            html.matches(">hidden</span>").count(),
            1,
            "exactly one of the two outputs is a hidden RingCT amount"
        );
        assert!(
            html.contains(r#"title="Hidden in a Pedersen commitment. A Bulletproofs+ range proof"#),
            "hovering says what hides the amount"
        );
        assert!(
            html.contains("3.0"),
            "the pre-RingCT output amount is shown"
        );
    }

    /// `num_txes` counts non-coinbase transactions only, but the block page
    /// counts every rendered row. A block reading 16 on the index used to
    /// read 17 once opened, because the two pages counted differently and
    /// nothing tied them together. They now agree because both mean "every
    /// transaction, coinbase included" -- the index computes that total from
    /// `num_txes` since it never fetches the block body, and the block page
    /// simply counts what it renders. The coinbase is not called out a
    /// second time in the count: the table directly beneath it already
    /// tags which row is the coinbase.
    #[test]
    fn the_index_and_the_block_page_count_transactions_the_same_way() {
        assert_eq!(total_tx_count(29), 30, "num_txes plus the one coinbase");
        assert_eq!(total_tx_count(0), 1, "a coinbase-only block is still one");
        assert_eq!(
            total_tx_count(u64::MAX),
            u64::MAX,
            "saturates rather than wrapping past the header's own type"
        );

        // 29 non-coinbase transactions plus the coinbase itself, counted
        // through the block handler's own `table_tx_count` rather than
        // recomputed here -- recomputing `txs.len()` a second time would
        // pass even if the handler's copy silently excluded the coinbase
        // again, since both copies would agree with each other and with
        // nothing else.
        let mut txs = vec![block_tx(true)];
        txs.extend((0..29).map(|_| block_tx(false)));
        assert_eq!(txs.len(), 30, "fixture is 1 coinbase + 29 others");

        let mut page = block_page();
        page.tx_count = table_tx_count(&txs);
        page.txs = txs;

        assert_eq!(
            u64::try_from(page.tx_count).expect("small count"),
            total_tx_count(29),
            "the block page's own total disagrees with the index's"
        );

        let html = page.render().expect("renders");
        assert!(
            html.contains("<dt>Transactions</dt><dd>30</dd>"),
            "the page does not show the plain total:\n{html}"
        );
        assert!(
            !html.contains("coinbase</dd>"),
            "the count restates the coinbase, which the table below it \
             already tags:\n{html}"
        );
    }

    /// No header field carries the base emission, so the fee total of a block
    /// cannot be computed from one. A column headed "Fees" on this page is
    /// therefore always either the reward under a wrong name -- which is what
    /// it was -- or a number that was invented.
    #[test]
    fn the_front_page_does_not_claim_to_show_fees() {
        let html = index_page().render().expect("renders");
        assert!(html.contains(r#"<th class="num">Reward</th>"#));
        assert!(
            !html.to_lowercase().contains("fee"),
            "the front page names a fee it cannot compute:\n{html}"
        );
        assert!(html.contains("0.60160672"), "the reward value is shown");
    }

    /// Escaping and the content policy, checked on the pages that carry chain
    /// data rather than only on the error page.
    #[test]
    fn the_data_pages_escape_their_input_and_reference_nothing_external() {
        let hostile = r#"<script>alert(1)</script>"#.to_owned();

        let mut index = index_page();
        index.query = Some(hostile.clone());
        let mut block = block_page();
        block.query = Some(hostile.clone());
        let mut tx = tx_page();
        tx.query = Some(hostile.clone());
        tx.payment_id = hostile.clone();

        for (name, html) in [
            ("index", index.render().expect("renders")),
            ("block", block.render().expect("renders")),
            ("tx", tx.render().expect("renders")),
        ] {
            let lower = html.to_lowercase();
            assert!(!lower.contains("<script"), "{name} emitted a script tag");
            assert!(!lower.contains("javascript:"), "{name} emitted a js url");
            assert!(!lower.contains("<img"), "{name} emitted an image");
            assert!(!lower.contains("http://"), "{name} left the origin");
            assert!(!lower.contains("https://"), "{name} left the origin");
            assert_eq!(
                lower.matches("/static/style.css").count(),
                1,
                "{name} does not load exactly one stylesheet"
            );
            assert!(
                html.contains("&#60;script&#62;"),
                "{name} did not render the escaped form, so this test is not \
                 seeing the hostile value at all"
            );
        }
    }

    /// A page must still render when the daemon could not be reached, because
    /// that is exactly when someone is looking at it.
    #[test]
    fn a_page_renders_without_a_chain_status() {
        let page = ErrorPage {
            version: VERSION,
            query: None,
            chain: None,
            title: "monerod is unavailable".to_owned(),
            detail: "could not reach the daemon".to_owned(),
        };
        let html = page.render().expect("renders");
        assert!(html.contains("monerod is unavailable"));
        assert!(!html.contains("class=\"status\""));
    }

    /// monerod's `height` for an alternative chain is its tip's, the block
    /// `block_hash` names, so a three-block chain on 101, 102 and 103 comes
    /// as height 103 and length 3.
    #[test]
    fn an_alternative_chain_diverged_length_blocks_below_its_tip() {
        let chain = |height: u64, length: u64| -> monerod_rpc::types::ChainInfo {
            serde_json::from_value(serde_json::json!({
                "block_hash": "AB".repeat(32), "height": height, "length": length,
                "difficulty": 5, "difficulty_top64": 1, "wide_difficulty": "",
                "main_chain_parent_block": "CD".repeat(32),
            }))
            .expect("a chain")
        };
        let row = alt_chain_row(&chain(103, 3));
        assert_eq!((row.diverged, row.tip, row.length), (101, 103, 3));
        assert_eq!(row.difficulty, ((1u128 << 64) + 5).to_string());
        assert_eq!(
            (row.block_hash, row.parent),
            ("ab".repeat(32), "cd".repeat(32))
        );
        let row = alt_chain_row(&chain(50, 1));
        assert_eq!((row.diverged, row.tip), (50, 50));

        let html = AltBlocksPage {
            version: "test",
            query: None,
            chain: None,
            chains: vec![alt_chain_row(&chain(103, 3))],
        }
        .render()
        .expect("renders");
        assert!(
            html.contains(
                r#"<td class="num"><a href="/block/101">101</a></td>
      <td class="num">103</td>
      <td class="num">3</td>"#
            ),
            "{html}"
        );
    }

    /// A block off the main chain says so, and links only by hash: its
    /// height, sorted or stepped from, would name the main chain's block.
    #[test]
    fn an_orphaned_block_says_so_and_links_by_its_hash() {
        let header = |orphan: bool| -> monerod_rpc::types::BlockHeader {
            serde_json::from_value(serde_json::json!({
                "major_version": 16, "minor_version": 16, "timestamp": 0,
                "prev_hash": "b".repeat(64), "nonce": 0, "orphan_status": orphan,
                "height": 70, "depth": 3, "hash": "AB".repeat(32), "difficulty": 1,
                "difficulty_top64": 0, "wide_difficulty": "0x1", "cumulative_difficulty": 1,
                "cumulative_difficulty_top64": 0, "wide_cumulative_difficulty": "0x1",
                "reward": 1, "block_size": 1, "num_txes": 0, "pow_hash": "", "miner_tx_hash": "",
            }))
            .expect("a header")
        };
        assert_eq!(block_link(&header(false)), "/block/70");
        let link = block_link(&header(true));
        assert_eq!(link, format!("/block/{}", "ab".repeat(32)));

        let mut page = block_page();
        let main = page.render().expect("renders");
        assert!(!main.contains("not on the main chain") && !main.contains("orphaned"));
        assert!(main.contains(r#"<a href="/block/3185431">3185431 &rarr;</a>"#));

        page.orphan = true;
        page.fee_sort = column_sort(&link, SortKey::Fee, None);
        let html = page.render().expect("renders");
        assert!(html.contains("This block is not on the main chain."));
        assert!(html.contains(r#"<span class="tag bad">orphaned</span>"#));
        assert!(!html.contains("1 deep"));
        assert!(html.contains(&format!(
            r#"<a href="/block/{}">&larr; 3185429</a>"#,
            "b".repeat(64)
        )));
        assert!(
            !html.contains("/block/3185431"),
            "no step to the main chain's next block"
        );
        assert!(html.contains(&format!("/block/{}?sort=fee", "ab".repeat(32))));
    }

    /// A transaction the daemon sent that does not decode is counted and
    /// said to be missing from the table, not silently left out.
    #[test]
    fn an_unreadable_transaction_is_counted_and_noted() {
        let mut page = block_page();
        assert!(
            !page
                .render()
                .expect("renders")
                .contains("could not\nbe read")
        );
        page.unreadable = 2;
        page.tx_count += 2;
        let html = page.render().expect("renders");
        assert!(html.contains("<dt>Transactions</dt><dd>5</dd>"));
        assert!(
            html.contains(
                "2 of this block's transactions could not\nbe read, so they are not\nlisted below."
            ),
            "{html}"
        );
    }

    /// A lone ring input's card opens on its members; a lone FCMP++ input
    /// has none to show, so its card starts closed.
    #[test]
    fn a_lone_input_opens_only_when_it_has_a_ring_to_show() {
        let card = r#"<details class="input-card">"#;
        let open = r#"<details class="input-card" open>"#;

        let mut ring = tx_page();
        ring.inputs.truncate(1);
        let html = ring.render().expect("renders");
        assert_eq!(
            (html.matches(open).count(), html.matches(card).count()),
            (1, 0)
        );

        let mut fcmp = fcmp_tx_page();
        fcmp.inputs.truncate(1);
        let html = fcmp.render().expect("renders");
        assert_eq!(
            (html.matches(open).count(), html.matches(card).count()),
            (0, 1)
        );
        assert!(html.contains("This input has no ring."));

        // Several inputs start closed either way.
        let html = tx_page().render().expect("renders");
        assert_eq!(
            (html.matches(open).count(), html.matches(card).count()),
            (0, 2)
        );
    }
}
