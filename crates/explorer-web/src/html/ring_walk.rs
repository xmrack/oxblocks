//! A walk through a ring-era spend: a CryptoNote ring signature, an MLSAG or
//! a CLSAG, one step at a time, in the FCMP++ walkthrough's format.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use explorer_core::{ResolvedInput, TxFacts};
use monerod_rpc::types::{RctType, TxEntry, TxJson};

use super::{
    AGE_TICKS, ChainStatus, Clock, Page, ProofSegment, StepLink, VERSION, error_page, fetch_tx,
    grouped, lay_bar, map_labels, render, status_of, xmr,
};
use crate::api::handlers::Shared;

/// The ring signature a transaction's inputs are signed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// A v1 transaction: one CryptoNote ring signature per input.
    CryptoNote,
    /// RingCT type 1: one MLSAG over every input and the balance.
    MlsagFull,
    /// RingCT types 2 to 4: one two-row MLSAG per input.
    Mlsag,
    /// RingCT types 5 and 6.
    Clsag,
}

impl Scheme {
    fn of(tx: &TxJson) -> Option<Self> {
        if tx.is_coinbase() {
            return None;
        }
        if tx.is_v1() {
            return Some(Self::CryptoNote);
        }
        match tx.rct_type()? {
            RctType::Full => Some(Self::MlsagFull),
            RctType::Simple | RctType::Bulletproof | RctType::Bulletproof2 => Some(Self::Mlsag),
            RctType::Clsag | RctType::BulletproofPlus => Some(Self::Clsag),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::CryptoNote => "Ring signatures",
            Self::MlsagFull | Self::Mlsag => "MLSAG",
            Self::Clsag => "CLSAG",
        }
    }

    /// What signs the inputs, as the lede says it.
    const fn signed_by(self) -> &'static str {
        match self {
            Self::CryptoNote => "a ring signature for each input",
            Self::MlsagFull => "a single MLSAG over every input",
            Self::Mlsag => "an MLSAG for each input",
            Self::Clsag => "a CLSAG for each input",
        }
    }

    const fn era(self) -> &'static str {
        match self {
            Self::CryptoNote => {
                "This is the ring signature Monero launched with in 2014, from the \
                 CryptoNote design, before RingCT hid amounts."
            }
            Self::MlsagFull | Self::Mlsag => {
                "MLSAG came with RingCT, which hid amounts, in January 2017, and CLSAG \
                 replaced it in October 2020."
            }
            Self::Clsag => {
                "CLSAG replaced MLSAG in October 2020, and FCMP++ replaces rings \
                 altogether."
            }
        }
    }

    /// Whether each input publishes a pseudo-output.
    const fn pseudo_outs(self) -> bool {
        matches!(self, Self::Mlsag | Self::Clsag)
    }
}

/// The steps, in order. The pseudo-output step is only in the schemes that
/// have them.
const RING: &str = "The ring";
const COMMIT: &str = "Commit to the amount afresh";
const SIGN: &str = "Prove the right to spend";
const BALANCE: &str = "Balance the amounts";
const TELL: &str = "What anyone can tell";

/// A walk through a ring-era transaction's signatures.
#[derive(Template)]
#[template(path = "ring.html")]
pub(super) struct RingPage {
    version: &'static str,
    query: Option<String>,
    chain: Option<ChainStatus>,
    hash: String,
    steps: Vec<StepLink>,
    scheme: &'static str,
    signed_by: &'static str,
    era: &'static str,
    cn: bool,
    full: bool,
    clsag: bool,
    /// Type 2, whose pseudo-outputs are in the signed RingCT data.
    base_pseudo: bool,
    /// Each step's number. `commit` is 0 where there is no such step.
    commit: usize,
    sign: usize,
    balance: usize,
    tell: usize,
    in_pool: bool,
    /// Whether this node still holds the signatures.
    held: bool,
    inputs: Vec<RingInputView>,
    /// Every ring's size, where they are all one size.
    ring_size: Option<usize>,
    /// Whether any ring has a decoy.
    decoys: bool,
    /// Whether any input's amount is in the clear, as a pre-RingCT output's
    /// is.
    pre_ringct: bool,
    /// The inputs whose rings have no decoys, as the last step says it.
    exposed: Option<String>,
    /// A type 1 MLSAG's bytes, rows and columns.
    full_sig: Option<(String, usize, usize)>,
    /// What an MLSAG over a ring this size takes, beside a CLSAG's.
    as_mlsag: Option<String>,
    fee: String,
    outputs: usize,
    /// A v1 transaction's inputs' and outputs' totals.
    plain: Option<(String, String)>,
    range: Option<RangeView>,
    compact_amounts: bool,
    map: Vec<ProofSegment>,
    map_labels: Option<map_labels::MapLabels>,
    timelines: [Timeline; 2],
    ring_facts: RingFacts,
    tell_pic: Vec<Dot>,
}

struct RingInputView {
    key_image: String,
    /// A pre-RingCT amount, in the clear.
    amount: Option<String>,
    size: usize,
    /// The blocks its members were made in, oldest first.
    blocks: Vec<u64>,
    unresolved: bool,
    offsets: String,
    indices: String,
    pseudo_out: Option<String>,
    sig_bytes: Option<String>,
    /// A CLSAG's commitment key image, as stored: D/8.
    d: Option<String>,
}

struct RangeView {
    name: &'static str,
    count: Option<usize>,
    bytes: Option<String>,
}

/// A dot in a step's picture.
struct Dot {
    x: u32,
    y: u32,
    r: &'static str,
    class: &'static str,
}

pub async fn ring_proof(State(state): Shared, Path(raw): Path<String>) -> Page {
    let mut chain = status_of(&state).await;
    let (entry, tx) = match fetch_tx(&state, &mut chain, &raw).await {
        Ok(found) => found,
        Err(page) => return page,
    };
    let hash = entry.tx_hash.to_lowercase();
    let Some(scheme) = Scheme::of(&tx) else {
        let why = if tx.is_coinbase() {
            "is a coinbase, which spends nothing"
        } else if tx.is_fcmp_pp() {
            "spends with FCMP++ rather than rings"
        } else {
            "has no ring signatures this explorer can walk through"
        };
        return error_page(
            chain,
            StatusCode::NOT_FOUND,
            "Not a ring signature",
            &format!("Transaction {hash} {why}."),
        );
    };
    // A pool transaction's ages count from the tip, so without the chain's
    // status its rings are shown as not looked up rather than as ages from 0.
    let (rings, v2) = if entry.in_pool && chain.is_none() {
        (Vec::new(), None)
    } else {
        tokio::join!(state.chain.resolve_rings(&tx), state.chain.v2_height())
    };
    render(
        StatusCode::OK,
        &ring_page(chain, &entry, &tx, scheme, &rings, v2),
    )
}

fn ring_page(
    chain: Option<ChainStatus>,
    entry: &TxEntry,
    tx: &TxJson,
    scheme: Scheme,
    rings: &[ResolvedInput],
    v2: Option<u64>,
) -> RingPage {
    let f = TxFacts::from_entry(entry, tx);
    let unknown_tip: &[ResolvedInput] = &[];
    let rings = if entry.in_pool && chain.is_none() {
        unknown_tip
    } else {
        rings
    };
    // Ages are measured against the block that spent them, or the tip for a
    // transaction still in the pool, as on the transaction's page.
    let clock = Clock {
        at: if entry.in_pool {
            chain.as_ref().map_or(0, |c| c.height)
        } else {
            entry.block_height
        },
        v2,
    };
    let prunable = tx.rctsig_prunable.as_ref();
    let keys: Vec<_> = tx.vin.iter().filter_map(|v| v.as_key()).collect();
    let pseudo_outs = tx.pseudo_outs();

    let titles: &[&'static str] = if scheme.pseudo_outs() {
        &[RING, COMMIT, SIGN, BALANCE, TELL]
    } else {
        &[RING, SIGN, BALANCE, TELL]
    };
    let at = |t: &str| titles.iter().position(|&s| s == t).map_or(0, |i| i + 1);
    let (commit, sign, balance, tell) = (at(COMMIT), at(SIGN), at(BALANCE), at(TELL));

    let sig_bytes = |i: usize| -> Option<usize> {
        match scheme {
            Scheme::CryptoNote => tx.ring_signatures_for_input(i).map(|s| s.len() * 64),
            Scheme::Mlsag => prunable?
                .mgs
                .as_ref()?
                .get(i)
                .map(|m| (m.ss.iter().map(Vec::len).sum::<usize>() + 1) * 32),
            Scheme::Clsag => prunable?
                .clsags
                .as_ref()?
                .get(i)
                .map(|c| (c.s.len() + 2) * 32),
            Scheme::MlsagFull => None,
        }
    };

    let inputs: Vec<RingInputView> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let ring = rings.get(i);
            let blocks: Vec<u64> = ring
                .map(|r| r.ring.iter().map(|m| m.block_height).collect())
                .unwrap_or_default();
            let mut sum = 0u64;
            let indices: Vec<String> = k
                .key_offsets
                .iter()
                .map(|o| {
                    sum = sum.saturating_add(*o);
                    grouped(sum)
                })
                .collect();
            RingInputView {
                key_image: k.k_image.clone(),
                amount: (k.amount != 0).then(|| xmr(k.amount)),
                size: k.key_offsets.len(),
                blocks,
                unresolved: ring.is_none_or(|r| r.ring_unavailable),
                offsets: k
                    .key_offsets
                    .iter()
                    .map(|&o| grouped(o))
                    .collect::<Vec<_>>()
                    .join(", "),
                indices: indices.join(", "),
                pseudo_out: pseudo_outs.get(i).cloned(),
                sig_bytes: sig_bytes(i).map(|b| grouped(b as u64)),
                d: prunable
                    .and_then(|p| p.clsags.as_ref())
                    .and_then(|c| c.get(i))
                    .map(|c| c.D.clone()),
            }
        })
        .collect();

    let sizes: Vec<usize> = inputs.iter().map(|i| i.size).collect();
    let ring_size = sizes
        .first()
        .copied()
        .filter(|&n| sizes.iter().all(|&s| s == n));
    let exposed: Vec<usize> = sizes
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n == 1)
        .map(|(i, _)| i + 1)
        .collect();

    let full = (scheme == Scheme::MlsagFull)
        .then(|| prunable?.mgs.as_ref()?.first())
        .flatten();
    let held = match scheme {
        Scheme::CryptoNote => tx.signatures.as_ref().is_some_and(|s| !s.is_empty()),
        Scheme::MlsagFull => full.is_some(),
        Scheme::Mlsag | Scheme::Clsag => inputs.iter().all(|i| i.sig_bytes.is_some()),
    };

    let range = range_view(tx);
    let map = if held {
        lay_bar(bar_parts(
            tx, scheme, &inputs, commit, sign, balance, &sig_bytes,
        ))
    } else {
        Vec::new()
    };

    let total = |amounts: Vec<u64>| xmr(amounts.into_iter().fold(0, u64::saturating_add));
    let plain = (scheme == Scheme::CryptoNote).then(|| {
        (
            total(keys.iter().map(|k| k.amount).collect()),
            total(tx.vout.iter().map(|o| o.amount).collect()),
        )
    });

    RingPage {
        version: VERSION,
        query: None,
        chain,
        hash: entry.tx_hash.to_lowercase(),
        steps: titles
            .iter()
            .enumerate()
            .map(|(i, &title)| StepLink { n: i + 1, title })
            .collect(),
        scheme: scheme.name(),
        signed_by: scheme.signed_by(),
        era: scheme.era(),
        cn: scheme == Scheme::CryptoNote,
        full: scheme == Scheme::MlsagFull,
        clsag: scheme == Scheme::Clsag,
        base_pseudo: tx.rct_type() == Some(RctType::Simple),
        commit,
        sign,
        balance,
        tell,
        in_pool: entry.in_pool,
        held,
        ring_size,
        decoys: sizes.iter().any(|&n| n > 1),
        pre_ringct: keys.iter().any(|k| k.amount != 0),
        exposed: exposed_text(&exposed, inputs.len()),
        full_sig: full.map(|m| {
            let bytes = (m.ss.iter().map(Vec::len).sum::<usize>() + 1) * 32;
            let rows = m.ss.first().map_or(0, Vec::len);
            (grouped(bytes as u64), rows, m.ss.len())
        }),
        as_mlsag: ring_size
            .filter(|_| scheme == Scheme::Clsag)
            .map(|n| grouped(((2 * n + 1) * 32) as u64)),
        fee: xmr(f.fee),
        outputs: tx.vout.len(),
        plain,
        range,
        compact_amounts: tx
            .rct_type()
            .and_then(RctType::ecdh_form)
            .is_some_and(|e| e == monerod_rpc::types::EcdhForm::Compact),
        map_labels: map_labels::map_labels(&map),
        map,
        timelines: [&WIDE, &NARROW].map(|g| timeline(g, &inputs, clock, entry.in_pool)),
        ring_facts: ring_facts(&inputs, clock),
        tell_pic: tell_pic(&sizes),
        inputs,
    }
}

/// The bar's parts: each input's pseudo-output and signature, in input
/// order, then the range proofs.
fn bar_parts(
    tx: &TxJson,
    scheme: Scheme,
    inputs: &[RingInputView],
    commit: usize,
    sign: usize,
    balance: usize,
    sig_bytes: &dyn Fn(usize) -> Option<usize>,
) -> Vec<(usize, &'static str, usize, String)> {
    let mut parts = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let n = i + 1;
        if input.pseudo_out.is_some() {
            parts.push((
                32,
                "pseudo",
                commit,
                format!("Input {n}'s pseudo-output, 32 bytes"),
            ));
        }
        if let Some(b) = sig_bytes(i) {
            parts.push((
                b,
                "ring",
                sign,
                format!("Input {n}'s ring signature, {} bytes", grouped(b as u64)),
            ));
        }
    }
    let prunable = tx.rctsig_prunable.as_ref();
    if scheme == Scheme::MlsagFull
        && let Some(m) = prunable
            .and_then(|p| p.mgs.as_ref())
            .and_then(|m| m.first())
    {
        let b = (m.ss.iter().map(Vec::len).sum::<usize>() + 1) * 32;
        parts.push((
            b,
            "ring",
            sign,
            format!("The ring signature, {} bytes", grouped(b as u64)),
        ));
    }
    let proofs = range_sizes(tx);
    let one = proofs.len() == 1;
    for (j, b) in proofs.into_iter().enumerate() {
        let what = match (prunable.and_then(|p| p.range_sigs.as_ref()).is_some(), one) {
            (true, _) => format!("Output {}'s range proof", j + 1),
            (false, true) => "The range proof".to_owned(),
            (false, false) => format!("Range proof {}", j + 1),
        };
        parts.push((
            b,
            "range",
            balance,
            format!("{what}, {} bytes", grouped(b as u64)),
        ));
    }
    parts
}

/// Bytes of a varint holding `n`.
fn varint_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// Each range proof's bytes as serialized: its points and scalars, 32 bytes
/// each, and a Bulletproof's length prefixes on `L` and `R`.
fn range_sizes(tx: &TxJson) -> Vec<usize> {
    let Some(p) = tx.rctsig_prunable.as_ref() else {
        return Vec::new();
    };
    if let Some(r) = &p.range_sigs {
        return r.iter().map(|s| (s.asig.len() + s.ci.len()) / 2).collect();
    }
    if let Some(b) = &p.bp {
        return b
            .iter()
            .map(|b| {
                (9 + b.L.len() + b.R.len()) * 32 + varint_len(b.L.len()) + varint_len(b.R.len())
            })
            .collect();
    }
    if let Some(b) = &p.bpp {
        return b
            .iter()
            .map(|b| {
                (6 + b.L.len() + b.R.len()) * 32 + varint_len(b.L.len()) + varint_len(b.R.len())
            })
            .collect();
    }
    Vec::new()
}

fn range_view(tx: &TxJson) -> Option<RangeView> {
    let name = match tx.rct_type()? {
        RctType::Full | RctType::Simple => "Borromean",
        RctType::Bulletproof | RctType::Bulletproof2 | RctType::Clsag => "Bulletproof",
        RctType::BulletproofPlus => "Bulletproofs+",
        _ => return None,
    };
    let sizes = range_sizes(tx);
    Some(RangeView {
        name,
        count: (!sizes.is_empty()).then_some(sizes.len()),
        bytes: (!sizes.is_empty()).then(|| grouped(sizes.iter().sum::<usize>() as u64)),
    })
}

/// The inputs with no decoys, as a sentence, or `None` where every ring has
/// some.
fn exposed_text(exposed: &[usize], inputs: usize) -> Option<String> {
    Some(match exposed {
        [] => return None,
        _ if inputs == 1 => {
            "Its ring holds a single output, so it shows which output it spent.".to_owned()
        }
        _ if exposed.len() == inputs => "No ring here holds more than one output, so every \
                                         input shows which output it spent."
            .to_owned(),
        [n] => {
            format!("Input {n}'s ring holds a single output, so it shows which output it spent.")
        }
        [rest @ .., last] => {
            let rest: Vec<String> = rest.iter().map(ToString::to_string).collect();
            format!(
                "Inputs {} and {last} have rings of a single output, so they show which \
                 outputs they spent.",
                rest.join(", ")
            )
        }
    })
}

/// Each ring along the chain: a row for every input, a dot for every
/// member, by how long before the spend it was made.
struct Timeline {
    g: &'static Geometry,
    height: u32,
    /// The rows' top and bottom, and the axis's line.
    top: u32,
    bottom: u32,
    axis_y: u32,
    spend: String,
    rows: Vec<TimelineRow>,
    ticks: Vec<TimelineTick>,
    /// The axis's right end, as an age.
    youngest: String,
}

struct TimelineRow {
    y: u32,
    label: String,
    /// A public amount, which the dots cannot show, and the width to squeeze
    /// it into where it would run past the label column.
    note: Option<(String, Option<u32>)>,
    /// For a ring of one, where "no decoys" is written beside its dot, and
    /// which way it runs.
    alone: Option<(u32, &'static str)>,
    unresolved: bool,
    /// From the oldest member to the spend.
    band_x: u32,
    dots: Vec<TimelineDot>,
    solid: bool,
}

struct TimelineDot {
    x: u32,
    block: u64,
    title: String,
}

struct TimelineTick {
    x: u32,
    label: &'static str,
}

/// A timeline's layout: its width, its label column, where its youngest age
/// sits and the spend's place. Drawn wide, and narrow for a narrow column.
pub(super) struct Geometry {
    class: &'static str,
    width: u32,
    left: u32,
    young: u32,
    spend: u32,
}

const WIDE: Geometry = Geometry {
    class: "w",
    width: 860,
    left: 120,
    young: 816,
    spend: 846,
};
const NARROW: Geometry = Geometry {
    class: "n",
    width: 400,
    left: 84,
    young: 372,
    spend: 392,
};

/// Rows a timeline draws with room to spare.
const TL_ROOMY: usize = 8;
/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`: since hard fork 12, the youngest a
/// ring member can be, in blocks, and the wallets' rule before it. The axis
/// ends there, or at a younger member.
const SPENDABLE_AGE: u64 = 10;
/// The widest a character of a note runs, in its 10.5px font: digits and
/// "XMR" are about 0.55em.
const NOTE_PX_PER_CHAR: u32 = 6;

/// Where an age sits along a timeline: logarithmic, as on the age strips of
/// the transaction's page, from `oldest` at the left to `young` at the
/// geometry's `young`.
fn timeline_x(g: &Geometry, age: u64, oldest: u64, young: u64) -> u32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a chart coordinate, not chain arithmetic"
    )]
    let (age, oldest, young) = (age as f64, oldest as f64, young.max(1) as f64);
    let span = (oldest / young).ln();
    let w = f64::from(g.young - g.left);
    if span <= 0.0 {
        return g.young;
    }
    let from_left = w * (1.0 - (age / young).ln() / span);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to the axis before the cast"
    )]
    let x = from_left.clamp(0.0, w).round() as u32;
    g.left + x
}

/// The youngest and oldest ages of any member, in blocks.
fn age_span(inputs: &[RingInputView], spent_at: u64) -> Option<(u64, u64)> {
    let ages = inputs
        .iter()
        .flat_map(|i| &i.blocks)
        .map(|&h| spent_at.saturating_sub(h));
    let (lo, hi) = ages.fold((u64::MAX, 0), |(lo, hi), a| (lo.min(a), hi.max(a)));
    (lo <= hi).then_some((lo, hi))
}

fn timeline(
    g: &'static Geometry,
    inputs: &[RingInputView],
    clock: Clock,
    in_pool: bool,
) -> Timeline {
    let spent_at = clock.at;
    let (youngest, oldest) = age_span(inputs, spent_at).unwrap_or((SPENDABLE_AGE, 0));
    let young = youngest.clamp(1, SPENDABLE_AGE);
    let x = |age: u64| timeline_x(g, age, oldest, young);
    let room = g.left.saturating_sub(8);
    let notes: Vec<Option<(String, Option<u32>)>> = inputs
        .iter()
        .map(|input| {
            input.amount.as_ref().map(|a| {
                let text = format!("{a} XMR");
                let wide = u32::try_from(text.chars().count())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(NOTE_PX_PER_CHAR);
                (text, (wide > room).then_some(room))
            })
        })
        .collect();
    let pitch: u32 = match (inputs.len() <= TL_ROOMY, notes.iter().any(Option::is_some)) {
        (true, _) => 44,
        (false, true) => 32,
        (false, false) => 22,
    };
    let top = 30;

    let rows = inputs
        .iter()
        .zip(notes)
        .zip((0u32..).map(|r| top + pitch / 2 + r * pitch))
        .enumerate()
        .map(|(i, ((input, note), y))| {
            let dots: Vec<TimelineDot> = input
                .blocks
                .iter()
                .map(|&block| {
                    let age = spent_at.saturating_sub(block);
                    let when = clock
                        .minutes(age)
                        .map(|_| format!(" ({})", clock.age(age)))
                        .unwrap_or_default();
                    TimelineDot {
                        x: x(age),
                        block,
                        title: format!(
                            "Block {}, {} before the spend{when}",
                            grouped(block),
                            Clock { at: 0, v2: None }.age(age)
                        ),
                    }
                })
                .collect();
            let alone = (input.size == 1).then(|| dots.first()).flatten().map(|d| {
                if d.x + 90 < g.spend {
                    (d.x + 12, "start")
                } else {
                    (d.x - 12, "end")
                }
            });
            TimelineRow {
                y,
                label: format!("Input {}", i + 1),
                note,
                alone,
                unresolved: input.unresolved,
                band_x: dots.iter().map(|d| d.x).min().unwrap_or(g.spend),
                solid: input.size == 1,
                dots,
            }
        })
        .collect::<Vec<_>>();

    let rows_n = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    let bottom = top.saturating_add(pitch.saturating_mul(rows_n));
    let axis_y = bottom + 6;
    Timeline {
        g,
        height: axis_y + 22,
        top,
        bottom,
        axis_y,
        spend: if in_pool {
            "waiting in the pool".to_owned()
        } else {
            format!("spent in block {}", grouped(spent_at))
        },
        rows,
        // Only the range the rings cover, as on the transaction's page.
        ticks: AGE_TICKS
            .iter()
            .filter_map(|&(minutes, label)| Some((clock.blocks(minutes)?, label)))
            .filter(|&(age, _)| age <= oldest)
            .map(|(age, label)| TimelineTick { x: x(age), label })
            .collect(),
        youngest: clock.age(young),
    }
}

/// Step 1's facts: the rings' sizes, and their oldest and youngest members.
struct RingFacts {
    rings: String,
    oldest: Option<(u64, String)>,
    youngest: Option<(u64, String)>,
    /// Whether a member is younger than [`SPENDABLE_AGE`], which only an
    /// older ring could hold.
    under_age: bool,
}

fn ring_facts(inputs: &[RingInputView], clock: Clock) -> RingFacts {
    let sizes: Vec<usize> = inputs.iter().map(|i| i.size).collect();
    let (lo, hi) = (
        sizes.iter().copied().min().unwrap_or(0),
        sizes.iter().copied().max().unwrap_or(0),
    );
    let n = inputs.len();
    let rings = match (n, lo == hi) {
        (1, _) => format!("1 ring of {lo} output{}", if lo == 1 { "" } else { "s" }),
        (_, true) => format!(
            "{n} rings of {lo} output{} each",
            if lo == 1 { "" } else { "s" }
        ),
        (_, false) => format!("{n} rings, of {lo} to {hi} outputs"),
    };
    let blocks = inputs.iter().flat_map(|i| &i.blocks).copied();
    let member = |h: Option<u64>| {
        h.map(|h| {
            let age = clock.at.saturating_sub(h);
            (h, clock.age(age))
        })
    };
    let span = age_span(inputs, clock.at);
    RingFacts {
        rings,
        oldest: member(blocks.clone().min()),
        youngest: member(blocks.max()),
        under_age: span.is_some_and(|(young, _)| young < SPENDABLE_AGE),
    }
}

const PIC_ROW_MAX: usize = 16;
const PIC_ROWS: usize = 5;

/// A row of dots for each of the first inputs, one dot per ring member.
fn tell_pic(sizes: &[usize]) -> Vec<Dot> {
    let rows = sizes.len().min(PIC_ROWS);
    let Some(top) = u32::try_from(rows)
        .ok()
        .map(|r| 60 - (r.saturating_sub(1) * 22) / 2)
    else {
        return Vec::new();
    };
    sizes
        .iter()
        .take(rows)
        .zip((0u32..).map(|row| top + row * 22))
        .flat_map(|(&n, y)| {
            let shown = n.min(PIC_ROW_MAX);
            let class = if n == 1 { "solid" } else { "node" };
            (0..shown).map(move |i| {
                let x = match (u32::try_from(i), u32::try_from(shown)) {
                    (Ok(i), Ok(s)) if s > 1 => 22 + i * 156 / (s - 1),
                    _ => 100,
                };
                Dot {
                    x,
                    y,
                    r: "4.5",
                    class,
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use explorer_core::{Hash32, RingMember};

    fn fixture(json: &str) -> (TxEntry, TxJson) {
        let resp: monerod_rpc::types::GetTransactionsResponse =
            serde_json::from_str(json).expect("a fixture");
        let entry = resp.txs.into_iter().last().expect("a transaction");
        let tx = entry.parse_json().expect("decodes");
        (entry, tx)
    }

    fn rct1() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct1_full.json"
        ))
    }
    fn rct2() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_ringct.json"
        ))
    }
    fn rct3() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct3_bulletproof.json"
        ))
    }
    fn rct4() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct4_mixed_pruned.json"
        ))
    }
    fn rct5() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct5_clsag.json"
        ))
    }
    fn rct6() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct6_complete.json"
        ))
    }
    fn v1() -> (TxEntry, TxJson) {
        fixture(include_str!(
            "../../../../fixtures/testnet/get_transactions_multi_input.json"
        ))
    }

    fn page(f: &(TxEntry, TxJson)) -> RingPage {
        let scheme = Scheme::of(&f.1).expect("a ring signature");
        ring_page(None, &f.0, &f.1, scheme, &[], Some(1))
    }

    #[test]
    fn each_ring_era_type_has_its_scheme() {
        assert_eq!(Scheme::of(&v1().1), Some(Scheme::CryptoNote));
        assert_eq!(Scheme::of(&rct1().1), Some(Scheme::MlsagFull));
        for f in [rct2(), rct3(), rct4()] {
            assert_eq!(Scheme::of(&f.1), Some(Scheme::Mlsag));
        }
        for f in [rct5(), rct6()] {
            assert_eq!(Scheme::of(&f.1), Some(Scheme::Clsag));
        }
        let coinbase = fixture(include_str!(
            "../../../../fixtures/mainnet/get_transactions_coinbase_v2.json"
        ));
        assert_eq!(Scheme::of(&coinbase.1), None);
        let fcmp = fixture(include_str!(
            "../../../../fixtures/fcmp/get_transactions_fcmp.json"
        ));
        assert_eq!(Scheme::of(&fcmp.1), None);
    }

    /// The bar's parts are the prunable half's bytes, less only the length
    /// prefixes it frames the range proofs with.
    #[test]
    fn the_bar_is_the_prunable_half_to_the_byte() {
        for f in [v1(), rct1(), rct3(), rct4(), rct5(), rct6()] {
            let p = page(&f);
            assert!(p.held, "{}", f.0.tx_hash);
            let blob = f.0.prunable_as_hex.len() / 2;
            assert!(blob > 0);
            let prunable = f.1.rctsig_prunable.as_ref();
            let bps: Vec<(usize, usize)> = prunable
                .and_then(|p| {
                    p.bp.as_ref()
                        .map(|b| b.iter().map(|b| (b.L.len(), b.R.len())).collect())
                        .or_else(|| {
                            p.bpp
                                .as_ref()
                                .map(|b| b.iter().map(|b| (b.L.len(), b.R.len())).collect())
                        })
                })
                .unwrap_or_default();
            // Each proof counts its own L and R prefixes, a byte each at
            // these lengths. Only the proofs' count is left: a uint32 in type
            // 3, a one-byte varint after.
            assert!(bps.iter().all(|&(l, r)| l < 0x80 && r < 0x80) && bps.len() < 0x80);
            let framing = match f.1.rct_type() {
                Some(RctType::Bulletproof) => 4,
                Some(t) if t.to_raw() >= 4 => 1,
                _ => 0,
            };
            let drawn: usize = p.map.iter().map(|g| g.bytes).sum();
            assert_eq!(drawn + framing, blob, "{}", f.0.tx_hash);
        }
    }

    #[test]
    fn each_signature_is_sized_by_its_scheme() {
        let p = page(&v1());
        let rings: Vec<usize> = p.inputs.iter().map(|i| i.size).collect();
        let sigs: Vec<usize> = p
            .map
            .iter()
            .filter(|g| g.class == "ring")
            .map(|g| g.bytes)
            .collect();
        assert_eq!(sigs, rings.iter().map(|n| n * 64).collect::<Vec<_>>());
        assert!(p.map.iter().all(|g| g.class == "ring"));

        let p = page(&rct5());
        let n = p.ring_size.expect("one size");
        assert_eq!(n, 11);
        assert_eq!(p.inputs[0].sig_bytes.as_deref(), Some("416"));
        assert_eq!(p.as_mlsag.as_deref(), Some("736"));
        let classes: Vec<_> = p.map.iter().map(|g| (g.class, g.step)).collect();
        assert_eq!(classes, [("pseudo", 2), ("ring", 3), ("range", 4)]);

        let p = page(&rct1());
        assert_eq!(p.full_sig, Some(("224".to_owned(), 2, 3)));
        assert!(
            p.inputs
                .iter()
                .all(|i| i.pseudo_out.is_none() && i.sig_bytes.is_none())
        );
        let ranges: Vec<_> = p
            .map
            .iter()
            .filter(|g| g.class == "range")
            .map(|g| (g.bytes, g.step))
            .collect();
        assert_eq!(ranges.len(), f_outputs(&rct1()));
        assert!(ranges.iter().all(|&r| r == (6_176, 3)));
    }

    fn f_outputs(f: &(TxEntry, TxJson)) -> usize {
        f.1.vout.len()
    }

    #[test]
    fn each_scheme_walks_its_own_steps() {
        let cases = [
            (v1(), 4, "Ring signatures of "),
            (rct1(), 4, "MLSAG of "),
            (rct2(), 5, "MLSAG of "),
            (rct5(), 5, "CLSAG of "),
            (rct6(), 5, "CLSAG of "),
        ];
        for (f, steps, title) in cases {
            let p = page(&f);
            assert_eq!(p.steps.len(), steps);
            let html = p.render().expect("renders");
            assert!(html.contains(&format!("<title>{title}{}", f.0.tx_hash)));
            for n in 1..=steps {
                assert_eq!(html.matches(&format!(r#"id="s{n}""#)).count(), 1);
            }
            assert!(!html.contains(&format!(r#"id="s{}""#, steps + 1)));
            assert_eq!(html.matches("&larr; Back").count(), steps - 1);
            assert_eq!(html.matches("Start again").count(), 1);
            assert!(
                html.rfind(r#"id="s1""#) > html.rfind(&format!(r#"id="s{steps}""#)),
                "step 1 comes last, for the stylesheet's `~`"
            );
            assert!(!html.contains(" style="), "the CSP drops inline styles");
            assert!(!html.contains("<script"));
            for i in &p.inputs {
                assert!(html.contains(&format!(r#"<dd class="hash mark">{}</dd>"#, i.key_image)));
            }
            assert_eq!(html.contains("Commit to the amount afresh"), steps == 5);
        }
    }

    #[test]
    fn the_pseudo_outputs_and_d_are_read_from_where_each_type_keeps_them() {
        for f in [rct2(), rct3(), rct5()] {
            let p = page(&f);
            let html = p.render().expect("renders");
            for (i, want) in f.1.pseudo_outs().iter().enumerate() {
                assert_eq!(p.inputs[i].pseudo_out.as_ref(), Some(want));
                assert!(html.contains(&format!(
                    r#"<dd><span class="hash">{want}</span> <span class="tag">pseudo-output</span></dd>"#
                )));
            }
            assert!(!f.1.pseudo_outs().is_empty());
        }
        let f = rct5();
        let d =
            &f.1.rctsig_prunable
                .as_ref()
                .unwrap()
                .clsags
                .as_ref()
                .unwrap()[0]
                .D;
        let html = page(&f).render().expect("renders");
        assert!(html.contains(&format!(
            r#"<dt>Input 1 &middot; D/8</dt><dd class="hash">{d}</dd>"#
        )));
        assert!(!page(&rct3()).render().expect("renders").contains("D/8"));
    }

    #[test]
    fn each_type_names_its_range_proof_and_its_encrypted_amounts() {
        let cases = [
            (rct1(), "Borromean", false),
            (rct2(), "Borromean", false),
            (rct3(), "Bulletproof", false),
            (rct5(), "Bulletproof", true),
            (rct6(), "Bulletproofs+", true),
        ];
        for (f, name, compact) in cases {
            let p = page(&f);
            assert_eq!(
                p.range.as_ref().map(|r| r.name),
                Some(name),
                "{}",
                f.0.tx_hash
            );
            assert_eq!(p.compact_amounts, compact, "{}", f.0.tx_hash);
            let html = p.render().expect("renders");
            assert_eq!(html.contains("<dd>8 bytes for each output</dd>"), compact);
        }
        let html = page(&rct6()).render().unwrap();
        assert!(html.contains("<dd>1 Bulletproofs+ proof over the outputs, 642 bytes</dd>"));
        let html = page(&rct2()).render().unwrap();
        assert!(
            html.contains("<dd>7 Borromean range proofs, one for each output, 43,232 bytes</dd>")
        );
        assert!(page(&v1()).range.is_none());
    }

    /// A RingCT input that spends a pre-RingCT output names its amount, and
    /// the fee is no longer the only amount shown.
    #[test]
    fn a_ringct_spend_of_a_pre_ringct_output_shows_its_amount() {
        let mut f = rct2();
        assert_eq!(f.1.vin.len(), 2);
        if let Some(monerod_rpc::types::TxIn::Key(k)) = f.1.vin.first_mut() {
            k.amount = 5_000_000_000;
        }
        let p = page(&f);
        assert!(p.pre_ringct);
        let html = p.render().expect("renders");
        assert!(html.contains(">0.005 XMR</text>"));
        assert!(html.contains("public, amount."));
        assert!(html.contains("under a mask of 1"));
        assert!(!html.contains("the only amount in the clear"));
        assert!(html.contains("only the fee and the pre-RingCT amounts are shown"));
        assert!(!page(&rct5()).pre_ringct);
        assert!(
            page(&rct5())
                .render()
                .unwrap()
                .contains("XMR, the only amount in the clear</dd>")
        );
    }

    /// Rings of different sizes, as before November 2019, are each counted.
    #[test]
    fn rings_of_different_sizes_are_counted_apart() {
        let mut f = v1();
        let mut keys = f.1.vin.iter_mut().filter_map(|v| match v {
            monerod_rpc::types::TxIn::Key(k) => Some(k),
            _ => None,
        });
        keys.next().unwrap().key_offsets.truncate(2);
        keys.next().unwrap().key_offsets.truncate(1);
        let p = ring_page(None, &f.0, &f.1, Scheme::CryptoNote, &[], Some(1));
        assert_eq!(p.ring_size, None);
        assert_eq!(
            p.exposed.as_deref(),
            Some("Input 2's ring holds a single output, so it shows which output it spent.")
        );
        let html = p.render().expect("renders");
        assert!(html.contains(
            "<dt>Input 1 could be spending</dt><dd>any of the 2 outputs in its ring</dd>"
        ));
        assert!(html.contains(
            "<dt>Input 2 could be spending</dt><dd>only the one output in its ring</dd>"
        ));
        assert!(html.contains("It names a ring: a few outputs"));
        assert!(page(&v1()).ring_size.is_some());
    }

    #[test]
    fn a_pruned_spend_says_so_and_draws_no_bar() {
        let resp: monerod_rpc::types::GetTransactionsResponse = serde_json::from_str(include_str!(
            "../../../../fixtures/mainnet/get_transactions_rct4_mixed_pruned.json"
        ))
        .unwrap();
        let entry = resp.txs.into_iter().next().unwrap();
        let tx = entry.parse_json().unwrap();
        assert!(tx.rctsig_prunable.is_none());
        let p = ring_page(None, &entry, &tx, Scheme::Mlsag, &[], Some(1));
        assert!(!p.held);
        assert!(p.map.is_empty());
        let html = p.render().expect("renders");
        assert!(html.contains("no longer holds this transaction's signatures and range proofs"));
        assert!(!html.contains("proof-map"));
        assert!(html.contains("<dt>Range proof</dt><dd>Bulletproofs over the outputs</dd>"));
        assert!(!page(&rct3()).render().unwrap().contains("no longer holds"));

        let (entry, mut tx) = rct1();
        tx.rctsig_prunable = None;
        let p = ring_page(None, &entry, &tx, Scheme::MlsagFull, &[], Some(1));
        assert!(!p.held && p.map.is_empty() && p.full_sig.is_none());
    }

    fn resolved(heights: &[u64]) -> ResolvedInput {
        ResolvedInput {
            amount: 0,
            key_image: Hash32::ZERO,
            ring: heights
                .iter()
                .enumerate()
                .map(|(i, &block_height)| RingMember {
                    index: i as u64,
                    block_height,
                    public_key: Hash32::ZERO,
                    tx_hash: Hash32::ZERO,
                })
                .collect(),
            ring_unavailable: false,
        }
    }

    /// Every member is a dot on its input's row, linked to its block and
    /// placed by its age: the oldest at the left edge, the youngest that can
    /// be spent at the right.
    #[test]
    fn the_timeline_places_every_member_by_its_age() {
        let f = rct5();
        let k = f.1.vin[0].as_key().unwrap();
        let spent = f.0.block_height;
        let mut heights: Vec<u64> = (0..k.key_offsets.len() as u64)
            .map(|i| spent - 10 - i * 300)
            .collect();
        heights.reverse();
        heights[1] = heights[2];
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&heights)],
            Some(1),
        );
        assert_eq!(p.inputs[0].blocks, heights, "every member, twins included");
        let row = &p.timelines[0].rows[0];
        let xs: Vec<u32> = row.dots.iter().map(|d| d.x).collect();
        assert_eq!(xs.len(), 11);
        assert_eq!(xs.first(), Some(&WIDE.left), "the oldest at the left edge");
        assert_eq!(xs.last(), Some(&WIDE.young), "ten blocks old at the right");
        assert!(xs.windows(2).all(|w| w[0] <= w[1]), "younger further right");
        assert_eq!(xs[1], xs[2]);
        assert_eq!(row.band_x, WIDE.left);
        assert_eq!(row.note, None);
        assert_eq!(
            p.timelines[0].spend,
            format!("spent in block {}", grouped(spent))
        );
        assert!(p.render().unwrap().contains(&format!(
            r#"<text class="tick" x="{}" y="{}" text-anchor="middle">20 min</text>"#,
            WIDE.young,
            p.timelines[0].axis_y + 16
        )));
        let labels: Vec<_> = p.timelines[0].ticks.iter().map(|t| t.label).collect();
        assert_eq!(labels, ["1h", "6h", "1d"], "only ages the ring reaches");

        let html = p.render().expect("renders");
        let oldest = heights[0];
        assert!(html.contains(&format!(
            r#"<a href="/block/{oldest}"><circle class="mem" cx="{}" cy="{}" r="6"><title>Block {}, 3,010 blocks before the spend (4 d)</title></circle></a>"#,
            WIDE.left,
            row.y,
            grouped(oldest)
        )));
        assert_eq!(
            html.matches(r#"<circle class="mem""#).count(),
            22,
            "11 in each layout"
        );
        assert!(html.contains("<text class=\"tick\""));
        assert!(html.contains(&format!("Input 1's offsets, {},", p.inputs[0].offsets)));
        let mut sum = 0;
        let indices: Vec<String> = k
            .key_offsets
            .iter()
            .map(|o| {
                sum += o;
                grouped(sum)
            })
            .collect();
        assert_eq!(p.inputs[0].indices, indices.join(", "));

        let unresolved = page(&f);
        assert!(unresolved.inputs[0].unresolved);
        let html = unresolved.render().unwrap();
        assert!(html.contains("this node could not look up this ring"));
        assert!(!html.contains(r#"<circle class="mem""#));
    }

    #[test]
    fn the_timeline_axis_runs_from_the_oldest_member_to_ten_blocks() {
        assert_eq!(timeline_x(&WIDE, 5_000, 5_000, SPENDABLE_AGE), WIDE.left);
        assert_eq!(timeline_x(&WIDE, 10, 5_000, SPENDABLE_AGE), WIDE.young);
        assert_eq!(
            timeline_x(&WIDE, 3, 5_000, SPENDABLE_AGE),
            WIDE.young,
            "nothing younger exists"
        );
        assert_eq!(
            timeline_x(&WIDE, 10, 10, SPENDABLE_AGE),
            WIDE.young,
            "no span to spread over"
        );
        let mid = timeline_x(&WIDE, 224, 5_000, SPENDABLE_AGE);
        assert!((WIDE.left + 1..WIDE.young).contains(&mid));
        // Logarithmic: equal ratios of age take equal widths.
        let a = timeline_x(&WIDE, 100, 10_000, SPENDABLE_AGE)
            - timeline_x(&WIDE, 1_000, 10_000, SPENDABLE_AGE);
        let b = timeline_x(&WIDE, 1_000, 10_000, SPENDABLE_AGE)
            - timeline_x(&WIDE, 10_000, 10_000, SPENDABLE_AGE);
        assert!(a.abs_diff(b) <= 1, "{a} {b}");
    }

    /// A transaction in the pool is measured against the tip.
    #[test]
    fn a_pool_spend_is_measured_against_the_tip() {
        let (mut entry, tx) = rct5();
        entry.in_pool = true;
        let chain = ChainStatus {
            height: 1_000,
            nettype: String::new(),
            difficulty: String::new(),
            pool: 1,
            target: 120,
            syncing: false,
        };
        let p = ring_page(
            Some(chain),
            &entry,
            &tx,
            Scheme::Clsag,
            &[resolved(&[500, 990])],
            Some(1),
        );
        assert_eq!(p.timelines[0].spend, "waiting in the pool");
        let xs: Vec<u32> = p.timelines[0].rows[0].dots.iter().map(|d| d.x).collect();
        assert_eq!(xs, [WIDE.left, WIDE.young]);
    }

    /// What a dot cannot show is written under the input's name: a public
    /// amount, or a ring with no decoys.
    #[test]
    fn each_row_notes_what_its_dots_cannot_show() {
        let mut f = v1();
        for (i, v) in f.1.vin.iter_mut().take(2).enumerate() {
            if let monerod_rpc::types::TxIn::Key(k) = v {
                k.key_offsets.truncate(i + 1);
            }
        }
        let p = page(&f);
        let html = p.render().expect("renders");
        assert_eq!(
            html.matches(r#"<circle class="mem only""#).count(),
            0,
            "no lookup, no dots"
        );
        let rings: Vec<_> = (0..f.1.vin.len()).map(|_| resolved(&[100, 200])).collect();
        let drawn = ring_page(None, &f.0, &f.1, Scheme::CryptoNote, &rings, Some(1));
        let html = drawn.render().unwrap();
        assert!(html.contains(r#"<circle class="mem only""#));
        let row = &drawn.timelines[0].rows[0];
        let (x, anchor) = row.alone.expect("a ring of one");
        assert_eq!((x, anchor), (row.dots[0].x + 12, "start"));
        assert!(html.contains(&format!(
            r#"<text class="alone" x="{x}" y="{}" text-anchor="start">no decoys</text>"#,
            row.y + 4
        )));
        assert_eq!(
            html.matches(">no decoys</text>").count(),
            2,
            "once in each layout"
        );
        assert!(drawn.timelines[0].rows[1].alone.is_none());
        // Near the spend, it runs the other way.
        let mut young = f.clone();
        young.0.block_height = 100;
        let rings: Vec<_> = (0..f.1.vin.len()).map(|_| resolved(&[90])).collect();
        let p2 = ring_page(
            None,
            &young.0,
            &young.1,
            Scheme::CryptoNote,
            &rings,
            Some(1),
        );
        let row = &p2.timelines[0].rows[0];
        assert_eq!(row.alone, Some((row.dots[0].x - 12, "end")));
        let amount = |i: usize| xmr(f.1.vin[i].as_key().unwrap().amount);
        assert_eq!(
            p.timelines[0].rows[0].note,
            Some((format!("{} XMR", amount(0)), None))
        );
        assert_eq!(
            p.timelines[0].rows[0].alone, None,
            "no dot to write it beside"
        );
        assert_eq!(
            p.timelines[0].rows[1].note,
            Some((format!("{} XMR", amount(1)), None))
        );
        assert!(p.timelines[0].rows[0].solid && !p.timelines[0].rows[1].solid);
        assert!(
            page(&rct5()).timelines[0]
                .rows
                .iter()
                .all(|r| r.note.is_none())
        );
        // More than eight rows close up, unless one has a note to fit.
        let pitch = |p: &RingPage| p.timelines[0].rows[1].y - p.timelines[0].rows[0].y;
        assert_eq!(pitch(&p), 44, "up to eight rows have room");
        let mut eight = rct5();
        let input = eight.1.vin[0].clone();
        eight.1.vin = vec![input; 8];
        assert_eq!(pitch(&page(&eight)), 44);
        let mut many = rct5();
        let input = many.1.vin[0].clone();
        many.1.vin = vec![input; 9];
        assert_eq!(pitch(&page(&many)), 22);
        let mut noted = v1();
        let input = noted.1.vin[0].clone();
        noted.1.vin = vec![input; 9];
        assert_eq!(pitch(&page(&noted)), 32, "nine rows, with notes to fit");
    }

    #[test]
    fn a_v1_spend_shows_its_amounts() {
        let f = v1();
        let p = page(&f);
        let ins: u64 =
            f.1.vin
                .iter()
                .filter_map(|v| v.as_key())
                .map(|k| k.amount)
                .sum();
        let outs: u64 = f.1.vout.iter().map(|o| o.amount).sum();
        assert_eq!(p.plain, Some((xmr(ins), xmr(outs))));
        assert_eq!(xmr(ins - outs), p.fee);
        let html = p.render().expect("renders");
        assert!(html.contains(&format!("<dd>{} XMR, in the clear</dd>", xmr(ins))));
        assert!(html.contains("<dd>In the clear, and they balance.</dd>"));
        assert!(!html.contains("pseudo-output"));
        for k in f.1.vin.iter().filter_map(|v| v.as_key()) {
            assert!(html.contains(&format!(">{} XMR</text>", xmr(k.amount))));
        }
        let ringct = page(&rct5()).render().unwrap();
        assert!(!ringct.contains(" XMR</text>"));
        assert!(ringct.contains("<dd>They balance, and only the fee is shown.</dd>"));
    }

    #[test]
    fn rings_without_decoys_are_named() {
        assert_eq!(exposed_text(&[], 3), None);
        assert_eq!(
            exposed_text(&[1], 1).as_deref(),
            Some("Its ring holds a single output, so it shows which output it spent.")
        );
        assert_eq!(
            exposed_text(&[1, 2], 2).as_deref(),
            Some(
                "No ring here holds more than one output, so every input shows which output it spent."
            )
        );
        assert_eq!(
            exposed_text(&[2], 3).as_deref(),
            Some("Input 2's ring holds a single output, so it shows which output it spent.")
        );
        assert_eq!(
            exposed_text(&[1, 3, 4], 5).as_deref(),
            Some(
                "Inputs 1, 3 and 4 have rings of a single output, so they show which outputs they spent."
            )
        );

        let mut f = v1();
        for v in &mut f.1.vin {
            if let monerod_rpc::types::TxIn::Key(k) = v {
                k.key_offsets.truncate(1);
            }
        }
        let p = ring_page(None, &f.0, &f.1, Scheme::CryptoNote, &[], Some(1));
        assert!(!p.decoys);
        let html = p.render().expect("renders");
        assert!(html.contains("Every ring in this transaction holds a single output"));
        assert!(html.contains("spent the one output in its ring"));
        assert!(html.contains("Here\neach ring holds only its own output."));
        assert!(
            !page(&v1())
                .render()
                .unwrap()
                .contains("each ring holds only its own output")
        );
        assert!(!html.contains("without saying which"));
        assert!(!html.contains(r#"class="q""#));
        assert!(html.contains("<dd>only the one output in its ring</dd>"));
    }

    #[test]
    fn the_last_step_draws_a_row_for_each_ring() {
        let rows = tell_pic(&[16, 1, 11, 11, 11, 11]);
        assert_eq!(rows.len(), 16 + 1 + 11 * 3);
        let ys: std::collections::BTreeSet<u32> = rows.iter().map(|d| d.y).collect();
        assert_eq!(ys.len(), PIC_ROWS);
        assert!(rows.iter().all(|d| (22..=178).contains(&d.x) && d.y < 120));
        assert_eq!(rows.iter().filter(|d| d.class == "solid").count(), 1);
    }

    /// A ring from before November 2019 may hold a member younger than ten
    /// blocks, and the axis then ends at it rather than drawing it there.
    #[test]
    fn the_axis_ends_at_a_member_younger_than_ten_blocks() {
        let f = rct5();
        let spent = f.0.block_height;
        let heights: Vec<u64> = (0..11).map(|i| spent - 3 - i * 100).collect();
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&heights)],
            Some(1),
        );
        let row = &p.timelines[0].rows[0];
        assert_eq!(
            row.dots[0].x, WIDE.young,
            "the three-block-old member at the end"
        );
        assert!(row.dots[1].x < WIDE.young);
        assert_eq!(p.timelines[0].youngest, "6 min");
        assert!(p.ring_facts.under_age);
        let html = p.render().unwrap();
        assert!(html.contains("The axis ends at the youngest\nmember"));
        assert!(!html.contains("the youngest a ring member can be"));

        let usual: Vec<u64> = (0..11).map(|i| spent - 10 - i * 100).collect();
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&usual)],
            Some(1),
        );
        assert_eq!(p.timelines[0].youngest, "20 min");
        assert!(!p.ring_facts.under_age);
        let html = p.render().unwrap();
        assert!(html.contains("the youngest a ring member can be"));
    }

    /// A pool transaction's ages count from the tip, so without the chain's
    /// status its rings read as not looked up, not as ages from block 0.
    #[test]
    fn a_pool_spend_without_the_tip_has_no_ages() {
        let mut f = rct5();
        let spent = f.0.block_height;
        f.0.in_pool = true;
        let heights: Vec<u64> = (0..11).map(|i| spent - 10 - i * 300).collect();
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&heights)],
            Some(1),
        );
        assert!(p.inputs.iter().all(|i| i.unresolved && i.blocks.is_empty()));
        assert!(!p.ring_facts.under_age);
        assert_eq!(p.ring_facts.oldest, None);
    }

    /// Where the daemon will not say where hard fork 2 began, ages are in
    /// blocks and the axis carries no times.
    #[test]
    fn without_the_fork_height_ages_are_in_blocks() {
        let f = rct5();
        let spent = f.0.block_height;
        let heights: Vec<u64> = (0..11).map(|i| spent - 10 - i * 300).collect();
        let p = ring_page(None, &f.0, &f.1, Scheme::Clsag, &[resolved(&heights)], None);
        let t = &p.timelines[0];
        assert!(t.ticks.is_empty());
        assert_eq!(t.youngest, "10 blocks");
        assert_eq!(
            t.rows[0].dots[10].title,
            format!(
                "Block {}, 3,010 blocks before the spend",
                grouped(spent - 3_010)
            )
        );
        assert_eq!(
            p.ring_facts.oldest,
            Some((spent - 3_010, "3,010 blocks".to_owned()))
        );
    }

    #[test]
    fn step_one_sums_up_the_rings() {
        let f = rct5();
        let spent = f.0.block_height;
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&[spent - 720, spent - 30])],
            Some(1),
        );
        assert_eq!(p.ring_facts.rings, "1 ring of 11 outputs");
        assert_eq!(p.ring_facts.oldest, Some((spent - 720, "1 d".to_owned())));
        assert_eq!(p.ring_facts.youngest, Some((spent - 30, "1 h".to_owned())));
        let html = p.render().unwrap();
        assert!(html.contains(&format!(
            r#"<dt>Oldest member</dt><dd>block <a href="/block/{0}">{0}</a>, 1 d before the spend</dd>"#,
            spent - 720
        )));
        assert_eq!(page(&rct2()).ring_facts.rings, "2 rings of 4 outputs each");
        let mut mixed = v1();
        if let Some(monerod_rpc::types::TxIn::Key(k)) = mixed.1.vin.first_mut() {
            k.key_offsets.truncate(1);
        }
        assert_eq!(
            page(&mixed).ring_facts.rings,
            format!("{} rings, of 1 to 16 outputs", mixed.1.vin.len())
        );
        let mut one = v1();
        one.1.vin.truncate(1);
        if let Some(monerod_rpc::types::TxIn::Key(k)) = one.1.vin.first_mut() {
            k.key_offsets.truncate(1);
        }
        assert_eq!(page(&one).ring_facts.rings, "1 ring of 1 output");
        assert_eq!(page(&rct5()).ring_facts.oldest, None, "nothing looked up");
    }

    /// The narrow layout is the same timeline in a column under 520px, where
    /// the wide one would shrink its text past reading.
    #[test]
    fn a_narrow_column_gets_its_own_layout() {
        let f = rct5();
        let spent = f.0.block_height;
        let heights: Vec<u64> = (0..11).map(|i| spent - 10 - i * 300).collect();
        let p = ring_page(
            None,
            &f.0,
            &f.1,
            Scheme::Clsag,
            &[resolved(&heights)],
            Some(1),
        );
        let [wide, narrow] = &p.timelines;
        assert_eq!((wide.g.class, narrow.g.class), ("w", "n"));
        let xs = |t: &Timeline| t.rows[0].dots.iter().map(|d| d.x).collect::<Vec<_>>();
        assert_eq!(
            xs(narrow).first(),
            Some(&NARROW.young),
            "the youngest first"
        );
        assert_eq!(xs(narrow).last(), Some(&NARROW.left));
        assert!(xs(narrow).iter().all(|&x| x <= NARROW.width));
        let html = p.render().unwrap();
        assert!(html.contains(r#"<svg class="timeline tl-w" viewBox="0 0 860 "#));
        assert!(html.contains(r#"<svg class="timeline tl-n" viewBox="0 0 400 "#));
        assert!(!html.contains(r#"class="scroll""#));
    }

    /// A long public amount is squeezed into the label column rather than
    /// run into the dots.
    #[test]
    fn a_long_amount_is_squeezed_into_the_label_column() {
        let mut f = rct2();
        let mut keys = f.1.vin.iter_mut().filter_map(|v| match v {
            monerod_rpc::types::TxIn::Key(k) => Some(k),
            _ => None,
        });
        keys.next().unwrap().amount = 123_456_789;
        keys.next().unwrap().amount = 1_000_000_000_000;
        let p = page(&f);
        let [wide, narrow] = &p.timelines;
        assert_eq!(
            wide.rows[0].note,
            Some(("0.000123456789 XMR".to_owned(), None)),
            "18 characters fit the wide column"
        );
        assert_eq!(
            narrow.rows[0].note,
            Some(("0.000123456789 XMR".to_owned(), Some(NARROW.left - 8)))
        );
        assert_eq!(narrow.rows[1].note, Some(("1.0 XMR".to_owned(), None)));
        let html = p.render().unwrap();
        assert!(html.contains(&format!(
            r#"textLength="{}" lengthAdjust="spacingAndGlyphs">0.000123456789 XMR</text>"#,
            NARROW.left - 8
        )));
    }

    #[test]
    fn an_unresolved_ring_of_one_still_says_it_has_no_decoys() {
        let mut f = rct5();
        if let Some(monerod_rpc::types::TxIn::Key(k)) = f.1.vin.first_mut() {
            k.key_offsets.truncate(1);
        }
        let html = page(&f).render().unwrap();
        assert!(html.contains(
            ">a ring of one output, with no decoys, which this node could not look up</text>"
        ));
        assert!(!html.contains(">this node could not look up this ring</text>"));
        assert!(
            page(&rct5())
                .render()
                .unwrap()
                .contains(">this node could not look up this ring</text>")
        );
    }

    /// Wording the review found loose against the source.
    #[test]
    fn each_scheme_says_exactly_what_it_signs_and_checks() {
        let clsag = page(&rct5()).render().unwrap();
        assert!(clsag.contains("<var>I</var>, <var>D</var>/8, <var>C&#x303;</var>)"));
        let full = page(&rct1()).render().unwrap();
        assert!(full.contains(
            "<var>R<sub>k,i</sub></var>, <var>Z<sub>i</sub></var>, <var>L&prime;<sub>i</sub></var>)"
        ));
        let simple = page(&rct2()).render().unwrap();
        assert!(
            simple.contains("the output commitments, the pseudo-outputs, the encrypted amounts")
        );
        assert!(simple.contains("commitments, the pseudo-outputs and the\nencrypted amounts"));
        let later = page(&rct3()).render().unwrap();
        assert!(!later.contains("the pseudo-outputs, the encrypted"));
        let v1 = page(&v1()).render().unwrap();
        assert!(v1.contains("must add up to more than the outputs'"));
        assert!(v1.contains("which must be more than nothing"));
        assert!(!v1.contains("at least"));
        assert!(clsag.contains("any RingCT\noutput can stand in as a decoy"));
        assert!(
            clsag
                .contains("except when spending an old public amount too rare to find\ndecoys for")
        );
    }
}
