//! The FCMP++ walkthrough's picture of the curve tree: the whole tree as of
//! the proof's reference block, drawn as fine strands.
//!
//! Every output is a strand at the bottom, and they gather 38 to a Selene
//! node, those 18 to a Helios node, and so on up to the root at the top. The
//! shape follows from the tree's size alone. A layer with too many nodes to
//! draw one by one is a rule instead, broken where the subtrees above it end.
//! The root hash only seeds the fibres' bow, never the structure.

#![allow(
    clippy::cast_precision_loss,
    reason = "chart coordinates, not chain arithmetic"
)]

use explorer_core::curve_tree::{Curve, group_width};

use super::grouped;

/// The wide picture, drawn 1:1: its width, the axis the label column's row
/// ticks sit on, and the drawing's left and right.
const WIDE: Frame = Frame {
    class: "wide",
    width: 840,
    axis: 184.0,
    left: 200.0,
    right: 836.0,
};

/// The narrow picture, for a phone: the wide one's strokes squeezed sideways
/// beside a narrower label column.
const NARROW: Frame = Frame {
    class: "narrow",
    width: 340,
    axis: 112.0,
    left: 120.0,
    right: 338.0,
};

const CENTRE: f64 = f64::midpoint(WIDE.left, WIDE.right);
/// The most nodes a layer may have and still be drawn one by one.
const MAX_EXACT: u64 = 2000;
/// A young tree's outputs keep this spacing rather than spread to the edges.
const MAX_PITCH: f64 = 24.0;
const ROOT_Y: f64 = 30.0;
/// How much narrower the lowest drawn layer is than the drawing when rules
/// widen out below it.
const RULED: f64 = 0.74;

struct Frame {
    class: &'static str,
    width: u32,
    axis: f64,
    left: f64,
    right: f64,
}

impl Frame {
    fn wide(&self) -> bool {
        self.width == WIDE.width
    }

    fn scale(&self) -> f64 {
        (self.right - self.left) / (WIDE.right - WIDE.left)
    }

    /// The wide drawing's `x` in this picture.
    fn x(&self, x: f64) -> f64 {
        (x - WIDE.left).mul_add(self.scale(), self.left)
    }
}

/// One of the two pictures, laid out.
pub struct TreeField {
    pub class: &'static str,
    pub width: u32,
    pub height: String,
    pub aria: String,
    /// The drawing's strokes. The narrow picture has none of its own: it
    /// draws the wide one's again through `<use>`, under `reuse`.
    pub art: Vec<Stroke>,
    pub reuse: Option<String>,
    /// The nodes, in each picture's own units so that they stay round.
    pub nodes: Vec<Stroke>,
    pub root: RootMark,
    pub axis: String,
    pub ticks: String,
    pub leads: Vec<String>,
    pub labels: Vec<RowLabel>,
    pub brackets: String,
    pub measures: Vec<Measure>,
}

pub struct Stroke {
    pub class: String,
    pub d: String,
}

pub struct RootMark {
    pub x: String,
    pub y: String,
    pub bloom: &'static str,
    pub ring: &'static str,
    pub core: &'static str,
    pub curve: &'static str,
}

/// A row's name in the label column, and the lines under it.
pub struct RowLabel {
    /// Its key: a comb for the outputs, otherwise a dot for Selene (`s`) or
    /// a ring for Helios (`h`).
    pub comb: Option<String>,
    pub key: &'static str,
    pub key_x: String,
    pub key_y: String,
    pub key_r: &'static str,
    pub x: String,
    pub y: String,
    pub name: String,
    pub aside: Option<String>,
    pub lines: Vec<Line>,
}

pub struct Line {
    /// `sub`, or `hash` for a line of the root hash.
    pub class: &'static str,
    pub y: String,
    pub text: String,
    /// A block the line ends with, linked.
    pub block: Option<u64>,
}

/// A note under the outputs, with a number in it picked out.
pub struct Measure {
    pub x: String,
    pub y: String,
    pub anchor: &'static str,
    pub before: String,
    pub short: Option<String>,
    pub after: String,
}

/// The tree of `n` outputs as of block `as_of`, with `root` in block
/// `root_block`, laid out wide and narrow. `None` for an empty tree.
pub fn tree_field(
    n: u64,
    root: Option<&str>,
    as_of: Option<u64>,
    root_block: Option<u64>,
) -> Option<[TreeField; 2]> {
    let seed = root
        .and_then(|r| u64::from_str_radix(r.get(..16)?, 16).ok())
        .unwrap_or(n);
    let l = Layout::new(n, seed)?;
    let about = About {
        root,
        as_of,
        root_block,
        aria: aria(&l, as_of, root_block),
    };
    Some([
        picture(&l, &WIDE, art(&l), &about),
        picture(&l, &NARROW, Vec::new(), &about),
    ])
}

/// What the pictures say beside the tree's shape.
struct About<'a> {
    root: Option<&'a str>,
    as_of: Option<u64>,
    root_block: Option<u64>,
    aria: String,
}

fn picture(l: &Layout, f: &Frame, art: Vec<Stroke>, about: &About<'_>) -> TreeField {
    let wide = f.wide();
    let (axis, ticks, leads) = axis(l, f);
    let (brackets, measures) = measures(l, f);
    TreeField {
        class: f.class,
        width: f.width,
        height: num(l.height),
        aria: about.aria.clone(),
        art,
        reuse: (!wide).then(|| {
            format!(
                "matrix({:.5} 0 0 1 {:.3} 0)",
                f.scale(),
                WIDE.left.mul_add(-f.scale(), f.left)
            )
        }),
        nodes: nodes(l, f),
        root: RootMark {
            x: num(f.x(CENTRE)),
            y: num(l.y(l.top)),
            bloom: if wide { "40" } else { "28" },
            ring: if wide { "8" } else { "6.5" },
            core: if wide { "4" } else { "3.4" },
            curve: curve_class(l.top),
        },
        axis,
        ticks,
        leads,
        labels: labels(l, f, about),
        brackets,
        measures,
    }
}

/// How many children a node of `level` has at most.
fn children(level: usize) -> usize {
    usize::try_from(group_width(level.saturating_sub(1))).unwrap_or(usize::MAX)
}

const fn curve_class(level: usize) -> &'static str {
    match Curve::of_layer(level) {
        Curve::Helios => "h",
        Curve::Selene | Curve::Ed25519 => "s",
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

struct Layout {
    n: u64,
    seed: u64,
    /// Nodes in each layer: the outputs, layer 1, and so on to the root.
    sizes: Vec<u64>,
    top: usize,
    /// The lowest layer drawn node by node; those below it are rules.
    low: usize,
    /// Each layer's row, drawn or ruled.
    ys: Vec<f64>,
    height: f64,
    /// Each drawn layer's nodes' x, empty for the rules.
    xs: Vec<Vec<f64>>,
    /// How many of the lowest drawn layer's nodes each node sits over.
    under: Vec<Vec<u64>>,
    pitch: f64,
}

impl Layout {
    fn new(n: u64, seed: u64) -> Option<Self> {
        let layers = monerod_rpc::types::tree_layers(n);
        if layers.is_empty() {
            return None;
        }
        let sizes: Vec<u64> = std::iter::once(n).chain(layers).collect();
        let top = sizes.len() - 1;
        let low = sizes.iter().position(|&s| s <= MAX_EXACT).unwrap_or(top);
        let nb = usize::try_from(at_u(&sizes, low)).unwrap_or(1).max(1);

        // Room under the root for its hash, and the most for the last gap,
        // where the strands open.
        let rows = top - low + 1;
        let mut ys = vec![0.0; top + 1];
        let mut y = ROOT_Y;
        for (i, lv) in (low..=top).rev().enumerate() {
            set(&mut ys, lv, y);
            y += if rows == 2 {
                196.0
            } else if i == rows - 2 {
                if low == 0 { 150.0 } else { 128.0 }
            } else if i == 0 {
                112.0
            } else {
                96.0
            };
        }
        let bottom = at(&ys, low);
        let mut y = bottom + 22.0;
        for (i, lv) in (0..low).rev().enumerate() {
            y += if i == 0 { 40.0 } else { 54.0 };
            set(&mut ys, lv, y);
        }
        let height = at(&ys, 0).max(bottom) + 42.0;

        // The lowest drawn layer: a gap between groups, and a wider one
        // between groups of groups.
        let (g1, g2) = if nb > 1000 { (3.2, 9.0) } else { (6.0, 12.0) };
        let ancestor = |mut i: usize, k: usize| {
            for lv in low + 1..=low + k {
                i /= children(lv);
            }
            i
        };
        let gaps: Vec<f64> = (0..nb)
            .map(|i| {
                let parted = (1..=top - low)
                    .rev()
                    .find(|&k| i > 0 && ancestor(i, k) != ancestor(i - 1, k));
                match parted {
                    Some(k) if k >= 2 => g2,
                    Some(_) => g1,
                    None => 0.0,
                }
            })
            .collect();
        let full = WIDE.right - WIDE.left;
        let width = if low == 0 { full } else { full * RULED };
        let gap: f64 = gaps.iter().sum();
        let pitch = MAX_PITCH.min((width - gap) / (nb.max(2) - 1) as f64);
        let span = pitch.mul_add((nb - 1) as f64, gap);
        let mut x = CENTRE - span / 2.0 - pitch;
        let bottom_xs: Vec<f64> = gaps
            .iter()
            .map(|g| {
                x += g + pitch;
                x
            })
            .collect();

        // Each node over the mean of its children, drawn in toward the
        // centre so that the crown narrows to the root.
        let mut xs = vec![Vec::new(); top + 1];
        let mut under = vec![Vec::new(); top + 1];
        if let Some(slot) = xs.get_mut(low) {
            *slot = if nb == 1 { vec![CENTRE] } else { bottom_xs };
        }
        if let Some(slot) = under.get_mut(low) {
            *slot = vec![1; nb];
        }
        for lv in low + 1..=top {
            let w = children(lv);
            let pull = if lv == low + 1 { 0.8 } else { 0.6 };
            let row: Vec<f64> = xs.get(lv - 1).map_or_else(Vec::new, |below| {
                below
                    .chunks(w)
                    .map(|c| {
                        (c.iter().sum::<f64>() / c.len() as f64 - CENTRE).mul_add(pull, CENTRE)
                    })
                    .collect()
            });
            let counts: Vec<u64> = under
                .get(lv - 1)
                .map_or_else(Vec::new, |u| u.chunks(w).map(|c| c.iter().sum()).collect());
            if let Some(slot) = xs.get_mut(lv) {
                *slot = if lv == top { vec![CENTRE] } else { row };
            }
            if let Some(slot) = under.get_mut(lv) {
                *slot = counts;
            }
        }

        Some(Self {
            n,
            seed,
            sizes,
            top,
            low,
            ys,
            height,
            xs,
            under,
            pitch,
        })
    }

    fn y(&self, level: usize) -> f64 {
        at(&self.ys, level)
    }

    fn xs(&self, level: usize) -> &[f64] {
        self.xs.get(level).map_or(&[], Vec::as_slice)
    }

    fn size(&self, level: usize) -> u64 {
        at_u(&self.sizes, level)
    }

    /// The lowest drawn layer's groups, as their first and last node.
    fn groups(&self) -> Vec<(usize, usize)> {
        let w = children(self.low + 1);
        let nb = self.xs(self.low).len();
        (0..nb)
            .step_by(w)
            .map(|j| (j, (j + w).min(nb) - 1))
            .collect()
    }

    /// Where the lowest drawn layer starts and ends.
    fn ends(&self) -> (f64, f64) {
        let xs = self.xs(self.low);
        (
            xs.first().copied().unwrap_or(CENTRE),
            xs.last().copied().unwrap_or(CENTRE),
        )
    }

    /// How far the rule of `level` widens past the lowest drawn layer.
    fn widening(&self, level: usize) -> f64 {
        let k = (self.low - level) as f64;
        (1.0 / RULED - 1.0).mul_add(k / self.low as f64, 1.0)
    }

    /// `x` spread out by the rule of `level`'s widening.
    fn widened(&self, level: usize, x: f64) -> f64 {
        (x - CENTRE).mul_add(self.widening(level), CENTRE)
    }

    /// A number in [0, 1) that the root hash and `parts` fix.
    fn noise(&self, parts: [u64; 4]) -> f64 {
        let h = parts.iter().fold(self.seed, |h, &p| {
            splitmix(h ^ p.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        });
        (h >> 11) as f64 / (1u64 << 53) as f64
    }
}

const fn splitmix(x: u64) -> u64 {
    let x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn at(v: &[f64], i: usize) -> f64 {
    v.get(i).copied().unwrap_or_default()
}

fn at_u(v: &[u64], i: usize) -> u64 {
    v.get(i).copied().unwrap_or_default()
}

fn set(v: &mut [f64], i: usize, value: f64) {
    if let Some(slot) = v.get_mut(i) {
        *slot = value;
    }
}

/// A coordinate, to two places and no more than it needs.
fn num(v: f64) -> String {
    let s = format!("{v:.2}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" {
        return "0".to_owned();
    }
    if let Some(rest) = s.strip_prefix("0.") {
        format!(".{rest}")
    } else if let Some(rest) = s.strip_prefix("-0.") {
        format!("-.{rest}")
    } else {
        s.to_owned()
    }
}

/// A cubic from one point to another, vertical at both ends: `a` and `b` are
/// how far its handles reach, `bow` how far it swings sideways.
fn s_curve(from: (f64, f64), to: (f64, f64), a: f64, b: f64, bow: f64) -> String {
    let (dx, dy) = (to.0 - from.0, to.1 - from.1);
    format!(
        "M{} {}c{} {} {} {} {} {}",
        num(from.0),
        num(from.1),
        num(bow),
        num(a),
        num(dx + bow),
        num(dy - b),
        num(dx),
        num(dy)
    )
}

/// Vertical ticks `h` tall from `y`, one subpath each.
fn ticks(xs: &[f64], y: f64, h: f64) -> String {
    let mut d = String::new();
    let mut last: Option<f64> = None;
    for &x in xs {
        let x = (x * 100.0).round() / 100.0;
        d.push_str(&match last {
            None => format!("M{} {}v{}", num(x), num(y), num(h)),
            Some(l) => format!("m{} {}v{}", num(x - l), num(-h), num(h)),
        });
        last = Some(x);
    }
    d
}

/// Filled circles as one path, two arcs each.
fn discs(points: impl Iterator<Item = (f64, f64)>, r: f64) -> String {
    let (rr, dd) = (num(r), num(2.0 * r));
    points
        .map(|(x, y)| {
            format!(
                "M{} {}a{rr} {rr} 0 1 0 {dd} 0a{rr} {rr} 0 1 0 -{dd} 0",
                num(x - r),
                num(y)
            )
        })
        .collect()
}

/// A stroke of the drawing, `classes` each taking the drawing's prefix.
fn stroke(classes: &str, d: String) -> Stroke {
    let class = std::iter::once("tf".to_owned())
        .chain(classes.split(' ').map(|c| format!("tf-{c}")))
        .collect::<Vec<_>>()
        .join(" ");
    Stroke { class, d }
}

/// The tree's strokes, in the wide picture's units.
fn art(l: &Layout) -> Vec<Stroke> {
    // By curve, Helios first, and for the glows by how much each edge carries.
    let mut glows: [[String; 3]; 2] = Default::default();
    let mut fibres: [String; 2] = Default::default();
    let mut strands = String::new();
    for lv in l.low + 1..=l.top {
        let w = children(lv);
        let hue = usize::from(curve_class(lv) == "s");
        let (py, cy) = (l.y(lv), l.y(lv - 1));
        let dy = cy - py;
        let below = l.xs(lv - 1);
        let under = l.under.get(lv - 1).map_or(&[][..], Vec::as_slice);
        for (j, (&px, group)) in l.xs(lv).iter().zip(below.chunks(w)).enumerate() {
            for (k, &cx) in group.iter().enumerate() {
                let (from, to) = ((px, py), (cx, cy));
                if lv - 1 == l.low {
                    strands.push_str(&s_curve(
                        from,
                        to,
                        (dy * 0.52).round(),
                        (dy * 0.44).round(),
                        0.0,
                    ));
                    continue;
                }
                let ci = j * w + k;
                let m = at_u(under, ci);
                let bundle = (m as f64).sqrt() * if m > 60 { 2.0 } else { 1.7 };
                let floor = if lv == l.top { 18.0 } else { 1.0 };
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "clamped to a few dozen before the cast"
                )]
                let count = bundle.round().clamp(1.0, 80.0).max(floor) as u64;
                let spread = (1.8 * (m as f64).powf(0.33)).min(26.0);
                let tag = [lv as u64, ci as u64];
                for f in 0..count {
                    let lane = (f as f64 + 0.5) / count as f64 - 0.5;
                    let jitter = (l.noise([1, tag[0], tag[1], f]) - 0.5) * 0.3;
                    let t = (l.noise([2, tag[0], tag[1], f]) - 0.5).mul_add(0.1, 0.5);
                    if let Some(s) = fibres.get_mut(hue) {
                        s.push_str(&s_curve(
                            from,
                            to,
                            dy * t,
                            dy * (1.0 - t),
                            (lane + jitter) * spread,
                        ));
                    }
                }
                let weight = usize::from(m > 60) + usize::from(m > 400);
                if let Some(s) = glows.get_mut(hue).and_then(|g| g.get_mut(weight)) {
                    s.push_str(&s_curve(from, to, dy * 0.5, dy * 0.5, 0.0));
                }
            }
        }
    }

    let mut out = Vec::new();
    for (hue, by_weight) in ["h", "s"].into_iter().zip(glows) {
        for (weight, d) in ["g1", "g2", "g3"].into_iter().zip(by_weight) {
            if !d.is_empty() {
                out.push(stroke(&format!("glow {hue} {weight}"), d));
            }
        }
    }
    let density = if l.pitch >= 6.0 {
        "sparse"
    } else if l.pitch >= 1.2 {
        "mid"
    } else {
        "dense"
    };
    if l.low > 0 {
        out.push(drops(l));
    }
    out.push(stroke(
        &format!("strand {} {density}", curve_class(l.low + 1)),
        strands,
    ));
    for (hue, d) in ["h", "s"].into_iter().zip(fibres) {
        if !d.is_empty() {
            out.push(stroke(&format!("fibre {hue}"), d));
        }
    }

    let bottom = l.y(l.low);
    if l.low == 0 {
        // A tooth for each output, alternate groups in two tones. A sparse
        // row has a dot for each instead, among the nodes.
        if density != "sparse" {
            let (mut even, mut odd) = (Vec::new(), Vec::new());
            for (gi, (a, b)) in l.groups().into_iter().enumerate() {
                let xs = l.xs(0).get(a..=b).unwrap_or_default();
                if gi % 2 == 0 { &mut even } else { &mut odd }.extend_from_slice(xs);
            }
            out.push(stroke(
                &format!("tooth t0 {density}"),
                ticks(&even, bottom, 7.0),
            ));
            if !odd.is_empty() {
                out.push(stroke(
                    &format!("tooth t1 {density}"),
                    ticks(&odd, bottom, 7.0),
                ));
            }
        }
    } else {
        out.push(stroke(
            &format!("comb {}", curve_class(l.low)),
            ticks(l.xs(l.low), bottom - 3.0, 6.0),
        ));
        out.extend(rules(l));
    }
    out
}

/// The edges of the column each group of the lowest drawn layer covers,
/// down through the rules: where one subtree ends and the next begins.
fn drops(l: &Layout) -> Stroke {
    let (y0, y1) = (l.y(l.low), l.y(0));
    let reach = (y1 - y0) * 0.5;
    let xs = l.xs(l.low);
    let mut d = String::new();
    for (a, b) in l.groups() {
        for (x, o) in [(at(xs, a), -0.7), (at(xs, b), 0.7)] {
            d.push_str(&s_curve(
                (x + o, y0),
                (l.widened(0, x + o), y1),
                reach,
                reach,
                0.0,
            ));
        }
    }
    stroke("drop", d)
}

/// Each layer too dense to draw as a rule, broken at the subtrees above it,
/// heavier toward the outputs.
fn rules(l: &Layout) -> Vec<Stroke> {
    let xs = l.xs(l.low);
    let groups = l.groups();
    (0..l.low)
        .rev()
        .enumerate()
        .map(|(k, lv)| {
            let y = l.y(lv);
            let d: String = groups
                .iter()
                .map(|&(a, b)| {
                    format!(
                        "M{} {}H{}",
                        num(l.widened(lv, at(xs, a) - 0.7)),
                        num(y),
                        num(l.widened(lv, at(xs, b) + 0.7))
                    )
                })
                .collect();
            let weight = if lv == 0 {
                5
            } else {
                (k + 5).saturating_sub(l.low).min(4) + 1
            };
            let hue = if lv == 0 { "o" } else { curve_class(lv) };
            stroke(&format!("rule {hue} w{weight}"), d)
        })
        .collect()
}

/// The nodes between the root and the lowest drawn layer: a dot for Selene
/// and a ring for Helios, each on a faint halo, and a dot for each output of
/// a tree small enough to space them out.
fn nodes(l: &Layout, f: &Frame) -> Vec<Stroke> {
    let k = if f.wide() { 1.0 } else { 0.82 };
    let mut out = Vec::new();
    for lv in l.low + 1..l.top {
        let size = l.size(lv);
        let r = k * if size <= 4 {
            3.6
        } else if size <= 60 {
            2.1
        } else {
            1.3
        };
        let y = l.y(lv);
        let points = || l.xs(lv).iter().map(move |&x| (f.x(x), y));
        let hue = curve_class(lv);
        out.push(Stroke {
            class: format!("tf-halo tf-{hue}"),
            d: discs(points(), r * 2.6),
        });
        out.push(if hue == "h" {
            Stroke {
                class: "tf-ringnode".to_owned(),
                d: discs(points(), r - 0.5),
            }
        } else {
            Stroke {
                class: "tf-dot".to_owned(),
                d: discs(points(), r),
            }
        });
    }
    if l.low == 0 && l.pitch >= 6.0 {
        let y = l.y(0);
        out.push(Stroke {
            class: "tf-leafdot".to_owned(),
            d: discs(l.xs(0).iter().map(|&x| (f.x(x), y)), 2.4 * k),
        });
    }
    out
}

/// Every row's level, the root first and the outputs last.
fn rows(l: &Layout) -> impl Iterator<Item = usize> {
    (0..=l.top).rev()
}

/// The label column's axis, a tick on it at every row, and a dotted leader
/// across the empty space to each drawn row's first node.
fn axis(l: &Layout, f: &Frame) -> (String, String, Vec<String>) {
    let ax = f.axis;
    let axis = format!("M{} {}V{}", num(ax), num(l.y(l.top)), num(l.y(0)));
    let mut ticks = String::new();
    let mut leads = Vec::new();
    for lv in rows(l) {
        let y = l.y(lv);
        ticks.push_str(&format!("M{} {}h8", num(ax - 4.0), num(y)));
        if lv > l.low {
            let first = f.x(l.xs(lv).first().copied().unwrap_or(CENTRE))
                - if lv == l.top { 12.0 } else { 8.0 };
            if first - (ax + 8.0) > 14.0 {
                leads.push(format!("M{} {}H{}", num(ax + 8.0), num(y), num(first)));
            }
        }
    }
    (axis, ticks, leads)
}

fn labels(l: &Layout, f: &Frame, about: &About<'_>) -> Vec<RowLabel> {
    let wide = f.wide();
    let x = if wide { 13.0 } else { 11.0 };
    let (first, step, hash_step) = if wide {
        (15.0, 12.0, 12.0)
    } else {
        (12.5, 11.5, 10.5)
    };
    rows(l)
        .map(|lv| {
            let y = l.y(lv);
            let key_x = if wide { 4.5 } else { 3.5 };
            let curve = Curve::of_layer(lv).name();
            let (name, aside) = match lv {
                0 => ("Outputs".to_owned(), wide.then(|| grouped(l.n))),
                _ if lv == l.top => ("Root".to_owned(), wide.then(|| curve.to_owned())),
                _ => (format!("Layer {lv}"), wide.then(|| curve.to_owned())),
            };
            let mut texts: Vec<(&'static str, String, Option<u64>)> = Vec::new();
            if lv == l.top {
                if !wide {
                    texts.push(("sub", curve.to_owned(), None));
                }
                if let Some(root) = about.root {
                    let chars: Vec<char> = root.chars().collect();
                    for line in chars.chunks(16) {
                        texts.push(("hash", line.iter().collect(), None));
                    }
                }
                if let Some(b) = about.root_block {
                    texts.push(("sub", "in block ".to_owned(), Some(b)));
                }
            } else if lv == 0 {
                if !wide {
                    texts.push(("sub", grouped(l.n), None));
                }
                if let Some(b) = about.as_of {
                    texts.push(("sub", "as of block ".to_owned(), Some(b)));
                }
            } else {
                let size = l.size(lv);
                let nodes = format!("{} node{}", grouped(size), plural(size));
                let groups = format!("{} under each", children(lv));
                if wide {
                    texts.push(("sub", format!("{nodes} · {groups}"), None));
                } else if lv < l.low {
                    texts.push(("sub", format!("{curve} · {}", grouped(size)), None));
                    texts.push(("sub", groups, None));
                } else {
                    texts.push(("sub", curve.to_owned(), None));
                    texts.push(("sub", nodes, None));
                    texts.push(("sub", groups, None));
                }
            }

            // Hash lines follow closer together, and the root's block a
            // little apart from them.
            let mut at_y = y + 4.5 + first;
            let mut was_hash = false;
            let lines = texts
                .into_iter()
                .map(|(class, text, block)| {
                    if was_hash && class != "hash" {
                        at_y += 2.0;
                    }
                    let line = Line {
                        class,
                        y: num(at_y),
                        text,
                        block,
                    };
                    at_y += if class == "hash" { hash_step } else { step };
                    was_hash = class == "hash";
                    line
                })
                .collect();

            let (comb, key, key_r) = if lv == 0 {
                (
                    Some(format!(
                        "M{} {}v7m2.4 -7v7m2.4 -7v7",
                        num(key_x - 2.4),
                        num(y - 3.5)
                    )),
                    "o",
                    "0",
                )
            } else {
                let hue = curve_class(lv);
                let r = match (hue, lv == l.top) {
                    ("h", true) => "3",
                    ("h", false) => "2.4",
                    (_, true) => "3.6",
                    _ => "3",
                };
                (None, hue, r)
            };
            RowLabel {
                comb,
                key,
                key_x: num(key_x),
                key_y: num(y),
                key_r,
                x: num(x),
                y: num(y + 4.5),
                name,
                aside,
                lines,
            }
        })
        .collect()
}

/// The outputs measured: their first group bracketed and its size, and the
/// last, short one's. Under rules, only the short last group is noted.
fn measures(l: &Layout, f: &Frame) -> (String, Vec<Measure>) {
    let w = children(1);
    let last = usize::try_from(l.n % w as u64).unwrap_or(0);
    let mut out = Vec::new();
    if l.low > 0 {
        if last > 0 {
            let (_, x1) = l.ends();
            out.push(Measure {
                x: num(f.x(l.widened(0, x1 + 0.7))),
                y: num(l.y(0) + 16.0),
                anchor: "end",
                before: "last group ".to_owned(),
                short: Some(last.to_string()),
                after: String::new(),
            });
        }
        return (String::new(), out);
    }

    let groups = l.groups();
    let xs = l.xs(0);
    let y = l.y(0) + if l.pitch < 6.0 { 7.0 } else { 4.0 } + 6.0;
    let mut d = String::new();
    let mut bracket = |a: usize, b: usize| {
        let (mut x0, mut x1) = (f.x(at(xs, a)), f.x(at(xs, b)));
        if x1 - x0 < 2.0 {
            (x0, x1) = (x0 - 1.0, x1 + 1.0);
        }
        d.push_str(&format!(
            "M{} {}v2.5H{}v-2.5",
            num(x0),
            num(y - 2.5),
            num(x1)
        ));
        (x0, x1)
    };
    let note = |x: f64, anchor, before: String, short: Option<String>, after: String| Measure {
        x: num(x),
        y: num(y + 11.0),
        anchor,
        before,
        short,
        after,
    };
    match groups.as_slice() {
        [] => {}
        [(a, b)] => {
            let (x0, x1) = bracket(*a, *b);
            out.push(note(
                f64::midpoint(x0, x1),
                "middle",
                String::new(),
                Some((b - a + 1).to_string()),
                format!(" of up to {w}"),
            ));
        }
        [(a, b), .., (c, e)] => {
            let (x0, _) = bracket(*a, *b);
            out.push(note(x0, "start", format!("{w} each"), None, String::new()));
            if last > 0 {
                let (_, x1) = bracket(*c, *e);
                out.push(note(
                    x1,
                    "end",
                    "last ".to_owned(),
                    Some((e - c + 1).to_string()),
                    String::new(),
                ));
            }
        }
    }
    (d, out)
}

/// What the picture shows, for a screen reader.
fn aria(l: &Layout, as_of: Option<u64>, root_block: Option<u64>) -> String {
    let mut s = format!(
        "Curve tree of {} outputs in {} layer{}",
        grouped(l.n),
        l.top,
        plural(l.top as u64)
    );
    if let Some(b) = as_of {
        s.push_str(&format!(" as of block {b}"));
    }
    s.push_str(", the root at the top");
    for lv in 1..l.top {
        let size = l.size(lv);
        s.push_str(&format!(
            "; layer {lv}, {}, {} node{} with {} under each",
            Curve::of_layer(lv).name(),
            grouped(size),
            plural(size),
            children(lv)
        ));
    }
    s.push_str(&format!("; root, {}", Curve::of_layer(l.top).name()));
    if let Some(b) = root_block {
        s.push_str(&format!(", in block {b}"));
    }
    let last = l.n % group_width(0);
    if last > 0 && l.n > group_width(0) {
        s.push_str(&format!(". The last group of outputs holds {last}"));
    }
    s.push('.');
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    const ROOT: &str = "59611ee3f6db718506895ef0a487c070a4519e91eecad0269df8b4a74d5dbcc1";

    /// The one stroke or node path whose class is `class`.
    fn path<'a>(strokes: &'a [Stroke], class: &str) -> &'a str {
        let found: Vec<&Stroke> = strokes.iter().filter(|s| s.class == class).collect();
        assert_eq!(found.len(), 1, "{class}");
        &found[0].d
    }

    fn subpaths(d: &str) -> usize {
        d.matches(['M', 'm']).count()
    }

    fn label<'a>(t: &'a TreeField, name: &str) -> &'a RowLabel {
        t.labels.iter().find(|l| l.name == name).expect(name)
    }

    fn lines(l: &RowLabel) -> Vec<&str> {
        l.lines.iter().map(|l| l.text.as_str()).collect()
    }

    /// The captured page's tree: every output is a strand and a tooth, and
    /// every node a mark, with the layers named as the tree groups them.
    #[test]
    fn the_real_pages_tree_draws_every_output_and_node() {
        let [wide, narrow] = tree_field(1474, Some(ROOT), Some(337), Some(329)).unwrap();
        assert_eq!(
            subpaths(path(&wide.art, "tf tf-strand tf-s tf-dense")),
            1474
        );
        let teeth = subpaths(path(&wide.art, "tf tf-tooth tf-t0 tf-dense"))
            + subpaths(path(&wide.art, "tf tf-tooth tf-t1 tf-dense"));
        assert_eq!(teeth, 1474);
        assert_eq!(subpaths(path(&wide.nodes, "tf-dot")), 39);
        assert_eq!(subpaths(path(&wide.nodes, "tf-ringnode")), 3);

        assert_eq!(lines(label(&wide, "Layer 1")), ["39 nodes · 38 under each"]);
        assert_eq!(lines(label(&wide, "Layer 2")), ["3 nodes · 18 under each"]);
        let root = label(&wide, "Root");
        assert_eq!(root.aside.as_deref(), Some("Selene"));
        assert_eq!(
            lines(root),
            [
                &ROOT[..16],
                &ROOT[16..32],
                &ROOT[32..48],
                &ROOT[48..],
                "in block "
            ]
        );
        assert_eq!(root.lines[4].block, Some(329));
        assert_eq!(label(&wide, "Outputs").lines[0].block, Some(337));

        let notes: Vec<(&str, Option<&str>)> = wide
            .measures
            .iter()
            .map(|m| (m.before.as_str(), m.short.as_deref()))
            .collect();
        assert_eq!(notes, [("38 each", None), ("last ", Some("30"))]);
        assert!(
            wide.aria
                .contains("layer 1, Selene, 39 nodes with 38 under each")
        );

        // The narrow picture draws the wide one's strokes again, and says
        // each layer's facts over more lines.
        assert!(narrow.art.is_empty() && narrow.reuse.is_some());
        assert_eq!(
            lines(label(&narrow, "Layer 1")),
            ["Selene", "39 nodes", "38 under each"]
        );
    }

    /// Up to 38 outputs hash straight to the root: one group, each output
    /// spaced out with a dot of its own.
    #[test]
    fn a_young_tree_is_one_group_under_its_root() {
        let [wide, _] = tree_field(22, None, None, None).unwrap();
        let names: Vec<&str> = wide.labels.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["Root", "Outputs"]);
        assert_eq!(subpaths(path(&wide.art, "tf tf-strand tf-s tf-sparse")), 22);
        assert_eq!(subpaths(path(&wide.nodes, "tf-leafdot")), 22);
        assert!(wide.art.iter().all(|s| !s.class.contains("tooth")));
        let m = &wide.measures[0];
        assert_eq!(
            (m.short.as_deref(), m.after.as_str()),
            (Some("22"), " of up to 38")
        );
        assert!(tree_field(0, None, None, None).is_none());
    }

    /// A tree the size of mainnet's is drawn node by node down to its first
    /// layer of at most 2,000 nodes, and ruled below, each rule broken at the
    /// subtrees above it.
    #[test]
    fn a_mainnet_sized_tree_rules_the_layers_too_dense_to_draw() {
        let [wide, _] = tree_field(186_178_263, Some(ROOT), None, None).unwrap();
        assert_eq!(subpaths(path(&wide.art, "tf tf-comb tf-h")), 398);
        assert_eq!(subpaths(path(&wide.art, "tf tf-strand tf-s tf-dense")), 398);
        assert_eq!(subpaths(path(&wide.nodes, "tf-dot")), 11);
        let rules: Vec<(&str, usize)> = wide
            .art
            .iter()
            .filter(|s| s.class.contains("rule"))
            .map(|s| (s.class.as_str(), s.d.matches('H').count()))
            .collect();
        assert_eq!(
            rules,
            [
                ("tf tf-rule tf-s tf-w2", 11),
                ("tf tf-rule tf-h tf-w3", 11),
                ("tf tf-rule tf-s tf-w4", 11),
                ("tf tf-rule tf-o tf-w5", 11),
            ]
        );
        assert_eq!(
            lines(label(&wide, "Layer 1")),
            ["4,899,428 nodes · 38 under each"]
        );
        let m = &wide.measures[0];
        assert_eq!(
            (m.before.as_str(), m.short.as_deref()),
            ("last group ", Some("37"))
        );
    }

    #[test]
    fn coordinates_are_written_short() {
        assert_eq!(
            [num(0.5), num(-0.25), num(-0.001), num(12.0), num(3.456)],
            [".5", "-.25", "0", "12", "3.46"]
        );
    }
}
