//! The labels on the walkthrough's proof bar.
//!
//! The bar's parts are placed in percentages of its width, and its labels in
//! pixels, so the text stays one size however wide the column is. Each set of
//! labels is laid out for the narrowest column it is shown in: every gap
//! between two labels, or a label and a part, is a difference of percentages
//! less fixed pixels, so it only grows as the column widens.
//!
//! A part wide enough for its name and size carries them inside. The others
//! are labelled once for each kind of part, above or below the bar, with a
//! tick from every part of that kind. A label that would touch another is
//! shortened, moved to the other side, or, failing both, left to the parts'
//! tooltips.

#![allow(
    clippy::cast_precision_loss,
    reason = "chart coordinates, not chain arithmetic"
)]

use super::{MAP_WIDTH, ProofSegment, grouped};

/// The bar's height, and the room above it for the labels there.
pub const BAR_H: f64 = 26.0;
const ABOVE: f64 = 26.0;
/// Font sizes, which style.css sets to match.
const INSIDE_PX: f64 = 12.0;
const OUTSIDE_PX: f64 = 11.5;
/// More than any character in the labels takes, in ems, in the page's
/// sans-serif.
const EM_PER_CHAR: f64 = 0.62;
/// Room either side of a label inside its part.
const INSIDE_PAD: f64 = 8.0;
/// How far a label starts before its first tick, or ends after its last.
const TICK_REACH: f64 = 4.0;
/// The least space between a label and anything else beside it.
const CLEAR: f64 = 10.0;

/// A column width range a set of labels is for, from `min_width` up.
/// style.css switches between them at [`WIDE`]'s `min_width`.
struct Variant {
    class: &'static str,
    min_width: f64,
}

const WIDE: Variant = Variant {
    class: "w",
    min_width: 520.0,
};
const NARROW: Variant = Variant {
    class: "n",
    min_width: 248.0,
};

pub struct MapLabels {
    /// The bar's top.
    pub top: String,
    pub height: String,
    /// The baseline of the labels inside the parts.
    pub inside_y: String,
    pub sets: [LabelSet; 2],
}

pub struct LabelSet {
    pub class: &'static str,
    pub inside: Vec<Inside>,
    pub outside: Vec<Outside>,
}

/// A label inside a part, starting `INSIDE_PAD` in from its left.
pub struct Inside {
    pub step: usize,
    pub x: String,
    pub text: String,
}

/// A label for a kind of part, beside the bar.
pub struct Outside {
    pub step: usize,
    pub above: bool,
    /// A tick from each part of this kind: its x, and its ends.
    pub ticks: Vec<String>,
    pub tick_y: (String, String),
    /// The line joining the ticks, for a kind with more than one part.
    pub bracket: Option<(String, String)>,
    pub x: String,
    pub dx: &'static str,
    pub anchor: &'static str,
    pub y: String,
    pub text: String,
}

/// One kind of part: each part's left and width, in thousandths of the bar,
/// and its bytes.
struct Kind {
    class: &'static str,
    step: usize,
    parts: Vec<(f64, f64, usize)>,
}

impl Kind {
    fn centres(&self) -> impl Iterator<Item = f64> + '_ {
        self.parts.iter().map(|&(x, w, _)| x + w / 2.0)
    }

    fn name(&self) -> (&'static str, &'static str) {
        match self.class {
            "tuple" => ("Disguised output", "Disguise"),
            "sal" => ("Signature", "Signature"),
            "member" => ("Membership proof", "Membership"),
            "pseudo" => ("Pseudo-output", "Pseudo"),
            "ring" => ("Ring signature", "Signature"),
            "range" => ("Range proof", "Range"),
            _ => ("Root anchor", "Anchor"),
        }
    }

    /// What a part of `bytes` could say inside itself, longest first.
    fn inside_texts(&self, bytes: usize) -> [String; 3] {
        let ((long, short), b) = (self.name(), grouped(bytes as u64));
        [
            format!("{long} · {b} bytes"),
            format!("{short} · {b} B"),
            format!("{b} B"),
        ]
    }

    /// What the kind's label beside the bar could say, longest first: each
    /// part's size, or their total where they differ.
    fn outside_texts(&self) -> [String; 3] {
        let (long, short) = self.name();
        let n = self.parts.len();
        let first = self.parts.first().map_or(0, |p| p.2);
        let (b, times) = if self.parts.iter().all(|p| p.2 == first) {
            let times = if n > 1 {
                format!(" × {n}")
            } else {
                String::new()
            };
            (grouped(first as u64), times)
        } else {
            let total = self.parts.iter().map(|p| p.2).sum::<usize>();
            (grouped(total as u64), format!(" in {n}"))
        };
        [
            format!("{long} {b} B{times}"),
            format!("{short} {b} B{times}"),
            format!("{b} B{times}"),
        ]
    }

    /// Below the bar for the disguises, pseudo-outputs, range proofs and the
    /// anchor, above it for the rest, so the parts that alternate never
    /// share a side.
    fn prefers_above(&self) -> bool {
        matches!(self.class, "sal" | "member" | "ring")
    }
}

fn text_width(text: &str, px: f64) -> f64 {
    text.chars().count() as f64 * px * EM_PER_CHAR
}

/// Thousandths of the bar as a percentage, written short.
fn pct(thousandths: f64) -> String {
    format!("{}%", num(thousandths / 10.0))
}

fn num(v: f64) -> String {
    let s = format!("{v:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

/// A placed label beside the bar, in pixels at a column width.
struct Placed {
    above: bool,
    text: (f64, f64),
    bracket: (f64, f64),
}

impl Placed {
    fn clashes(&self, other: &Self) -> bool {
        let apart = |a: (f64, f64), b: (f64, f64), gap: f64| a.1 + gap <= b.0 || b.1 + gap <= a.0;
        self.above == other.above
            && !(apart(self.text, other.text, CLEAR)
                && apart(self.text, other.bracket, CLEAR)
                && apart(self.bracket, other.text, CLEAR)
                && apart(self.bracket, other.bracket, CLEAR))
    }
}

/// Where a label for `kind` saying `text` goes, if it fits in `width`: its
/// text's left and right, and how the page writes its x.
fn place(
    kind: &Kind,
    text: &str,
    width: f64,
) -> Option<((f64, f64), String, &'static str, &'static str)> {
    let px = |t: f64| t / f64::from(MAP_WIDTH) * width;
    let first = kind.centres().next()?;
    let last = kind.centres().last()?;
    let w = text_width(text, OUTSIDE_PX);
    // From just before the first tick, or from the bar's left edge.
    let (start, x, dx) = if px(first) >= TICK_REACH {
        (px(first) - TICK_REACH, pct(first), "-4")
    } else {
        (0.0, "0".to_owned(), "0")
    };
    if start + w <= width {
        return Some(((start, start + w), x, dx, "start"));
    }
    // Else ending just after the last tick, or at the bar's right edge.
    let (end, x, dx) = if px(last) + TICK_REACH <= width {
        (px(last) + TICK_REACH, pct(last), "4")
    } else {
        (width, "100%".to_owned(), "0")
    };
    (end - w >= 0.0).then_some(((end - w, end), x, dx, "end"))
}

fn lay_out(kinds: &[Kind], variant: &Variant, top: f64) -> LabelSet {
    let width = variant.min_width;
    let px = |t: f64| t / f64::from(MAP_WIDTH) * width;
    let mut inside = Vec::new();
    let mut outside = Vec::new();
    let mut placed: Vec<Placed> = Vec::new();

    for kind in kinds {
        let fits = (0..3).find_map(|t| {
            kind.parts
                .iter()
                .map(|&(x, w, bytes)| {
                    let text = kind.inside_texts(bytes).into_iter().nth(t)?;
                    (px(w) >= text_width(&text, INSIDE_PX) + 2.0 * INSIDE_PAD).then(|| Inside {
                        step: kind.step,
                        x: pct(x),
                        text,
                    })
                })
                .collect::<Option<Vec<_>>>()
        });
        if let Some(fits) = fits {
            inside.extend(fits);
            continue;
        }

        let sides = [kind.prefers_above(), !kind.prefers_above()];
        let spot = kind.outside_texts().into_iter().find_map(|text| {
            let (span, x, dx, anchor) = place(kind, &text, width)?;
            let first = px(kind.centres().next()?);
            let last = px(kind.centres().last()?);
            sides.into_iter().find_map(|above| {
                let p = Placed {
                    above,
                    text: span,
                    bracket: (first, last),
                };
                (!placed.iter().any(|q| q.clashes(&p)))
                    .then(|| (p, text.clone(), x.clone(), dx, anchor))
            })
        });
        let Some((p, text, x, dx, anchor)) = spot else {
            continue;
        };
        let (edge, reach, y) = if p.above {
            (top - 3.0, top - 8.0, top - 14.0)
        } else {
            (top + BAR_H + 3.0, top + BAR_H + 8.0, top + BAR_H + 22.0)
        };
        let ticks: Vec<String> = kind.centres().map(pct).collect();
        let bracket = (ticks.len() > 1).then(|| {
            (
                pct(kind.centres().next().unwrap_or_default()),
                pct(kind.centres().last().unwrap_or_default()),
            )
        });
        outside.push(Outside {
            step: kind.step,
            above: p.above,
            ticks,
            tick_y: (num(edge), num(reach)),
            bracket,
            x,
            dx,
            anchor,
            y: num(y),
            text,
        });
        placed.push(p);
    }
    LabelSet {
        class: variant.class,
        inside,
        outside,
    }
}

/// The labels for a bar laid out as `map`, `None` for an empty one.
pub fn map_labels(map: &[ProofSegment]) -> Option<MapLabels> {
    let mut kinds: Vec<Kind> = Vec::new();
    for g in map {
        let part = (f64::from(g.x), f64::from(g.width), g.bytes);
        match kinds.iter_mut().find(|k| k.class == g.class) {
            Some(k) => k.parts.push(part),
            None => kinds.push(Kind {
                class: g.class,
                step: g.step,
                parts: vec![part],
            }),
        }
    }
    if kinds.is_empty() {
        return None;
    }

    // Laid out once to learn which sides are used, then for real.
    let trial = [
        lay_out(&kinds, &WIDE, ABOVE),
        lay_out(&kinds, &NARROW, ABOVE),
    ];
    let used = |above: bool| {
        trial
            .iter()
            .flat_map(|s| &s.outside)
            .any(|o| o.above == above)
    };
    let top = if used(true) { ABOVE } else { 2.0 };
    let bottom = if used(false) { 30.0 } else { 2.0 };
    Some(MapLabels {
        top: num(top),
        height: num(top + BAR_H + bottom),
        inside_y: num(top + BAR_H / 2.0 + 4.5),
        sets: [lay_out(&kinds, &WIDE, top), lay_out(&kinds, &NARROW, top)],
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use crate::html::proof_map;
    use explorer_core::fcmp::MembershipShape;

    fn read_pct(s: &str) -> f64 {
        s.strip_suffix('%').unwrap_or(s).parse::<f64>().unwrap() / 100.0
    }

    /// Every label, as the page would draw it at `width`: its lane (`None`
    /// inside the bar) and its text's left and right, recomputed from what
    /// the page is given rather than from the layout's own figures.
    /// Each box carries the index of the label it belongs to, so a label's
    /// text is not held against its own ticks.
    fn drawn(
        set: &LabelSet,
        map: &[ProofSegment],
        width: f64,
    ) -> Vec<(usize, Option<bool>, f64, f64)> {
        let mut boxes = Vec::new();
        for l in &set.inside {
            let x = read_pct(&l.x) * width + INSIDE_PAD;
            let w = text_width(&l.text, INSIDE_PX);
            let part = map
                .iter()
                .find(|g| (read_pct(&pct(f64::from(g.x))) - read_pct(&l.x)).abs() < 1e-9)
                .expect("the label's part");
            let right = f64::from(part.x + part.width) / f64::from(MAP_WIDTH) * width;
            assert!(
                x + w + INSIDE_PAD <= right + 1e-6,
                "{} spills out of its part",
                l.text
            );
            boxes.push((boxes.len(), None, x, x + w));
        }
        for (i, l) in set.outside.iter().enumerate() {
            let id = 1000 + i;
            let at = read_pct(&l.x) * width + l.dx.parse::<f64>().unwrap();
            let w = text_width(&l.text, OUTSIDE_PX);
            let (a, b) = if l.anchor == "start" {
                (at, at + w)
            } else {
                (at - w, at)
            };
            assert!(
                a >= -1e-6 && b <= width + 1e-6,
                "{} leaves the bar at {width}",
                l.text
            );
            let above = l.y.parse::<f64>().unwrap() < l.tick_y.0.parse::<f64>().unwrap();
            assert_eq!(above, l.above);
            boxes.push((id, Some(above), a, b));
            // Its ticks and bracket sit in its lane, where no other text is.
            let ticks: Vec<f64> = l.ticks.iter().map(|t| read_pct(t) * width).collect();
            boxes.push((
                id,
                Some(above),
                ticks.iter().copied().fold(f64::MAX, f64::min),
                ticks.iter().copied().fold(f64::MIN, f64::max),
            ));
        }
        boxes
    }

    fn assert_apart(boxes: &[(usize, Option<bool>, f64, f64)], what: &str) {
        for (i, a) in boxes.iter().enumerate() {
            for b in &boxes[i + 1..] {
                if a.0 != b.0 && a.1.is_some() && a.1 == b.1 {
                    assert!(
                        a.3 + CLEAR <= b.2 + 1e-6 || b.3 + CLEAR <= a.2 + 1e-6,
                        "{what}: {a:?} and {b:?} touch"
                    );
                }
            }
        }
    }

    /// For every proof consensus allows, at every width each set is shown
    /// at, no label leaves the bar, spills out of its part or comes within
    /// `CLEAR` of another label or another kind's ticks.
    #[test]
    fn no_label_touches_another_at_any_width() {
        for inputs in 1..=128 {
            for layers in 1..=12u8 {
                let shape = MembershipShape::of(inputs, layers).unwrap();
                let map = proof_map(inputs, shape.len);
                let labels = map_labels(&map).unwrap();
                for (set, widths) in labels.sets.iter().zip([
                    [520.0, 600.0, 720.0, 865.0, 1200.0],
                    [248.0, 300.0, 360.0, 440.0, 519.9],
                ]) {
                    for width in widths {
                        let what = format!("{inputs} inputs, {layers} layers, {width} px");
                        assert_apart(&drawn(set, &map, width), &what);
                    }
                    // Up to 16 inputs, every kind of part is named somewhere.
                    let mut named: Vec<usize> = set.inside.iter().map(|l| l.step).collect();
                    named.extend(set.outside.iter().map(|l| l.step));
                    named.sort_unstable();
                    named.dedup();
                    if inputs <= 16 {
                        assert_eq!(named, [2, 3, 4, 5], "{inputs} inputs, {layers} layers");
                    }
                }
            }
        }
    }

    /// Parts of one kind but different sizes, as rings of different sizes
    /// sign: each labelled with its own size inside, and their total beside
    /// the bar.
    #[test]
    fn parts_of_one_kind_keep_their_own_sizes() {
        let bar = |sizes: &[usize], range: usize| {
            crate::html::lay_bar(
                sizes
                    .iter()
                    .map(|&b| (b, "ring", 2, String::new()))
                    .chain([(range, "range", 3, String::new())])
                    .collect(),
            )
        };
        let labels = map_labels(&bar(&[3_000, 5_000], 400)).unwrap();
        let inside: Vec<_> = labels.sets[0]
            .inside
            .iter()
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(inside, ["Signature · 3,000 B", "Signature · 5,000 B"]);

        let small = bar(&[64, 128, 64], 40_000);
        let labels = map_labels(&small).unwrap();
        let ring: Vec<_> = labels.sets[0]
            .outside
            .iter()
            .filter(|l| l.step == 2)
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(ring, ["Ring signature 256 B in 3"]);
        let equal = map_labels(&bar(&[64, 64], 40_000)).unwrap();
        assert!(
            equal.sets[0]
                .outside
                .iter()
                .any(|l| l.text == "Ring signature 64 B × 2")
        );
    }

    /// The real page's one input: the membership proof labelled inside, the
    /// small parts beside the bar, signatures above and the rest below.
    #[test]
    fn one_input_labels_every_part() {
        let map = proof_map(1, 4_160);
        let labels = map_labels(&map).unwrap();
        let [wide, narrow] = &labels.sets;
        let inside: Vec<_> = wide.inside.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(inside, ["Membership proof · 4,096 bytes"]);
        let outside: Vec<_> = wide
            .outside
            .iter()
            .map(|l| (l.text.as_str(), l.anchor, l.y.as_str()))
            .collect();
        assert_eq!(
            outside,
            [
                ("Disguised output 96 B", "start", "74"),
                ("Signature 384 B", "start", "12"),
                ("Root anchor 64 B", "end", "74")
            ]
        );
        assert_eq!((labels.top.as_str(), labels.height.as_str()), ("26", "82"));
        assert_eq!(narrow.inside[0].text, "Membership · 4,096 B");
        assert_eq!(narrow.outside.len(), 3, "the phone keeps every label");
        // Too near the edge on a phone to start before its tick, the first
        // label starts at the bar's edge.
        let first = &narrow.outside[0];
        assert_eq!((first.x.as_str(), first.dx), ("0", "0"));
        assert_eq!(wide.outside[0].dx, "-4");
        assert!(wide.outside.iter().all(|l| l.bracket.is_none()));
    }

    /// Two inputs' disguises share one label, ticked from both and joined.
    #[test]
    fn a_kind_with_several_parts_is_labelled_once() {
        let map = proof_map(2, 5_568);
        let labels = map_labels(&map).unwrap();
        let tuple = labels.sets[0]
            .outside
            .iter()
            .find(|l| l.step == 2)
            .expect("the disguises' label");
        assert_eq!(tuple.text, "Disguised output 96 B × 2");
        assert_eq!(tuple.ticks.len(), 2);
        assert_eq!(
            tuple.bracket,
            Some((tuple.ticks[0].clone(), tuple.ticks[1].clone()))
        );
    }

    #[test]
    fn no_bar_has_no_labels() {
        assert!(map_labels(&[]).is_none());
    }
}
