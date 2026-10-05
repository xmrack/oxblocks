//! The alternative chains as branches off the main chain, newest at the top.
//!
//! Every height a fork touches is a row: the main chain's parent, and each
//! alternative block beside the main block at its height. Runs of heights in
//! between collapse to one row with their count, and so does the middle of a
//! long alternative chain.

use std::collections::{BTreeMap, BTreeSet};

use monerod_rpc::types::ChainInfo;

use super::grouped;

/// Row heights; `.ag-row` and `.ag-gap` in style.css match them.
const ROW: u64 = 36;
const GAP: u64 = 30;
/// An alternative chain longer than this shows its first and last few blocks.
const KEEP: u64 = 3;

fn lane_x(lane: usize) -> u64 {
    16 + 24 * lane as u64
}

pub struct AltGraph {
    pub width: u64,
    pub height: u64,
    pub paths: Vec<(&'static str, String)>,
    pub blocks: Vec<(&'static str, u64, u64)>,
    pub rows: Vec<Row>,
}

pub enum Row {
    Block {
        height: u64,
        /// `None` above the main chain's tip, or where its hash is unknown.
        main: Option<String>,
        on_main: bool,
        /// One per lane, left to right.
        alts: Vec<Option<String>>,
        tip: bool,
        parent: bool,
    },
    Gap(u64),
    Tail,
}

struct Fork {
    first: u64,
    tip: u64,
    lane: usize,
    parent: String,
    /// Tip first, as monerod lists them.
    hashes: Vec<String>,
}

impl Fork {
    fn hash(&self, height: u64) -> Option<String> {
        let i = usize::try_from(self.tip.checked_sub(height)?).ok()?;
        self.hashes.get(i).map(|h| h.to_lowercase())
    }

    fn shown(&self, height: u64) -> bool {
        (self.first..=self.tip).contains(&height)
            && (self.tip - self.first < 2 * KEEP + 1
                || height < self.first + KEEP
                || height + KEEP > self.tip)
    }
}

fn forks(chains: &[ChainInfo]) -> Vec<Fork> {
    let mut forks: Vec<Fork> = chains
        .iter()
        .filter(|c| c.length > 0 && c.height >= c.length)
        .map(|c| Fork {
            first: c.height + 1 - c.length,
            tip: c.height,
            lane: 0,
            parent: c.main_chain_parent_block.to_lowercase(),
            hashes: if c.block_hashes.is_empty() {
                vec![c.block_hash.clone()]
            } else {
                c.block_hashes.clone()
            },
        })
        .collect();
    forks.sort_by(|a, b| b.tip.cmp(&a.tip).then(b.first.cmp(&a.first)));
    // A lane is free once every fork in it started above this one's tip.
    let mut lowest: Vec<u64> = Vec::new();
    for f in &mut forks {
        let start = f.first - 1;
        f.lane = match lowest.iter().position(|&l| l > f.tip) {
            Some(l) => l,
            None => {
                lowest.push(u64::MAX);
                lowest.len() - 1
            }
        };
        if let Some(l) = lowest.get_mut(f.lane) {
            *l = start;
        }
    }
    forks
}

/// Every main-chain height the graph shows, besides the tip and the parents,
/// whose hashes it already has.
pub fn main_heights(chains: &[ChainInfo], tip: u64) -> Vec<u64> {
    forks(chains)
        .iter()
        .flat_map(|f| (f.first..=f.tip.min(tip)).filter(|&h| f.shown(h) && h != tip))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn alt_graph(
    chains: &[ChainInfo],
    tip: u64,
    tip_hash: &str,
    main: &BTreeMap<u64, String>,
) -> AltGraph {
    let forks = forks(chains);
    let lanes = forks.iter().map(|f| f.lane + 1).max().unwrap_or(0);
    let parents: BTreeSet<u64> = forks.iter().map(|f| f.first - 1).collect();
    let mut main: BTreeMap<u64, String> = main.clone();
    main.insert(tip, tip_hash.to_lowercase());
    for f in &forks {
        main.insert(f.first - 1, f.parent.clone());
    }

    let heights: BTreeSet<u64> = std::iter::once(tip)
        .chain(parents.iter().copied())
        .chain(
            forks
                .iter()
                .flat_map(|f| (f.first..=f.tip).filter(|&h| f.shown(h))),
        )
        .collect();

    let mut rows = Vec::new();
    let mut above: Option<u64> = None;
    for &h in heights.iter().rev() {
        if let Some(a) = above
            && a - h > 1
        {
            rows.push(Row::Gap(a - h - 1));
        }
        let mut alts = vec![None; lanes];
        for f in forks.iter().filter(|f| f.shown(h)) {
            if let Some(a) = alts.get_mut(f.lane) {
                *a = Some(f.hash(h).unwrap_or_default());
            }
        }
        rows.push(Row::Block {
            height: h,
            main: main.get(&h).cloned(),
            on_main: h <= tip,
            alts,
            tip: h == tip,
            parent: parents.contains(&h),
        });
        above = Some(h);
    }
    rows.push(Row::Tail);

    let mut paths = Vec::new();
    let mut blocks = Vec::new();
    let mut y = 0;
    let mut prev: Option<u64> = None;
    for (i, row) in rows.iter().enumerate() {
        let rh = if matches!(row, Row::Block { .. }) {
            ROW
        } else {
            GAP
        };
        let cy = y + rh / 2;
        let x0 = lane_x(0);
        match row {
            Row::Block {
                height,
                on_main,
                tip: is_tip,
                ..
            } => {
                if *on_main {
                    let top = if *is_tip { cy } else { y };
                    paths.push(("ag-ln", format!("M{x0} {top}V{}", y + rh)));
                    blocks.push((if *is_tip { "ag-blk ag-tip" } else { "ag-blk" }, x0, cy));
                }
                for f in forks.iter().filter(|f| f.shown(*height)) {
                    let x = lane_x(f.lane + 1);
                    if *height < f.tip {
                        paths.push(("ag-ln ag-alt", format!("M{x} {y}V{cy}")));
                    }
                    if *height == f.first {
                        let py = y + rh + ROW / 2;
                        paths.push((
                            "ag-ln ag-alt",
                            format!("M{x0} {py}C{x0} {} {x} {} {x} {cy}", py - 20, cy + 16),
                        ));
                    } else {
                        paths.push(("ag-ln ag-alt", format!("M{x} {cy}V{}", y + rh)));
                    }
                    blocks.push(("ag-blk ag-altb", x, cy));
                }
                prev = Some(*height);
            }
            Row::Gap(n) => {
                let below = prev.map_or(0, |p| p - n - 1);
                if prev.is_some_and(|p| p <= tip) {
                    paths.push(("ag-ln ag-dash", format!("M{x0} {y}V{}", y + rh)));
                }
                for f in forks
                    .iter()
                    .filter(|f| f.first <= below && f.tip > below + n)
                {
                    let x = lane_x(f.lane + 1);
                    paths.push(("ag-ln ag-alt ag-dash", format!("M{x} {y}V{}", y + rh)));
                }
            }
            Row::Tail => {
                if i > 0 {
                    paths.push(("ag-ln ag-fade", format!("M{x0} {y}V{}", y + rh)));
                }
            }
        }
        y += rh;
    }

    AltGraph {
        width: lane_x(lanes) + 22,
        height: y,
        paths,
        blocks,
        rows,
    }
}

impl Row {
    pub fn gap_text(&self) -> String {
        match self {
            Self::Gap(n) => format!("{} block{}", grouped(*n), if *n == 1 { "" } else { "s" }),
            _ => String::new(),
        }
    }
}

pub fn short(hash: &str) -> &str {
    hash.get(..8).unwrap_or(hash)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn chain(tip: u64, length: u64, tag: char) -> ChainInfo {
        let hashes: Vec<String> = (0..length)
            .map(|i| format!("{tag}{:063}", tip - i))
            .collect();
        serde_json::from_value(serde_json::json!({
            "block_hash": hashes[0], "height": tip, "length": length,
            "difficulty": 1, "difficulty_top64": 0, "wide_difficulty": "",
            "block_hashes": hashes,
            "main_chain_parent_block": format!("p{:063}", tip - length),
        }))
        .expect("a chain")
    }

    /// Each row as text: a block's height, then its lanes, `a` for an
    /// alternative block, `.` for none; a gap as its count.
    fn shape(g: &AltGraph) -> Vec<String> {
        g.rows
            .iter()
            .map(|r| match r {
                Row::Block {
                    height,
                    alts,
                    tip,
                    parent,
                    ..
                } => format!(
                    "{height} {}{}{}",
                    alts.iter()
                        .map(|a| if a.is_some() { 'a' } else { '.' })
                        .collect::<String>(),
                    if *tip { " tip" } else { "" },
                    if *parent { " parent" } else { "" },
                ),
                Row::Gap(n) => format!("({n})"),
                Row::Tail => "~".to_owned(),
            })
            .collect()
    }

    /// The three one-block forks oxblocks.net held on 2026-10-05.
    #[test]
    fn separate_forks_share_a_lane_and_the_runs_between_collapse() {
        let chains = [
            chain(3_103_106, 1, 'a'),
            chain(3_103_341, 1, 'b'),
            chain(3_103_208, 1, 'c'),
        ];
        let g = alt_graph(&chains, 3_103_402, "t", &BTreeMap::new());
        assert_eq!(
            shape(&g),
            [
                "3103402 . tip",
                "(60)",
                "3103341 a",
                "3103340 . parent",
                "(131)",
                "3103208 a",
                "3103207 . parent",
                "(100)",
                "3103106 a",
                "3103105 . parent",
                "~",
            ]
        );
        assert_eq!(
            main_heights(&chains, 3_103_402),
            [3_103_106, 3_103_208, 3_103_341]
        );
    }

    #[test]
    fn a_block_shows_its_own_hash_in_its_own_lane() {
        let g = alt_graph(&[chain(12, 3, 'a')], 20, "t", &BTreeMap::new());
        let Row::Block {
            height: 11,
            alts,
            main,
            ..
        } = &g.rows[3]
        else {
            panic!("{:?}", shape(&g))
        };
        assert_eq!(alts, &[Some(format!("a{:063}", 11))]);
        assert_eq!(main, &None);
        let Row::Block {
            height: 9, main, ..
        } = &g.rows[5]
        else {
            panic!("{:?}", shape(&g))
        };
        assert_eq!(main.as_deref(), Some(&*format!("p{:063}", 9)));
    }

    #[test]
    fn overlapping_forks_take_separate_lanes() {
        let g = alt_graph(
            &[chain(12, 3, 'a'), chain(11, 1, 'b')],
            12,
            "t",
            &BTreeMap::new(),
        );
        assert_eq!(
            shape(&g),
            ["12 a. tip", "11 aa", "10 a. parent", "9 .. parent", "~"]
        );
    }

    #[test]
    fn a_long_fork_shows_its_ends() {
        let chains = [chain(30, 10, 'a')];
        let g = alt_graph(&chains, 40, "t", &BTreeMap::new());
        assert_eq!(
            shape(&g),
            [
                "40 . tip",
                "(9)",
                "30 a",
                "29 a",
                "28 a",
                "(4)",
                "23 a",
                "22 a",
                "21 a",
                "20 . parent",
                "~"
            ]
        );
        let dashed_lane = format!("M{} ", lane_x(1));
        assert!(
            g.paths
                .iter()
                .any(|(c, d)| *c == "ag-ln ag-alt ag-dash" && d.starts_with(&dashed_lane))
        );
        assert_eq!(main_heights(&chains, 40), [21, 22, 23, 28, 29, 30]);
    }

    #[test]
    fn a_fork_above_the_tip_has_no_main_block_beside_it() {
        let g = alt_graph(&[chain(12, 2, 'a')], 11, "t", &BTreeMap::new());
        assert_eq!(shape(&g), ["12 a", "11 a tip", "10 . parent", "~"]);
        let Row::Block { on_main, .. } = &g.rows[0] else {
            panic!()
        };
        assert!(!on_main);
        assert_eq!(
            g.blocks.iter().filter(|b| b.0 == "ag-blk ag-tip").count(),
            1
        );
        assert_eq!(g.blocks.iter().filter(|b| b.1 == lane_x(0)).count(), 2);
    }
}
