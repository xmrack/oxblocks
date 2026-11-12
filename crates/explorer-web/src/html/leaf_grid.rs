//! The paths page's picture of the curve tree: the part of it the paths
//! shown climb through, drawn whole.
//!
//! Each row is one group of leaves, and the cell at its end is the node of
//! layer 1 the row hashes to, so that column of cells is a group of layer 1.
//! Each layer above is a column of the group the paths pass through, joined
//! by a bracket to the node it hashes to, up to the root. Cells on a path
//! are solid, and the rest of each group on one, which a wallet keeps as
//! well, is tinted. Rows no path passes through are drawn as a pattern.

use std::collections::{BTreeMap, BTreeSet};

use explorer_core::curve_tree::{Group, PlacedPath, group_width};

use super::grouped;

/// A cell's side, and the distance from one cell to the next, in the
/// drawing's units.
pub const CELL: u32 = 6;
pub const PITCH: u32 = 7;
/// Room for the column labels above the grid: whole pitches, so that the
/// grid's rows fall on the pattern its untouched rows are drawn with.
const HEADER: u32 = 3 * PITCH;
/// From the end of a column to the start of the next, where the bracket
/// joining them goes.
const BRACKET: u32 = 14;
/// A layer's group is a column of at least this many cells, or as many as
/// the grid has rows, before it wraps into another column beside it.
const MIN_WRAP: u64 = 6;
/// Room at the right for the last column's label.
const LAST_LABEL: u32 = 24;

/// The picture, laid out.
pub struct LeafGrid {
    pub width: u32,
    pub height: u32,
    /// Rows of leaves that no path shown passes through, one patterned bar
    /// each.
    pub bars: Vec<Bar>,
    pub cells: Vec<Cell>,
    /// One bracket from each group to the node above it hashes to, as SVG
    /// path data.
    pub brackets: Vec<String>,
    /// Over the grid and over each column.
    pub labels: Vec<Label>,
    /// For a screen reader, what the picture shows.
    pub summary: String,
    /// Whether any of the transaction's outputs are drawn outlined, being
    /// in a group shown but not among the outputs shown.
    pub has_others: bool,
}

pub struct Bar {
    pub y: u32,
    pub width: u32,
}

pub struct Cell {
    pub x: u32,
    pub y: u32,
    /// `on` for a path's own, `kept` for the rest of a group on one, and
    /// `other` for another of the transaction's outputs.
    pub class: &'static str,
    pub title: String,
}

pub struct Label {
    pub x: u32,
    pub text: String,
}

/// Lay out the part of a tree of `n_leaf_tuples` leaves that `placed`
/// climb through. `outputs` numbers the transaction's outputs from 1 by
/// unified id, all of them, shown or not.
///
/// `None` when there is no path to draw.
pub fn leaf_grid(
    placed: &[&PlacedPath],
    n_leaf_tuples: u64,
    outputs: &BTreeMap<u64, usize>,
) -> Option<LeafGrid> {
    let depth = placed.first()?.groups.len().checked_sub(1)?;
    if depth == 0 || placed.iter().any(|p| p.groups.len() != depth + 1) {
        return None;
    }

    // At each layer, the groups the paths pass through, by their first
    // member, and the members on a path.
    let mut shown: Vec<BTreeMap<u64, Group>> = vec![BTreeMap::new(); depth + 1];
    let mut on: Vec<BTreeSet<u64>> = vec![BTreeSet::new(); depth + 1];
    for g in placed.iter().flat_map(|p| &p.groups) {
        if let (Some(s), Some(o)) = (shown.get_mut(g.layer), on.get_mut(g.layer)) {
            s.entry(g.start).or_insert_with(|| g.clone());
            o.insert(g.member);
        }
    }
    // The leaves of the groups the paths hold, by their place in the tree.
    let mut leaves = BTreeMap::new();
    for p in placed {
        let start = p.groups.first().map_or(0, |g| g.start);
        for (leaf, place) in p.path.leaves.iter().zip(start..) {
            leaves.insert(place, leaf);
        }
    }

    let width0 = group_width(0);
    let mut cells = Vec::new();
    let mut bars = Vec::new();
    // Each layer's cells by node, for the brackets.
    let mut at: Vec<BTreeMap<u64, (u32, u32)>> = vec![BTreeMap::new(); depth + 1];

    // The grid: a row for each node of layer 1 shown, a blank row between
    // groups, and the node itself at the row's end.
    let x1 = u32::try_from(width0).ok()? * PITCH + PITCH;
    let mut y = HEADER;
    let (mut first_leaf, mut last_leaf) = (u64::MAX, 0);
    for (k, g) in shown.get(1)?.values().enumerate() {
        if k > 0 {
            y += PITCH;
        }
        for node in g.start..g.start.saturating_add(g.len) {
            let from = node.saturating_mul(width0);
            let to = from.saturating_add(width0).min(n_leaf_tuples);
            first_leaf = first_leaf.min(from);
            last_leaf = last_leaf.max(to);
            if shown.first()?.contains_key(&from) {
                for place in from..to {
                    let uid = leaves.get(&place).map(|l| l.unified_id);
                    let output = uid.and_then(|u| outputs.get(&u));
                    let class = if on.first()?.contains(&place) {
                        "on"
                    } else if output.is_some() {
                        "other"
                    } else {
                        "kept"
                    };
                    let title = match output {
                        Some(k) => format!("Leaf {}, output {k}", grouped(place)),
                        None => format!("Leaf {}", grouped(place)),
                    };
                    let x = u32::try_from(place - from).ok()? * PITCH;
                    cells.push(Cell { x, y, class, title });
                }
            } else {
                bars.push(Bar {
                    y,
                    width: u32::try_from(to - from).ok()? * PITCH - 1,
                });
            }
            let class = if on.get(1)?.contains(&node) {
                "on"
            } else {
                "kept"
            };
            let title = if depth == 1 {
                "The root".to_owned()
            } else {
                format!(
                    "Layer 1, node {} of {}",
                    grouped(node),
                    grouped(g.layer_size)
                )
            };
            cells.push(Cell {
                x: x1,
                y,
                class,
                title,
            });
            at.get_mut(1)?.insert(node, (x1, y));
            y += PITCH;
        }
    }
    let grid_bottom = y;
    let grid_rows = u64::from((grid_bottom - HEADER) / PITCH);

    let mut labels = vec![Label {
        x: 0,
        text: format!(
            "Leaves {}–{} of {}",
            grouped(first_leaf),
            grouped(last_leaf.saturating_sub(1)),
            grouped(n_leaf_tuples)
        ),
    }];
    let column_label = |layer: usize| {
        if layer == depth {
            "Root".to_owned()
        } else {
            format!("L{layer}")
        }
    };
    labels.push(Label {
        x: x1,
        text: column_label(1),
    });

    // Each layer above: its groups as columns, wrapped when tall, centred
    // on the grid.
    let mut brackets = Vec::new();
    let mut x = x1 + CELL + BRACKET;
    let mut bottom = grid_bottom;
    let wrap = grid_rows.max(MIN_WRAP);
    for layer in 2..=depth {
        let groups: Vec<&Group> = shown.get(layer)?.values().collect();
        let tall: u64 = groups.iter().map(|g| g.len.min(wrap)).sum::<u64>()
            + (groups.len() as u64).saturating_sub(1);
        let tall = u32::try_from(tall).ok()? * PITCH;
        let mut top = HEADER + (grid_bottom - HEADER).saturating_sub(tall) / 2;
        let mut columns = 1;
        for g in groups {
            let rows = g.len.min(wrap).max(1);
            for (j, node) in (g.start..g.start.saturating_add(g.len)).enumerate() {
                let j = j as u64;
                let cx = x + u32::try_from(j / rows).ok()? * PITCH;
                let cy = top + u32::try_from(j % rows).ok()? * PITCH;
                columns = columns.max(j / rows + 1);
                let class = if on.get(layer)?.contains(&node) {
                    "on"
                } else {
                    "kept"
                };
                let title = if layer == depth {
                    "The root".to_owned()
                } else {
                    format!(
                        "Layer {layer}, node {} of {}",
                        grouped(node),
                        grouped(g.layer_size)
                    )
                };
                cells.push(Cell {
                    x: cx,
                    y: cy,
                    class,
                    title,
                });
                at.get_mut(layer)?.insert(node, (cx, cy));
            }
            top += u32::try_from(rows + 1).ok()? * PITCH;
            bottom = bottom.max(top - PITCH);
        }
        labels.push(Label {
            x,
            text: column_label(layer),
        });

        // Each group of the layer below, bracketed to the node it hashes to.
        for g in shown.get(layer - 1)?.values() {
            let parent = g.start / group_width(layer - 1);
            let (Some(&(px, py)), Some(below)) = (at.get(layer)?.get(&parent), at.get(layer - 1))
            else {
                continue;
            };
            let spots: Vec<(u32, u32)> = below
                .range(g.start..g.start.saturating_add(g.len))
                .map(|(_, &spot)| spot)
                .collect();
            let (Some(y0), Some(y1), Some(xr)) = (
                spots.iter().map(|s| s.1).min(),
                spots.iter().map(|s| s.1 + CELL).max(),
                spots.iter().map(|s| s.0 + CELL).max(),
            ) else {
                continue;
            };
            let xb = xr + 3;
            let mid = (y0 + y1) / 2;
            let target = py + CELL / 2;
            let turn = (xb + px) / 2;
            brackets.push(format!(
                "M{},{y0} H{xb} V{y1} H{} M{xb},{mid} H{turn} V{target} H{}",
                xr + 1,
                xr + 1,
                px - 1
            ));
        }
        x += u32::try_from(columns).ok()? * PITCH - 1 + BRACKET;
    }

    let width = x - BRACKET + LAST_LABEL;
    let has_others = cells.iter().any(|c| c.class == "other");
    let shown_outputs = on.first().map_or(0, BTreeSet::len);
    let summary = format!(
        "{} {} in the curve tree, among leaves {} to {}, with the groups above \
         them up to the root",
        shown_outputs,
        if shown_outputs == 1 {
            "output"
        } else {
            "outputs"
        },
        grouped(first_leaf),
        grouped(last_leaf.saturating_sub(1))
    );
    Some(LeafGrid {
        width,
        height: bottom + 2,
        bars,
        cells,
        brackets,
        labels,
        summary,
        has_others,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use explorer_core::curve_tree::{PathCheck, path_groups};
    use monerod_rpc::types::{LeafKind, PathLeaf, TreePath};

    use super::*;

    /// A path to `leaf` in a tree of `n` leaves, shaped right; its points are
    /// not, which the grid does not look at.
    fn placed(n: u64, leaf: u64) -> PlacedPath {
        let groups = path_groups(n, leaf);
        let leaves = (groups[0].start..groups[0].start + groups[0].len)
            .map(|place| PathLeaf {
                unified_id: place + 1000,
                kind: LeafKind::Carrot,
                output_key: [0; 32],
                commitment: [0; 32],
            })
            .collect();
        let layers = groups[1..]
            .iter()
            .map(|g| vec![[0; 32]; usize::try_from(g.len).unwrap()])
            .collect();
        PlacedPath {
            unified_id: leaf + 1000,
            path: TreePath {
                leaf_idx: leaf,
                leaves,
                layers,
            },
            groups,
            check: PathCheck::Holds,
        }
    }

    /// Two outputs either side of a boundary between groups of layer 1, in
    /// a tree four layers deep: both groups of layer 1 are drawn, layer 2's
    /// group of 38 wraps into a second column, and every group is bracketed
    /// to the node above it, up to the root.
    #[test]
    fn a_deep_tree_with_outputs_across_groups_is_drawn_whole() {
        let n = 100_000;
        let boundary = 38 * 18 * 3;
        let (a, b) = (placed(n, boundary - 1), placed(n, boundary));
        let outputs: BTreeMap<u64, usize> = [(boundary - 1 + 1000, 1), (boundary + 1000, 2)].into();
        let g = leaf_grid(&[&a, &b], n, &outputs).unwrap();

        let labels: Vec<&str> = g.labels.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            labels,
            ["Leaves 1,368–2,735 of 100,000", "L1", "L2", "L3", "Root"]
        );
        // Two groups of layer 1, 18 rows each; two rows hold the outputs.
        let rows = g.bars.len() + 2;
        assert_eq!(rows, 36);
        assert_eq!(
            g.cells.iter().filter(|c| c.class == "on").count(),
            2 + 2 + 2 + 1 + 1
        );
        // Two brackets from layer 1, one from each layer above.
        assert_eq!(g.brackets.len(), 4);
        // Layer 2's 38 nodes, in two columns.
        let l2: BTreeSet<u32> = g
            .cells
            .iter()
            .filter(|c| c.title.starts_with("Layer 2"))
            .map(|c| c.x)
            .collect();
        assert_eq!(l2.len(), 2);
        // No two cells in one place, and all inside the drawing.
        let spots: BTreeSet<(u32, u32)> = g.cells.iter().map(|c| (c.x, c.y)).collect();
        assert_eq!(spots.len(), g.cells.len());
        assert!(
            g.cells
                .iter()
                .all(|c| c.x + CELL <= g.width && c.y + CELL <= g.height)
        );
    }
}
