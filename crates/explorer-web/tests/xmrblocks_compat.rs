//! Proof that the `/api/*` bodies match xmrblocks, built from captured
//! responses so it needs neither a daemon nor a network.
//!
//! Both sides are real captures **of the same chain**:
//!
//! * `fixtures/devel-api/` holds xmrblocks responses for the local testnet.
//! * `fixtures/testnet/devel_*` holds monerod's answers for the same blocks
//!   and transactions, from the daemon that explorer was reading.
//!
//! Because both come from one chain at one moment, there is nothing
//! tip-relative to excuse: `current_height` and `confirmations` must match
//! exactly, and any difference at all is a real difference.
//!
//! The keys in [`FCMP_PP_KEYS`] are absent from the captures, so they are
//! checked on the oxblocks side only: each must be `null` on these pre-FCMP++
//! blocks, except `view_tag`, which a tagged output carries. `in_pool` is
//! absent from them too, and must be `false`, since every captured
//! transaction is mined. Every key the captures do contain must be present
//! and equal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;

use serde_json::Value;

#[path = "../src/api/shapes.rs"]
#[allow(dead_code)]
mod shapes;

fn load(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel} is not JSON: {e}"))
}

/// The keys for FCMP++, Carrot and view tags. Named one by one, so any other
/// key missing from the captures still fails.
const FCMP_PP_KEYS: &[&str] = &[
    "anonymity_set",
    "encrypted_janus_anchor",
    "fcmp_pp_proof_size",
    "n_tree_layers",
    "reference_block",
    "tree_root",
    "unified_id",
    "view_tag",
];

fn diff(ours: &Value, theirs: &Value, path: &str, out: &mut Vec<String>) {
    match (ours, theirs) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            for k in keys {
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => diff(x, y, &format!("{path}/{k}"), out),
                    (None, Some(y)) => {
                        out.push(format!("{path}/{k}: missing from ours (xmrblocks {y})"));
                    }
                    // A one-byte tag, as these pre-Carrot outputs carry.
                    (Some(Value::String(t)), None)
                        if k == "view_tag"
                            && t.len() == 2
                            && t.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                    (Some(Value::Null), None) if FCMP_PP_KEYS.contains(&k.as_str()) => {}
                    (Some(Value::Bool(false)), None) if k == "in_pool" => {}
                    (Some(x), None) => out.push(format!("{path}/{k}: extra in ours ({x})")),
                    (None, None) => unreachable!("key came from one of the two maps"),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                out.push(format!("{path}: length {} vs {}", a.len(), b.len()));
            }
            for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                diff(x, y, &format!("{path}[{i}]"), out);
            }
        }
        (x, y) if x == y => {}
        (x, y) => out.push(format!("{path}: {x} vs xmrblocks {y}")),
    }
}

fn assert_identical(ours: &Value, capture: &str) {
    let theirs = load(&format!("devel-api/{capture}"));
    let mut out = Vec::new();
    diff(ours, &theirs, "", &mut out);
    assert!(
        out.is_empty(),
        "{capture} differs from xmrblocks in {} place(s):\n  {}",
        out.len(),
        out.join("\n  ")
    );
}

/// Render a block exactly as the handler does, from captured monerod responses.
fn render_block(height: u64) -> Value {
    use monerod_rpc::types::{GetBlock, GetTransactionsResponse};

    let got: GetBlock = serde_json::from_value(
        load(&format!("testnet/devel_block_{height}.json"))["result"].clone(),
    )
    .expect("block decodes");
    let fetched: GetTransactionsResponse =
        serde_json::from_value(load(&format!("testnet/devel_block_{height}_txs.json")))
            .expect("transactions decode");

    let header = &got.block_header;
    let tree = explorer_core::BlockTree::of(&got);
    let detail = shapes::BlockDetail::build(header, header.depth, &fetched.txs, tree.as_ref());
    serde_json::json!({
        "data": serde_json::to_value(detail).expect("serialises"),
        "status": "success",
    })
}

#[test]
fn a_block_with_a_ring_transaction_matches_its_capture() {
    assert_identical(&render_block(134_721), "block_134721.json");
}

#[test]
fn a_block_with_a_seven_input_transaction_matches_its_capture() {
    assert_identical(&render_block(3_900), "block_3900.json");
}

#[test]
fn a_coinbase_only_block_matches_its_capture() {
    assert_identical(&render_block(134_720), "block_coinbase_only.json");
}

/// `/api/blocks/<start>/<end>`, the k-anonymous block lookup. Its `data` is a
/// bare **list** of single-block objects, not an object wrapping one.
#[test]
fn a_block_range_matches_its_capture() {
    let blocks: Vec<Value> = (134_719..=134_721)
        .map(|h| render_block(h)["data"].clone())
        .collect();
    let ours = serde_json::json!({ "data": blocks, "status": "success" });
    assert_identical(&ours, "blocks_range.json");
}

#[test]
fn a_ring_transaction_matches_its_capture() {
    use explorer_core::{Hash32, ResolvedInput, RingMember};
    use monerod_rpc::types::{GetOutsResponse, GetTransactionsResponse, TxIn};

    let fetched: GetTransactionsResponse =
        serde_json::from_value(load("testnet/devel_tx_ring.json")).expect("decodes");
    let entry = &fetched.txs[0];
    let tx = entry.parse_json().expect("as_json present");

    // One /get_outs per input, as the handler issues them.
    let per_input: Vec<GetOutsResponse> =
        serde_json::from_value(load("testnet/get_outs_ring.json"))
            .map(|r: GetOutsResponse| vec![r])
            .expect("decodes");

    let rings: Vec<ResolvedInput> = tx
        .vin
        .iter()
        .zip(per_input.iter())
        .map(|(vin, outs)| {
            let TxIn::Key(k) = vin else {
                panic!("a ring transaction's inputs are key inputs")
            };
            let requests = k.ring_members().expect("offsets sum");
            ResolvedInput {
                amount: k.amount,
                key_image: k.k_image.parse().expect("valid key image"),
                ring: requests
                    .iter()
                    .zip(outs.outs.iter())
                    .map(|(req, o)| RingMember {
                        index: req.index(),
                        block_height: o.height,
                        public_key: o.key.parse().unwrap_or(Hash32::ZERO),
                        tx_hash: o.txid.parse().unwrap_or(Hash32::ZERO),
                    })
                    .collect(),
                ring_unavailable: false,
            }
        })
        .collect();

    let current = entry.block_height + entry.confirmations;
    let detail = shapes::TxDetail::build(entry, &tx, &rings, current);
    let ours = serde_json::json!({
        "data": serde_json::to_value(&detail).expect("serialises"),
        "status": "success",
    });
    assert_identical(&ours, "transaction_ring.json");
}

/// `unlock_time` gets an assertion of its own rather than being covered only
/// by the whole-object comparisons.
#[test]
fn unlock_time_is_present_and_carries_the_real_value() {
    let block = render_block(134_721);
    let txs = block["data"]["txs"].as_array().expect("txs is an array");

    for tx in txs {
        assert!(
            tx.get("unlock_time").is_some(),
            "every transaction object carries unlock_time"
        );
    }

    // The coinbase of block 134721 unlocks 60 blocks later, which is the one
    // place the value is neither zero nor arbitrary.
    let captured = load("devel-api/block_134721.json");
    let theirs = captured["data"]["txs"][0]["unlock_time"].as_u64();
    assert_eq!(txs[0]["unlock_time"].as_u64(), theirs);
    assert!(
        theirs.is_some_and(|t| t > 0),
        "a coinbase has a non-zero unlock_time, so this test is not vacuous"
    );
}

/// The FCMP++ keys are on every transaction object, and hold `null` on a chain
/// from before FCMP++ rather than being left out.
#[test]
fn the_fcmp_pp_keys_are_present_and_null_before_the_fork() {
    let block = render_block(134_721);
    for tx in block["data"]["txs"].as_array().expect("txs is an array") {
        assert_eq!(tx.get("reference_block"), Some(&Value::Null));
        assert_eq!(tx.get("n_tree_layers"), Some(&Value::Null));
        assert_eq!(tx.get("fcmp_pp_proof_size"), Some(&Value::Null));
    }
    assert_eq!(block["data"].get("tree_root"), Some(&Value::Null));
    assert_eq!(block["data"].get("n_tree_layers"), Some(&Value::Null));
}

/// The FCMP++ keys filled from a real FCMP++ capture: the reference block and
/// layer count from the proof, and each Carrot output's tag and anchor.
#[test]
fn a_captured_fcmp_pp_transaction_fills_the_fcmp_pp_keys() {
    use monerod_rpc::types::GetTransactionsResponse;

    let fetched: GetTransactionsResponse =
        serde_json::from_value(load("fcmp/get_transactions_fcmp.json")).expect("decodes");
    for entry in &fetched.txs {
        let tx = entry.parse_json().expect("as_json present");
        let rings = explorer_core::unexpanded_inputs(&tx);
        let detail = serde_json::to_value(shapes::TxDetail::build(
            entry,
            &tx,
            &rings,
            entry.block_height + 1,
        ))
        .expect("serialises");

        let (ids, tags, anchors): (&[u64], &[&str], &[&str]) = match entry.tx_hash.as_str() {
            "c61a89a96da974dd4dfda3fc5098b9769ea3110dd6c55faeb9c117770c7a6a8e" => (
                &[122, 123],
                &["2dcfb0", "63bc5c"],
                &[
                    "ff912f8f997a8302c2f2e81db9ed4584",
                    "4d8db2ee61f6a8eb341302b7aee4dc80",
                ],
            ),
            "16152336142f941ddc6cc7c0df697ca1a393541d9661504c3b120996303c4949" => (
                &[124, 125, 126, 127],
                &["05483e", "eb5bd8", "5e5faf", "f802b0"],
                &[
                    "bd3d6a1ea09b614e0de1e80270a329aa",
                    "ef983e3f234b840828f55832efbab2c9",
                    "77b22255ca3cec609bba2c1c09e26fe8",
                    "cdbcaf222121bf493b37d4526f0f63ea",
                ],
            ),
            other => panic!("not in the capture: {other}"),
        };
        assert_eq!(detail["reference_block"].as_u64(), Some(120));
        assert_eq!(detail["n_tree_layers"].as_u64(), Some(2));
        assert_eq!(detail["fcmp_pp_proof_size"].as_u64(), Some(6528));
        let outputs = detail["outputs"].as_array().expect("outputs");
        let field = |k: &str| -> Vec<Value> { outputs.iter().map(|o| o[k].clone()).collect() };
        assert_eq!(
            field("unified_id"),
            ids.iter().map(|&i| Value::from(i)).collect::<Vec<_>>()
        );
        assert_eq!(
            field("view_tag"),
            tags.iter().map(|&t| Value::from(t)).collect::<Vec<_>>()
        );
        assert_eq!(
            field("encrypted_janus_anchor"),
            anchors.iter().map(|&a| Value::from(a)).collect::<Vec<_>>()
        );
    }
}
