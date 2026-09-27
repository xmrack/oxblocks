//! Replay of real monerod responses captured in `fixtures/`.
//!
//! Every assertion here is against bytes a daemon actually sent, so these are
//! the tests that catch a field this crate models as required which monerod
//! omits — the failure mode that no amount of reading the C++ headers finds,
//! because the headers describe what monerod *has*, not what it *emits*.
//!
//! Nothing here touches the network. The few tests that do are `#[ignore]`d and
//! read node URLs from the environment.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use monerod_rpc::types::{
    BlockHeader, BlockJson, ChainInfo, EcdhForm, EcdhInfo, FeeEstimate, GetAlternateChains,
    GetBlock, GetBlockCount, GetBlockHeader, GetBlockHeadersRange, GetHeight, GetInfo,
    GetOutsResponse, GetTransactionPool, GetTransactionsResponse, IsKeyImageSpentResponse,
    NestedJsonError, OutKey, OutKeyRequest, PseudoOutsLocation, RctSigBase, RctType, SpentStatus,
    TxEntry, TxIn, TxJson, TxOutTarget, parse_wide, reassemble_u128, split_ring_signatures,
};

/// `"signatures": [ ]` — present and empty, which is what a v1 coinbase emits
/// in the non-split form and is a different fact from the key being absent.
const NO_SIGNATURES: &[String] = &[];

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn raw(rel: &str) -> Value {
    let path = fixtures_root().join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("fixture {} is not valid JSON: {e}", path.display()))
}

/// The `result` member of a JSON-RPC fixture.
fn result_of(rel: &str) -> Value {
    let v = raw(rel);
    v.get("result")
        .unwrap_or_else(|| panic!("{rel} has no result member"))
        .clone()
}

/// Deserialize into `T` and prove nothing was silently dropped on the way.
///
/// Re-serializing and diffing catches the quiet failure a "does it parse?" test
/// misses: a field name we got wrong deserializes fine (serde ignores unknown
/// keys) and then vanishes from our model.
fn replay<T: DeserializeOwned + Serialize>(original: &Value, what: &str) -> T {
    let parsed: T = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("{what} did not deserialize: {e}"));
    let produced = serde_json::to_value(&parsed)
        .unwrap_or_else(|e| panic!("{what} did not re-serialize: {e}"));
    assert_no_data_loss(original, &produced, what);
    parsed
}

/// Assert every key and value in `original` survives into `produced`.
///
/// One-directional on purpose: we may legitimately emit *more* than monerod
/// does, because the inner serializer keeps empty arrays that epee drops.
fn assert_no_data_loss(original: &Value, produced: &Value, path: &str) {
    match (original, produced) {
        (Value::Object(o), Value::Object(p)) => {
            for (key, ov) in o {
                let pv = p
                    .get(key)
                    .unwrap_or_else(|| panic!("{path}.{key} was dropped by our model"));
                assert_no_data_loss(ov, pv, &format!("{path}.{key}"));
            }
        }
        (Value::Array(o), Value::Array(p)) => {
            assert_eq!(o.len(), p.len(), "{path} changed length");
            for (i, (ov, pv)) in o.iter().zip(p.iter()).enumerate() {
                assert_no_data_loss(ov, pv, &format!("{path}[{i}]"));
            }
        }
        _ => assert_eq!(original, produced, "{path} changed value"),
    }
}

/// Every fixture this suite understands, with the type it replays into.
///
/// A fixture not in this list still has to be valid JSON (see
/// [`every_fixture_on_disk_is_at_least_valid_json`]) but is not typed — that is
/// deliberate, so another crate adding a capture does not break this one.
const REPLAYED: &[&str] = &[
    "testnet/get_info.json",
    "testnet/get_info_master.json",
    "testnet/get_block_134721.json",
    "testnet/get_block_coinbase_only.json",
    "testnet/get_block_headers_range.json",
    "testnet/get_last_block_header.json",
    "testnet/get_block_count.json",
    "testnet/get_fee_estimate.json",
    "testnet/get_alternate_chains.json",
    "testnet/get_height.json",
    "testnet/get_transaction_pool.json",
    "testnet/get_transactions_ring.json",
    "testnet/get_transactions_coinbase.json",
    "testnet/get_transactions_coinbase_split.json",
    "testnet/get_transactions_multi_input.json",
    "testnet/get_outs_ring.json",
    "testnet/get_outs_no_txid.json",
    "testnet/is_key_image_spent.json",
    "testnet/tx_as_json_parsed.json",
    "mainnet/get_block_ringct.json",
    "mainnet/get_outs_ringct.json",
    "mainnet/get_transactions_ringct.json",
    "mainnet/get_transactions_rct1_full.json",
    "mainnet/get_transactions_rct3_bulletproof.json",
    "mainnet/get_transactions_rct4_mixed_pruned.json",
    "mainnet/get_transactions_rct5_clsag.json",
    "mainnet/get_transactions_coinbase_v2.json",
    "mainnet/get_transactions_rct6_complete.json",
    "mainnet/get_transactions_rct6_bulletproofplus.json",
    "mainnet/tx_ringct_as_json_parsed.json",
    "fcmp/get_info.json",
    "fcmp/get_block_fcmp.json",
    "fcmp/get_block_coinbase_only.json",
    "fcmp/get_last_block_header.json",
    "fcmp/get_fee_estimate.json",
    "fcmp/get_transaction_pool.json",
    "fcmp/get_transactions_fcmp.json",
    "fcmp/get_transactions_fcmp_pruned.json",
    "fcmp/get_transactions_coinbase.json",
    "fcmp/get_transactions_pool.json",
    "fcmp/paths/get_block_root_tip.json",
    "fcmp/paths/get_block_root_later.json",
    "fcmp/paths/get_transactions.json",
];

fn replay_by_name(rel: &str) {
    match rel {
        "testnet/get_info.json" | "testnet/get_info_master.json" | "fcmp/get_info.json" => {
            drop(replay::<GetInfo>(&result_of(rel), rel));
        }
        "testnet/get_block_134721.json"
        | "testnet/get_block_coinbase_only.json"
        | "mainnet/get_block_ringct.json"
        | "fcmp/get_block_fcmp.json"
        | "fcmp/get_block_coinbase_only.json"
        | "fcmp/paths/get_block_root_tip.json"
        | "fcmp/paths/get_block_root_later.json" => {
            let block: GetBlock = replay(&result_of(rel), rel);
            // The block's own JSON is a second wire format, and the one that
            // carries the curve tree.
            let nested: Value = serde_json::from_str(&block.json)
                .unwrap_or_else(|e| panic!("{rel} json is not JSON: {e}"));
            drop(replay::<BlockJson>(&nested, &format!("{rel}:json")));
        }
        "testnet/get_block_headers_range.json" => {
            drop(replay::<GetBlockHeadersRange>(&result_of(rel), rel));
        }
        "testnet/get_last_block_header.json" | "fcmp/get_last_block_header.json" => {
            drop(replay::<GetBlockHeader>(&result_of(rel), rel));
        }
        "testnet/get_block_count.json" => drop(replay::<GetBlockCount>(&result_of(rel), rel)),
        "testnet/get_fee_estimate.json" | "fcmp/get_fee_estimate.json" => {
            drop(replay::<FeeEstimate>(&result_of(rel), rel));
        }
        "testnet/get_alternate_chains.json" => {
            drop(replay::<GetAlternateChains>(&result_of(rel), rel));
        }
        "testnet/get_height.json" => drop(replay::<GetHeight>(&raw(rel), rel)),
        "testnet/get_transaction_pool.json" | "fcmp/get_transaction_pool.json" => {
            let pool: GetTransactionPool = replay(&raw(rel), rel);
            for t in &pool.transactions {
                let nested: Value = serde_json::from_str(&t.tx_json)
                    .unwrap_or_else(|e| panic!("{rel} tx_json is not JSON: {e}"));
                drop(replay::<TxJson>(&nested, &format!("{rel}:{}", t.id_hash)));
            }
        }
        "testnet/get_transactions_ring.json"
        | "testnet/get_transactions_coinbase.json"
        | "testnet/get_transactions_coinbase_split.json"
        | "testnet/get_transactions_multi_input.json"
        | "mainnet/get_transactions_ringct.json"
        | "mainnet/get_transactions_rct1_full.json"
        | "mainnet/get_transactions_rct3_bulletproof.json"
        | "mainnet/get_transactions_rct4_mixed_pruned.json"
        | "mainnet/get_transactions_rct5_clsag.json"
        | "mainnet/get_transactions_coinbase_v2.json"
        | "mainnet/get_transactions_rct6_complete.json"
        | "mainnet/get_transactions_rct6_bulletproofplus.json"
        | "fcmp/get_transactions_fcmp.json"
        | "fcmp/get_transactions_fcmp_pruned.json"
        | "fcmp/get_transactions_coinbase.json"
        | "fcmp/get_transactions_pool.json"
        | "fcmp/paths/get_transactions.json" => {
            let resp: GetTransactionsResponse = replay(&raw(rel), rel);
            // The nested documents are a second wire format; replay them too.
            for entry in &resp.txs {
                let nested: Value = serde_json::from_str(&entry.as_json)
                    .unwrap_or_else(|e| panic!("{rel} as_json is not JSON: {e}"));
                drop(replay::<TxJson>(
                    &nested,
                    &format!("{rel}:{}", entry.tx_hash),
                ));
            }
        }
        "testnet/get_outs_ring.json"
        | "testnet/get_outs_no_txid.json"
        | "mainnet/get_outs_ringct.json" => drop(replay::<GetOutsResponse>(&raw(rel), rel)),
        "testnet/is_key_image_spent.json" => {
            drop(replay::<IsKeyImageSpentResponse>(&raw(rel), rel));
        }
        "testnet/tx_as_json_parsed.json" | "mainnet/tx_ringct_as_json_parsed.json" => {
            drop(replay::<TxJson>(&raw(rel), rel));
        }
        other => panic!("{other} is listed in REPLAYED but has no case"),
    }
}

// ---------------------------------------------------------------------------
// Whole-corpus replay
// ---------------------------------------------------------------------------

#[test]
fn every_known_fixture_round_trips_without_losing_a_field() {
    for rel in REPLAYED {
        replay_by_name(rel);
    }
}

#[test]
fn every_fixture_on_disk_is_at_least_valid_json() {
    let mut on_disk = std::collections::BTreeSet::new();
    for net in ["testnet", "mainnet", "fcmp", "fcmp/paths"] {
        let dir = fixtures_root().join(net);
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("readable dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 name");
            let rel = format!("{net}/{name}");
            drop(raw(&rel));
            on_disk.insert(rel);
        }
    }

    // Containment, not a count. Comparing two totals compares two numbers that
    // both go up when an unrelated capture is added, so the day anyone adds one
    // the check stops being able to fail. This one names the file that went
    // missing instead of reporting an arithmetic tie.
    let missing: Vec<&str> = REPLAYED
        .iter()
        .copied()
        .filter(|rel| !on_disk.contains(*rel))
        .collect();
    assert!(
        missing.is_empty(),
        "REPLAYED names {} fixture(s) that are not on disk: {missing:?}",
        missing.len()
    );
}

// ---------------------------------------------------------------------------
// 1. ecdhInfo changes shape at rct type 4
// ---------------------------------------------------------------------------

fn decoded_txs(rel: &str) -> Vec<(TxEntry, TxJson)> {
    let resp: GetTransactionsResponse = serde_json::from_value(raw(rel)).expect("deserializes");
    // Guard every caller from one place. Most tests below are a `for` loop over
    // what this returns, and a loop over an empty vector passes every assertion
    // inside it -- so a single wrong `#[serde(rename)]` on `txs` would turn a
    // dozen of them green rather than red.
    assert!(resp.status_is_ok(), "{rel} was not captured with status OK");
    assert!(!resp.txs.is_empty(), "{rel} decoded to zero transactions");
    resp.txs
        .into_iter()
        .map(|e| {
            let json = e
                .parse_json()
                .expect("fixtures were captured with decode_as_json");
            (e, json)
        })
        .collect()
}

/// The nested `as_json` documents of a `/get_transactions` fixture, left raw.
///
/// Needed wherever the claim is about *which keys monerod put on the wire*: an
/// `Option<String>` reads a missing key and an explicit `null` as the same
/// `None`, so only the unparsed object can tell those two apart.
fn nested_raw(rel: &str) -> Vec<Value> {
    raw(rel)["txs"]
        .as_array()
        .unwrap_or_else(|| panic!("{rel} has no txs array"))
        .iter()
        .map(|e| {
            let text = e["as_json"].as_str().expect("as_json is a string");
            serde_json::from_str(text).unwrap_or_else(|err| panic!("{rel} as_json: {err}"))
        })
        .collect()
}

/// The key set monerod emitted in `rctsig_prunable`, sorted.
///
/// This is the per-type fingerprint: the scheme decides which of `nbp`,
/// `rangeSigs`, `bp`, `bpp`, `MGs`, `CLSAGs` and `pseudoOuts` appear at all.
fn prunable_keys(doc: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = doc["rctsig_prunable"]
        .as_object()
        .expect("a complete transaction has an rctsig_prunable object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn ecdh_of(tx: &TxJson) -> &[EcdhInfo] {
    tx.rct_signatures
        .as_ref()
        .and_then(|b| b.ecdh_info.as_deref())
        .unwrap_or(&[])
}

#[test]
fn rct_type_2_emits_mask_and_a_full_width_amount() {
    let tx: TxJson = serde_json::from_value(raw("mainnet/tx_ringct_as_json_parsed.json")).unwrap();
    assert_eq!(tx.rct_type(), Some(RctType::Simple));

    // One element per output. `ecdh_of` answers an absent `ecdhInfo` with an
    // empty slice, so `!is_empty()` is the only thing standing between this
    // loop and asserting nothing whatsoever.
    let ecdh = ecdh_of(&tx);
    assert_eq!(
        ecdh.len(),
        tx.vout.len(),
        "ecdhInfo is one element per output"
    );
    assert_eq!(ecdh.len(), 7);
    for e in ecdh {
        assert_eq!(e.form(), Some(EcdhForm::Full));
        assert_eq!(e.mask.as_ref().expect("types 1-3 carry a mask").len(), 64);
        assert_eq!(e.amount.len(), 64);
    }
    assert_eq!(tx.rct_type().unwrap().ecdh_form(), Some(EcdhForm::Full));
    assert_eq!(
        RctType::Simple.pseudo_outs_location(),
        PseudoOutsLocation::Base,
        "type 2 is the only scheme that keeps pseudoOuts in the base"
    );
}

/// Fixture-verified, not spec-derived: `get_transactions_rct4_mixed_pruned.json`
/// was pulled from the local mainnet node at heights 1,900,000 and 1,992,960,
/// both past the type-4 fork.
#[test]
fn rct_type_4_drops_mask_and_truncates_the_amount_to_eight_bytes() {
    let txs = decoded_txs("mainnet/get_transactions_rct4_mixed_pruned.json");
    assert_eq!(txs.len(), 2, "one pruned tx and one complete one");

    for (_, tx) in &txs {
        assert_eq!(tx.rct_type(), Some(RctType::Bulletproof2));
        let ecdh = ecdh_of(tx);
        assert_eq!(
            ecdh.len(),
            tx.vout.len(),
            "ecdhInfo is one element per output"
        );
        for e in ecdh {
            assert!(
                e.mask.is_none(),
                "a required mask field fails on every mainnet tx after height 1,788,000"
            );
            assert_eq!(e.amount.len(), 16);
            assert_eq!(e.form(), Some(EcdhForm::Compact));
        }
    }

    // `mask.is_none()` above cannot say *why* it is none, because serde reads a
    // missing key and an explicit null into the same value:
    assert_eq!(
        serde_json::from_str::<EcdhInfo>(r#"{"mask":null,"amount":"0011223344556677"}"#)
            .unwrap()
            .mask,
        None,
        "an explicit null is indistinguishable from an absent key after parsing"
    );
    // ...so the "absent, not null" half of the claim is made against the bytes.
    // It is worth defending separately: a monerod that started emitting a null
    // here would be a wire change, and the typed view would absorb it in
    // silence.
    for doc in nested_raw("mainnet/get_transactions_rct4_mixed_pruned.json") {
        let ecdh = doc["rct_signatures"]["ecdhInfo"]
            .as_array()
            .expect("a type 4 tx still carries ecdhInfo in its surviving base");
        assert!(!ecdh.is_empty());
        for e in ecdh {
            let obj = e.as_object().expect("an ecdhInfo element is an object");
            assert_eq!(
                obj.keys().map(String::as_str).collect::<Vec<_>>(),
                ["amount"],
                "the mask key is gone at type 4, not present-and-null"
            );
        }
    }
}

#[test]
fn rct_type_5_also_uses_the_compact_ecdh_form() {
    let txs = decoded_txs("mainnet/get_transactions_rct5_clsag.json");
    let (_, tx) = txs.first().expect("one tx");
    assert_eq!(tx.rct_type(), Some(RctType::Clsag));
    let ecdh = ecdh_of(tx);
    assert_eq!(
        ecdh.len(),
        tx.vout.len(),
        "ecdhInfo is one element per output"
    );
    for e in ecdh {
        assert_eq!(e.form(), Some(EcdhForm::Compact));
        assert_eq!(e.amount.len(), 16);
    }
}

/// The *ordering* hazard, on constructed documents: an untagged decoder that
/// tries the compact arm first swallows a full element and discards its mask.
///
/// These are hand-built rather than captured because the hazard is about two
/// shapes meeting in one decoder, which no single real transaction exhibits.
/// Real type-6 data now backs
/// [`a_bulletproof_plus_transaction_decodes_to_its_actual_values`].
#[test]
fn a_compact_element_is_never_confused_with_a_full_one() {
    let full_src = raw("mainnet/tx_ringct_as_json_parsed.json");
    let full_elem = &full_src["rct_signatures"]["ecdhInfo"][0];
    let full: EcdhInfo = serde_json::from_value(full_elem.clone()).unwrap();

    let compact: EcdhInfo = serde_json::from_str(r#"{"amount":"a0017052c6e34e9a"}"#).unwrap();

    assert_eq!(full.form(), Some(EcdhForm::Full));
    assert_eq!(compact.form(), Some(EcdhForm::Compact));
    assert_ne!(full.form(), compact.form());
    // Width, not field count, is what separates them: strip the mask from a
    // full element and it is still not compact.
    let stripped = EcdhInfo {
        mask: None,
        amount: full.amount.clone(),
    };
    assert_eq!(stripped.form(), None);
}

// ---------------------------------------------------------------------------
// 1b. The two RingCT schemes that only a mainnet node can show us
// ---------------------------------------------------------------------------

/// Fetched, not constructed: tx `78cc4443...43de5` at mainnet height 1,236,992
/// (hard fork 4), prunable half intact.
///
/// Type 1 (Full) is the only *signing* scheme that emits no `pseudoOuts` in
/// either half — type 0 also has none, but type 0 is a coinbase and has no
/// inputs to balance. That makes this the one capture where "we found none" has
/// to be a fact about the chain rather than a symptom of looking in the wrong
/// object.
#[test]
fn rct_type_1_full_carries_borromean_proofs_and_no_pseudo_outs_at_all() {
    let rel = "mainnet/get_transactions_rct1_full.json";
    let txs = decoded_txs(rel);
    let (entry, tx) = txs.first().expect("one tx");
    assert_eq!(entry.block_height, 1_236_992);
    assert_eq!(tx.rct_type(), Some(RctType::Full));
    assert!(
        !entry.prunable_as_hex.is_empty(),
        "captured from a kept stripe, so the prunable half is real data"
    );
    assert!(!tx.looks_pruned());

    let doc = &nested_raw(rel)[0];
    assert_eq!(prunable_keys(doc), ["MGs", "rangeSigs"]);
    // Absent from both halves -- the assertion that makes `pseudo_outs()`
    // returning nothing here meaningful.
    assert!(doc["rct_signatures"].get("pseudoOuts").is_none());
    assert!(doc["rctsig_prunable"].get("pseudoOuts").is_none());
    assert!(tx.pseudo_outs().is_empty());
    assert_eq!(
        RctType::Full.pseudo_outs_location(),
        PseudoOutsLocation::Absent
    );

    let prunable = tx.rctsig_prunable.as_ref().unwrap();
    assert!(prunable.nbp.is_none(), "nbp arrives at type 3, not before");
    assert!(prunable.bp.is_none() && prunable.bpp.is_none() && prunable.clsags.is_none());
    assert!(prunable.pseudo_outs.is_none());

    // Borromean proofs: one per output, each a pair of flat blobs rather than a
    // nested structure. 4128 and 2048 bytes, hex-encoded.
    let range_sigs = prunable
        .range_sigs
        .as_ref()
        .expect("types 1 and 2 emit rangeSigs");
    assert_eq!(range_sigs.len(), tx.vout.len());
    for rs in range_sigs {
        assert_eq!(rs.asig.len(), 8256);
        assert_eq!(rs.ci.len(), 4096);
    }

    // One MLSAG for the whole transaction rather than one per input: that is
    // what "Full" means. Its `ss` rows are `n_inputs + 1` wide, which is why
    // the model uses `Vec<Vec<_>>` and not a fixed 2-wide matrix. The reference
    // wallet only ever built single-input Full transactions, so this capture
    // cannot show a row wider than 2 -- the assertion is written against
    // `vin.len() + 1` so that it stays honest if one ever turns up.
    let mgs = prunable.mgs.as_ref().expect("type 1 signs with an MLSAG");
    assert_eq!(mgs.len(), 1, "one MLSAG, however many inputs there are");
    assert_eq!(tx.vin.len(), 1, "no multi-input Full transaction is known");
    assert_eq!(mgs[0].ss.len(), tx.vin[0].as_key().unwrap().ring_size());
    assert_eq!(mgs[0].ss.len(), 3, "a ring of 3");
    for row in &mgs[0].ss {
        assert_eq!(row.len(), tx.vin.len() + 1);
    }
    assert_eq!(mgs[0].cc.len(), 64);

    // Type 1 keeps the 32-byte ecdh form, like types 2 and 3.
    let ecdh = ecdh_of(tx);
    assert_eq!(
        ecdh.len(),
        tx.vout.len(),
        "ecdhInfo is one element per output"
    );
    for e in ecdh {
        assert_eq!(e.form(), Some(EcdhForm::Full));
        assert_eq!(e.mask.as_ref().expect("type 1 carries a mask").len(), 64);
        assert_eq!(e.amount.len(), 64);
    }
    assert_eq!(RctType::Full.ecdh_form(), Some(EcdhForm::Full));
}

/// Fetched, not constructed: tx `0a4a1dfc...85d3` at mainnet height 1,695,744
/// (hard fork 9), prunable half intact.
///
/// Type 3 is the only scheme where `pseudoOuts` lives in `rctsig_prunable`
/// *while* `nbp` is also present, so it is the only capture that can catch a
/// `pseudo_outs()` that reads the base object for bulletproof transactions, or
/// one that keys the location off whether `nbp` is there.
#[test]
fn rct_type_3_bulletproof_puts_pseudo_outs_in_the_prunable_half_beside_nbp() {
    let rel = "mainnet/get_transactions_rct3_bulletproof.json";
    let txs = decoded_txs(rel);
    let (entry, tx) = txs.first().expect("one tx");
    assert_eq!(entry.block_height, 1_695_744);
    assert_eq!(tx.rct_type(), Some(RctType::Bulletproof));
    assert!(
        !entry.prunable_as_hex.is_empty(),
        "captured from a kept stripe, so the prunable half is real data"
    );
    assert!(!tx.looks_pruned());

    let doc = &nested_raw(rel)[0];
    assert_eq!(prunable_keys(doc), ["MGs", "bp", "nbp", "pseudoOuts"]);
    assert!(
        doc["rct_signatures"].get("pseudoOuts").is_none(),
        "type 3 moved pseudoOuts out of the base, where type 2 keeps them"
    );
    assert!(
        doc["rctsig_prunable"]["nbp"].is_number(),
        "nbp is a scalar, not an array"
    );

    let prunable = tx.rctsig_prunable.as_ref().unwrap();
    // The value, not just its presence: `is_some()` still holds if the number
    // arrives wrong, and nbp can legitimately exceed 1.
    assert_eq!(
        prunable.nbp.map(u64::from),
        doc["rctsig_prunable"]["nbp"].as_u64(),
        "the parsed nbp is the number monerod sent"
    );
    assert_eq!(prunable.nbp, Some(1));
    assert!(
        prunable.range_sigs.is_none(),
        "bulletproofs replaced rangeSigs at type 3"
    );
    assert!(prunable.bpp.is_none(), "bpp arrives at type 6");
    assert!(prunable.clsags.is_none(), "CLSAGs arrive at type 5");

    // The reason this fixture exists: found in the prunable half, one per
    // input, and the same slice the prunable object holds.
    assert_eq!(tx.pseudo_outs().len(), tx.vin.len());
    assert_eq!(tx.pseudo_outs().len(), 1);
    assert!(tx.pseudo_outs().iter().all(|p| p.len() == 64));
    assert_eq!(
        tx.pseudo_outs(),
        prunable.pseudo_outs.as_deref().unwrap(),
        "read out of rctsig_prunable, not out of rct_signatures"
    );
    assert_eq!(
        RctType::Bulletproof.pseudo_outs_location(),
        PseudoOutsLocation::Prunable
    );

    // Bulletproofs and still the 32-byte ecdh form: the compact encoding starts
    // at type 4, not at the bulletproof fork.
    let ecdh = ecdh_of(tx);
    assert_eq!(
        ecdh.len(),
        tx.vout.len(),
        "ecdhInfo is one element per output"
    );
    for e in ecdh {
        assert_eq!(e.form(), Some(EcdhForm::Full));
        assert_eq!(e.amount.len(), 64);
        assert_eq!(
            e.mask.as_ref().expect("type 3 still carries a mask").len(),
            64
        );
    }
    assert_eq!(RctType::Bulletproof.ecdh_form(), Some(EcdhForm::Full));

    let bp = prunable.bp.as_ref().expect("type 3 emits bp");
    assert_eq!(bp.len(), 1);
    // `L.len() == R.len()` is true by definition of a bulletproof, so it is
    // not an assertion -- it cannot fail. The proof is pinned by value in
    // `a_bulletproof_reads_l_and_r_from_their_own_wire_keys`; here it is just
    // enough to show this fixture carries a real one.
    assert_eq!(
        bp[0].L.len(),
        7,
        "seven rounds, which is the aggregated proof for two outputs"
    );
    assert_eq!(
        bp[0].L[0],
        "85ab173bc021a99cd0885f4934277dceae6238c544b2c27456f3b3deb35251a7"
    );
    assert_eq!(
        bp[0].R[0],
        "7feea22f6f0cd901620525e7eb62b3a5b1c2a18afc27bc0421b6ba94bf386009"
    );
    let mgs = prunable
        .mgs
        .as_ref()
        .expect("type 3 still signs with MLSAGs");
    assert_eq!(
        mgs.len(),
        tx.vin.len(),
        "one MLSAG per input from type 2 on"
    );
    assert_eq!(mgs[0].ss.len(), tx.vin[0].as_key().unwrap().ring_size());
    for row in &mgs[0].ss {
        assert_eq!(row.len(), 2, "types 2, 3 and 4 use 2-wide rows");
    }
}

/// Types 1 and 2 put the *same two* keys in `rctsig_prunable`, so nothing in
/// the prunable half distinguishes them. The scheme has to come from the `type`
/// scalar in `rct_signatures` -- and getting it wrong is not a parse failure,
/// it is a silently missing set of pseudo-outputs.
#[test]
fn the_prunable_key_set_alone_cannot_tell_a_full_transaction_from_a_simple_one() {
    let full_doc = nested_raw("mainnet/get_transactions_rct1_full.json").remove(0);
    let simple_doc = raw("mainnet/tx_ringct_as_json_parsed.json");

    assert_eq!(prunable_keys(&full_doc), prunable_keys(&simple_doc));
    assert_eq!(prunable_keys(&full_doc), ["MGs", "rangeSigs"]);
    assert_eq!(full_doc["rct_signatures"]["type"], serde_json::json!(1));
    assert_eq!(simple_doc["rct_signatures"]["type"], serde_json::json!(2));

    let full: TxJson = serde_json::from_value(full_doc).unwrap();
    let simple: TxJson = serde_json::from_value(simple_doc).unwrap();
    assert_eq!(full.rct_type(), Some(RctType::Full));
    assert_eq!(simple.rct_type(), Some(RctType::Simple));

    // And the consequence of that one integer: pseudo-outputs for one, none
    // for the other, from documents whose prunable halves look identical.
    assert!(full.pseudo_outs().is_empty());
    assert_eq!(simple.pseudo_outs().len(), simple.vin.len());
    assert_eq!(simple.pseudo_outs().len(), 2);
}

/// A census of which RingCT schemes the corpus actually contains.
///
/// It is a test rather than a comment because a comment cannot notice a deleted
/// fixture or a capture that quietly changed era.
#[test]
fn the_corpus_covers_every_rct_type_reachable_from_these_nodes() {
    let mut seen: Vec<u8> = Vec::new();
    for rel in REPLAYED {
        if !rel.contains("get_transactions") {
            continue;
        }
        for (_, tx) in decoded_txs(rel) {
            if let Some(t) = tx.rct_type() {
                seen.push(t.to_raw());
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();

    // Every scheme Monero has ever used on mainnet, each behind a real capture.
    // Type 6 (BulletproofPlus) was out of reach when this corpus was first
    // built -- HF15 is height 2,688,888 and the node was at 2,583,912 -- and is
    // now covered by mainnet tx 281d0f52...9981 at height 3,120,801. Type 7
    // (FCMP++) comes from a regtest daemon built from the stressnet branch;
    // see `fixtures/fcmp`.
    assert_eq!(
        seen,
        vec![0, 1, 2, 3, 4, 5, 6, 7],
        "every RingCT type from Null to FCMP++ has a real capture behind it"
    );
}

// ---------------------------------------------------------------------------
// 2. nbp is a number, present for types 3-6 and absent for 1-2
// ---------------------------------------------------------------------------

#[test]
fn nbp_is_absent_for_borromean_types_and_a_number_for_bulletproof_ones() {
    // Type 2: rangeSigs + MGs, no nbp at all.
    let borromean = raw("mainnet/tx_ringct_as_json_parsed.json");
    assert_eq!(
        prunable_keys(&borromean),
        ["MGs", "rangeSigs"],
        "no nbp, no bp, no pseudoOuts"
    );

    let tx: TxJson = serde_json::from_value(borromean).unwrap();
    let prunable = tx.rctsig_prunable.as_ref().unwrap();
    assert!(prunable.nbp.is_none());
    assert!(prunable.range_sigs.is_some());
    assert!(prunable.mgs.is_some());
    assert!(prunable.bp.is_none() && prunable.bpp.is_none() && prunable.clsags.is_none());

    // Type 4: nbp, bp, MGs, pseudoOuts.
    let txs = decoded_txs("mainnet/get_transactions_rct4_mixed_pruned.json");
    let (_, complete) = txs
        .iter()
        .find(|(e, _)| !e.prunable_as_hex.is_empty())
        .expect("the kept-stripe tx still has its prunable half");
    let prunable = complete.rctsig_prunable.as_ref().unwrap();
    let nested: Value = serde_json::from_str(&complete_as_json()).unwrap();
    assert_eq!(prunable_keys(&nested), ["MGs", "bp", "nbp", "pseudoOuts"]);
    assert!(
        nested["rctsig_prunable"]["nbp"].is_number(),
        "nbp is a number, not an array"
    );
    // The value, not merely its presence: `is_some()` holds just as well for a
    // wrong number, and nbp is not a constant -- pre-padding wallets emitted
    // more than one proof per transaction.
    assert_eq!(
        prunable.nbp.map(u64::from),
        nested["rctsig_prunable"]["nbp"].as_u64()
    );
    assert!(prunable.bp.is_some());
    assert!(prunable.mgs.is_some());
    assert!(prunable.pseudo_outs.is_some());
    assert!(prunable.range_sigs.is_none());

    // Type 5: nbp, bp, CLSAGs, pseudoOuts.
    let rel = "mainnet/get_transactions_rct5_clsag.json";
    let txs = decoded_txs(rel);
    let prunable = txs[0].1.rctsig_prunable.as_ref().unwrap();
    let nested = nested_raw(rel).remove(0);
    assert_eq!(
        prunable_keys(&nested),
        ["CLSAGs", "bp", "nbp", "pseudoOuts"]
    );
    assert_eq!(
        prunable.nbp.map(u64::from),
        nested["rctsig_prunable"]["nbp"].as_u64()
    );
    assert!(prunable.bp.is_some());
    assert!(prunable.clsags.is_some());
    assert!(prunable.mgs.is_none(), "CLSAG transactions carry no MGs");

    // Type 3 sits between the two and is the only one carrying both nbp and a
    // prunable pseudoOuts alongside MGs; see
    // `rct_type_3_bulletproof_puts_pseudo_outs_in_the_prunable_half_beside_nbp`.
}

fn complete_as_json() -> String {
    decoded_txs("mainnet/get_transactions_rct4_mixed_pruned.json")
        .into_iter()
        .find(|(e, _)| !e.prunable_as_hex.is_empty())
        .expect("complete tx")
        .0
        .as_json
}

#[test]
fn pseudo_outs_are_found_wherever_the_rct_type_puts_them() {
    // Type 2 keeps them in the base, so they survive pruning.
    let simple: TxJson =
        serde_json::from_value(raw("mainnet/tx_ringct_as_json_parsed.json")).unwrap();
    assert_eq!(simple.pseudo_outs().len(), simple.vin.len());
    assert!(
        simple
            .rct_signatures
            .as_ref()
            .unwrap()
            .pseudo_outs
            .is_some()
    );

    // Types 3, 4 and 5 move them into the prunable half.
    let mut complete = 0usize;
    let mut pruned = 0usize;
    for rel in [
        "mainnet/get_transactions_rct3_bulletproof.json",
        "mainnet/get_transactions_rct4_mixed_pruned.json",
        "mainnet/get_transactions_rct5_clsag.json",
    ] {
        for (entry, tx) in decoded_txs(rel) {
            assert!(
                tx.rct_signatures.as_ref().unwrap().pseudo_outs.is_none(),
                "types 3-6 do not put pseudoOuts in the base"
            );
            if entry.prunable_as_hex.is_empty() {
                // Pruned: they went with the prunable half.
                assert!(tx.pseudo_outs().is_empty());
                pruned += 1;
            } else {
                assert!(!tx.vin.is_empty());
                assert_eq!(tx.pseudo_outs().len(), tx.vin.len());
                complete += 1;
            }
        }
    }
    // Both branches have to have run, or half this test is decoration: the
    // complete branch is what catches reading the wrong object, and the pruned
    // branch is what catches calling that an error rather than an absence.
    assert_eq!(complete, 3);
    assert_eq!(pruned, 1);
}

// ---------------------------------------------------------------------------
// 3. v1 signatures: one concatenated entry per input
// ---------------------------------------------------------------------------

#[test]
fn a_single_input_v1_transaction_has_one_concatenated_signature_entry() {
    let tx: TxJson = serde_json::from_value(raw("testnet/tx_as_json_parsed.json")).unwrap();
    let sigs = tx
        .signatures
        .as_ref()
        .expect("a complete v1 tx has signatures");
    assert_eq!(sigs.len(), 1, "one entry per INPUT, not per ring member");
    assert_eq!(sigs[0].len(), 2048, "ring 16 x 128 hex chars, concatenated");

    let members = split_ring_signatures(&sigs[0]).expect("2048 is 16 signatures");
    assert_eq!(members.len(), 16);
    assert!(members.iter().all(|m| m.len() == 128));
    assert_eq!(
        tx.ring_signatures_for_input(0).unwrap().len(),
        tx.vin[0].as_key().unwrap().ring_size()
    );
}

/// The decisive case: testnet block 3900's transaction has seven inputs.
#[test]
fn a_seven_input_v1_transaction_has_seven_entries_not_one_per_ring_member() {
    let txs = decoded_txs("testnet/get_transactions_multi_input.json");
    let (_, tx) = txs.first().expect("one tx");
    assert_eq!(tx.vin.len(), 7);

    let sigs = tx.signatures.as_ref().unwrap();
    assert_eq!(sigs.len(), 7, "7 entries, not 112, and not a nested array");

    for (i, sig) in sigs.iter().enumerate() {
        let ring = tx.vin[i].as_key().unwrap().key_offsets.len();
        assert_eq!(
            sig.len(),
            128 * ring,
            "signatures[{i}] must be 128 hex chars per ring member of vin[{i}]"
        );
        assert_eq!(tx.ring_signatures_for_input(i).unwrap().len(), ring);
    }

    // Each input has its own denomination. Asserted by value: "all non-zero"
    // holds for any seven amounts at all, including seven copies of one.
    let amounts: Vec<u64> = tx.vin.iter().map(|v| v.as_key().unwrap().amount).collect();
    assert_eq!(
        amounts,
        vec![
            4_000_000_000,
            10_000_000_000_000,
            4_000_000_000,
            9_000_000_000,
            500_000_000_000,
            60_000_000_000,
            3_000_000_000,
        ],
        "v1 inputs are denominated, and the denominations are per-input"
    );
}

// ---------------------------------------------------------------------------
// 4. as_json can be the empty string
// ---------------------------------------------------------------------------

#[test]
fn an_empty_as_json_is_absent_rather_than_a_parse_failure() {
    // Derived from a real entry by blanking the field, which is exactly what a
    // request without decode_as_json produces.
    let mut fixture = raw("testnet/get_transactions_ring.json");
    fixture["txs"][0]["as_json"] = Value::String(String::new());
    fixture["txs_as_json"] = Value::Array(vec![]);

    let resp: GetTransactionsResponse = serde_json::from_value(fixture).unwrap();
    let entry = &resp.txs[0];
    assert!(entry.as_json.is_empty());
    assert!(matches!(entry.parse_json(), Err(NestedJsonError::Absent)));
    // The entry itself is still perfectly usable.
    assert!(!entry.tx_hash.is_empty());
    assert!(entry.raw_hex().is_some());
}

// ---------------------------------------------------------------------------
// 5. The pruned encoding triggers without the caller asking
// ---------------------------------------------------------------------------

/// Captured with `prune: false`. One entry still came back pruned, because the
/// node no longer holds that stripe — and the other did not.
#[test]
fn one_response_can_mix_pruned_and_complete_transactions() {
    let txs = decoded_txs("mainnet/get_transactions_rct4_mixed_pruned.json");
    assert_eq!(txs.len(), 2);

    let pruned = txs
        .iter()
        .find(|(e, _)| e.prunable_as_hex.is_empty())
        .expect("one entry lost its prunable half");
    let complete = txs
        .iter()
        .find(|(e, _)| !e.prunable_as_hex.is_empty())
        .expect("the other kept it");

    assert!(pruned.1.rctsig_prunable.is_none());
    assert!(pruned.0.prunable_missing(&pruned.1));
    assert!(pruned.1.looks_pruned());

    assert!(complete.1.rctsig_prunable.is_some());
    assert!(!complete.0.prunable_missing(&complete.1));
    assert!(!complete.1.looks_pruned());

    // prunable_hash is populated for both, so it is not the signal.
    assert_eq!(pruned.0.prunable_hash.len(), 64);
    assert_ne!(pruned.0.prunable_hash, "0".repeat(64));

    // Neither is as_hex: the split form is forced for both.
    assert!(pruned.0.as_hex.is_empty() && complete.0.as_hex.is_empty());
}

#[test]
fn the_raw_hex_of_a_complete_transaction_is_the_two_halves_concatenated() {
    let txs = decoded_txs("mainnet/get_transactions_rct4_mixed_pruned.json");
    let (entry, _) = txs
        .iter()
        .find(|(e, _)| !e.prunable_as_hex.is_empty())
        .unwrap();
    let full = entry.raw_hex().unwrap();
    assert!(!entry.pruned_as_hex.is_empty() && !entry.prunable_as_hex.is_empty());
    assert_eq!(
        full.len(),
        entry.pruned_as_hex.len() + entry.prunable_as_hex.len()
    );
    // Order and content, not just length. Concatenating the two halves the
    // wrong way round yields a string of exactly the same length and a
    // completely different transaction, so a length check alone cannot fail.
    assert_eq!(
        full,
        format!("{}{}", entry.pruned_as_hex, entry.prunable_as_hex)
    );
    assert!(full.starts_with(&entry.pruned_as_hex));
    assert!(full.ends_with(&entry.prunable_as_hex));
    assert!(
        full.starts_with("02"),
        "the prefix comes first, and it opens with the varint version"
    );

    // And a non-split capture puts it all in as_hex instead.
    let txs = decoded_txs("testnet/get_transactions_ring.json");
    let (entry, _) = &txs[0];
    assert!(!entry.as_hex.is_empty());
    assert_eq!(entry.raw_hex().as_deref(), Some(entry.as_hex.as_str()));
}

// ---------------------------------------------------------------------------
// 6. A coinbase always takes the pruned JSON form under split:true
// ---------------------------------------------------------------------------

#[test]
fn a_v1_coinbase_has_no_signatures_key_at_all_under_split() {
    let txs = decoded_txs("testnet/get_transactions_coinbase_split.json");
    let (entry, tx) = txs.first().expect("one tx");
    assert!(tx.is_coinbase());
    assert!(
        tx.signatures.is_none(),
        "a coinbase's prunable blob is always empty, so split:true always \
         yields the pruned JSON form"
    );
    assert!(
        !tx.looks_pruned(),
        "a coinbase has nothing to prune -- calling it pruned would mislabel \
         every block on the chain"
    );
    assert!(!entry.prunable_missing(tx));
    assert!(entry.as_hex.is_empty() && !entry.pruned_as_hex.is_empty());
    assert_eq!(
        entry.prunable_hash,
        "0".repeat(64),
        "v1 prunable hash is null"
    );
}

#[test]
fn the_same_v1_coinbase_fetched_without_split_carries_an_empty_signatures_array() {
    let txs = decoded_txs("testnet/get_transactions_coinbase.json");
    let (entry, tx) = txs.first().expect("one tx");
    assert!(tx.is_coinbase());
    assert_eq!(
        tx.signatures.as_deref(),
        Some(NO_SIGNATURES),
        "present and empty, which is a different fact from absent"
    );
    assert!(!entry.as_hex.is_empty());
    assert!(!tx.looks_pruned());
}

#[test]
fn a_v2_coinbase_is_a_type_zero_rct_with_no_prunable_half() {
    let txs = decoded_txs("mainnet/get_transactions_coinbase_v2.json");
    let (entry, tx) = txs.first().expect("one tx");
    assert_eq!(tx.version, 2);
    assert!(tx.is_coinbase());
    assert!(matches!(tx.vin.first(), Some(TxIn::Gen(_))));
    assert_eq!(tx.rct_type(), Some(RctType::Null));
    assert!(tx.rctsig_prunable.is_none());
    assert!(tx.signatures.is_none());
    assert!(!tx.looks_pruned());
    assert!(!entry.prunable_missing(tx));
    assert_eq!(
        entry.prunable_hash, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "keccak of the empty string, for every v2 coinbase"
    );
    // Coinbase outputs are never RingCT: the amounts are in the clear.
    assert!(tx.vout.iter().all(|o| o.amount != 0));
}

// ---------------------------------------------------------------------------
// 7. Every vector is absent when empty
// ---------------------------------------------------------------------------

#[test]
fn an_empty_mempool_omits_both_of_its_arrays() {
    let fixture = raw("testnet/get_transaction_pool.json");
    let mut keys: Vec<&str> = fixture
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["credits", "status", "top_hash", "untrusted"]);

    let pool: GetTransactionPool = serde_json::from_value(fixture).unwrap();
    assert!(pool.transactions.is_empty());
    assert!(pool.spent_key_images.is_empty());
    assert_eq!(pool.status, "OK");
}

#[test]
fn a_coinbase_only_block_omits_tx_hashes() {
    let fixture = result_of("testnet/get_block_coinbase_only.json");
    assert!(
        fixture.get("tx_hashes").is_none(),
        "epee drops the key entirely rather than emitting []"
    );
    let block: GetBlock = serde_json::from_value(fixture).unwrap();
    assert!(block.tx_hashes.is_empty());

    // The *inner* serializer has the opposite convention.
    let inner = block.parse_json().unwrap();
    assert!(inner.tx_hashes.is_empty());
    let inner_raw: Value = serde_json::from_str(&block.json).unwrap();
    assert!(
        inner_raw.get("tx_hashes").is_some(),
        "the nested document keeps its empty array"
    );
}

#[test]
fn missed_transactions_arrive_without_a_status_change() {
    let fixture = raw("mainnet/get_transactions_rct4_mixed_pruned.json");
    let resp: GetTransactionsResponse = serde_json::from_value(fixture).unwrap();
    assert!(
        resp.status_is_ok(),
        "a missed tx does not change the status"
    );
    assert_eq!(resp.missed_tx, vec!["0".repeat(64)]);
    assert_eq!(resp.txs.len(), 2, "the found ones are still there");
}

// ---------------------------------------------------------------------------
// 8. A "Failed" status can coexist with a populated txs array
// ---------------------------------------------------------------------------

#[test]
fn a_failed_status_does_not_empty_the_array_it_invalidates() {
    // Built from a real response by flipping the status, which is precisely
    // what monerod does when get_tx_outputs_gindexs fails mid-loop.
    let mut fixture = raw("testnet/get_transactions_ring.json");
    fixture["status"] = Value::String("Failed".to_owned());

    let resp: GetTransactionsResponse = serde_json::from_value(fixture).unwrap();
    assert!(!resp.status_is_ok());
    assert_eq!(
        resp.txs.len(),
        1,
        "the array is populated and must not be trusted on that basis"
    );
}

// ---------------------------------------------------------------------------
// 9. /get_outs get_txid defaults to false on the JSON endpoint
// ---------------------------------------------------------------------------

#[test]
fn txid_is_present_but_empty_when_get_txid_was_not_sent() {
    let without: GetOutsResponse =
        serde_json::from_value(raw("testnet/get_outs_no_txid.json")).unwrap();
    assert_eq!(without.outs.len(), 1);
    assert_eq!(
        without.outs[0].txid, "",
        "present and empty, not absent -- an Option<String> would read as Some(\"\")"
    );
    // The rest of the entry is unaffected, pinned by value: `!is_empty()`
    // holds just as well for a `key` that was read out of `mask`.
    assert_eq!(
        without.outs[0].key,
        "fb5e7415133c8e08d29f6592a274169f3480ef66925db5ded7a3bedf760b33ab"
    );
    assert_eq!(
        without.outs[0].mask,
        "59a03a3153a994d72327e4d92421d3e3291b1fa1b240de44b92d7f62ec0128f1"
    );
    assert_eq!(without.outs[0].height, 4733);

    // The same request with get_txid set: sixteen entries, each carrying the
    // transaction that created it. Compared against the wire key by key --
    // `txid.len() == 64` is equally true of a txid read out of `key`.
    let doc = raw("testnet/get_outs_ring.json");
    let with: GetOutsResponse = serde_json::from_value(doc.clone()).unwrap();
    assert_eq!(with.outs.len(), 16);
    for (i, out) in with.outs.iter().enumerate() {
        let wire = &doc["outs"][i];
        let what = format!("get_outs_ring outs[{i}]");
        assert_reads_wire_key(&out.txid, wire, "txid", &what);
        assert_reads_wire_key(&out.key, wire, "key", &what);
        assert_reads_wire_key(&out.mask, wire, "mask", &what);
    }
    assert_eq!(
        with.outs[0].txid,
        "d2adaf179fb251ae8beadbd7ae59f39f5a913f68b03dcc112548b937feea07d8"
    );
}

// ---------------------------------------------------------------------------
// 10. 128-bit split values
// ---------------------------------------------------------------------------

fn every_header_in_fixtures() -> Vec<BlockHeader> {
    let mut out = Vec::new();
    for rel in [
        "testnet/get_block_134721.json",
        "testnet/get_block_coinbase_only.json",
        "mainnet/get_block_ringct.json",
    ] {
        let block: GetBlock = serde_json::from_value(result_of(rel)).unwrap();
        out.push(block.block_header);
    }
    let last: GetBlockHeader =
        serde_json::from_value(result_of("testnet/get_last_block_header.json")).unwrap();
    out.push(last.block_header);
    let range: GetBlockHeadersRange =
        serde_json::from_value(result_of("testnet/get_block_headers_range.json")).unwrap();
    out.extend(range.headers);
    out
}

#[test]
fn reassembled_difficulty_agrees_with_the_wide_hex_on_every_fixture() {
    let headers = every_header_in_fixtures();
    // Exact: three blocks, one last-header, and a five-wide range. A floor
    // would keep passing after a fixture stopped contributing its header.
    assert_eq!(headers.len(), 9);
    for h in &headers {
        assert_eq!(
            Some(h.difficulty()),
            parse_wide(&h.wide_difficulty),
            "difficulty mismatch at height {}",
            h.height
        );
        assert_eq!(
            Some(h.cumulative_difficulty()),
            parse_wide(&h.wide_cumulative_difficulty),
            "cumulative difficulty mismatch at height {}",
            h.height
        );
        // top64 is 0 today and for decades; the point is that reassembly is
        // correct regardless, not that this fixture exercises it.
        assert_eq!(h.difficulty_top64, 0);
    }

    let info: GetInfo = serde_json::from_value(result_of("testnet/get_info.json")).unwrap();
    assert_eq!(Some(info.difficulty()), parse_wide(&info.wide_difficulty));
    assert_eq!(
        Some(info.cumulative_difficulty()),
        parse_wide(&info.wide_cumulative_difficulty)
    );

    let chains: GetAlternateChains =
        serde_json::from_value(result_of("testnet/get_alternate_chains.json")).unwrap();
    assert!(!chains.chains.is_empty());
    for c in &chains.chains {
        assert_eq!(
            Some(c.cumulative_difficulty()),
            parse_wide(&c.wide_difficulty)
        );
    }
}

#[test]
fn a_synthetic_high_word_survives_reassembly() {
    // No fixture can exercise this -- mainnet's top64 is 0 -- so the check is
    // that the arithmetic is right, not that a daemon produced it.
    let low = 0x0123_4567_89ab_cdefu64;
    let top = 0xfedc_ba98_7654_3210u64;
    assert_eq!(
        reassemble_u128(low, top),
        parse_wide(concat!("0x", "fedcba9876543210", "0123456789abcdef")).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 11. get_block's json is a string
// ---------------------------------------------------------------------------

#[test]
fn the_block_json_field_is_a_string_that_needs_a_second_parse() {
    let fixture = result_of("testnet/get_block_134721.json");
    assert!(
        fixture["json"].is_string(),
        "it is a JSON document encoded as a string, not an object"
    );

    let block: GetBlock = serde_json::from_value(fixture).unwrap();
    let inner = block.parse_json().expect("the nested document parses");
    assert_eq!(
        inner.prev_id, block.block_header.prev_hash,
        "prev_id and prev_hash are the same value under two names"
    );
    assert_eq!(inner.timestamp, block.block_header.timestamp);
    assert_eq!(inner.tx_hashes, block.tx_hashes);
    assert!(inner.miner_tx.is_coinbase());
    assert_eq!(inner.miner_tx.version, 1);
    assert_eq!(inner.miner_tx.signatures.as_deref(), Some(NO_SIGNATURES));
}

#[test]
fn a_ringct_block_carries_a_v2_miner_transaction() {
    let block: GetBlock =
        serde_json::from_value(result_of("mainnet/get_block_ringct.json")).unwrap();
    let inner = block.parse_json().unwrap();
    assert_eq!(inner.miner_tx.version, 2);
    assert!(inner.miner_tx.is_coinbase());
    assert_eq!(inner.miner_tx.rct_type(), Some(RctType::Null));
    // The values, not the counts: the two serializers name this list
    // differently and a length check passes for any two lists of the same size.
    assert_eq!(
        inner.tx_hashes, block.tx_hashes,
        "the nested document and the epee envelope list the same transactions"
    );
    assert_eq!(
        block.tx_hashes.len(),
        2,
        "a block with user transactions, so the comparison above is not vacuous"
    );
}

// ---------------------------------------------------------------------------
// 12. Restricted-mode error code
// ---------------------------------------------------------------------------
//
// No fixture: both local nodes run unrestricted, so the -19 and -32601 shapes
// are covered by the unit tests in `types.rs` against the exact bodies the spec
// records.

// ---------------------------------------------------------------------------
// 13. key_offsets resolve against a denomination, not a global index
// ---------------------------------------------------------------------------

#[test]
fn a_pre_ringct_input_resolves_its_ring_against_its_own_denomination() {
    let tx: TxJson = serde_json::from_value(raw("testnet/tx_as_json_parsed.json")).unwrap();
    let input = tx.vin[0].as_key().expect("a key input");
    assert_eq!(input.amount, 7_000_000_000_000, "a v1 denomination");

    let members = input.ring_members().expect("no overflow");
    assert_eq!(members.len(), 16);
    assert_eq!(
        members.iter().map(OutKeyRequest::index).collect::<Vec<_>>(),
        vec![
            4732, 9814, 11338, 12687, 16105, 16422, 20967, 22322, 29773, 31441, 31906, 32526,
            34105, 34127, 34866, 35151
        ],
        "offsets are relative; only the first is absolute"
    );
    assert!(
        members
            .iter()
            .all(|m| m.amount() == input.amount && !m.is_ringct()),
        "the amount travels with the index, because 4732 means nothing without it"
    );

    // The outputs this ring actually resolves to.
    let outs: GetOutsResponse = serde_json::from_value(raw("testnet/get_outs_ring.json")).unwrap();
    assert_eq!(outs.outs.len(), members.len());

    // And the request we would send carries both halves.
    let wire = serde_json::to_value(members.first().unwrap()).unwrap();
    assert_eq!(wire["amount"], serde_json::json!(7_000_000_000_000u64));
    assert_eq!(wire["index"], serde_json::json!(4732));
}

#[test]
fn a_ringct_input_resolves_its_ring_against_the_global_index() {
    let tx: TxJson = serde_json::from_value(raw("mainnet/tx_ringct_as_json_parsed.json")).unwrap();
    let input = tx.vin[0].as_key().unwrap();
    assert_eq!(input.amount, 0, "RingCT inputs carry no amount");

    let members = input.ring_members().unwrap();
    assert_eq!(
        members.iter().map(OutKeyRequest::index).collect::<Vec<_>>(),
        vec![47664, 142009, 144187, 180198]
    );
    assert!(members.iter().all(OutKeyRequest::is_ringct));

    let outs: GetOutsResponse =
        serde_json::from_value(raw("mainnet/get_outs_ringct.json")).unwrap();
    assert_eq!(outs.outs.len(), members.len());
    assert!(outs.outs.iter().all(|o| o.height > 0));

    // Pinned by value. Widths cannot make this claim: `key`, `mask` and `txid`
    // are all 64 hex characters, so a `#[serde(rename)]` that crossed two of
    // them satisfies a width check unchanged -- and re-serializes
    // byte-identically, so `assert_no_data_loss` is blind to it too. Every
    // entry is checked against its own wire keys in
    // `get_outs_reads_key_mask_and_txid_from_their_own_wire_keys`.
    assert_eq!(
        outs.outs[0].key, "d7daee4c35a95e9164fd526b5ec9a4bb34295530300c24f0879748a9468ef699",
        "the one-time public key, not the commitment beside it"
    );
    assert_eq!(
        outs.outs[0].mask,
        "d5478fecc8ca7f38ffb4d07ce1b387a0d2c89f436ee2a69e95209757ec312a00"
    );
    assert_eq!(
        outs.outs[0].txid,
        "1371613108f69643263de3b29dfaac0aac3a1d699c1bc0fd09a82d444a512e0f"
    );
}

#[test]
fn every_key_input_in_every_fixture_resolves_without_overflow() {
    let mut checked = 0usize;
    for rel in [
        "testnet/get_transactions_ring.json",
        "testnet/get_transactions_multi_input.json",
        "mainnet/get_transactions_ringct.json",
        "mainnet/get_transactions_rct1_full.json",
        "mainnet/get_transactions_rct3_bulletproof.json",
        "mainnet/get_transactions_rct4_mixed_pruned.json",
        "mainnet/get_transactions_rct5_clsag.json",
    ] {
        for (_, tx) in decoded_txs(rel) {
            for input in tx.vin.iter().filter_map(TxIn::as_key) {
                let members = input.ring_members().expect("real offsets do not overflow");
                // Recompute the running sum here rather than asking the method
                // under test to confirm itself: `members.len() ==
                // input.ring_size()` is true by construction whatever the
                // arithmetic does, so on its own it can never fail.
                let expected: Vec<u64> = input
                    .key_offsets
                    .iter()
                    .scan(0u64, |acc, offset| {
                        *acc += offset;
                        Some(*acc)
                    })
                    .collect();
                assert_eq!(
                    members.iter().map(OutKeyRequest::index).collect::<Vec<_>>(),
                    expected,
                    "member i sits at sum(key_offsets[0..=i]); only the first is absolute"
                );
                assert_eq!(members.len(), input.ring_size());
                assert!(members.iter().all(|m| m.amount() == input.amount));
                assert!(members.iter().all(|m| m.is_ringct() == (input.amount == 0)));
                checked += 1;
            }
        }
    }
    // Exact, not a floor: a floor two thirds below the real number stops being
    // able to notice a fixture that has quietly stopped being decoded.
    assert_eq!(checked, 20, "checked {checked} key inputs, expected 20");
}

// ---------------------------------------------------------------------------
// Remaining per-call shapes
// ---------------------------------------------------------------------------

/// A monerod built from master, which dropped the bootstrap-daemon fields in
/// `a01b4c2a3` (2026-05-31). Requiring them made every page fail with "could
/// not decode monerod's response to get_info: missing field
/// `bootstrap_daemon_address`" -- the explorer could not talk to a current
/// daemon at all. Captured from `0.18.1.0-4f0f8390b` serving the same chain as
/// the fixture beside it.
#[test]
fn get_info_from_a_master_daemon_decodes_without_the_bootstrap_fields() {
    let raw = result_of("testnet/get_info_master.json");
    for gone in [
        "bootstrap_daemon_address",
        "height_without_bootstrap",
        "was_bootstrap_ever_used",
    ] {
        assert!(
            raw.get(gone).is_none(),
            "{gone} is still in the capture, so it proves nothing"
        );
    }

    let info: GetInfo = serde_json::from_value(raw).expect("a master daemon's get_info");
    assert_eq!(info.height, 137_082);
    assert_eq!(info.nettype, "testnet");
    assert_eq!(info.version, "0.18.1.0-4f0f8390b");
    assert_eq!(info.bootstrap_daemon_address, "");
}

#[test]
fn get_info_reports_the_testnet_node_it_was_captured_from() {
    let info: GetInfo = serde_json::from_value(result_of("testnet/get_info.json")).unwrap();
    assert_eq!(info.nettype, "testnet");
    assert!(info.testnet && !info.mainnet);
    assert!(
        !info.restricted,
        "the capture came from an unrestricted node"
    );
    assert_eq!(
        info.height, 134_861,
        "the testnet tip when this was captured"
    );
    assert_eq!(info.top_hash, "", "rpc payments are off, so this is empty");
    assert_eq!(info.credits, 0);
}

#[test]
fn a_block_header_range_is_inclusive_of_both_ends() {
    let range: GetBlockHeadersRange =
        serde_json::from_value(result_of("testnet/get_block_headers_range.json")).unwrap();
    let heights: Vec<u64> = range.headers.iter().map(|h| h.height).collect();
    assert_eq!(
        heights,
        vec![134_718, 134_719, 134_720, 134_721, 134_722],
        "both ends of the requested range came back, and nothing in between is missing"
    );
    let span = heights.last().unwrap() - heights[0] + 1;
    assert_eq!(
        span as usize,
        heights.len(),
        "a contiguous, both-ends-inclusive run"
    );
    for h in &range.headers {
        // Non-zero first: block_weight is KV_SERIALIZE_OPT(0), so if it were
        // absent it would default to 0 -- and the equality below would then
        // only be saying that a zero equals a zero.
        assert!(h.block_weight > 0);
        assert_eq!(h.block_size, h.block_weight);
        assert_eq!(h.pow_hash, "", "fill_pow_hash was not requested");
    }
}

#[test]
fn the_fee_estimate_keeps_its_quantization_mask() {
    let fixture = result_of("testnet/get_fee_estimate.json");
    assert!(
        fixture.get("quantization_mask").is_some(),
        "this node sends the key because the value is not 1; the omitted-when-1 \
         case is a unit test in types.rs, since no capture can show it here"
    );
    let fee: FeeEstimate = serde_json::from_value(fixture).unwrap();
    assert_eq!(fee.quantization_mask, 10_000);
    assert_eq!(fee.fee, 520_000);
    assert_eq!(fee.fees, vec![520_000, 2_100_000, 8_300_000, 110_000_000]);
    assert_eq!(fee.fees.first(), Some(&fee.fee), "fees[0] mirrors fee");
}

#[test]
fn alternate_chains_carry_their_own_block_hash_lists() {
    let chains: GetAlternateChains =
        serde_json::from_value(result_of("testnet/get_alternate_chains.json")).unwrap();
    assert!(!chains.chains.is_empty());
    for c in &chains.chains {
        assert_eq!(c.block_hashes.len() as u64, c.length);
        assert_eq!(c.block_hash.len(), 64);
        assert_eq!(c.main_chain_parent_block.len(), 64);
    }
}

#[test]
fn spent_status_maps_positionally_onto_the_request() {
    let resp: IsKeyImageSpentResponse =
        serde_json::from_value(raw("testnet/is_key_image_spent.json")).unwrap();
    let statuses: Vec<SpentStatus> = resp
        .spent_status
        .iter()
        .copied()
        .map(SpentStatus::from_raw)
        .collect();
    assert_eq!(
        statuses,
        vec![SpentStatus::SpentInBlockchain, SpentStatus::Unspent],
        "a real spent key image first, then an all-zero one"
    );
    assert!(statuses[0].is_spent());
}

#[test]
fn get_height_and_get_block_count_agree_and_carry_no_credits() {
    let height: GetHeight = serde_json::from_value(raw("testnet/get_height.json")).unwrap();
    let count: GetBlockCount =
        serde_json::from_value(result_of("testnet/get_block_count.json")).unwrap();
    assert_eq!(height.height, count.count);
    assert_eq!(height.hash.len(), 64);

    // Neither response has credits or top_hash; a shared base with those
    // required would fail here.
    assert!(raw("testnet/get_height.json").get("credits").is_none());
    assert!(
        result_of("testnet/get_block_count.json")
            .get("top_hash")
            .is_none()
    );
}

#[test]
fn a_confirmed_entry_carries_block_fields_and_no_pool_fields() {
    let fixture = raw("testnet/get_transactions_ring.json");
    let entry_keys: Vec<&str> = fixture["txs"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(entry_keys.contains(&"block_height"));
    assert!(entry_keys.contains(&"output_indices"));
    assert!(
        !entry_keys.contains(&"relayed") && !entry_keys.contains(&"received_timestamp"),
        "the in_pool branch's fields are absent, not zeroed"
    );

    let resp: GetTransactionsResponse = serde_json::from_value(fixture).unwrap();
    let entry = &resp.txs[0];
    assert!(!entry.in_pool);
    assert!(entry.block_height > 0);
    assert_eq!(entry.received_timestamp, 0, "defaulted, never sent");
    assert_eq!(
        entry.output_indices.len(),
        entry.parse_json().unwrap().vout.len()
    );
}

#[test]
fn v1_outputs_are_bare_keys_and_ringct_outputs_carry_no_amount() {
    let v1: TxJson = serde_json::from_value(raw("testnet/tx_as_json_parsed.json")).unwrap();
    for out in &v1.vout {
        assert!(out.amount != 0, "v1 outputs are denominated");
        assert_eq!(out.target.public_key().map(str::len), Some(64));
        assert_eq!(
            out.target.view_tag(),
            None,
            "testnet is far below the view-tag fork"
        );
    }

    let v2: TxJson = serde_json::from_value(raw("mainnet/tx_ringct_as_json_parsed.json")).unwrap();
    for out in &v2.vout {
        assert_eq!(out.amount, 0, "RingCT hides the amount");
        assert_eq!(out.target.public_key().map(str::len), Some(64));
    }
}

#[test]
fn tx_extra_is_an_array_of_bytes_not_a_hex_string() {
    let raw_tx = raw("testnet/tx_as_json_parsed.json");
    let on_wire = raw_tx["extra"]
        .as_array()
        .expect("extra is an array of decimal integers, not a hex string")
        .clone();
    let tx: TxJson = serde_json::from_value(raw_tx).unwrap();
    // Byte for byte, in order: a model that decoded this as hex, or reversed
    // it, would still satisfy a length check and a first-element check.
    assert_eq!(
        tx.extra.iter().map(|b| Value::from(*b)).collect::<Vec<_>>(),
        on_wire
    );
    // A public-key field: tag 0x01 followed by 32 bytes, and nothing else.
    assert_eq!(tx.extra.first(), Some(&1u8));
    assert_eq!(tx.extra.len(), 33);
}

// ---------------------------------------------------------------------------
// 14. Same-width fields have to be read from their own wire keys
// ---------------------------------------------------------------------------
//
// `assert_no_data_loss` cannot see a swap between two fields of the same type:
// a symmetric pair of `#[serde(rename)]`s re-serializes byte-identically, so
// the round trip is a fixed point. Width assertions are no better -- `key`,
// `mask` and `txid` are all 64 hex characters, `L` and `R` are the same length
// by definition of a bulletproof, and `c1` and `D` are both bare 32-byte
// scalars. Only the values themselves separate these pairs.

/// Assert that `model` is what the raw document holds under `key`.
///
/// The comparison is against the *named* key rather than against a position or
/// a width, which is the only form that fails when two same-typed fields are
/// crossed.
fn assert_reads_wire_key(model: &str, doc: &Value, key: &str, what: &str) {
    assert_eq!(
        Value::String(model.to_owned()),
        doc[key],
        "{what}.{key} did not come from the wire's `{key}`"
    );
}

#[test]
fn get_outs_reads_key_mask_and_txid_from_their_own_wire_keys() {
    let doc = raw("mainnet/get_outs_ringct.json");
    let outs: GetOutsResponse = serde_json::from_value(doc.clone()).unwrap();
    assert_eq!(outs.outs.len(), 4);

    // The literal bytes mainnet sent for the first ring member. Crossing `key`
    // and `mask` shows the Pedersen commitment where the one-time public key
    // belongs on every ring member the explorer renders.
    let first = &outs.outs[0];
    assert_eq!(
        first.key,
        "d7daee4c35a95e9164fd526b5ec9a4bb34295530300c24f0879748a9468ef699"
    );
    assert_eq!(
        first.mask,
        "d5478fecc8ca7f38ffb4d07ce1b387a0d2c89f436ee2a69e95209757ec312a00"
    );
    assert_eq!(
        first.txid,
        "1371613108f69643263de3b29dfaac0aac3a1d699c1bc0fd09a82d444a512e0f"
    );
    assert_eq!(first.height, 1_228_296);
    assert!(first.unlocked);

    // ...and the same claim for all four, made against the document instead of
    // against this file, so a re-capture cannot silently invalidate it.
    for (i, out) in outs.outs.iter().enumerate() {
        let wire = &doc["outs"][i];
        let what = format!("outs[{i}]");
        assert_reads_wire_key(&out.key, wire, "key", &what);
        assert_reads_wire_key(&out.mask, wire, "mask", &what);
        assert_reads_wire_key(&out.txid, wire, "txid", &what);
        assert_eq!(Value::from(out.height), wire["height"], "{what}.height");
        assert_eq!(
            Value::from(out.unlocked),
            wire["unlocked"],
            "{what}.unlocked"
        );
        // The three hex strings differ from each other, so none of the
        // comparisons above is a value agreeing with itself.
        assert_ne!(out.key, out.mask);
        assert_ne!(out.key, out.txid);
        assert_ne!(out.mask, out.txid);
    }
}

/// The type-3 capture's bulletproof, field by field.
///
/// `L` and `R` are two equal-length lists of 32-byte scalars, so
/// `L.len() == R.len()` holds whatever the wire names say. The nine single
/// scalars are the same hazard: nine 64-character hex strings, any two of which
/// can be crossed without changing a single width.
#[test]
fn a_bulletproof_reads_l_and_r_from_their_own_wire_keys() {
    let rel = "mainnet/get_transactions_rct3_bulletproof.json";
    let doc = nested_raw(rel).remove(0);
    let txs = decoded_txs(rel);
    let (_, tx) = txs.first().expect("one tx");
    let bp = tx
        .rctsig_prunable
        .as_ref()
        .unwrap()
        .bp
        .as_ref()
        .expect("type 3 emits bp");
    assert_eq!(bp.len(), 1);
    let p = &bp[0];

    assert_eq!(p.L.len(), 7);
    assert_eq!(
        p.L[0],
        "85ab173bc021a99cd0885f4934277dceae6238c544b2c27456f3b3deb35251a7"
    );
    assert_eq!(
        p.R[0],
        "7feea22f6f0cd901620525e7eb62b3a5b1c2a18afc27bc0421b6ba94bf386009"
    );
    assert_eq!(
        p.L[6],
        "196389875ab9941f4cec4f92a12a8b23b502d96a07a0d78cde1ce61a2fa4595d"
    );
    assert_eq!(
        p.R[6],
        "73e2975bb3b33de93d7e8a7cd1693cdc0885425f412193e1f8c64eb744205e2c"
    );

    // Both lists in full, in order, against their own wire keys.
    let wire = &doc["rctsig_prunable"]["bp"][0];
    let as_values = |v: &[String]| v.iter().map(|s| Value::from(s.clone())).collect::<Vec<_>>();
    assert_eq!(as_values(&p.L), *wire["L"].as_array().unwrap(), "bp[0].L");
    assert_eq!(as_values(&p.R), *wire["R"].as_array().unwrap(), "bp[0].R");

    // The nine scalars. `A` and `a` are different keys -- JSON is
    // case-sensitive and monerod uses both.
    for (model, key) in [
        (&p.A, "A"),
        (&p.S, "S"),
        (&p.T1, "T1"),
        (&p.T2, "T2"),
        (&p.taux, "taux"),
        (&p.mu, "mu"),
        (&p.a, "a"),
        (&p.b, "b"),
        (&p.t, "t"),
    ] {
        assert_reads_wire_key(model, wire, key, "bp[0]");
    }
    assert_eq!(
        p.A,
        "b4c7b844669e598e07145f180a95f2c3784ed817d9b96a8d36e5eb0e350a8a5b"
    );
    assert_eq!(
        p.t,
        "6bbfb46e1edfbf3ceb6ef964c36e1f4748ab5f9c53e532af7a6faa2b4435a50f"
    );

    // All nine are distinct in this capture, which is what makes the per-key
    // comparisons above able to fail: two equal scalars could be crossed
    // undetected.
    let distinct: std::collections::BTreeSet<&str> = [
        p.A.as_str(),
        p.S.as_str(),
        p.T1.as_str(),
        p.T2.as_str(),
        p.taux.as_str(),
        p.mu.as_str(),
        p.a.as_str(),
        p.b.as_str(),
        p.t.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(distinct.len(), 9);
}

/// The type-5 capture's CLSAG, field by field.
///
/// Before this test the fixture proved a key named `CLSAGs` existed and nothing
/// about what was in it. `c1` is the challenge and `D` the auxiliary key image
/// commitment; both are bare 32-byte scalars, so crossing their wire names
/// yields a perfectly well-formed object with the two values transposed.
#[test]
fn a_clsag_signature_is_read_field_by_field_from_the_type_five_capture() {
    let rel = "mainnet/get_transactions_rct5_clsag.json";
    let doc = nested_raw(rel).remove(0);
    let txs = decoded_txs(rel);
    let (entry, tx) = txs.first().expect("one tx");
    assert_eq!(entry.block_height, 2_489_000);
    assert_eq!(tx.rct_type(), Some(RctType::Clsag));

    let clsags = tx
        .rctsig_prunable
        .as_ref()
        .unwrap()
        .clsags
        .as_ref()
        .expect("type 5 signs with CLSAGs");
    assert_eq!(clsags.len(), tx.vin.len(), "one CLSAG per input");
    assert_eq!(clsags.len(), 1);
    let c = &clsags[0];

    // One `s` scalar per ring member.
    assert_eq!(c.s.len(), tx.vin[0].as_key().unwrap().ring_size());
    assert_eq!(c.s.len(), 11);
    assert_eq!(
        c.s[0],
        "b5f4bef777456e4be125a2f0f90430b2d7938e67fd67233468c0cbf4c5678e02"
    );
    assert_eq!(
        c.s[10],
        "2c03a0dc804897547e3601919bfff23f9ed9f54f2e0f2d34d0810e7a2f0d3106"
    );

    // The two scalars a crossed rename would transpose.
    assert_eq!(
        c.c1,
        "61d6463211ac3d1908409410f4f5fe04316cbb556fbd7b6ed0a717334631440a"
    );
    assert_eq!(
        c.D,
        "eab3213deb911e6fa9b2c6343dfe2cefa8effb302b239a286d3df23b55372285"
    );

    let wire = &doc["rctsig_prunable"]["CLSAGs"][0];
    assert_reads_wire_key(&c.c1, wire, "c1", "CLSAGs[0]");
    assert_reads_wire_key(&c.D, wire, "D", "CLSAGs[0]");
    assert_ne!(
        c.c1, c.D,
        "so the two comparisons above are not the same one"
    );
    assert_eq!(
        c.s.iter()
            .map(|s| Value::from(s.clone()))
            .collect::<Vec<_>>(),
        *wire["s"].as_array().unwrap(),
        "the s vector comes out of `s`, in order"
    );

    // The key image `I` is reconstructed rather than serialized, so monerod
    // sends exactly these three keys and the model has exactly three fields.
    let mut keys: Vec<&str> = wire
        .as_object()
        .expect("a CLSAG is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["D", "c1", "s"]);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 16. The 128-bit accessors, which no capture can exercise
// ---------------------------------------------------------------------------

/// Every capture has `difficulty_top64 == 0` and
/// `cumulative_difficulty_top64 == 0`, so an accessor that reads the wrong top
/// word, the same word twice, or none at all still agrees with `wide_*` on all
/// nine headers. `a_synthetic_high_word_survives_reassembly` defends
/// [`reassemble_u128`] itself; this defends the five accessors that wire the
/// halves into it. The high words are injected into real captures so that
/// everything except the four numbers under test is still the daemon's.
#[test]
fn the_128_bit_accessors_each_read_their_own_top_word() {
    // Four distinct low words and four distinct top words, so no accessor can
    // reach for the wrong one and still produce the right answer.
    let mut header_doc = result_of("testnet/get_block_134721.json")["block_header"].clone();
    header_doc["difficulty"] = 0x0123_4567_89ab_cdefu64.into();
    header_doc["difficulty_top64"] = 3u64.into();
    header_doc["wide_difficulty"] = "0x30123456789abcdef".into();
    header_doc["cumulative_difficulty"] = 0xfedc_ba98_7654_3210u64.into();
    header_doc["cumulative_difficulty_top64"] = 5u64.into();
    header_doc["wide_cumulative_difficulty"] = "0x5fedcba9876543210".into();
    let header: BlockHeader = serde_json::from_value(header_doc).unwrap();
    assert_eq!(
        header.difficulty(),
        0x0000_0000_0000_0003_0123_4567_89ab_cdef
    );
    assert_eq!(
        header.cumulative_difficulty(),
        0x0000_0000_0000_0005_fedc_ba98_7654_3210
    );
    // The daemon's own cross-check agrees, which is the same claim
    // `reassembled_difficulty_agrees_with_the_wide_hex_on_every_fixture` makes
    // -- except that here the top words are not zero.
    assert_eq!(
        Some(header.difficulty()),
        parse_wide(&header.wide_difficulty)
    );
    assert_eq!(
        Some(header.cumulative_difficulty()),
        parse_wide(&header.wide_cumulative_difficulty)
    );

    let mut info_doc = result_of("testnet/get_info.json");
    info_doc["difficulty"] = 0x1111_2222_3333_4444u64.into();
    info_doc["difficulty_top64"] = 7u64.into();
    info_doc["cumulative_difficulty"] = 0x5555_6666_7777_8888u64.into();
    info_doc["cumulative_difficulty_top64"] = 9u64.into();
    let info: GetInfo = serde_json::from_value(info_doc).unwrap();
    assert_eq!(info.difficulty(), 0x0000_0000_0000_0007_1111_2222_3333_4444);
    assert_eq!(
        info.cumulative_difficulty(),
        0x0000_0000_0000_0009_5555_6666_7777_8888
    );

    // ChainInfo has one 128-bit value under two names: the field is
    // `difficulty` and the accessor is `cumulative_difficulty`, because that is
    // what the number means for an alternate chain.
    let mut chain_doc = result_of("testnet/get_alternate_chains.json")["chains"][0].clone();
    chain_doc["difficulty"] = 0x0a0b_0c0d_0e0f_0102u64.into();
    chain_doc["difficulty_top64"] = 0xbu64.into();
    let chain: ChainInfo = serde_json::from_value(chain_doc).unwrap();
    assert_eq!(
        chain.cumulative_difficulty(),
        0x0000_0000_0000_000b_0a0b_0c0d_0e0f_0102
    );
}

// ---------------------------------------------------------------------------
// 17. The scalars a response cannot be read without
// ---------------------------------------------------------------------------

/// Drop one key at a time from a document that parses, and require each drop to
/// be an error naming that key.
///
/// The corpus is all well-formed daemon output, so a field silently gaining a
/// `#[serde(default)]` changes nothing any replay can see: the field is always
/// there. What it changes is what happens to a *malformed* document, which
/// stops being rejected and starts being read as a zero.
fn each_key_is_required<T: DeserializeOwned>(doc: &Value, keys: &[&str], what: &str) {
    assert!(
        serde_json::from_value::<T>(doc.clone()).is_ok(),
        "{what} does not parse intact, so this test proves nothing"
    );
    for key in keys {
        let mut broken = doc.clone();
        broken
            .as_object_mut()
            .unwrap_or_else(|| panic!("{what} is not an object"))
            .remove(*key);
        let err = serde_json::from_value::<T>(broken)
            .err()
            .unwrap_or_else(|| panic!("{what} parsed without its `{key}`"));
        assert!(
            err.to_string().contains(&format!("missing field `{key}`")),
            "{what} without `{key}` failed for the wrong reason: {err}"
        );
    }
}

#[test]
fn the_scalars_a_response_cannot_be_read_without_are_required_not_defaulted() {
    // `rct_signatures.type` is the one that matters most: every other shape
    // decision in the model keys off it, so a default there reads any
    // `rct_signatures` that lost its type as a coinbase's `{"type": 0}`.
    let rct5 = nested_raw("mainnet/get_transactions_rct5_clsag.json").remove(0);
    assert_eq!(rct5["rct_signatures"]["type"], Value::from(5));
    each_key_is_required::<RctSigBase>(&rct5["rct_signatures"], &["type"], "rct_signatures");
    // Its siblings genuinely are optional -- type 0 truncates the object right
    // after `type` -- so the check above is about `type` and not about the
    // struct being strict everywhere.
    for optional in ["txnFee", "ecdhInfo", "outPk"] {
        let mut doc = rct5["rct_signatures"].clone();
        assert!(doc.as_object_mut().unwrap().remove(optional).is_some());
        assert_eq!(
            serde_json::from_value::<RctSigBase>(doc)
                .unwrap()
                .rct_type(),
            RctType::Clsag
        );
    }

    each_key_is_required::<TxJson>(
        &rct5,
        &["version", "unlock_time", "vin", "vout", "extra"],
        "as_json",
    );

    let outs = raw("mainnet/get_outs_ringct.json");
    each_key_is_required::<OutKey>(
        &outs["outs"][0],
        &["key", "mask", "unlocked", "height"],
        "outs[0]",
    );
    // `txid` is the exception: present-but-empty when `get_txid` was false, and
    // the key itself is absent on `/get_outs.bin`.
    let mut no_txid = outs["outs"][0].clone();
    assert!(no_txid.as_object_mut().unwrap().remove("txid").is_some());
    assert_eq!(serde_json::from_value::<OutKey>(no_txid).unwrap().txid, "");

    // A block header: every field is required except the two
    // `KV_SERIALIZE_OPT(0)` weights, which vanish exactly when they are zero.
    let header = result_of("testnet/get_block_134721.json")["block_header"].clone();
    each_key_is_required::<BlockHeader>(
        &header,
        &[
            "major_version",
            "minor_version",
            "timestamp",
            "prev_hash",
            "nonce",
            "orphan_status",
            "height",
            "depth",
            "hash",
            "difficulty",
            "difficulty_top64",
            "wide_difficulty",
            "cumulative_difficulty",
            "cumulative_difficulty_top64",
            "wide_cumulative_difficulty",
            "reward",
            "block_size",
            "num_txes",
            "pow_hash",
            "miner_tx_hash",
        ],
        "block_header",
    );
    for optional in ["block_weight", "long_term_weight"] {
        let mut doc = header.clone();
        assert!(doc.as_object_mut().unwrap().remove(optional).is_some());
        let parsed: BlockHeader = serde_json::from_value(doc).unwrap();
        assert_eq!(parsed.block_weight + parsed.long_term_weight, 1606);
    }
}

// ---------------------------------------------------------------------------
// Live checks
// ---------------------------------------------------------------------------

fn node_url(var: &str) -> Option<String> {
    std::env::var(var).ok()
}

/// The claim from item 13, checked against a daemon rather than a fixture: a
/// pre-RingCT ring index resolves only when its amount travels with it.
///
/// ```text
/// OXBLOCKS_TEST_RPC=http://127.0.0.1:28081 cargo test -p monerod-rpc -- --ignored
/// ```
#[test]
#[ignore = "requires a running testnet monerod"]
fn live_pre_ringct_index_is_meaningless_without_its_amount() {
    let Some(url) = node_url("OXBLOCKS_TEST_RPC") else {
        eprintln!("skipping: set OXBLOCKS_TEST_RPC");
        return;
    };
    let post = |body: Value| -> Value {
        let out = std::process::Command::new("curl")
            .args(["-s", "-m", "10", "-X", "POST", &format!("{url}/get_outs")])
            .arg("-d")
            .arg(body.to_string())
            .output()
            .expect("curl runs");
        serde_json::from_slice(&out.stdout).expect("a JSON response")
    };

    let with_amount = post(serde_json::json!({
        "outputs": [{"amount": 7_000_000_000_000u64, "index": 4732}],
        "get_txid": true
    }));
    assert_eq!(with_amount["status"], "OK");
    assert!(with_amount["outs"][0]["key"].is_string());

    let without_amount = post(serde_json::json!({
        "outputs": [{"amount": 0, "index": 4732}],
        "get_txid": true
    }));
    assert_ne!(
        without_amount["status"], "OK",
        "dropping the amount asks about the RingCT set instead, which is why \
         OutKeyRequest will not let you build one without it"
    );
}

/// The excuse for having no type-6 fixture, written so that it expires.
#[test]
#[ignore = "requires a running testnet monerod"]
fn live_get_outs_omits_the_txid_unless_asked() {
    let Some(url) = node_url("OXBLOCKS_TEST_RPC") else {
        eprintln!("skipping: set OXBLOCKS_TEST_RPC");
        return;
    };
    let out = std::process::Command::new("curl")
        .args(["-s", "-m", "10", "-X", "POST", &format!("{url}/get_outs")])
        .arg("-d")
        .arg(r#"{"outputs":[{"amount":7000000000000,"index":4732}]}"#)
        .output()
        .expect("curl runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("a JSON response");
    assert_eq!(
        v["outs"][0]["txid"], "",
        "the JSON endpoint's get_txid defaults to false, unlike /get_outs.bin"
    );
}

// ---------------------------------------------------------------------------
// RCT type 6 (BulletproofPlus) and view tags.
//
// These were unreachable when the model was written -- HF15 is height
// 2,688,888 and HF16 is 2,689,608, and the local node had not synced that far,
// so BulletproofPlus, Clsag and TaggedKey were backed only by hand-built
// documents. They are now real chain data.
//
// Every assertion below pins a VALUE. Widths and key-set membership are what
// let a swapped serde rename survive the last round; `L.len() == R.len()` is
// true of any bulletproof ever constructed and proves nothing.
// ---------------------------------------------------------------------------

/// Real mainnet tx 281d0f52…9981 at height 3,120,801: type 6, unpruned.
#[test]
fn a_bulletproof_plus_transaction_decodes_to_its_actual_values() {
    let txs = decoded_txs("mainnet/get_transactions_rct6_complete.json");
    assert_eq!(txs.len(), 1);
    let (entry, tx) = &txs[0];

    assert_eq!(
        entry.tx_hash,
        "281d0f52ecae0e80e98000489f5013a08e4067c6c08611a098bbd379fa6a9981"
    );
    assert_eq!(tx.rct_type(), Some(RctType::BulletproofPlus));

    let base = tx.rct_signatures.as_ref().expect("type 6 has a base");
    assert_eq!(base.txn_fee, Some(6_128_000_000));

    let prunable = tx.rctsig_prunable.as_ref().expect("this one is not pruned");
    assert_eq!(prunable.nbp, Some(1), "nbp is a number, and it is 1 here");

    // Bulletproof+: each scalar pinned individually. A serde rename swapping
    // any two of these -- the exact mutation that survived last round on L/R --
    // fails here.
    let bpp = prunable.bpp.as_ref().expect("bpp present");
    assert_eq!(bpp.len(), 1);
    let b = &bpp[0];
    assert_eq!(
        b.A,
        "550c3b9274e8649358644eb13c75dd4c45088ee32f5df16a9331871b950d29a3"
    );
    assert_eq!(
        b.A1,
        "6745be75287753af5cbf0b003cd288103f092f7e7c6a90e9b06a203ef4633dac"
    );
    assert_eq!(
        b.B,
        "65124ddeb9ff1773555ca0e34e5b618af97dbc49e2e48b73e04d566ac04cea47"
    );
    assert_eq!(
        b.r1,
        "bcca57d1c2194739a1560201fe3280ed35f8ec40b070d7af398bec6a776a7c0b"
    );
    assert_eq!(
        b.s1,
        "ca45b8c40ad48965a745ae33f28245023c203981ecf7cff422e5511454673f0e"
    );
    assert_eq!(
        b.d1,
        "5363e068a0e38ed536bba74e6907de8c1b4bf54bb9b2a0d9cc49fdccd698670a"
    );
    assert_eq!(
        b.L[0],
        "813292e8984d550ab74bf776533eac4b492adf4906c6c7e416e9d198450615be"
    );
    assert_eq!(
        b.R[0],
        "f8f40bea6406dd6c2d9ac24be2799d1a205e6f53d5847ac5e4516721f77c0466"
    );
    assert_ne!(b.L[0], b.R[0], "distinct values, so a swap cannot hide");
    assert_eq!(b.L.len(), 7);

    // CLSAG: the whole body went unasserted last round, so a c1/D swap survived.
    let clsags = prunable.clsags.as_ref().expect("CLSAGs present");
    assert_eq!(clsags.len(), 1);
    let c = &clsags[0];
    assert_eq!(
        c.c1,
        "753e131c015032cb26d1cd0150727ff9b5b5af9c0067994d0029fa71c9cbf30e"
    );
    assert_eq!(
        c.D,
        "464e1736b79893ddcee3be0f4d79b0d6123c4229bdac79753ab840c8486997f4"
    );
    assert_eq!(
        c.s[0],
        "3c7c8065e65e56f6c04b372cc346d4daf56a82c74a2c65a8f0b8bf34a2441904"
    );
    assert_eq!(c.s.len(), 16, "one signature per ring member");

    // Type 6 keeps pseudo-outs in the prunable half, not the base.
    assert_eq!(
        tx.pseudo_outs(),
        ["728f6db542665ff1b9f50a6471bf4ca456a8e777dabe4c53501e0bb8caa82b50".to_owned()]
    );

    // Compact ecdhInfo: amount only, 16 hex, no mask.
    let ecdh = ecdh_of(tx);
    assert_eq!(ecdh[0].amount, "32e5c846565b6a04");
    assert_eq!(ecdh[0].mask, None);
    assert_eq!(ecdh[0].form(), Some(EcdhForm::Compact));
}

/// View tags (HF16). `tagged_key`'s body is an object, where `key`'s is a bare
/// hex string -- the documented trap in `TxOutTarget`, now covered by real data.
#[test]
fn a_view_tagged_output_keeps_its_key_and_its_tag_apart() {
    let txs = decoded_txs("mainnet/get_transactions_rct6_complete.json");
    let (_, tx) = &txs[0];

    match &tx.vout[0].target {
        TxOutTarget::TaggedKey(tagged) => {
            assert_eq!(
                tagged.key,
                "0270e5a93c91bd4866ca2500c80b12e5eb5e83038215293bf11451bc77fb5701"
            );
            assert_eq!(tagged.view_tag, "63", "one byte, so two hex characters");
        }
        other => panic!("expected a tagged_key after HF16, got {other:?}"),
    }
}

/// The same era, but a transaction whose prunable half this pruned node no
/// longer holds: `rctsig_prunable` is absent even though `prune: false` was
/// sent. That is the per-transaction pruning rule, on real data.
#[test]
fn a_pruned_bulletproof_plus_transaction_loses_only_its_prunable_half() {
    let txs = decoded_txs("mainnet/get_transactions_rct6_bulletproofplus.json");
    let (entry, tx) = &txs[0];

    assert_eq!(tx.rct_type(), Some(RctType::BulletproofPlus));
    assert!(
        tx.rctsig_prunable.is_none(),
        "this block is outside the node's kept stripe"
    );
    assert!(tx.looks_pruned());
    assert!(entry.prunable_missing(tx));

    // The prefix survives pruning intact, which is why ring expansion still
    // works on a pruned node.
    assert!(!tx.vin.is_empty());
    assert!(!tx.vout.is_empty());
    let base = tx
        .rct_signatures
        .as_ref()
        .expect("the base is not prunable");
    assert!(base.txn_fee.is_some(), "the fee survives pruning");

    // Type 6 keeps pseudo-outs in the prunable half, so pruning takes them.
    assert!(tx.pseudo_outs().is_empty());
}

// ---------------------------------------------------------------------------
// FCMP++ and Carrot, from a daemon built from the stressnet branch
// ---------------------------------------------------------------------------

/// Regtest runs the newest fork from block 1, so every spend in these captures
/// is an FCMP++ spend and every output a Carrot output.
#[test]
fn an_fcmp_pp_spend_has_no_ring_and_names_the_tree_it_proved_against() {
    let txs = decoded_txs("fcmp/get_transactions_fcmp.json");
    assert_eq!(txs.len(), 2);
    for (entry, tx) in &txs {
        assert_eq!(tx.rct_type(), Some(RctType::FcmpPlusPlus));
        assert!(tx.is_fcmp_pp());
        assert!(!tx.looks_pruned());
        assert!(!entry.prunable_missing(tx));

        for input in &tx.vin {
            let k = input
                .as_key()
                .expect("an FCMP++ input is still a key input");
            assert!(k.key_offsets.is_empty(), "present and empty, not a ring");
        }

        // The reference block is below the block the transaction landed in,
        // and the layer count matches what the block reports for its tree.
        let reference = tx.reference_block().expect("a complete tx names its tree");
        assert!(reference < entry.block_height);
        assert!(tx.n_tree_layers().expect("and its layer count") >= 1);

        // One pseudo-output per input, in the prunable half as for types 3-6.
        assert_eq!(tx.pseudo_outs().len(), tx.vin.len());
    }

    // The proof's length is fixed by the input count at a given layer count:
    // the same count gives the same length, and more inputs a longer proof.
    // Which counts the wallet chose varies from one capture to the next.
    let lens: Vec<(usize, usize)> = txs
        .iter()
        .map(|(_, tx)| {
            let p = tx.rctsig_prunable.as_ref().unwrap();
            assert_eq!(tx.n_tree_layers(), txs[0].1.n_tree_layers());
            (tx.vin.len(), p.fcmp_pp_len().expect("an even-length blob"))
        })
        .collect();
    for (a_in, a_len) in &lens {
        assert!(*a_len > 0);
        for (b_in, b_len) in &lens {
            assert_eq!(a_in.cmp(b_in), a_len.cmp(b_len), "{lens:?}");
        }
    }
}

/// The prunable key set is the per-type fingerprint. Type 7 keeps `nbp`,
/// `bpp` and `pseudoOuts` from type 6 and replaces `CLSAGs` with the proof and
/// the two tree fields.
#[test]
fn type_7_trades_clsags_for_the_proof_and_its_tree() {
    for doc in nested_raw("fcmp/get_transactions_fcmp.json") {
        assert_eq!(
            prunable_keys(&doc),
            [
                "bpp",
                "fcmp_pp",
                "n_tree_layers",
                "nbp",
                "pseudoOuts",
                "reference_block"
            ]
        );
    }
}

#[test]
fn carrot_outputs_carry_a_three_byte_view_tag_and_an_anchor() {
    let mut txs = decoded_txs("fcmp/get_transactions_fcmp.json");
    txs.extend(decoded_txs("fcmp/get_transactions_coinbase.json"));
    for (entry, tx) in &txs {
        assert!(!tx.vout.is_empty());
        for out in &tx.vout {
            let TxOutTarget::CarrotV1(c) = &out.target else {
                panic!("{} has a non-Carrot output", entry.tx_hash);
            };
            assert_eq!(out.target.public_key(), Some(c.key.as_str()));
            assert_eq!(out.target.view_tag(), Some(c.view_tag.as_str()));
            assert_eq!(
                out.target.encrypted_janus_anchor(),
                Some(c.encrypted_janus_anchor.as_str())
            );
        }
        // One unified id per output, beside the per-amount indices.
        assert_eq!(entry.unified_ids.len(), tx.vout.len());
        assert_eq!(entry.output_indices.len(), tx.vout.len());
    }
    for (_, tx) in decoded_txs("fcmp/get_transactions_fcmp.json") {
        for e in ecdh_of(&tx) {
            assert_eq!(e.form(), Some(EcdhForm::Compact));
        }
    }
}

/// A coinbase after the fork is still type 0 with a public amount; only its
/// output type changed.
#[test]
fn a_post_fork_coinbase_is_public_and_not_fcmp_pp() {
    let txs = decoded_txs("fcmp/get_transactions_coinbase.json");
    let (_, tx) = txs.first().unwrap();
    assert!(tx.is_coinbase());
    assert_eq!(tx.rct_type(), Some(RctType::Null));
    assert!(!tx.is_fcmp_pp());
    assert!(tx.vout.iter().all(|o| o.amount > 0 && o.target.is_carrot()));
}

/// Pruning takes the proof and the tree fields with it. The transaction is
/// still recognisably FCMP++ from the half that remains.
#[test]
fn a_pruned_fcmp_pp_spend_keeps_its_type_and_loses_its_tree() {
    let txs = decoded_txs("fcmp/get_transactions_fcmp_pruned.json");
    let (entry, tx) = txs.first().unwrap();
    assert!(tx.is_fcmp_pp());
    assert!(tx.looks_pruned());
    assert!(entry.prunable_missing(tx));
    assert_eq!(tx.reference_block(), None);
    assert_eq!(tx.n_tree_layers(), None);
    assert!(tx.vin.iter().all(|i| i.as_key().is_some()));
}

#[test]
fn an_fcmp_pp_block_commits_to_its_curve_tree() {
    for rel in [
        "fcmp/get_block_fcmp.json",
        "fcmp/get_block_coinbase_only.json",
    ] {
        let block: GetBlock = serde_json::from_value(result_of(rel)).unwrap();
        let body = block.parse_json().unwrap();
        assert!(body.major_version >= 17, "{rel}");
        assert!(body.fcmp_pp_n_tree_layers.is_some_and(|n| n >= 1), "{rel}");
        assert!(body.fcmp_pp_tree_root.is_some(), "{rel}");
    }

    // The lean parse finds the same two fields as the full one.
    for rel in [
        "fcmp/get_block_fcmp.json",
        "fcmp/get_block_coinbase_only.json",
    ] {
        let block: GetBlock = serde_json::from_value(result_of(rel)).unwrap();
        let full = block.parse_json().unwrap();
        let lean = block.parse_tree().unwrap();
        assert_eq!(lean.fcmp_pp_n_tree_layers, full.fcmp_pp_n_tree_layers);
        assert_eq!(lean.fcmp_pp_tree_root, full.fcmp_pp_tree_root);
    }

    // Below the fork there are no tree fields at all.
    let old: GetBlock = serde_json::from_value(result_of("testnet/get_block_134721.json")).unwrap();
    let body = old.parse_json().unwrap();
    assert_eq!(body.fcmp_pp_n_tree_layers, None);
    assert_eq!(body.fcmp_pp_tree_root, None);
}

/// The mempool's nested documents are FCMP++ too, and still decode.
#[test]
fn an_fcmp_pp_pool_entry_decodes() {
    let pool: GetTransactionPool =
        serde_json::from_value(raw("fcmp/get_transaction_pool.json")).unwrap();
    assert!(!pool.transactions.is_empty());
    for t in &pool.transactions {
        let tx = t.parse_json().unwrap();
        assert!(tx.is_fcmp_pp());
        // monerod reports the reference block as the highest block the pool
        // entry depends on.
        assert_eq!(tx.reference_block(), Some(t.max_used_block_height));
    }
}

// ---------------------------------------------------------------------------
// /get_path_by_unified_id.bin, in epee's binary format
// ---------------------------------------------------------------------------

fn binary(rel: &str, wanted: &[&str]) -> monerod_rpc::epee::Root {
    let path = fixtures_root().join(rel);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
    monerod_rpc::epee::read_root(&bytes, wanted)
        .unwrap_or_else(|e| panic!("{rel} did not decode: {e}"))
}

/// The same tree size, asked two ways as of block 120 of the capture chain.
/// Regtest's coinbases unlock after 60 blocks, so by then coinbases 0 to 61
/// are in the tree: 62 outputs.
#[test]
fn the_tree_size_is_the_same_whichever_output_probes_it() {
    use monerod_rpc::epee::Value;
    use monerod_rpc::types::TreeSizeQuery;

    let wanted = ["status", "n_leaf_tuples", "paths", "credits", "top_hash"];
    let own = binary("fcmp/get_path_by_unified_id_probe_own_output.bin", &wanted);
    // Probed with an early coinbase, the answer carries a whole path through
    // the tree, nested sections and all, kept here because it was asked for.
    let in_tree = binary("fcmp/get_path_by_unified_id_probe_in_tree.bin", &wanted);

    for root in [&own, &in_tree] {
        assert_eq!(root.text("status"), Some("OK"));
        assert_eq!(TreeSizeQuery::answer(root), Some(62));
        // One path, for the one id asked about: epee writes it as it writes
        // a lone section.
        assert!(matches!(root.array("paths"), Some([Value::Section(_)])));
        assert_eq!(root.unsigned("credits"), Some(0));
    }

    // What the explorer itself asks for is enough for the answer.
    let lean = binary(
        "fcmp/get_path_by_unified_id_probe_in_tree.bin",
        TreeSizeQuery::WANTED,
    );
    assert_eq!(TreeSizeQuery::answer(&lean), Some(62));
    assert_eq!(lean.get("paths"), None, "nothing unasked for is kept");
}

/// Paths for the four outputs of one transaction, captured by
/// `tools/capture-path-fixtures.py` on a chain whose tree holds more than
/// 38 * 18 leaves, and so has three layers.
fn paths(rel: &str, as_of_block: u64, ids: &[u64]) -> monerod_rpc::types::TreePaths {
    use monerod_rpc::types::PathQuery;
    let query = PathQuery::as_of_block(as_of_block, ids).expect("a query");
    query
        .answer(&binary(rel, PathQuery::WANTED))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

const PATH_TX_IDS: [u64; 4] = [802, 803, 804, 805];

#[test]
fn a_transactions_outputs_have_paths_once_they_unlock() {
    use monerod_rpc::types::LeafKind;

    // Mined, but ten blocks from unlocking: in no tree yet.
    let locked = paths(
        "fcmp/paths/get_path_by_unified_id_locked.bin",
        801,
        &PATH_TX_IDS,
    );
    assert_eq!(locked.n_leaf_tuples, 743);
    assert_eq!(locked.paths, vec![None; 4]);

    let tip = paths(
        "fcmp/paths/get_path_by_unified_id_tip.bin",
        811,
        &PATH_TX_IDS,
    );
    let found: Vec<_> = tip
        .paths
        .iter()
        .map(|p| p.as_ref().expect("in the tree"))
        .collect();
    // Unlocked together, the four joined the tree side by side.
    let first = found[0].leaf_idx;
    for (k, (path, id)) in found.iter().zip(PATH_TX_IDS).enumerate() {
        assert_eq!(path.leaf_idx, first + k as u64);
        let leaf = &path.leaves[(path.leaf_idx % 38) as usize];
        assert_eq!(leaf.unified_id, id);
        assert_eq!(leaf.kind, LeafKind::Carrot);
        assert_eq!(path.layers.len(), 3, "three layers");
        assert_eq!(path.layers.last().map(Vec::len), Some(1), "the root alone");
    }
    assert!(tip.n_leaf_tuples > 38 * 18);
}

#[test]
fn a_path_holds_whole_groups_and_ends_at_one_root() {
    let old = paths("fcmp/paths/get_path_by_unified_id_old.bin", 814, &[10, 60]);
    let [Some(a), Some(b)] = &old.paths[..] else {
        panic!("both in the tree")
    };
    assert_eq!((a.leaf_idx, b.leaf_idx), (10, 60));
    // Deep in the tree, both leaf groups are full, and they are different
    // groups under one parent.
    assert_eq!((a.leaves.len(), b.leaves.len()), (38, 38));
    assert_eq!(a.leaves[0].unified_id, 0);
    assert_eq!(b.leaves[0].unified_id, 38);
    assert_eq!(a.layers, b.layers);
    let sizes: Vec<usize> = a.layers.iter().map(Vec::len).collect();
    // 760 leaves: 20 parents, in groups of 18; 2 above them; then the root.
    assert_eq!(old.n_leaf_tuples, 760);
    assert_eq!(sizes, [18, 2, 1]);
}

/// The capture's spends name block 120, when the tree held 62 outputs, and
/// monerod reports the layer count those 62 give.
#[test]
fn the_layer_count_follows_from_the_tree_size() {
    use monerod_rpc::types::{TreeSizeQuery, tree_layers};

    let root = binary(
        "fcmp/get_path_by_unified_id_probe_in_tree.bin",
        TreeSizeQuery::WANTED,
    );
    let leaves = TreeSizeQuery::answer(&root).expect("a tree size");
    let txs = decoded_txs("fcmp/get_transactions_fcmp.json");
    assert_eq!(txs.len(), 2);
    for (_, tx) in &txs {
        assert_eq!(tx.reference_block(), Some(120));
        assert_eq!(
            tx.n_tree_layers().map(usize::from),
            Some(tree_layers(leaves).len())
        );
    }
}

/// The reader is fed remote input, so every corruption of a real answer must
/// come back as a value or an error, never a panic or a hang: each
/// truncation, and each byte replaced by values that hit the type, count and
/// length codes.
#[test]
fn a_corrupted_binary_answer_never_panics_the_reader() {
    use monerod_rpc::types::PathQuery;

    let path = fixtures_root().join("fcmp/paths/get_path_by_unified_id_old.bin");
    let original = std::fs::read(&path).expect("the fixture is readable");
    let query = PathQuery::as_of_block(814, &[10, 60]).expect("a query");
    let wanted = PathQuery::WANTED;

    for len in 0..original.len() {
        let cut = original.get(..len).expect("a prefix");
        assert!(
            monerod_rpc::epee::read_root(cut, wanted).is_err(),
            "a body cut to {len} bytes was accepted"
        );
    }

    // Changed a byte at a time, it is read and its paths decoded, or refused.
    let mut body = original.clone();
    for at in 0..original.len() {
        let was = *original.get(at).expect("in range");
        for value in [0x00, 0x01, 0x03, 0x0c, 0x0d, 0x7f, 0x80, 0x8d, 0xfe, 0xff] {
            *body.get_mut(at).expect("in range") = value;
            if let Ok(root) = monerod_rpc::epee::read_root(&body, wanted) {
                drop(query.answer(&root));
            }
        }
        *body.get_mut(at).expect("in range") = was;
    }
}
