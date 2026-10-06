//! Response shapes.
//!
//! **Every struct here declares its fields in alphabetical order.** The API
//! emits keys byte-ascending, recursively, and serde emits them in
//! *declaration* order. Declaring them sorted is how the two agree without
//! routing everything through `serde_json::Value`.
//!
//! Two things hold the property up, and only one of them is load-bearing today.
//! The declaration order is the belt: `declaration_order_is_alphabetical` below
//! checks it by serialising each struct **directly**, which streams its fields
//! in the order they are written. The braces is that `serde_json::Map` is a
//! `BTreeMap` unless the `preserve_order` feature is on, and the real response
//! path goes through `serde_json::to_value`, which therefore sorts whatever it
//! is given. That feature could be switched on by a transitive dependency
//! without anyone here noticing, at which point the belt is all that is left --
//! so `no_preserve_order` pins it.
//!
//! Both live in this file's `tests` module, which is where they were missing
//! from: this comment claimed they existed long before they did.

use explorer_core::fmt::timestamp_utc;
use explorer_core::{BlockTree, Hash32, ResolvedInput, TxFacts};
use monerod_rpc::types::{BlockHeader, PoolTxInfo, TxEntry, TxJson};
use serde::Serialize;

/// One ring member.
///
/// The height field is named `block_no`, not `height`. Clients index on that
/// name, so it is not ours to tidy.
#[derive(Debug, Clone, Serialize)]
pub struct ApiMixin {
    pub block_no: u64,
    pub public_key: String,
    pub tx_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiInput {
    pub amount: u64,
    pub key_image: String,
    /// `null`, not `[]`, when the ring could not be resolved.
    ///
    /// An input whose very first ring member fails to resolve serialises as
    /// `"mixins":null`. A plain `Vec` would emit `[]`, which says the input
    /// has no ring members at all.
    pub mixins: Option<Vec<ApiMixin>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiOutput {
    pub amount: u64,
    /// A Carrot output's encrypted Janus anchor, 32 hex characters. `null` for
    /// every output from before Carrot, which has none.
    pub encrypted_janus_anchor: Option<String>,
    pub public_key: String,
    /// The output's index among every output on the chain, of every amount,
    /// which a wallet uses to ask for the output's path through the curve
    /// tree. `null` for a transaction still in the pool, and on a daemon from
    /// before FCMP++.
    pub unified_id: Option<u64>,
    /// Two hex characters before Carrot and six from it. `null` for an output
    /// from before view tags, not `""`, which would read as a tag of no bytes.
    pub view_tag: Option<String>,
}

/// The transaction object that appears inside `/api/block`,
/// `/api/transactions` and `/api/mempool`.
#[derive(Debug, Clone, Serialize)]
pub struct TxSummary {
    pub coinbase: bool,
    pub extra: String,
    /// The FCMP++ proof's length in bytes. `null` in the same cases as
    /// `reference_block`.
    pub fcmp_pp_proof_size: Option<u64>,
    pub mixin: u64,
    /// The curve tree's layer count when the FCMP++ proof was built. `null`
    /// in the same cases as `reference_block`.
    pub n_tree_layers: Option<u8>,
    pub payment_id: String,
    pub payment_id8: String,
    pub rct_type: u8,
    /// The height the curve tree was taken at when an FCMP++ transaction's
    /// inputs were proven. Its root is in block `reference_block - 8`; see
    /// [`monerod_rpc::types::TREE_ROOT_LAG`]. `null` for a ring spend and a
    /// coinbase, and for an FCMP++ transaction whose prunable half the node no
    /// longer holds, since the field is stored there. Read `rct_type` to tell
    /// the last case apart.
    pub reference_block: Option<u64>,
    pub tx_fee: u64,
    pub tx_hash: String,
    pub tx_size: u64,
    pub tx_version: u64,
    /// Emitted because a transaction that cannot be spent until a given
    /// height or time is a fact a reader wants, and it costs one field.
    pub unlock_time: u64,
    pub xmr_inputs: u64,
    pub xmr_outputs: u64,
}

/// `/api/transaction` — the shared keys plus the placement, the inputs, the
/// outputs and the tree size.
#[derive(Debug, Clone, Serialize)]
pub struct TxDetail {
    /// How many outputs the curve tree held as of `reference_block`: the
    /// number of outputs each FCMP++ input could be spending. `null` for a
    /// ring spend, for a transaction still in the pool, where `reference_block`
    /// is `null`, and when the daemon cannot say. Filled only by
    /// `/api/transaction`, and so by `/api/search` on a transaction hash,
    /// which answers through it, because it costs a daemon call.
    pub anonymity_set: Option<u64>,
    pub block_height: u64,
    pub coinbase: bool,
    pub confirmations: u64,
    pub current_height: u64,
    pub extra: String,
    /// See [`TxSummary::fcmp_pp_proof_size`].
    pub fcmp_pp_proof_size: Option<u64>,
    /// `null`, not `[]`, for a coinbase transaction, which spends nothing.
    pub inputs: Option<Vec<ApiInput>>,
    pub mixin: u64,
    /// See [`TxSummary::n_tree_layers`].
    pub n_tree_layers: Option<u8>,
    pub outputs: Vec<ApiOutput>,
    pub payment_id: String,
    pub payment_id8: String,
    pub rct_type: u8,
    /// See [`TxSummary::reference_block`].
    pub reference_block: Option<u64>,
    pub timestamp: u64,
    pub timestamp_utc: String,
    pub tx_fee: u64,
    pub tx_hash: String,
    pub tx_size: u64,
    pub tx_version: u64,
    pub unlock_time: u64,
    pub xmr_inputs: u64,
    pub xmr_outputs: u64,
}

/// `/api/block`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockDetail {
    pub block_height: u64,
    pub current_height: u64,
    pub hash: String,
    /// The curve tree's layer count, from the FCMP++ fork on, and 0 while the
    /// tree is empty. `null` when no tree is reported: below the fork, when
    /// the daemon's block carries no well-formed tree, and in `/api/blocks`
    /// for a post-fork block whose body could not be fetched.
    pub n_tree_layers: Option<u8>,
    /// Integer here. The *same* value is a JSON float in `/api/transactions`.
    /// On one block that is 95511 against 95511.0.
    pub size: u64,
    pub timestamp: u64,
    pub timestamp_utc: String,
    /// The curve tree root this block commits to, hex, from the FCMP++ fork
    /// on. `null` in the same cases as `n_tree_layers`.
    pub tree_root: Option<String>,
    pub txs: Vec<TxSummary>,
}

impl BlockDetail {
    /// One block's API representation, from its header and its transactions.
    ///
    /// Shared by `/api/block` and `/api/blocks/<start>/<end>`, because the
    /// element type of the range response is exactly the single-block
    /// response. Takes the header rather than a whole `get_block`, because a
    /// range is answered from `get_block_headers_range` and fetches a block's
    /// body only when the block holds transactions or carries a curve tree.
    pub fn build(
        header: &BlockHeader,
        depth: u64,
        entries: &[TxEntry],
        tree: Option<&BlockTree>,
    ) -> BlockDetail {
        let mut txs = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry.parse_json() {
                Ok(tx) => txs.push(TxSummary::build(entry, &tx)),
                // One undecodable transaction must not lose the whole block page.
                Err(e) => tracing::warn!(tx = %entry.tx_hash, "skipping: {e}"),
            }
        }

        BlockDetail {
            block_height: header.height,
            // The tip, derived from this block's depth: `depth` is 0 for the tip,
            // and `current_height` is the chain *height* (tip + 1). Block
            // 2,000,000 at depth 1,765,612 reports current_height 3,765,613.
            current_height: header.height.saturating_add(depth).saturating_add(1),
            hash: normalise_hash(&header.hash),
            n_tree_layers: tree.map(|t| t.n_layers),
            size: header.block_size,
            timestamp: header.timestamp,
            timestamp_utc: timestamp_utc(header.timestamp),
            tree_root: tree.map(|t| t.root.clone()),
            txs,
        }
    }
}

impl TxSummary {
    pub fn build(entry: &TxEntry, tx: &TxJson) -> Self {
        Self::from_facts(&entry.tx_hash, &TxFacts::from_entry(entry, tx))
    }

    /// The same shape for a transaction that is still in the pool.
    ///
    /// A pool entry has no `TxEntry`: there is no block, no confirmations, and
    /// the size is the pool's own `blob_size` rather than a reassembled hex
    /// blob. The fee is stated by the pool too, so it is taken rather than
    /// recomputed.
    pub fn build_pool(info: &PoolTxInfo, tx: &TxJson) -> Self {
        Self::from_facts(&info.id_hash, &TxFacts::from_pool(info, tx))
    }

    fn from_facts(hash: &str, f: &TxFacts) -> Self {
        Self {
            coinbase: f.coinbase,
            extra: f.extra_hex(),
            fcmp_pp_proof_size: f.fcmp_pp.and_then(|x| x.proof_size),
            mixin: f.ring_size as u64,
            n_tree_layers: f.fcmp_pp.and_then(|x| x.n_tree_layers),
            payment_id: f.payment_id_hex(),
            payment_id8: f.payment_id8_hex(),
            rct_type: f.rct_type,
            reference_block: f.fcmp_pp.and_then(|x| x.reference_block),
            tx_fee: f.fee,
            tx_hash: hash.to_lowercase(),
            tx_size: f.size,
            tx_version: f.version,
            unlock_time: f.unlock_time,
            xmr_inputs: f.xmr_inputs,
            xmr_outputs: f.xmr_outputs,
        }
    }
}

/// Where a transaction sits, which is all three of the fields that answer
/// "when". A transaction in the pool is in no block: height zero,
/// confirmations zero, and the time it carries is the time it arrived --
/// monerod puts that in `received_timestamp`, and reading `block_timestamp`
/// regardless reports every unconfirmed transaction as dated 1970.
struct Placement {
    block_height: u64,
    timestamp: u64,
    confirmations: u64,
}

impl Placement {
    fn of(entry: &TxEntry, current_height: u64) -> Self {
        if entry.in_pool {
            return Self::pool(entry.received_timestamp);
        }
        Self {
            block_height: entry.block_height,
            timestamp: entry.block_timestamp,
            confirmations: current_height.saturating_sub(entry.block_height),
        }
    }

    const fn pool(received: u64) -> Self {
        Self {
            block_height: 0,
            timestamp: received,
            confirmations: 0,
        }
    }
}

impl TxDetail {
    pub fn build(
        entry: &TxEntry,
        tx: &TxJson,
        rings: &[ResolvedInput],
        current_height: u64,
    ) -> Self {
        Self::assemble(
            &entry.tx_hash,
            &TxFacts::from_entry(entry, tx),
            tx,
            entry
                .unified_ids_per_output(tx.vout.len())
                .unwrap_or_default(),
            rings,
            &Placement::of(entry, current_height),
            current_height,
        )
    }

    /// The same shape for a transaction still in the pool, built from the pool
    /// listing itself, which carries each transaction's JSON, size and fee.
    pub fn build_pool(
        info: &PoolTxInfo,
        tx: &TxJson,
        rings: &[ResolvedInput],
        current_height: u64,
    ) -> Self {
        Self::assemble(
            &info.id_hash,
            &TxFacts::from_pool(info, tx),
            tx,
            &[],
            rings,
            &Placement::pool(info.receive_time),
            current_height,
        )
    }

    fn assemble(
        hash: &str,
        f: &TxFacts,
        tx: &TxJson,
        unified_ids: &[u64],
        rings: &[ResolvedInput],
        at: &Placement,
        current_height: u64,
    ) -> Self {
        let inputs = if f.coinbase {
            None
        } else {
            Some(
                rings
                    .iter()
                    .map(|r| ApiInput {
                        amount: r.amount,
                        key_image: r.key_image.to_hex(),
                        mixins: if r.ring.is_empty() && r.ring_unavailable {
                            None
                        } else {
                            Some(
                                r.ring
                                    .iter()
                                    .map(|m| ApiMixin {
                                        block_no: m.block_height,
                                        public_key: m.public_key.to_hex(),
                                        tx_hash: m.tx_hash.to_hex(),
                                    })
                                    .collect(),
                            )
                        },
                    })
                    .collect(),
            )
        };

        let outputs = tx
            .vout
            .iter()
            .enumerate()
            .map(|(i, o)| ApiOutput {
                amount: o.amount,
                // Legacy script outputs exist only in the pre-v1 era and carry
                // no one-time key, so they render empty rather than inventing
                // one. Every other target, Carrot's included, names its key
                // through the target's own accessors, which the HTML pages
                // share.
                encrypted_janus_anchor: o.target.encrypted_janus_anchor().map(str::to_owned),
                public_key: o.target.public_key().map(str::to_owned).unwrap_or_default(),
                unified_id: unified_ids.get(i).copied(),
                view_tag: o.target.view_tag().map(str::to_owned),
            })
            .collect();

        Self {
            anonymity_set: None,
            block_height: at.block_height,
            coinbase: f.coinbase,
            confirmations: at.confirmations,
            current_height,
            extra: f.extra_hex(),
            fcmp_pp_proof_size: f.fcmp_pp.and_then(|x| x.proof_size),
            inputs,
            mixin: f.ring_size as u64,
            n_tree_layers: f.fcmp_pp.and_then(|x| x.n_tree_layers),
            outputs,
            payment_id: f.payment_id_hex(),
            payment_id8: f.payment_id8_hex(),
            rct_type: f.rct_type,
            reference_block: f.fcmp_pp.and_then(|x| x.reference_block),
            timestamp: at.timestamp,
            timestamp_utc: timestamp_utc(at.timestamp),
            tx_fee: f.fee,
            tx_hash: hash.to_lowercase(),
            tx_size: f.size,
            tx_version: f.version,
            unlock_time: f.unlock_time,
            xmr_inputs: f.xmr_inputs,
            xmr_outputs: f.xmr_outputs,
        }
    }
}

/// Hash rendering for a value that came off the wire as a string.
///
/// monerod returns lowercase hex, but a caller may have *asked* in uppercase.
/// The parsed value is echoed, so normalise rather than pass through.
#[must_use]
pub fn normalise_hash(raw: &str) -> String {
    raw.parse::<Hash32>()
        .map_or_else(|_| raw.to_lowercase(), |h| h.to_hex())
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

    /// The key order a struct *emits* at its own level, before anything
    /// re-sorts it.
    ///
    /// Two traps, both of which this walked into on the first attempt:
    ///
    /// * going through `to_value` first would sort the keys and make every
    ///   assertion below vacuously true, so this serialises the struct
    ///   directly, which streams its fields in declaration order;
    /// * a nested object's keys are *not* part of its parent's ordering.
    ///   Flattening them into one list compares `block_no` against
    ///   `confirmations` and fails on structs that are perfectly ordered. Only
    ///   keys at depth 1 are collected; the nested shapes are asserted in their
    ///   own right.
    fn declared_keys<T: Serialize>(value: &T) -> Vec<String> {
        let rendered = serde_json::to_string(value).expect("serialises");
        let mut keys = Vec::new();
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        let mut current = String::new();
        let mut chars = rendered.chars().peekable();

        while let Some(c) = chars.next() {
            if in_string {
                if escaped {
                    escaped = false;
                    current.push(c);
                } else if c == '\\' {
                    escaped = true;
                    current.push(c);
                } else if c == '"' {
                    in_string = false;
                    // A string at depth 1 followed by ':' is a key of the
                    // object under test; anything else is a value.
                    if depth == 1 && chars.peek() == Some(&':') {
                        keys.push(current.clone());
                    }
                } else {
                    current.push(c);
                }
                continue;
            }
            match c {
                '"' => {
                    in_string = true;
                    current.clear();
                }
                '{' | '[' => depth += 1,
                '}' | ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        keys
    }

    fn assert_sorted(keys: &[String], what: &str) {
        let mut expected = keys.to_vec();
        expected.sort();
        assert_eq!(
            keys, expected,
            "{what} declares its fields out of alphabetical order, so it would \
             emit its keys out of order if serde_json ever stopped sorting \
             them"
        );
    }

    fn mixin() -> ApiMixin {
        ApiMixin {
            block_no: 1,
            public_key: String::new(),
            tx_hash: String::new(),
        }
    }

    fn summary() -> TxSummary {
        TxSummary {
            coinbase: false,
            extra: String::new(),
            fcmp_pp_proof_size: None,
            mixin: 16,
            n_tree_layers: None,
            payment_id: String::new(),
            payment_id8: String::new(),
            rct_type: 0,
            reference_block: None,
            tx_fee: 0,
            tx_hash: String::new(),
            tx_size: 0,
            tx_version: 1,
            unlock_time: 0,
            xmr_inputs: 0,
            xmr_outputs: 0,
        }
    }

    fn detail() -> TxDetail {
        TxDetail {
            anonymity_set: None,
            block_height: 0,
            coinbase: false,
            confirmations: 0,
            current_height: 0,
            extra: String::new(),
            fcmp_pp_proof_size: None,
            inputs: Some(vec![ApiInput {
                amount: 0,
                key_image: String::new(),
                mixins: Some(vec![mixin()]),
            }]),
            mixin: 16,
            n_tree_layers: None,
            outputs: vec![ApiOutput {
                amount: 0,
                encrypted_janus_anchor: None,
                public_key: String::new(),
                unified_id: None,
                view_tag: None,
            }],
            payment_id: String::new(),
            payment_id8: String::new(),
            rct_type: 0,
            reference_block: None,
            timestamp: 0,
            timestamp_utc: String::new(),
            tx_fee: 0,
            tx_hash: String::new(),
            tx_size: 0,
            tx_version: 2,
            unlock_time: 0,
            xmr_inputs: 0,
            xmr_outputs: 0,
        }
    }

    /// Every response emits its keys byte-ascending, so every struct here has
    /// to be declared in that order to agree without routing through a sorting
    /// container.
    #[test]
    fn declaration_order_is_alphabetical() {
        assert_sorted(&declared_keys(&mixin()), "ApiMixin");
        assert_sorted(
            &declared_keys(&ApiInput {
                amount: 0,
                key_image: String::new(),
                mixins: None,
            }),
            "ApiInput",
        );
        assert_sorted(
            &declared_keys(&ApiOutput {
                amount: 0,
                encrypted_janus_anchor: Some(String::new()),
                public_key: String::new(),
                unified_id: Some(0),
                view_tag: Some(String::new()),
            }),
            "ApiOutput",
        );
        assert_sorted(&declared_keys(&summary()), "TxSummary");
        assert_sorted(&declared_keys(&detail()), "TxDetail");
        assert_sorted(
            &declared_keys(&BlockDetail {
                block_height: 0,
                current_height: 0,
                hash: String::new(),
                n_tree_layers: Some(2),
                size: 0,
                timestamp: 0,
                timestamp_utc: String::new(),
                tree_root: Some(String::new()),
                txs: vec![summary()],
            }),
            "BlockDetail",
        );
    }

    /// The helper itself, because an ordering test built on a broken scanner
    /// would pass for the wrong reason.
    ///
    /// Sorting is recursive, so every nested object has to be ordered too.
    /// Each one is ordered *against its own siblings*, not against its
    /// parent's fields. `ApiMixin` and `ApiOutput` are asserted separately
    /// above for that reason, and must not leak into `TxDetail`'s list here.
    #[test]
    fn the_scanner_reads_one_level_and_does_not_mistake_values_for_keys() {
        let keys = declared_keys(&detail());
        assert!(
            !keys.iter().any(|k| k == "block_no"),
            "a nested ring-member key was counted as one of TxDetail's own"
        );
        assert!(
            keys.iter().any(|k| k == "inputs") && keys.iter().any(|k| k == "outputs"),
            "the containing fields themselves were missed"
        );
        assert_eq!(keys.len(), 24, "TxDetail has 24 fields of its own");

        // A value that happens to be a string must not be read as a key.
        let probe = ApiOutput {
            amount: 0,
            encrypted_janus_anchor: None,
            public_key: "not_a_key".to_owned(),
            unified_id: None,
            view_tag: None,
        };
        assert_eq!(
            declared_keys(&probe),
            vec![
                "amount",
                "encrypted_janus_anchor",
                "public_key",
                "unified_id",
                "view_tag"
            ]
        );
    }

    /// An FCMP++ transaction with Carrot outputs, through the same builder
    /// `/api/transaction` uses: every output publishes its one-time address.
    #[test]
    fn an_fcmp_pp_transaction_publishes_its_keys_and_an_empty_ring() {
        let entry: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": "AB".repeat(32), "in_pool": false,
            "block_height": 3_012_400, "block_timestamp": 1_790_000_000,
        }))
        .unwrap();
        let tx: TxJson = serde_json::from_value(serde_json::json!({
            "version": 2, "unlock_time": 0,
            "vin": [{"key": {"amount": 0, "key_offsets": [], "k_image": "cc".repeat(32)}}],
            "vout": [{"amount": 0, "target": {"carrot_v1": {
                "key": "dd".repeat(32), "view_tag": "a1b2c3",
                "encrypted_janus_anchor": "ee".repeat(16)}}}],
            "extra": [],
            "rct_signatures": {"type": 7, "txnFee": 91_000_000},
            "rctsig_prunable": {"reference_block": 3_012_390, "n_tree_layers": 6},
        }))
        .unwrap();
        let rings = explorer_core::unexpanded_inputs(&tx);
        let detail = TxDetail::build(&entry, &tx, &rings, 3_012_401);

        assert_eq!(detail.rct_type, 7);
        assert_eq!(detail.mixin, 0);
        assert_eq!(detail.reference_block, Some(3_012_390));
        assert_eq!(detail.n_tree_layers, Some(6));
        assert_eq!(detail.outputs[0].public_key, "dd".repeat(32));
        assert_eq!(detail.outputs[0].view_tag.as_deref(), Some("a1b2c3"));
        assert_eq!(
            detail.outputs[0].encrypted_janus_anchor,
            Some("ee".repeat(16))
        );

        // The block and mempool lists carry the tree fields too.
        let summary = TxSummary::build(&entry, &tx);
        assert_eq!(summary.reference_block, Some(3_012_390));
        assert_eq!(summary.n_tree_layers, Some(6));

        let inputs = detail.inputs.as_ref().expect("a spend lists its inputs");
        assert_eq!(inputs.len(), 1);
        assert_eq!(
            inputs[0].mixins.as_ref().map(Vec::len),
            Some(0),
            "no ring is an empty list, not a withheld one"
        );
    }

    /// A ring-era transaction answers `null` for everything FCMP++ and Carrot
    /// added, and a one-byte view tag where its output has one.
    #[test]
    fn a_ring_transaction_has_null_tree_fields_and_no_anchor() {
        let entry: TxEntry = serde_json::from_value(serde_json::json!({
            "tx_hash": "AB".repeat(32), "in_pool": true, "received_timestamp": 1,
        }))
        .unwrap();
        let tx: TxJson = serde_json::from_value(serde_json::json!({
            "version": 2, "unlock_time": 0,
            "vin": [{"key": {"amount": 0, "key_offsets": [5], "k_image": "cc".repeat(32)}}],
            "vout": [
                {"amount": 0, "target": {"tagged_key": {"key": "dd".repeat(32), "view_tag": "9f"}}},
                {"amount": 0, "target": {"key": "ee".repeat(32)}},
            ],
            "extra": [],
            "rct_signatures": {"type": 6, "txnFee": 1},
        }))
        .unwrap();
        let rings = explorer_core::unexpanded_inputs(&tx);
        let value = serde_json::to_value(TxDetail::build(&entry, &tx, &rings, 10)).unwrap();

        assert_eq!(value["reference_block"], serde_json::Value::Null);
        assert_eq!(value["n_tree_layers"], serde_json::Value::Null);
        assert_eq!(value["outputs"][0]["view_tag"], "9f");
        assert_eq!(value["outputs"][1]["view_tag"], serde_json::Value::Null);
        for out in value["outputs"].as_array().unwrap() {
            assert_eq!(out["encrypted_janus_anchor"], serde_json::Value::Null);
        }
    }

    /// What the ordering actually rests on today.
    ///
    /// `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature is
    /// enabled, and the response path runs every payload through
    /// `serde_json::to_value`, so the map sorts the keys whatever order the
    /// struct declared them in. Cargo unifies features across the whole graph,
    /// so a dependency added three levels away could switch that on; the
    /// ordering would then silently become declaration order.
    #[test]
    fn no_preserve_order() {
        #[derive(Serialize)]
        struct OutOfOrder {
            zebra: u64,
            apple: u64,
        }
        let sorted_by_the_map =
            serde_json::to_value(OutOfOrder { zebra: 1, apple: 2 }).expect("serialises");
        assert_eq!(
            serde_json::to_string(&sorted_by_the_map).expect("serialises"),
            r#"{"apple":2,"zebra":1}"#,
            "serde_json is no longer sorting object keys, which means the \
             `preserve_order` feature has been switched on somewhere in the \
             dependency graph. Responses emit keys byte-ascending, so every \
             response struct's declaration order is now load-bearing."
        );
    }
}
