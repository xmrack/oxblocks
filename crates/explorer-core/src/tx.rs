//! What a transaction *is*, independent of how it is shown.
//!
//! Both front ends need the same handful of derived facts -- is it a coinbase,
//! what did it pay in fees, how big is its ring. Deriving them twice is how the
//! HTML pages came to report a fee of zero for every pre-RingCT transaction
//! while the JSON API reported it correctly: one copy fell back to `0` where
//! the other subtracted outputs from inputs. This module is the single copy.

use monerod_rpc::types::{PoolTxInfo, TxEntry, TxIn, TxJson};

use crate::tx_extra::{self, ParsedTxExtra, PaymentId};

/// What an FCMP++ transaction says about the tree it proved membership in.
///
/// Its fields sit in the prunable half, so a pruned node that no longer holds
/// it knows the transaction is FCMP++ and nothing about the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcmpFacts {
    /// The height whose curve tree the inputs were proven against.
    pub reference_block: Option<u64>,
    pub n_tree_layers: Option<u8>,
    /// The proof's length in bytes. It is fixed by the input count and the
    /// layer count, so it grows as the tree does.
    pub proof_size: Option<u64>,
}

/// Facts derived from a transaction, shared by every presentation of it.
#[derive(Debug, Clone)]
pub struct TxFacts {
    pub coinbase: bool,
    pub version: u64,
    pub unlock_time: u64,
    /// `rct_signatures.type`, or 0 where there is none -- every v1 transaction
    /// and every v2 coinbase.
    pub rct_type: u8,
    /// The ring size of the first key input, which the JSON API calls
    /// `mixin`. Not ring size minus one, and 0 for a coinbase -- and 0 for an
    /// FCMP++ transaction, whose inputs have no ring. Read [`TxFacts::fcmp_pp`]
    /// before treating 0 as "no inputs".
    pub ring_size: usize,
    /// Present when the transaction spends with FCMP++ (RingCT type 7).
    pub fcmp_pp: Option<FcmpFacts>,
    /// Whether any output is a Carrot output. Carrot arrives with FCMP++, but
    /// a coinbase has Carrot outputs and no FCMP++ spend, so the two are
    /// separate facts.
    pub carrot: bool,
    pub fee: u64,
    /// Serialized length in bytes, as far as this node can tell. On a pruned
    /// daemon a transaction outside the kept stripe yields only its prefix.
    pub size: u64,
    /// Sum of input amounts: zero for RingCT, denominated before it.
    pub xmr_inputs: u64,
    pub xmr_outputs: u64,
    pub payment_id: Option<PaymentId>,
    pub extra: ParsedTxExtra,
    /// The raw `tx_extra` bytes the fields above were decoded from.
    pub extra_bytes: Vec<u8>,
}

impl TxFacts {
    /// Derive from a confirmed or mempool transaction as `/get_transactions`
    /// returned it.
    #[must_use]
    pub fn from_entry(entry: &TxEntry, tx: &TxJson) -> Self {
        let size = entry.raw_hex_len().map_or(0, |n| (n / 2) as u64);
        Self::derive(tx, size, None)
    }

    /// Derive from a pool entry, which states its own size and fee rather than
    /// carrying a blob to measure.
    #[must_use]
    pub fn from_pool(info: &PoolTxInfo, tx: &TxJson) -> Self {
        Self::derive(tx, info.blob_size, Some(info.fee))
    }

    fn derive(tx: &TxJson, size: u64, stated_fee: Option<u64>) -> Self {
        let coinbase = tx.is_coinbase();

        let ring_size = tx
            .vin
            .iter()
            .find_map(|i| match i {
                TxIn::Key(k) => Some(k.key_offsets.len()),
                // A coinbase, and the pre-v1 script forms, carry no ring.
                _ => None,
            })
            .unwrap_or(0);

        let xmr_inputs = tx
            .vin
            .iter()
            .filter_map(|i| match i {
                TxIn::Key(k) => Some(k.amount),
                _ => None,
            })
            .fold(0u64, u64::saturating_add);

        let xmr_outputs = tx
            .vout
            .iter()
            .map(|o| o.amount)
            .fold(0u64, u64::saturating_add);

        // A coinbase pays nothing. A v2 transaction states its fee. A v1 one
        // does not, and its fee is whatever the inputs did not pay out --
        // getting this wrong renders every pre-RingCT fee as zero, which is
        // exactly the bug that put this function here.
        let fee = if coinbase {
            0
        } else {
            stated_fee
                .or_else(|| tx.rct_signatures.as_ref().and_then(|r| r.txn_fee))
                .unwrap_or_else(|| xmr_inputs.saturating_sub(xmr_outputs))
        };

        let extra = tx_extra::parse(&tx.extra);

        let fcmp_pp = tx.is_fcmp_pp().then(|| FcmpFacts {
            reference_block: tx.reference_block(),
            n_tree_layers: tx.n_tree_layers(),
            proof_size: tx
                .rctsig_prunable
                .as_ref()
                .and_then(monerod_rpc::types::RctSigPrunable::fcmp_pp_len)
                .map(|n| n as u64),
        });
        let carrot = tx.vout.iter().any(|o| o.target.is_carrot());

        Self {
            coinbase,
            version: tx.version,
            unlock_time: tx.unlock_time,
            rct_type: tx.rct_type().map_or(0, |t| t.to_raw()),
            ring_size,
            fcmp_pp,
            carrot,
            fee,
            size,
            xmr_inputs,
            xmr_outputs,
            payment_id: extra.payment_id(),
            extra,
            extra_bytes: tx.extra.clone(),
        }
    }

    /// The unencrypted 32-byte payment id, hex, or empty.
    #[must_use]
    pub fn payment_id_hex(&self) -> String {
        match self.payment_id {
            Some(PaymentId::Long(id)) => id.to_hex(),
            _ => String::new(),
        }
    }

    /// The encrypted 8-byte payment id, hex, or empty.
    #[must_use]
    pub fn payment_id8_hex(&self) -> String {
        match self.payment_id {
            Some(PaymentId::Encrypted(id)) => id.to_hex(),
            _ => String::new(),
        }
    }

    #[must_use]
    pub fn extra_hex(&self) -> String {
        crate::hex::encode(&self.extra_bytes)
    }
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

    use monerod_rpc::types::{RctSigBase, TxInToKey, TxOut, TxOutTarget};

    use super::*;

    fn tx(version: u64, vin: Vec<TxIn>, vout_amounts: &[u64], fee: Option<u64>) -> TxJson {
        TxJson {
            version,
            unlock_time: 0,
            vin,
            vout: vout_amounts
                .iter()
                .map(|a| TxOut {
                    amount: *a,
                    target: TxOutTarget::Key("aa".repeat(32)),
                })
                .collect(),
            extra: Vec::new(),
            signatures: None,
            rct_signatures: fee.map(|f| RctSigBase {
                rct_type: 2,
                txn_fee: Some(f),
                pseudo_outs: None,
                ecdh_info: None,
                out_pk: None,
            }),
            rctsig_prunable: None,
        }
    }

    fn key_input(amount: u64, ring: usize) -> TxIn {
        TxIn::Key(TxInToKey {
            amount,
            key_offsets: vec![1; ring],
            k_image: "bb".repeat(32),
        })
    }

    /// The regression this module exists for. A v1 transaction states no fee,
    /// so it has to be inferred -- and a fallback of zero is both wrong and
    /// completely plausible on screen.
    #[test]
    fn a_pre_ringct_fee_is_inferred_from_inputs_minus_outputs() {
        // Real testnet transaction 2917a83e…eb83: 7 XMR in, 6.996 XMR out.
        let t = tx(
            1,
            vec![key_input(7_000_000_000_000, 16)],
            &[6_996_000_000_000],
            None,
        );
        let facts = TxFacts::derive(&t, 1329, None);

        assert_eq!(facts.fee, 4_000_000_000, "0.004 XMR, not 0");
        assert_eq!(facts.xmr_inputs, 7_000_000_000_000);
        assert_eq!(facts.xmr_outputs, 6_996_000_000_000);
        assert_eq!(facts.ring_size, 16);
        assert!(!facts.coinbase);
    }

    #[test]
    fn a_ringct_fee_is_taken_from_the_transaction_not_inferred() {
        // RingCT amounts are hidden, so inputs minus outputs is 0 and the
        // stated fee is the only real answer.
        let t = tx(2, vec![key_input(0, 11)], &[0, 0], Some(75_336_453_412));
        let facts = TxFacts::derive(&t, 1970, None);
        assert_eq!(facts.fee, 75_336_453_412);
        assert_eq!(facts.xmr_inputs, 0);
        assert_eq!(facts.ring_size, 11);
    }

    #[test]
    fn a_coinbase_pays_no_fee_and_has_no_ring() {
        let t = tx(
            2,
            vec![TxIn::Gen(monerod_rpc::types::TxInGen { height: 100 })],
            &[2_040_028_039_279],
            None,
        );
        let facts = TxFacts::derive(&t, 103, None);
        assert!(facts.coinbase);
        assert_eq!(facts.fee, 0);
        assert_eq!(facts.ring_size, 0);
        assert_eq!(facts.xmr_inputs, 0);
    }

    /// A pool entry states its fee, which must win over any inference.
    #[test]
    fn a_pool_entry_uses_the_fee_the_pool_states() {
        let t = tx(2, vec![key_input(0, 16)], &[0, 0], None);
        let facts = TxFacts::derive(&t, 1533, Some(490_560_000));
        assert_eq!(facts.fee, 490_560_000);
        assert_eq!(facts.size, 1533);
    }

    /// An FCMP++ spend has no ring, so its ring size is 0 -- which is also
    /// what a coinbase reads. `fcmp_pp` is what tells the two apart.
    #[test]
    fn an_fcmp_pp_spend_has_no_ring_but_is_not_a_coinbase() {
        let mut t = tx(2, vec![key_input(0, 0), key_input(0, 0)], &[0, 0], Some(1));
        t.rct_signatures.as_mut().unwrap().rct_type = 7;
        t.rctsig_prunable = Some(monerod_rpc::types::RctSigPrunable {
            reference_block: Some(3_012_345),
            n_tree_layers: Some(6),
            fcmp_pp: Some("ab".repeat(4256)),
            ..Default::default()
        });
        for o in &mut t.vout {
            o.target = TxOutTarget::CarrotV1(monerod_rpc::types::CarrotV1 {
                key: "aa".repeat(32),
                view_tag: "a1b2c3".to_owned(),
                encrypted_janus_anchor: "00".repeat(16),
            });
        }
        let facts = TxFacts::derive(&t, 3000, None);
        assert!(!facts.coinbase);
        assert!(facts.carrot);
        assert_eq!(
            facts.fcmp_pp,
            Some(FcmpFacts {
                reference_block: Some(3_012_345),
                n_tree_layers: Some(6),
                proof_size: Some(4256),
            })
        );
    }

    /// A ring-era transaction is not FCMP++ even with an empty ring, and a
    /// legacy output is not Carrot.
    #[test]
    fn a_ring_spend_carries_no_fcmp_pp_facts() {
        let t = tx(2, vec![key_input(0, 16)], &[0], Some(1));
        let facts = TxFacts::derive(&t, 1500, None);
        assert_eq!(facts.fcmp_pp, None);
        assert!(!facts.carrot);
    }

    /// Remote sums must not wrap into a small, believable number.
    #[test]
    fn absurd_amounts_saturate_rather_than_wrap() {
        let t = tx(
            1,
            vec![key_input(u64::MAX, 1), key_input(u64::MAX, 1)],
            &[u64::MAX, u64::MAX],
            None,
        );
        let facts = TxFacts::derive(&t, 0, None);
        assert_eq!(facts.xmr_inputs, u64::MAX);
        assert_eq!(facts.xmr_outputs, u64::MAX);
        assert_eq!(facts.fee, 0, "saturating subtraction, not a wrap");
    }
}
