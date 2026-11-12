//! The shape of an FCMP++ proof, as monero-oxide lays it out.

use monero_fcmp_plus_plus::Curves;
use monero_fcmp_plus_plus::fcmps::Fcmp;
use monero_fcmp_plus_plus_generators::{MAX_FCMP_INPUTS, MAX_FCMP_LAYERS};

/// The shape of an FCMP++ membership proof: the rows of each of its two
/// arithmetic-circuit proofs, one on Selene and one on Helios, and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipShape {
    pub selene_rows: usize,
    pub helios_rows: usize,
    /// Bytes, the root blind's proof of knowledge included.
    pub len: usize,
}

impl MembershipShape {
    /// The shape for `inputs` inputs in a tree of `layers` layers:
    /// `Fcmp::ipa_rows` and `Fcmp::proof_size`.
    ///
    /// `None` outside what consensus allows, 1 to 128 inputs and 1 to 12
    /// layers, since the counts come from the transaction and the arithmetic
    /// is only defined, and only checked for overflow, within them.
    #[must_use]
    pub fn of(inputs: usize, layers: u8) -> Option<Self> {
        let layers = usize::from(layers);
        if !(1..=MAX_FCMP_INPUTS).contains(&inputs) || !(1..=MAX_FCMP_LAYERS).contains(&layers) {
            return None;
        }
        let (selene_rows, helios_rows) = Fcmp::<Curves>::ipa_rows(inputs, layers);
        Some(Self {
            selene_rows,
            helios_rows,
            len: Fcmp::<Curves>::proof_size(inputs, layers),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use monero_fcmp_plus_plus::{FcmpPlusPlus, fcmps};
    use monerod_rpc::types::{
        FCMP_PP_SAL_LEN, FCMP_PP_TUPLE_LEN, GetTransactionsResponse, HELIOS_CHUNK_WIDTH,
        SELENE_CHUNK_WIDTH, TxJson,
    };

    fn captured() -> Vec<TxJson> {
        let resp: GetTransactionsResponse = serde_json::from_str(include_str!(
            "../../../fixtures/fcmp/get_transactions_fcmp.json"
        ))
        .unwrap();
        assert!(!resp.txs.is_empty());
        resp.txs.iter().map(|e| e.parse_json().unwrap()).collect()
    }

    /// The split of each input's part of the proof, which monerod-rpc reads
    /// by offset, adds up to monero-oxide's size for the whole proof, and the
    /// tree's widths are the ones its circuit takes.
    #[test]
    fn the_per_input_parts_and_widths_agree_with_monero_oxide() {
        for inputs in 1..=MAX_FCMP_INPUTS {
            for layers in 1..=MAX_FCMP_LAYERS {
                let shape = MembershipShape::of(inputs, u8::try_from(layers).unwrap()).unwrap();
                assert_eq!(
                    inputs * (FCMP_PP_TUPLE_LEN + FCMP_PP_SAL_LEN) + shape.len,
                    FcmpPlusPlus::proof_size(inputs, layers)
                );
            }
        }
        assert_eq!(SELENE_CHUNK_WIDTH, fcmps::LAYER_ONE_LEN as u64);
        assert_eq!(HELIOS_CHUNK_WIDTH, fcmps::LAYER_TWO_LEN as u64);
    }

    #[test]
    fn counts_outside_consensus_have_no_shape() {
        assert_eq!(MembershipShape::of(0, 2), None);
        assert_eq!(MembershipShape::of(2, 0), None);
        assert_eq!(MembershipShape::of(129, 2), None);
        assert_eq!(MembershipShape::of(2, 13), None);
        assert_eq!(MembershipShape::of(usize::MAX, u8::MAX), None);
    }

    /// Each captured proof is one monero-oxide reads whole, and splits where
    /// its shape says the membership proof starts.
    #[test]
    fn each_captured_proof_reads_whole_and_splits_at_its_shape() {
        for tx in captured() {
            let prunable = tx.rctsig_prunable.as_ref().unwrap();
            let proof = crate::hex::decode(prunable.fcmp_pp.as_deref().unwrap()).unwrap();
            let pseudo_outs: Vec<[u8; 32]> = tx
                .pseudo_outs()
                .iter()
                .map(|p| crate::hex::decode(p).unwrap().try_into().unwrap())
                .collect();
            let layers = tx.n_tree_layers().unwrap();
            let mut reader = proof.as_slice();
            FcmpPlusPlus::read(&pseudo_outs, usize::from(layers), &mut reader).unwrap();
            assert!(reader.is_empty(), "nothing left over");

            let parts = prunable.fcmp_pp_parts(tx.vin.len()).unwrap();
            let shape = MembershipShape::of(tx.vin.len(), layers).unwrap();
            assert_eq!(parts.membership_len, shape.len);
        }
    }
}
