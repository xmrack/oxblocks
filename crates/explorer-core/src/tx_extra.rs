//! The `tx_extra` blob.
//!
//! Every other number oxblocks displays was already parsed by monerod before we
//! saw it. `tx_extra` is the exception: monerod hands it over as a raw byte
//! array and we decode it ourselves, which makes this the one place where an
//! attacker-chosen length field meets our code. Everything here is written to
//! be total — no panic, no allocation that is not bounded by the input length,
//! no arithmetic that can wrap.
//!
//! The format is a flat sequence of `tag byte || payload`, where the payload is
//! self-delimiting and only six tags exist. The parse is *best effort by
//! design*: unparseable `tx_extra` is consensus-valid and really does occur on
//! chain, monerod's `parse_tx_extra` keeps every field it decoded before the
//! bad byte, and its callers use those partial results. So [`parse`] returns a
//! [`ParsedTxExtra`] rather than a `Result`; the failure, if any, is a field of
//! the answer instead of a replacement for it.
//!
//! The behaviours below are monerod's, quirks included. Where they look wrong
//! they are still what the network does, and matching them is the whole
//! point:
//!
//! * A length varint cut off by the end of the buffer is **accepted** with its
//!   partially accumulated value, so `02 80` is a valid empty nonce. Only an
//!   empty buffer at the varint's first byte is an error.
//! * A `0x00` continuation byte at a non-zero shift is **rejected** as
//!   non-canonical, which most LEB128 decoders accept.
//! * Padding runs to end-of-buffer and *fails* (rather than stopping) on a
//!   non-zero byte, so at most one padding field exists and it is always last.
//! * The `0x04` varint counts 32-byte keys, not bytes.
//! * Payment IDs are recognised by exact nonce length, not by prefix.
//!
//! Derived from monerod v0.18 `src/cryptonote_basic/tx_extra.h`,
//! `src/cryptonote_basic/cryptonote_format_utils.cpp:564-583` and the
//! serialization archive templates that actually implement the parse, then
//! checked against monerod's own parser by the differential test below.

use std::fmt;

use crate::hash::{HASH_LEN, Hash32};

/// `TX_EXTRA_TAG_PADDING`.
pub const TAG_PADDING: u8 = 0x00;
/// `TX_EXTRA_TAG_PUBKEY`.
pub const TAG_PUBKEY: u8 = 0x01;
/// `TX_EXTRA_NONCE`.
pub const TAG_NONCE: u8 = 0x02;
/// `TX_EXTRA_MERGE_MINING_TAG`.
pub const TAG_MERGE_MINING: u8 = 0x03;
/// `TX_EXTRA_TAG_ADDITIONAL_PUBKEYS`.
pub const TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;
/// `TX_EXTRA_MYSTERIOUS_MINERGATE_TAG`.
///
/// One raw byte, not a varint: the tag is read as a `uint8_t`, so this is `de`
/// on the wire and never `de 01`.
pub const TAG_MINERGATE: u8 = 0xDE;

/// `TX_EXTRA_NONCE_MAX_COUNT` — applies to tag `0x02` only. The `0xDE` field
/// has the same framing and no cap at all.
pub const NONCE_MAX_COUNT: u64 = 255;

/// `TX_EXTRA_PADDING_MAX_COUNT`, counting the tag byte, so at most 254 zero
/// bytes may follow.
pub const PADDING_MAX_COUNT: u16 = 255;

/// `TX_EXTRA_NONCE_PAYMENT_ID` — first byte of a 33-byte nonce.
pub const NONCE_PAYMENT_ID: u8 = 0x00;
/// `TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID` — first byte of a 9-byte nonce.
pub const NONCE_ENCRYPTED_PAYMENT_ID: u8 = 0x01;

/// Length of an encrypted (short) payment id.
pub const PAYMENT_ID8_LEN: usize = 8;

/// Hex characters in a rendered [`PaymentId8`].
pub const PAYMENT_ID8_HEX_LEN: usize = PAYMENT_ID8_LEN * 2;

/// One decoded `tx_extra` field.
///
/// 32-byte keys and roots are carried as [`Hash32`]. They are not hashes, but
/// `Hash32` is this crate's "validated 32 bytes, rendered as 64 lowercase hex"
/// type and that is exactly how the explorer prints them.
#[derive(Clone, PartialEq, Eq)]
pub enum TxExtraField {
    /// `size` **includes** the tag byte, matching `tx_extra_padding::size`, so
    /// the smallest padding field is `Padding { size: 1 }` — a lone `00`.
    Padding {
        size: u16,
    },
    PubKey(Hash32),
    /// 0..=255 arbitrary bytes. Often, but not necessarily, a payment id.
    Nonce(Vec<u8>),
    MergeMining {
        depth: u64,
        merkle_root: Hash32,
    },
    AdditionalPubKeys(Vec<Hash32>),
    /// Same framing as a nonce but with no length cap.
    MinerGate(Vec<u8>),
}

impl TxExtraField {
    /// The wire tag this field was decoded from.
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Padding { .. } => TAG_PADDING,
            Self::PubKey(_) => TAG_PUBKEY,
            Self::Nonce(_) => TAG_NONCE,
            Self::MergeMining { .. } => TAG_MERGE_MINING,
            Self::AdditionalPubKeys(_) => TAG_ADDITIONAL_PUBKEYS,
            Self::MinerGate(_) => TAG_MINERGATE,
        }
    }
}

/// Byte strings render as hex, because a nonce printed as a list of decimal
/// integers cannot be compared against anything else an operator has to hand.
impl fmt::Debug for TxExtraField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Padding { size } => write!(f, "Padding {{ size: {size} }}"),
            Self::PubKey(key) => write!(f, "PubKey({key})"),
            Self::Nonce(data) => write!(f, "Nonce({})", crate::hex::encode(data)),
            Self::MergeMining { depth, merkle_root } => {
                write!(
                    f,
                    "MergeMining {{ depth: {depth}, merkle_root: {merkle_root} }}"
                )
            }
            Self::AdditionalPubKeys(keys) => {
                write!(f, "AdditionalPubKeys([")?;
                for (i, key) in keys.iter().enumerate() {
                    if i != 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{key}")?;
                }
                write!(f, "])")
            }
            Self::MinerGate(data) => write!(f, "MinerGate({})", crate::hex::encode(data)),
        }
    }
}

/// Why the parse stopped, and where.
///
/// This is diagnostic, not fatal: a `tx_extra` that fails to parse is still a
/// valid transaction on chain, and the fields decoded before the failure are
/// still good. It is never returned as an `Err` for that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("tx_extra: {kind} at byte {offset}")]
pub struct TxExtraError {
    /// The byte monerod's cursor had reached when the field failed.
    ///
    /// Diagnostic only. It is **not** where the undecodable tail begins: the
    /// tail starts at [`ParsedTxExtra::consumed`], and the two differ for every
    /// kind but [`TxExtraErrorKind::UnknownTag`], because the failing field has
    /// already moved the cursor past bytes no field ended up owning. Rendering
    /// `extra[offset..]` prints a short tail — `parse(&hex!("000000ff"))` has
    /// `consumed() == 0` and `offset == 3`, so it would show `ff` when monerod
    /// failed on the whole four-byte blob. Use [`ParsedTxExtra::consumed`] or
    /// [`ParsedTxExtra::undecoded_tail`] for that.
    pub offset: usize,
    pub kind: TxExtraErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TxExtraErrorKind {
    #[error("unknown field tag {0:#04x}")]
    UnknownTag(u8),
    #[error("non-zero byte inside padding")]
    PaddingNonZero,
    #[error("padding longer than {PADDING_MAX_COUNT} bytes")]
    PaddingTooLong,
    #[error("public key needs 32 bytes")]
    TruncatedPubKey,
    /// Overflowing, non-canonical, or entirely absent length/count varint.
    #[error("malformed length varint")]
    BadVarint,
    /// A declared length or count that runs past the end of the blob. This is
    /// the guard that keeps a 2^64-1 length field from ever reaching a slice.
    #[error("declared length runs past the end of the blob")]
    LengthBeyondEnd,
    #[error("nonce longer than {NONCE_MAX_COUNT} bytes")]
    NonceTooLong,
    /// The merge-mining blob must be consumed exactly: `varint(depth) || 32`
    /// and nothing else.
    #[error("merge-mining blob is not exactly a depth varint plus 32 bytes")]
    MergeMiningBlob,
    #[error("additional public keys run past the end of the blob")]
    TruncatedAdditionalKeys,
}

/// An 8-byte encrypted payment id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PaymentId8([u8; PAYMENT_ID8_LEN]);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaymentId8ParseError {
    #[error("expected {PAYMENT_ID8_HEX_LEN} hex characters, got {0}")]
    WrongLength(usize),
    #[error("{0:?} is not a hex character")]
    NotHex(char),
}

impl PaymentId8 {
    pub const fn from_bytes(bytes: [u8; PAYMENT_ID8_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; PAYMENT_ID8_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        crate::hex::encode(self.0)
    }
}

impl std::str::FromStr for PaymentId8 {
    type Err = PaymentId8ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PAYMENT_ID8_HEX_LEN {
            return Err(PaymentId8ParseError::WrongLength(s.len()));
        }
        if let Some(c) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(PaymentId8ParseError::NotHex(c));
        }
        let mut out = [0u8; PAYMENT_ID8_LEN];
        crate::hex::decode_to_slice(s, &mut out)
            // Unreachable: length and alphabet are checked above.
            .map_err(|_| PaymentId8ParseError::WrongLength(s.len()))?;
        Ok(Self(out))
    }
}

impl fmt::Display for PaymentId8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PaymentId8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PaymentId8({self})")
    }
}

impl serde::Serialize for PaymentId8 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PaymentId8 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = <std::borrow::Cow<'_, str> as serde::Deserialize>::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// A payment id carried in a nonce field.
///
/// The two forms are distinguished by the nonce's exact length, so they are
/// mutually exclusive — the explorer emits them as two separate JSON keys
/// (`payment_id` and `payment_id8`) of which at most one is ever populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentId {
    /// 32-byte cleartext payment id (nonce `00 || 32 bytes`).
    Long(Hash32),
    /// 8-byte encrypted payment id (nonce `01 || 8 bytes`).
    Encrypted(PaymentId8),
}

impl PaymentId {
    pub fn to_hex(self) -> String {
        match self {
            Self::Long(id) => id.to_hex(),
            Self::Encrypted(id) => id.to_hex(),
        }
    }

    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypted(_))
    }
}

impl fmt::Display for PaymentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Long(id) => write!(f, "{id}"),
            Self::Encrypted(id) => write!(f, "{id}"),
        }
    }
}

/// The outcome of decoding one `tx_extra` blob.
///
/// Allocation is bounded by the input: every field costs at least two input
/// bytes, and the bytes a field owns are a subset of the input. monerod has no
/// field-count cap and neither do we, so a 60 KB blob of `de 00` really does
/// decode to 30,000 empty MinerGate fields — that is O(n) and deliberate, since
/// capping it would silently disagree with monerod about what a transaction
/// contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTxExtra {
    fields: Vec<TxExtraField>,
    input_len: usize,
    consumed: usize,
    error: Option<TxExtraError>,
}

impl ParsedTxExtra {
    /// Every field decoded, in wire order. Tags may repeat and may appear in
    /// any order; `01` is *not* reliably first.
    pub fn fields(&self) -> &[TxExtraField] {
        &self.fields
    }

    /// True when the whole blob decoded. `parse_tx_extra` returning `true`.
    pub const fn is_complete(&self) -> bool {
        self.error.is_none()
    }

    /// Why decoding stopped, when it did.
    pub const fn error(&self) -> Option<TxExtraError> {
        self.error
    }

    /// Bytes covered by [`Self::fields`]; the rest of the blob is undecodable.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn input_len(&self) -> usize {
        self.input_len
    }

    /// Number of trailing bytes no field claimed.
    pub const fn undecoded_len(&self) -> usize {
        self.input_len.saturating_sub(self.consumed)
    }

    /// The undecodable tail, given the blob this was parsed from.
    ///
    /// Takes the bytes back rather than owning a copy of them. The caller is
    /// trusted to pass the same slice it parsed; the only thing checked here is
    /// the **length**, which guarantees the returned tail is
    /// [`Self::undecoded_len`] bytes long rather than silently longer or
    /// shorter. It cannot tell one blob from another blob of the same length,
    /// so passing a different one of equal length returns that blob's tail —
    /// wrong bytes, right length.
    pub fn undecoded_tail<'a>(&self, extra: &'a [u8]) -> &'a [u8] {
        if extra.len() != self.input_len {
            return &[];
        }
        extra.get(self.consumed..).unwrap_or(&[])
    }

    /// Every `0x01` field, in order.
    pub fn pub_keys(&self) -> impl Iterator<Item = Hash32> + '_ {
        self.fields.iter().filter_map(|f| match f {
            TxExtraField::PubKey(key) => Some(*key),
            _ => None,
        })
    }

    /// The transaction public key as **monerod** picks it: the first `0x01`
    /// field, partial results included (`get_tx_pub_key_from_extra`).
    ///
    /// Callers that want monerod's null-key sentinel should map `None` to
    /// [`Hash32::ZERO`]; it is left explicit here because "absent" and "all
    /// zeroes" are different facts.
    pub fn tx_pub_key(&self) -> Option<Hash32> {
        self.pub_keys().next()
    }

    /// The transaction public key as the pages report it: the second `0x01`
    /// field when two or more exist, otherwise the first.
    ///
    /// The rule dates to a wallet that wrote two pubkeys. It is the value
    /// every explorer of this API shows, so it is the value shown here.
    pub fn tx_pub_key_explorer_compat(&self) -> Option<Hash32> {
        let mut keys = self.pub_keys();
        let first = keys.next()?;
        Some(keys.next().unwrap_or(first))
    }

    /// The first `0x04` field's keys, matching monerod's
    /// `get_additional_tx_pub_keys_from_extra`, which ignores any later ones.
    pub fn additional_pub_keys(&self) -> &[Hash32] {
        self.fields
            .iter()
            .find_map(|f| match f {
                TxExtraField::AdditionalPubKeys(keys) => Some(keys.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Every `0x02` payload, in order.
    pub fn nonces(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.fields.iter().filter_map(|f| match f {
            TxExtraField::Nonce(data) => Some(data.as_slice()),
            _ => None,
        })
    }

    pub fn first_nonce(&self) -> Option<&[u8]> {
        self.nonces().next()
    }

    /// The payment id as the pages and the JSON API report it.
    ///
    /// Two deliberate narrownesses, both of which change the answer:
    /// * a blob that failed to parse *anywhere* yields no payment id at all,
    ///   even though the nonce may have decoded cleanly before the bad byte —
    ///   unlike the pubkey getters, this one does not use partial results;
    /// * only the **first** nonce is examined, so a second nonce holding a
    ///   payment id is never seen.
    pub fn payment_id(&self) -> Option<PaymentId> {
        if !self.is_complete() {
            return None;
        }
        payment_id_from_nonce(self.first_nonce()?)
    }

    /// Every `0x03` field, in order.
    pub fn merge_mining_tags(&self) -> impl Iterator<Item = (u64, Hash32)> + '_ {
        self.fields.iter().filter_map(|f| match f {
            TxExtraField::MergeMining { depth, merkle_root } => Some((*depth, *merkle_root)),
            _ => None,
        })
    }

    pub fn merge_mining_tag(&self) -> Option<(u64, Hash32)> {
        self.merge_mining_tags().next()
    }

    /// The padding field's size, tag byte included. At most one can exist.
    pub fn padding(&self) -> Option<u16> {
        self.fields.iter().find_map(|f| match f {
            TxExtraField::Padding { size } => Some(*size),
            _ => None,
        })
    }

    /// Every `0xDE` payload, in order.
    pub fn minergate_fields(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.fields.iter().filter_map(|f| match f {
            TxExtraField::MinerGate(data) => Some(data.as_slice()),
            _ => None,
        })
    }
}

/// monerod's payment-id recognition, which is an exact-length test on the whole
/// nonce plus a first-byte check — not a prefix match
/// (`get_payment_id_from_tx_extra_nonce` /
/// `get_encrypted_payment_id_from_tx_extra_nonce`).
///
/// The encrypted form is tested first only because the explorer tests it first;
/// the two lengths are disjoint, so the order cannot change the answer.
///
/// A consequence worth knowing before it surprises someone: nothing here says
/// "this nonce is a payment id" — it says "this nonce is shaped like one". A
/// coinbase miner nonce that happened to be 9 bytes long and to start with
/// `0x01` would be reported as an encrypted payment id. That is monerod's
/// behaviour and the explorer's, so it is ours. The mechanism is real but the
/// collision has not been seen: across 3,213 sampled mainnet blobs the coinbase
/// nonce lengths were 4, 8, 13, 17, 27, 29, 32, 64 and 98, never 9, and every
/// 9-byte nonce found belonged to an ordinary transaction and really was an
/// encrypted payment id.
pub fn payment_id_from_nonce(nonce: &[u8]) -> Option<PaymentId> {
    if nonce.len() == PAYMENT_ID8_LEN + 1
        && nonce.first() == Some(&NONCE_ENCRYPTED_PAYMENT_ID)
        && let Some(bytes) = nonce.get(1..)
        && let Ok(id) = <[u8; PAYMENT_ID8_LEN]>::try_from(bytes)
    {
        return Some(PaymentId::Encrypted(PaymentId8::from_bytes(id)));
    }
    if nonce.len() == HASH_LEN + 1
        && nonce.first() == Some(&NONCE_PAYMENT_ID)
        && let Some(bytes) = nonce.get(1..)
        && let Ok(id) = <[u8; HASH_LEN]>::try_from(bytes)
    {
        return Some(PaymentId::Long(Hash32::from_bytes(id)));
    }
    None
}

/// Decode a `tx_extra` blob.
///
/// Total: every input yields an answer. An empty blob is valid and decodes to
/// zero fields.
pub fn parse(extra: &[u8]) -> ParsedTxExtra {
    let mut out = ParsedTxExtra {
        // Two bytes is the smallest field, but the overwhelmingly common blob
        // holds one to four fields; reserving n/2 would be a pointless
        // allocation for the 99% case and an attacker-scaled one for the rest.
        fields: Vec::new(),
        input_len: extra.len(),
        consumed: 0,
        error: None,
    };

    let mut pos = 0usize;
    while pos < extra.len() {
        match parse_field(extra, pos) {
            Ok((field, next)) => {
                // Every arm consumes at least its tag byte, so this holds; it
                // is asserted because a zero-consuming arm would be an infinite
                // loop rather than a wrong answer, and the `break` below keeps
                // that from being possible even if the invariant is broken.
                debug_assert!(next > pos, "a field arm consumed no input");
                if next <= pos {
                    out.error = Some(TxExtraError {
                        offset: pos,
                        kind: TxExtraErrorKind::BadVarint,
                    });
                    break;
                }
                pos = next;
                out.consumed = pos;
                out.fields.push(field);
            }
            Err(e) => {
                out.error = Some(e);
                break;
            }
        }
    }

    out
}

/// Decode the field whose tag byte is at `start`, returning it and the position
/// just past it.
fn parse_field(extra: &[u8], start: usize) -> Result<(TxExtraField, usize), TxExtraError> {
    let n = extra.len();
    let err = |offset: usize, kind: TxExtraErrorKind| TxExtraError { offset, kind };

    let Some(&tag) = extra.get(start) else {
        // Unreachable: the caller only enters with start < n.
        return Err(err(start, TxExtraErrorKind::BadVarint));
    };
    let mut pos = start.saturating_add(1);

    match tag {
        TAG_PADDING => {
            // `for (size = 1; size <= 255; ++size)`: size counts the tag byte,
            // EOF ends the field successfully, a non-zero byte fails it, and
            // 255 zero bytes push size to 256 and fail it. Padding therefore
            // always runs to the end of the blob.
            let mut size: u16 = 1;
            while size <= PADDING_MAX_COUNT {
                let Some(&byte) = extra.get(pos) else { break };
                if byte != 0 {
                    return Err(err(pos, TxExtraErrorKind::PaddingNonZero));
                }
                pos = pos.saturating_add(1);
                size = size.saturating_add(1);
            }
            if size > PADDING_MAX_COUNT {
                return Err(err(pos, TxExtraErrorKind::PaddingTooLong));
            }
            Ok((TxExtraField::Padding { size }, pos))
        }

        TAG_PUBKEY => {
            // No length prefix: exactly 32 raw bytes.
            let (key, next) =
                take_hash(extra, pos).ok_or(err(pos, TxExtraErrorKind::TruncatedPubKey))?;
            Ok((TxExtraField::PubKey(key), next))
        }

        TAG_NONCE | TAG_MINERGATE => {
            let (len, after, status) = read_varint(extra, pos);
            let good = status.is_good();
            pos = after;
            // The archive reports zero remaining bytes once it has failed, so a
            // bad varint can never satisfy a length check. Keeping that shape
            // rather than returning early keeps the failure offset identical to
            // monerod's cursor position.
            let avail = if good { remaining(n, pos) } else { 0 };
            if avail < len {
                return Err(err(pos, TxExtraErrorKind::LengthBeyondEnd));
            }
            let Ok(len_usize) = usize::try_from(len) else {
                // Unreachable on any 64-bit target: len <= avail <= n.
                return Err(err(pos, TxExtraErrorKind::LengthBeyondEnd));
            };
            let end = pos.saturating_add(len_usize);
            let data = extra
                .get(pos..end)
                .ok_or(err(pos, TxExtraErrorKind::LengthBeyondEnd))?;
            pos = end;
            if !good {
                return Err(err(pos, TxExtraErrorKind::BadVarint));
            }
            if tag == TAG_NONCE {
                // Checked after the payload is read, as monerod does, so the
                // reported offset matches.
                if len > NONCE_MAX_COUNT {
                    return Err(err(pos, TxExtraErrorKind::NonceTooLong));
                }
                Ok((TxExtraField::Nonce(data.to_vec()), pos))
            } else {
                Ok((TxExtraField::MinerGate(data.to_vec()), pos))
            }
        }

        TAG_MERGE_MINING => {
            let (blob_len, after, status) = read_varint(extra, pos);
            let good = status.is_good();
            pos = after;
            let avail = if good { remaining(n, pos) } else { 0 };
            if avail < blob_len {
                return Err(err(pos, TxExtraErrorKind::LengthBeyondEnd));
            }
            let Ok(blob_len) = usize::try_from(blob_len) else {
                return Err(err(pos, TxExtraErrorKind::LengthBeyondEnd));
            };
            let end = pos.saturating_add(blob_len);
            let inner = extra
                .get(pos..end)
                .ok_or(err(pos, TxExtraErrorKind::LengthBeyondEnd))?;
            pos = end;
            if !good {
                return Err(err(pos, TxExtraErrorKind::BadVarint));
            }

            // The blob is handed to a second, independent archive that must
            // consume it *exactly*: `varint depth || 32 byte root` and nothing
            // else. Parsing depth and root off the outer cursor instead, or
            // tolerating a trailing byte, desynchronises us from monerod — and
            // computing the depth varint's length instead of reading it is how
            // an existing Rust implementation mis-parses the commonest form of
            // this field, `03 21 00 <32>`.
            let (depth, inner_pos, inner_status) = read_varint(inner, 0);
            if !inner_status.is_good() {
                return Err(err(pos, TxExtraErrorKind::MergeMiningBlob));
            }
            let (merkle_root, inner_pos) =
                take_hash(inner, inner_pos).ok_or(err(pos, TxExtraErrorKind::MergeMiningBlob))?;
            if inner_pos != inner.len() {
                return Err(err(pos, TxExtraErrorKind::MergeMiningBlob));
            }
            Ok((TxExtraField::MergeMining { depth, merkle_root }, pos))
        }

        TAG_ADDITIONAL_PUBKEYS => {
            let (count, after, status) = read_varint(extra, pos);
            pos = after;
            if !status.is_good() {
                return Err(err(pos, TxExtraErrorKind::BadVarint));
            }
            // monerod's only pre-allocation guard compares remaining BYTES
            // against a count of ELEMENTS, which is weak but is what bounds the
            // loop below. Reserving `count` keys before this check would turn a
            // ten-byte blob into a 16 EiB allocation request.
            let avail = remaining(n, pos);
            if avail < count {
                return Err(err(pos, TxExtraErrorKind::LengthBeyondEnd));
            }
            let capacity = usize::try_from(count.min(avail / HASH_LEN as u64)).unwrap_or(0);
            let mut keys = Vec::with_capacity(capacity);
            // `count <= avail <= n`, so this iterates at most `n` times and
            // each pass either consumes 32 bytes or fails.
            for _ in 0..count {
                let (key, next) = take_hash(extra, pos)
                    .ok_or(err(pos, TxExtraErrorKind::TruncatedAdditionalKeys))?;
                keys.push(key);
                pos = next;
            }
            Ok((TxExtraField::AdditionalPubKeys(keys), pos))
        }

        unknown => Err(err(start, TxExtraErrorKind::UnknownTag(unknown))),
    }
}

/// Bytes left after `pos`, as the `u64` the length fields are compared in.
///
/// The comparison has to happen in `u64` *before* any cast: a length field can
/// legitimately encode 2^64-1, and casting that to `usize` first is how a
/// 32-bit build would truncate it into something that looks in range.
const fn remaining(len: usize, pos: usize) -> u64 {
    len.saturating_sub(pos) as u64
}

/// Copy the 32 bytes at `pos`, returning them and the position just past them.
fn take_hash(buf: &[u8], pos: usize) -> Option<(Hash32, usize)> {
    let end = pos.checked_add(HASH_LEN)?;
    let bytes = <[u8; HASH_LEN]>::try_from(buf.get(pos..end)?).ok()?;
    Some((Hash32::from_bytes(bytes), end))
}

/// What `tools::read_varint` told the archive.
///
/// The distinction that matters is `TruncatedAtEof`: monerod's reader returns
/// the number of bytes it managed to read, the archive only checks `1 <= read`,
/// and so a varint cut short by the end of the buffer is *good* with whatever
/// value it accumulated. `Overflow` and `NonCanonical` return negative counts
/// and are never good — which is why callers must ask [`Self::is_good`] rather
/// than look at a byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarintStatus {
    Ok { bytes_read: u32 },
    TruncatedAtEof { bytes_read: u32 },
    Overflow,
    NonCanonical,
}

impl VarintStatus {
    const fn is_good(self) -> bool {
        match self {
            Self::Ok { .. } => true,
            Self::TruncatedAtEof { bytes_read } => bytes_read >= 1,
            Self::Overflow | Self::NonCanonical => false,
        }
    }
}

/// monerod's `read_varint<uint64_t>`: little-endian base-128, 7 bits a byte,
/// high bit continues.
///
/// Returns the value accumulated so far even when the status is bad, because
/// the archive advances its cursor regardless and the caller needs the same
/// position monerod would have.
fn read_varint(buf: &[u8], mut pos: usize) -> (u64, usize, VarintStatus) {
    let mut value: u64 = 0;
    let mut bytes_read: u32 = 0;

    // shift takes exactly the ten values 0, 7, … 63. A 64-bit varint cannot be
    // longer than that: at shift 63 only `0x01` is accepted (`0x00` is
    // non-canonical, anything else overflows) and it has no continuation bit.
    // Bounding the loop this way also makes a shift of 64 or more — which would
    // panic in a debug build — unrepresentable rather than merely unreachable.
    for shift in (0u32..64).step_by(7) {
        let Some(&byte) = buf.get(pos) else {
            return (value, pos, VarintStatus::TruncatedAtEof { bytes_read });
        };
        pos = pos.saturating_add(1);
        bytes_read = bytes_read.saturating_add(1);

        if shift + 7 >= 64 && u64::from(byte) >= (1u64 << (64 - shift)) {
            return (value, pos, VarintStatus::Overflow);
        }
        if byte == 0 && shift != 0 {
            return (value, pos, VarintStatus::NonCanonical);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return (value, pos, VarintStatus::Ok { bytes_read });
        }
    }

    // Unreachable, per the loop-bound argument above. Reported as overflow
    // rather than asserted, so that being wrong costs a rejected field.
    (value, pos, VarintStatus::Overflow)
}

#[cfg(test)]
mod tests {
    // Panicking is the correct failure mode in a test; the workspace lints
    // exist to keep panics out of request handling, not out of assertions.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]

    use std::path::{Path, PathBuf};

    use super::*;

    /// Every vector here was run through `tools/txextra-oracle/batch` — a verbatim
    /// copy of monerod's `parse_tx_extra` compiled against Monero's own headers —
    /// and the expected strings are that program's output, not a guess at it.
    ///
    /// They spell out every decoded byte, which is why they are long: an
    /// expectation of `tags=K,M,` holds just as well for a parser that returns
    /// the wrong key and a truncated depth. `tools/txextra-oracle/regen_corpus.py`
    /// re-derives them from the oracle rather than by hand.
    const SYNTHETIC_CORPUS: &[(&str, &str)] = &[
        // a lone padding tag
        ("00", "OK n=1 consumed=1/1 tags=P1,"),
        // a non-zero byte inside padding
        ("000000ff", "FAIL n=0 consumed=0/4 tags="),
        // a pubkey one byte short
        (
            "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "FAIL n=0 consumed=0/32 tags=",
        ),
        // a single pubkey
        (
            "011111111111111111111111111111111111111111111111111111111111111111",
            "OK n=1 consumed=33/33 tags=K:111111111111111111111111111111111111111111111111111111111111\
          1111,",
        ),
        // duplicate pubkeys
        (
            "011111111111111111111111111111111111111111111111111111111111111111012222222222222222222222222222\
         222222222222222222222222222222222222",
            "OK n=2 consumed=66/66 tags=K:111111111111111111111111111111111111111111111111111111111111\
          1111,K:2222222222222222222222222222222222222222222222222222222222222222,",
        ),
        // an empty nonce
        ("0200", "OK n=1 consumed=2/2 tags=N0:,"),
        // a nonce length varint truncated at eof
        ("0280", "OK n=1 consumed=2/2 tags=N0:,"),
        // nonce length 127 with nothing left
        ("02ff", "FAIL n=0 consumed=0/2 tags="),
        // a non-canonical nonce length varint
        ("02800001", "FAIL n=0 consumed=0/4 tags="),
        // a nonce length varint that is not there at all
        ("02", "FAIL n=0 consumed=0/1 tags="),
        // a declared nonce length past the end
        ("021000", "FAIL n=0 consumed=0/3 tags="),
        // nonce length 2^64-1
        (
            "02ffffffffffffffffff01abababab",
            "FAIL n=0 consumed=0/15 tags=",
        ),
        // a nonce length varint that overflows u64
        (
            "02ffffffffffffffffff02abababab",
            "FAIL n=0 consumed=0/15 tags=",
        ),
        // a varint longer than ten bytes
        ("028080808080808080808001", "FAIL n=0 consumed=0/12 tags="),
        // a 9-byte nonce starting 0x01
        (
            "020901cdcdcdcdcdcdcdcd",
            "OK n=1 consumed=11/11 tags=N9:01cdcdcdcdcdcdcdcd,",
        ),
        // a 33-byte nonce starting 0x00
        (
            "022100cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "OK n=1 consumed=35/35 tags=N33:00cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
          cdcdcdcd,",
        ),
        // a 9-byte nonce starting 0x00
        (
            "020900cdcdcdcdcdcdcdcd",
            "OK n=1 consumed=11/11 tags=N9:00cdcdcdcdcdcdcdcd,",
        ),
        // merge mining at depth 0
        (
            "0321003333333333333333333333333333333333333333333333333333333333333333",
            "OK n=1 consumed=35/35 tags=M:0:3333333333333333333333333333333333333333333333333333333333\
          333333,",
        ),
        // merge mining at depth 128
        (
            "032280013333333333333333333333333333333333333333333333333333333333333333",
            "OK n=1 consumed=36/36 tags=M:128:33333333333333333333333333333333333333333333333333333333\
          33333333,",
        ),
        // merge mining at depth 2^32 - 1, 2^32 and 2^64 - 1: the widths that
        // tell a uint64_t depth from a truncated one
        (
            "0325ffffffff0f3333333333333333333333333333333333333333333333333333333333333333",
            "OK n=1 consumed=39/39 tags=M:4294967295:3333333333333333333333333333333333333333333333333\
          333333333333333,",
        ),
        (
            "032580808080103333333333333333333333333333333333333333333333333333333333333333",
            "OK n=1 consumed=39/39 tags=M:4294967296:3333333333333333333333333333333333333333333333333\
          333333333333333,",
        ),
        (
            "032affffffffffffffffff013333333333333333333333333333333333333333333333333333333333333333",
            "OK n=1 consumed=44/44 tags=M:18446744073709551615:333333333333333333333333333333333333333\
          3333333333333333333333333,",
        ),
        // a merge-mining blob one byte short
        (
            "0320003333333333333333333333333333333333333333333333333333333333333333",
            "FAIL n=0 consumed=0/35 tags=",
        ),
        // a merge-mining blob with a trailing byte
        (
            "0322003333333333333333333333333333333333333333333333333333333333333333ff",
            "FAIL n=0 consumed=0/36 tags=",
        ),
        // a merge-mining blob that is one continuation byte
        ("030180", "FAIL n=0 consumed=0/3 tags="),
        // a non-canonical merge-mining depth varint
        (
            "032280003333333333333333333333333333333333333333333333333333333333333333",
            "FAIL n=0 consumed=0/36 tags=",
        ),
        // a merge-mining depth varint that overflows
        (
            "032affffffffffffffffff023333333333333333333333333333333333333333333333333333333333333333",
            "FAIL n=0 consumed=0/44 tags=",
        ),
        // a non-canonical merge-mining blob length
        (
            "0380003333333333333333333333333333333333333333333333333333333333333333",
            "FAIL n=0 consumed=0/35 tags=",
        ),
        // a merge-mining blob length that overflows
        (
            "03ffffffffffffffffff023333333333333333333333333333333333333333333333333333333333333333",
            "FAIL n=0 consumed=0/43 tags=",
        ),
        // zero additional pubkeys
        ("0400", "OK n=1 consumed=2/2 tags=A0:,"),
        // an additional-pubkey count truncated at eof
        ("0480", "OK n=1 consumed=2/2 tags=A0:,"),
        // one additional pubkey
        (
            "04014444444444444444444444444444444444444444444444444444444444444444",
            "OK n=1 consumed=34/34 tags=A1:44444444444444444444444444444444444444444444444444444444444\
          44444,",
        ),
        // two additional pubkeys
        (
            "040244444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\
         444444444444444444444444444444444444",
            "OK n=1 consumed=66/66 tags=A2:44444444444444444444444444444444444444444444444444444444444\
          444444444444444444444444444444444444444444444444444444444444444444444,",
        ),
        // an additional-pubkey count larger than the keys present
        (
            "040344444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\
         444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/66 tags=",
        ),
        // an additional-pubkey count of 255 with 32 bytes left
        (
            "04ff014444444444444444444444444444444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/35 tags=",
        ),
        // an additional-pubkey count of 33 with 32 bytes left
        (
            "04214444444444444444444444444444444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/34 tags=",
        ),
        // a non-canonical additional-pubkey count
        (
            "0480004444444444444444444444444444444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/35 tags=",
        ),
        // an additional-pubkey count that overflows u64
        (
            "04ffffffffffffffffff024444444444444444444444444444444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/43 tags=",
        ),
        // an additional-pubkey count of 2^64-1
        (
            "04ffffffffffffffffff014444444444444444444444444444444444444444444444444444444444444444",
            "FAIL n=0 consumed=0/43 tags=",
        ),
        // an empty minergate field
        ("de00", "OK n=1 consumed=2/2 tags=G0:,"),
        // a 4-byte minergate field
        ("de04deadbeef", "OK n=1 consumed=6/6 tags=G4:deadbeef,"),
        // a non-canonical minergate length varint
        ("de800001", "FAIL n=0 consumed=0/4 tags="),
        // an unknown tag
        ("05", "FAIL n=0 consumed=0/1 tags="),
        // an unknown tag after a good pubkey
        (
            "01111111111111111111111111111111111111111111111111111111111111111105ff",
            "FAIL n=1 consumed=33/35 tags=K:1111111111111111111111111111111111111111111111111111111111\
          111111,",
        ),
        // a field after padding
        ("0000000201aa", "FAIL n=0 consumed=0/6 tags="),
        // a nonce before a pubkey
        (
            "022100cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd01111111111111111111111111\
         1111111111111111111111111111111111111111",
            "OK n=2 consumed=68/68 tags=N33:00cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
          cdcdcdcd,K:1111111111111111111111111111111111111111111111111111111111111111,",
        ),
        // pubkey, nonce, merge mining, padding
        (
            "011111111111111111111111111111111111111111111111111111111111111111020901cdcdcdcdcdcdcdcd03210033\
         3333333333333333333333333333333333333333333333333333333333333300000000000000000000",
            "OK n=4 consumed=89/89 tags=K:111111111111111111111111111111111111111111111111111111111111\
          1111,N9:01cdcdcdcdcdcdcdcd,M:0:3333333333333333333333333333333333333333333333333333333333\
          333333,P10,",
        ),
        // three repeated minergate fields
        ("de00de00de00", "OK n=3 consumed=6/6 tags=G0:,G0:,G0:,"),
        // padding in the middle
        (
            "011111111111111111111111111111111111111111111111111111111111111111000000000122222222222222222222\
         22222222222222222222222222222222222222222222",
            "FAIL n=1 consumed=33/70 tags=K:1111111111111111111111111111111111111111111111111111111111\
          111111,",
        ),
    ];

    /// Real `tx_extra` blobs pulled from the local nodes, with the same oracle's
    /// verdict. These are the shapes the chain actually contains.
    const REAL_CORPUS: &[(&str, &str)] = &[
        // mainnet tx 32ee937d7824d7fd73956cd32906db2b42aec7c8df915ec4bc93abf71d5fbca2
        (
            "01455fe610dfc1b1efec57b39885c28ac08defac0291ae19349a354d159473e00a02090155e10418dec2fd58",
            "OK n=2 consumed=44/44 tags=K:455fe610dfc1b1efec57b39885c28ac08defac0291ae19349a354d159473\
          e00a,N9:0155e10418dec2fd58,",
        ),
        // mainnet tx e8256130dacda44577152cea7ba5c625dc0fe0c0fbf3f6230f0197c31d5d3d2a
        (
            "0221002715536cb0e7c24faeb02b6659dbdae5d701da922cc1034846695b72157a4b650156268a40135e84463e970896\
         8924dc93b9aaa2954b462f949f69c7363c2f43f9",
            "OK n=2 consumed=68/68 tags=N33:002715536cb0e7c24faeb02b6659dbdae5d701da922cc1034846695b72\
          157a4b65,K:56268a40135e84463e9708968924dc93b9aaa2954b462f949f69c7363c2f43f9,",
        ),
        // mainnet tx f0d450ad914620c115c7c4d11bcee5da862314e4647300b67796f7326459ce53
        (
            "010397a0d0b5b7a4f247007475dc6e3d02fba96de663a461f174904b84ec08a9e2de206de0332d02832042ee8b7d7839\
         bfc10d3b4e38307ea1cc14825b1fcac2df1021",
            "OK n=2 consumed=67/67 tags=K:0397a0d0b5b7a4f247007475dc6e3d02fba96de663a461f174904b84ec08\
          a9e2,G32:6de0332d02832042ee8b7d7839bfc10d3b4e38307ea1cc14825b1fcac2df1021,",
        ),
        // mainnet tx d257fc1b3e291b7812ac4af0f34ad4a96f822f4ef09a2f5861fd6a0e56625778
        (
            "01776265b0e273694de887932cc21bc18942e59a3c2ca6f78b3a8fc5986b7fe47f040453da502b78b9e2a1ddc58541bd\
         b16c90a5b204c02bf2998db5c1dbc7d25c2d5a7680ff5948e5082f3f0ed518dcc903064c91678b76c4c5436ea91a9a0a\
         e499293fca97c5cae1b2becb57094cb0c2fe4bfca2c328a566c129bc8438eabf696788fb2d2a73b1addb2111245b7ed1\
         ab5983af1ea7df377877ad2de3f5e0287ae7b5",
            "OK n=2 consumed=163/163 tags=K:776265b0e273694de887932cc21bc18942e59a3c2ca6f78b3a8fc5986b\
          7fe47f,A4:53da502b78b9e2a1ddc58541bdb16c90a5b204c02bf2998db5c1dbc7d25c2d5a7680ff5948e5082\
          f3f0ed518dcc903064c91678b76c4c5436ea91a9a0ae499293fca97c5cae1b2becb57094cb0c2fe4bfca2c328\
          a566c129bc8438eabf696788fb2d2a73b1addb2111245b7ed1ab5983af1ea7df377877ad2de3f5e0287ae7b5,",
        ),
        // mainnet tx d387fd4957f4666427d8bf3e5fad4468cc91e457c431423f0138c2c1a6207856
        (
            "01e16c24c31ca32e6a5b721b2cba9f9cf2cc94cc3d3bca6dd5d167d5662571f8f30410814dc53a758ff29f43504f76ea\
         d234da2243cd0fae423cef2af6e40d0e6303ab3e92438d0e226b818379cc60be2a41c396696d0f3fb2901af18631b592\
         aa6f9c8f4d76cbf158f463147139694a186eb45c2f08dc5e866177518fad872ee963114cd94a5f4b8566b8b9a31b06f7\
         3742c8802cd9784f8632dea22005ace31943b50b420ca70e23997d9ccb0567d3319f03a211171d1f6d1a8ff246eefb51\
         e4bce0de6f841a559c30f392b7f045d1b4c37c199b09f8e93b5f55ee2e800b0d5c91a14eef3e7440e0e0aac0f55265a5\
         4d85692a7edf24732c16878b72e8439f3c91c99e8f531770a2f1e500246f625d7a4e1c239e35e9b625190323b5234398\
         621c27c4a54648d0b603fd99e271e717261c2df3242d53e42ed32f2974c0b34dd9a8afe3cb8775c6168185dddf08284e\
         374d0795f28c910546b6d495a5a0ad109770156d364932cb26e072c6a4ae27927a6ce09dbfdfdb466da2ccf01963b564\
         63e5a0ebfd8f3fa8f961021642c01d591977ee33bc4e7d664bf3c86d0d926997f3f61245d97258b49d7e3ca821d26683\
         c9ba0c08ad924c2ba64d724ee3b617de5966d7b9b6898baebbdd60bbde942b3d8568bcdde538ba6633a2fb7daf5aee82\
         75e8ba7a47ef2c47be75b2a6dd424a8361266ebb730f46206c1c89c62248dfe5dabb657de3c155c74ce9e432901ee9e5\
         ec72915453a035672ecfb49895dbf9877dbcc1",
            "OK n=2 consumed=547/547 tags=K:e16c24c31ca32e6a5b721b2cba9f9cf2cc94cc3d3bca6dd5d167d56625\
          71f8f3,A16:814dc53a758ff29f43504f76ead234da2243cd0fae423cef2af6e40d0e6303ab3e92438d0e226b\
          818379cc60be2a41c396696d0f3fb2901af18631b592aa6f9c8f4d76cbf158f463147139694a186eb45c2f08d\
          c5e866177518fad872ee963114cd94a5f4b8566b8b9a31b06f73742c8802cd9784f8632dea22005ace31943b5\
          0b420ca70e23997d9ccb0567d3319f03a211171d1f6d1a8ff246eefb51e4bce0de6f841a559c30f392b7f045d\
          1b4c37c199b09f8e93b5f55ee2e800b0d5c91a14eef3e7440e0e0aac0f55265a54d85692a7edf24732c16878b\
          72e8439f3c91c99e8f531770a2f1e500246f625d7a4e1c239e35e9b625190323b5234398621c27c4a54648d0b\
          603fd99e271e717261c2df3242d53e42ed32f2974c0b34dd9a8afe3cb8775c6168185dddf08284e374d0795f2\
          8c910546b6d495a5a0ad109770156d364932cb26e072c6a4ae27927a6ce09dbfdfdb466da2ccf01963b56463e\
          5a0ebfd8f3fa8f961021642c01d591977ee33bc4e7d664bf3c86d0d926997f3f61245d97258b49d7e3ca821d2\
          6683c9ba0c08ad924c2ba64d724ee3b617de5966d7b9b6898baebbdd60bbde942b3d8568bcdde538ba6633a2f\
          b7daf5aee8275e8ba7a47ef2c47be75b2a6dd424a8361266ebb730f46206c1c89c62248dfe5dabb657de3c155\
          c74ce9e432901ee9e5ec72915453a035672ecfb49895dbf9877dbcc1,",
        ),
        // mainnet tx 1d9088450fbaf8d63d75031e0126127e4456917504edf596514a5b6c41b201c4
        (
            "01145986b6e777aadff8b01227060e567af635c33a7f6c4bc11fd43250304e3efd0403b3a2e24ab6c8bbf90c660cb1a9\
         fc22e8a86e159c6fc1c55a85cb5196e499f8d894c070a3b4f3a4d04013b13484447fd86372c0c23d511146a576046519\
         db66a55ebdd93b02900ea6c852a8a42a16a9a1570dc654d770bc92f426a8ba9fe7cf05",
            "OK n=2 consumed=131/131 tags=K:145986b6e777aadff8b01227060e567af635c33a7f6c4bc11fd4325030\
          4e3efd,A3:b3a2e24ab6c8bbf90c660cb1a9fc22e8a86e159c6fc1c55a85cb5196e499f8d894c070a3b4f3a4d\
          04013b13484447fd86372c0c23d511146a576046519db66a55ebdd93b02900ea6c852a8a42a16a9a1570dc654\
          d770bc92f426a8ba9fe7cf05,",
        ),
        // mainnet tx 44d9556d2e8292815d2274b1d695479183d775d462908c8201c947462579a3ff
        (
            "0153fc91c6923ea8e9b6e7d34914bdfe3c027e4b5874e99e42e603dd8e03904be2022100876bd74da7a84e56020dd1de\
         22d32c6f1254021e4b0d777941da049888fbaaaede200de1a081290532210a913d78bbf245d7144def467ffac34a54c9\
         0d665b671c22",
            "OK n=3 consumed=102/102 tags=K:53fc91c6923ea8e9b6e7d34914bdfe3c027e4b5874e99e42e603dd8e03\
          904be2,N33:00876bd74da7a84e56020dd1de22d32c6f1254021e4b0d777941da049888fbaaae,G32:0de1a08\
          1290532210a913d78bbf245d7144def467ffac34a54c90d665b671c22,",
        ),
        // mainnet tx 53752da947181f5fd902c13c6264b909ed264e55a5b0d2d4667d23c3faf76dd1
        (
            "01db0d198b01c0f8a4f5244445aa5173e0743e6ff86267cab2af690ba19078166bde20dd45ddda81222377c0ca6fd7d0\
         b4bfdccf2e19c281e60b32a685fa440bc98b33022100f4abfe6034772fbd15ccba8a5e843481f78d2448023ec963086d\
         d344f33f4816",
            "OK n=3 consumed=102/102 tags=K:db0d198b01c0f8a4f5244445aa5173e0743e6ff86267cab2af690ba190\
          78166b,G32:dd45ddda81222377c0ca6fd7d0b4bfdccf2e19c281e60b32a685fa440bc98b33,N33:00f4abfe6\
          034772fbd15ccba8a5e843481f78d2448023ec963086dd344f33f4816,",
        ),
        // mainnet coinbase at height 500000
        (
            "012aaee37ea173229ab552f6b7e5fb9870f412dc6fa853d443eb3a48e40a983b90021142cb6a00000000000000000000\
         0000000003210165fd83daffbd2b088496463ed4cdc508b0dfd5a6610f22b47739136c073e918b",
            "OK n=3 consumed=87/87 tags=K:2aaee37ea173229ab552f6b7e5fb9870f412dc6fa853d443eb3a48e40a98\
          3b90,N17:42cb6a0000000000000000000000000000,M:1:65fd83daffbd2b088496463ed4cdc508b0dfd5a66\
          10f22b47739136c073e918b,",
        ),
        // mainnet coinbase at height 73060
        (
            "01d4f881f253632053f7858c837ed526acd25c89c5506ed6049a53b993a656aa660262b1bd5c00204d696e6572476174\
         65273932200066050000000000eaf02568c5664b00ffffffff0000000000000000000000000000000000000000000000\
         00000000000000000000000000000000000000000000000000000000000000000000000000032100ff9c2be08c0fdfad\
         7fcf0f0a52d6ed3c11e7f5152a46def341343933e8ef4cc500000000000000000000",
            "OK n=4 consumed=178/178 tags=K:d4f881f253632053f7858c837ed526acd25c89c5506ed6049a53b993a6\
          56aa66,N98:b1bd5c00204d696e657247617465273932200066050000000000eaf02568c5664b00ffffffff00\
          00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
          00000000000000000000000000000,M:0:ff9c2be08c0fdfad7fcf0f0a52d6ed3c11e7f5152a46def34134393\
          3e8ef4cc5,P10,",
        ),
        // mainnet coinbase at height 61190
        (
            "010511d7abbca8479bf7d9569b938c3edb8b06c31640de817c321ea0d0a35e3614000000000000000000000000000000\
         000000000000000000000000000000000000000000000000",
            "OK n=2 consumed=72/72 tags=K:0511d7abbca8479bf7d9569b938c3edb8b06c31640de817c321ea0d0a35e\
          3614,P39,",
        ),
        // mainnet coinbase at height 17170
        (
            "01db714d176a1c3b8f4fa9ee13e7fe6cd1edd50162e6c972b37e4fc71a6d0ecedd",
            "OK n=1 consumed=33/33 tags=K:db714d176a1c3b8f4fa9ee13e7fe6cd1edd50162e6c972b37e4fc71a6d0e\
          cedd,",
        ),
        // mainnet coinbase at height 1358254
        (
            "0171c24575fafa87e8eb568a0f6364b472dfc45952f39a580a13968d0eada3a461020800000000097421f9",
            "OK n=2 consumed=43/43 tags=K:71c24575fafa87e8eb568a0f6364b472dfc45952f39a580a13968d0eada3\
          a461,N8:00000000097421f9,",
        ),
        // mainnet coinbase at height 1533811
        (
            "018f44aaa46812ddb05fb7d5af1b8a216e9d7ac4d538b2c88b18a081e44bda3f7b02044570d31d",
            "OK n=2 consumed=39/39 tags=K:8f44aaa46812ddb05fb7d5af1b8a216e9d7ac4d538b2c88b18a081e44bda\
          3f7b,N4:4570d31d,",
        ),
        // mainnet coinbase at height 2444391
        (
            "018b1c4fdc00f321e635227f84548625f2a93e6cbb09852b5f25562560977e1bb102110000072bbf6f045b0000000000\
         00000000",
            "OK n=2 consumed=52/52 tags=K:8b1c4fdc00f321e635227f84548625f2a93e6cbb09852b5f25562560977e\
          1bb1,N17:0000072bbf6f045b000000000000000000,",
        ),
        // mainnet coinbase at height 1293867
        (
            "017c094d1b08af299e6719a66fb81d3f6a9e26d789e792666e4d32f8c3636f7c2c021db0559100000000004d696e6572\
         47617465303031000000000000000000032100a7e18dcc23c930c75f23efb9947086104996ed5436b0109a6fb16dc024\
         a85e7a",
            "OK n=3 consumed=99/99 tags=K:7c094d1b08af299e6719a66fb81d3f6a9e26d789e792666e4d32f8c3636f\
          7c2c,N29:b0559100000000004d696e657247617465303031000000000000000000,M:0:a7e18dcc23c930c75\
          f23efb9947086104996ed5436b0109a6fb16dc024a85e7a,",
        ),
        // mainnet coinbase at height 254467
        (
            "01e89a51bce2552c90502dd7d43c00052e665c0d1a0eed4577db8faeeb68d284fd02080000000e277a3e930000000000\
         000000000000000000000000000000000000000000000000000000000000000000",
            "OK n=3 consumed=81/81 tags=K:e89a51bce2552c90502dd7d43c00052e665c0d1a0eed4577db8faeeb68d2\
          84fd,N8:0000000e277a3e93,P38,",
        ),
        // mainnet coinbase at height 202528
        (
            "01bc1af23f5ba5fd8d97c188d4a8c597aafa677cdfd85639d93ec82ae1e8d2970d020800000000a171c75c00",
            "OK n=3 consumed=44/44 tags=K:bc1af23f5ba5fd8d97c188d4a8c597aafa677cdfd85639d93ec82ae1e8d2\
          970d,N8:00000000a171c75c,P1,",
        ),
        // testnet tx 2917a83ec63c66b14922ec0383ea682d2e3c2708aaeb1434d15762d32984eb83
        (
            "01495bbb2d69001caf7dfd13b662f3ea1b7c247e68b10750418652d5f3909c98d2",
            "OK n=1 consumed=33/33 tags=K:495bbb2d69001caf7dfd13b662f3ea1b7c247e68b10750418652d5f3909c\
          98d2,",
        ),
        // testnet coinbase at height 134721
        (
            "0115a1f4a3913414d73640baaf6498af7c55bafb418b7aff003a240d759352cfac",
            "OK n=1 consumed=33/33 tags=K:15a1f4a3913414d73640baaf6498af7c55bafb418b7aff003a240d759352\
          cfac,",
        ),
        // testnet coinbase at height 3900
        (
            "0195ef777e1a75634e1da0096787cf1e6d69bf43549b85ace72045f5b59c7fd4cf",
            "OK n=1 consumed=33/33 tags=K:95ef777e1a75634e1da0096787cf1e6d69bf43549b85ace72045f5b59c7f\
          d4cf,",
        ),
    ];

    fn bytes(hex_str: &str) -> Vec<u8> {
        crate::hex::decode(hex_str).expect("test vector is valid hex")
    }

    fn hash(hex_str: &str) -> Hash32 {
        hex_str.parse().expect("test vector is a valid hash")
    }

    /// Render a parse the way `tools/txextra-oracle/batch` renders the C++ one,
    /// so that the expectations in this file can be that program's own output
    /// and a differential run is a string comparison.
    ///
    /// Every decoded **value** goes into the line, not just its tag and length.
    /// A line of tags alone, `M,` for a merge-mining field and `K,` for a
    /// pubkey, would agree with any parser that got the framing right, one
    /// that truncated the depth to 32 bits or returned the wrong 32 bytes for
    /// a key included. The grammar is documented in
    /// `tools/txextra-oracle/build.sh` and must be changed on both sides at
    /// once.
    fn oracle_line(extra: &[u8]) -> String {
        use std::fmt::Write as _;

        let parsed = parse(extra);
        let mut line = format!(
            "{} n={} consumed={}/{} tags=",
            if parsed.is_complete() { "OK" } else { "FAIL" },
            parsed.fields().len(),
            parsed.consumed(),
            extra.len()
        );
        for field in parsed.fields() {
            // `write!` to a String is infallible; the Result is discarded
            // rather than unwrapped so this stays panic-free either way.
            let _ = match field {
                // Padding carries no payload, so its size is its whole value.
                TxExtraField::Padding { size } => write!(line, "P{size},"),
                TxExtraField::PubKey(key) => write!(line, "K:{key},"),
                TxExtraField::Nonce(data) => {
                    write!(line, "N{}:{},", data.len(), crate::hex::encode(data))
                }
                TxExtraField::MergeMining { depth, merkle_root } => {
                    write!(line, "M:{depth}:{merkle_root},")
                }
                TxExtraField::AdditionalPubKeys(keys) => {
                    let joined: String = keys.iter().map(|key| key.to_hex()).collect();
                    write!(line, "A{}:{joined},", keys.len())
                }
                TxExtraField::MinerGate(data) => {
                    write!(line, "G{}:{},", data.len(), crate::hex::encode(data))
                }
            };
        }
        line
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    // ---------------------------------------------------------------- corpora

    #[test]
    fn synthetic_corpus_matches_the_cpp_oracle() {
        for (hex_str, expected) in SYNTHETIC_CORPUS {
            let extra = bytes(hex_str);
            assert_eq!(&oracle_line(&extra), expected, "vector {hex_str}");
        }
    }

    #[test]
    fn real_chain_corpus_matches_the_cpp_oracle() {
        for (hex_str, expected) in REAL_CORPUS {
            let extra = bytes(hex_str);
            assert_eq!(&oracle_line(&extra), expected, "vector {hex_str}");
        }
        // Every real blob decoded whole. If that ever stops being true the
        // count below is the thing to look at, not the assertion above.
        let complete = REAL_CORPUS
            .iter()
            .filter(|(hex_str, _)| parse(&bytes(hex_str)).is_complete())
            .count();
        assert_eq!(complete, REAL_CORPUS.len());
    }

    // ------------------------------------------------------------- the basics

    #[test]
    fn empty_extra_is_valid_and_has_no_fields() {
        let parsed = parse(&[]);
        assert!(parsed.is_complete());
        assert!(parsed.fields().is_empty());
        assert_eq!(parsed.consumed(), 0);
        assert_eq!(parsed.undecoded_len(), 0);
        // Absent, not null: the caller decides whether to render monerod's
        // 64-hex-zeroes sentinel.
        assert_eq!(parsed.tx_pub_key(), None);
        assert_eq!(parsed.payment_id(), None);
        assert!(parsed.additional_pub_keys().is_empty());
    }

    #[test]
    fn a_lone_padding_tag_is_a_field_of_size_one() {
        let parsed = parse(&[0x00]);
        assert!(parsed.is_complete());
        assert_eq!(parsed.fields(), [TxExtraField::Padding { size: 1 }]);
        assert_eq!(parsed.padding(), Some(1));
    }

    #[test]
    fn every_tag_decodes() {
        let pubkey = "11".repeat(32);
        let root = "33".repeat(32);
        let mut extra = Vec::new();
        extra.push(TAG_PUBKEY);
        extra.extend(bytes(&pubkey));
        extra.extend(bytes("0204deadbeef"));
        extra.push(TAG_MERGE_MINING);
        extra.extend(bytes("2100"));
        extra.extend(bytes(&root));
        extra.push(TAG_ADDITIONAL_PUBKEYS);
        extra.push(0x01);
        extra.extend(bytes(&pubkey));
        extra.extend(bytes("de02cafe"));
        extra.extend([TAG_PADDING, 0, 0, 0]);

        let parsed = parse(&extra);
        assert!(parsed.is_complete(), "{:?}", parsed.error());
        assert_eq!(
            parsed.fields(),
            [
                TxExtraField::PubKey(hash(&pubkey)),
                TxExtraField::Nonce(bytes("deadbeef")),
                TxExtraField::MergeMining {
                    depth: 0,
                    merkle_root: hash(&root)
                },
                TxExtraField::AdditionalPubKeys(vec![hash(&pubkey)]),
                TxExtraField::MinerGate(bytes("cafe")),
                TxExtraField::Padding { size: 4 },
            ]
        );
        assert_eq!(parsed.consumed(), extra.len());
    }

    #[test]
    fn tags_may_repeat_and_may_arrive_in_any_order() {
        // Nonce-before-pubkey is the commonest shape on modern mainnet, so an
        // implementation that assumes 0x01 comes first is wrong about the
        // majority of transactions.
        let pid = "cd".repeat(32);
        let key = "11".repeat(32);
        let parsed = parse(&bytes(&format!("022100{pid}01{key}")));
        assert!(parsed.is_complete());
        assert_eq!(parsed.tx_pub_key(), Some(hash(&key)));
        assert_eq!(parsed.payment_id(), Some(PaymentId::Long(hash(&pid))));

        let dup = parse(&bytes(&format!(
            "01{a}01{b}",
            a = "11".repeat(32),
            b = "22".repeat(32)
        )));
        assert!(dup.is_complete());
        assert_eq!(dup.pub_keys().count(), 2);
    }

    // --------------------------------------------------------------- padding

    #[test]
    fn padding_boundary_is_254_zero_bytes_after_the_tag() {
        // size counts the tag, so 254 zeros is the maximum and 255 is a whole-
        // blob parse failure rather than a truncated field.
        let mut at_max = vec![TAG_PADDING];
        at_max.extend(std::iter::repeat_n(0u8, 254));
        let parsed = parse(&at_max);
        assert!(parsed.is_complete());
        assert_eq!(parsed.padding(), Some(PADDING_MAX_COUNT));
        assert_eq!(parsed.consumed(), 255);

        let mut over = vec![TAG_PADDING];
        over.extend(std::iter::repeat_n(0u8, 255));
        let parsed = parse(&over);
        assert!(!parsed.is_complete());
        assert!(parsed.fields().is_empty());
        assert_eq!(
            parsed.error().map(|e| e.kind),
            Some(TxExtraErrorKind::PaddingTooLong)
        );
    }

    #[test]
    fn padding_fails_on_a_non_zero_byte_rather_than_ending() {
        let parsed = parse(&bytes("000000ff"));
        assert!(!parsed.is_complete());
        assert_eq!(parsed.error().map(|e| e.offset), Some(3));
        assert_eq!(
            parsed.error().map(|e| e.kind),
            Some(TxExtraErrorKind::PaddingNonZero)
        );

        // Which is why padding is always the last field: a perfectly good
        // pubkey behind it is unreachable.
        let after = parse(&bytes("0000000201aa"));
        assert!(!after.is_complete());
        assert!(after.fields().is_empty());
    }

    // ---------------------------------------------------------------- varints

    #[test]
    fn a_varint_truncated_at_end_of_buffer_is_accepted_with_its_partial_value() {
        // monerod's reader returns the byte count it managed, and the archive
        // only checks `1 <= read`. Rejecting this is the single most likely way
        // to disagree with the network.
        let parsed = parse(&bytes("0280"));
        assert!(parsed.is_complete());
        assert_eq!(parsed.fields(), [TxExtraField::Nonce(Vec::new())]);

        let parsed = parse(&bytes("0480"));
        assert!(parsed.is_complete());
        assert_eq!(
            parsed.fields(),
            [TxExtraField::AdditionalPubKeys(Vec::new())]
        );

        // But an empty buffer at the varint's first byte reads zero bytes,
        // which is a failure.
        assert!(!parse(&bytes("02")).is_complete());
        assert!(!parse(&bytes("04")).is_complete());
        assert!(!parse(&bytes("de")).is_complete());
        assert!(!parse(&bytes("03")).is_complete());
    }

    #[test]
    fn non_canonical_and_overflowing_varints_are_rejected_in_every_arm() {
        // The reference pseudocode guards these four sites on a byte count that
        // its own status type does not carry for the bad cases; transcribing it
        // literally accepts all eight of these blobs.
        let root = "33".repeat(32);
        let key = "44".repeat(32);
        let cases = [
            // nonce length
            "02800001".to_owned(),
            format!("02{}02abababab", "ff".repeat(9)),
            // minergate length
            "de800001".to_owned(),
            format!("de{}02abababab", "ff".repeat(9)),
            // merge-mining outer blob length
            format!("038000{root}"),
            format!("03{}02{root}", "ff".repeat(9)),
            // merge-mining inner depth, parsed by a second archive
            format!("03228000{root}"),
            format!("032a{}02{root}", "ff".repeat(9)),
            // additional-pubkey count
            format!("048000{key}"),
            format!("04{}02{key}", "ff".repeat(9)),
        ];
        for case in cases {
            let parsed = parse(&bytes(&case));
            assert!(!parsed.is_complete(), "must be rejected: {case}");
            assert!(parsed.fields().is_empty(), "no field may survive: {case}");
        }
    }

    #[test]
    fn a_length_of_two_to_the_sixty_four_minus_one_never_reaches_a_slice() {
        // The comparison happens in u64 before any cast, so this is a clean
        // rejection rather than a truncating cast or a wrapped `pos + len`.
        for tag in ["02", "03", "de", "04"] {
            let case = format!("{tag}{}01{}", "ff".repeat(9), "ab".repeat(40));
            let parsed = parse(&bytes(&case));
            assert!(!parsed.is_complete(), "{case}");
            assert_eq!(
                parsed.error().map(|e| e.kind),
                Some(TxExtraErrorKind::LengthBeyondEnd),
                "{case}"
            );
        }
    }

    #[test]
    fn varint_reader_reproduces_monerods_truth_table() {
        assert_eq!(
            read_varint(&[0x00], 0),
            (0, 1, VarintStatus::Ok { bytes_read: 1 })
        );
        assert_eq!(
            read_varint(&[0x7f], 0),
            (127, 1, VarintStatus::Ok { bytes_read: 1 })
        );
        assert_eq!(
            read_varint(&[0x80, 0x01], 0),
            (128, 2, VarintStatus::Ok { bytes_read: 2 })
        );
        assert_eq!(
            read_varint(&[0x80, 0x80, 0x01], 0),
            (16384, 3, VarintStatus::Ok { bytes_read: 3 })
        );

        // Empty at the first byte: zero bytes read, not good.
        let (_, _, status) = read_varint(&[], 0);
        assert_eq!(status, VarintStatus::TruncatedAtEof { bytes_read: 0 });
        assert!(!status.is_good());

        // Cut off mid-continuation: good, with the partial value.
        let (value, _, status) = read_varint(&[0x80], 0);
        assert_eq!(value, 0);
        assert_eq!(status, VarintStatus::TruncatedAtEof { bytes_read: 1 });
        assert!(status.is_good());

        // The only non-canonicality monerod rejects is a zero continuation byte.
        assert_eq!(read_varint(&[0x80, 0x00], 0).2, VarintStatus::NonCanonical);
        assert!(read_varint(&[0x80, 0x80, 0x01], 0).2.is_good());

        // Ten bytes is the maximum and the tenth must be exactly 0x01.
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(
            read_varint(&max, 0),
            (u64::MAX, 10, VarintStatus::Ok { bytes_read: 10 })
        );
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(read_varint(&over, 0).2, VarintStatus::Overflow);
        let zero_tenth = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
        assert_eq!(read_varint(&zero_tenth, 0).2, VarintStatus::NonCanonical);
        // An eleventh continuation byte can never be reached.
        let eleven = [0x80u8; 11];
        assert!(!read_varint(&eleven, 0).2.is_good());

        // Reading past the end of a buffer is a status, not a panic.
        assert_eq!(
            read_varint(&[0x01], 99).2,
            VarintStatus::TruncatedAtEof { bytes_read: 0 }
        );
    }

    // ------------------------------------------------------------------ nonce

    #[test]
    fn the_nonce_cap_is_255_and_the_minergate_field_has_none() {
        let mut at_max = bytes("02ff01");
        at_max.extend(std::iter::repeat_n(0xabu8, 255));
        let parsed = parse(&at_max);
        assert!(parsed.is_complete());
        assert_eq!(parsed.first_nonce().map(<[u8]>::len), Some(255));

        let mut over = bytes("028002");
        over.extend(std::iter::repeat_n(0xabu8, 256));
        assert_eq!(
            parse(&over).error().map(|e| e.kind),
            Some(TxExtraErrorKind::NonceTooLong)
        );

        // Same framing, no cap: 300 bytes is fine behind 0xDE and fatal behind
        // 0x02.
        let mut minergate = bytes("deac02");
        minergate.extend(std::iter::repeat_n(0xeeu8, 300));
        let parsed = parse(&minergate);
        assert!(parsed.is_complete());
        assert_eq!(parsed.minergate_fields().next().map(<[u8]>::len), Some(300));

        let mut long_nonce = bytes("02ac02");
        long_nonce.extend(std::iter::repeat_n(0xeeu8, 300));
        assert!(!parse(&long_nonce).is_complete());
    }

    // ------------------------------------------------------------ payment ids

    #[test]
    fn payment_ids_are_recognised_by_exact_length() {
        let pid = "cd".repeat(32);
        let long = parse(&bytes(&format!("022100{pid}")));
        assert_eq!(long.payment_id(), Some(PaymentId::Long(hash(&pid))));
        assert!(!long.payment_id().unwrap().is_encrypted());

        let short = parse(&bytes("020901cdcdcdcdcdcdcdcd"));
        assert_eq!(
            short.payment_id(),
            Some(PaymentId::Encrypted(PaymentId8::from_bytes([0xcd; 8])))
        );
        assert_eq!(short.payment_id().unwrap().to_hex(), "cdcdcdcdcdcdcdcd");

        // Right length, wrong sub-tag.
        assert_eq!(parse(&bytes("020900cdcdcdcdcdcdcdcd")).payment_id(), None);
        assert_eq!(parse(&bytes(&format!("022101{pid}"))).payment_id(), None);
        // Right sub-tag, wrong length. A prefix match would accept both.
        assert_eq!(parse(&bytes("020801cdcdcdcdcdcdcd")).payment_id(), None);
        assert_eq!(parse(&bytes("020a01cdcdcdcdcdcdcdcdcd")).payment_id(), None);
        assert_eq!(parse(&bytes("0200")).payment_id(), None);
    }

    #[test]
    fn a_nine_byte_miner_nonce_beginning_with_one_is_reported_as_an_encrypted_payment_id() {
        // This is the known false positive in monerod's helpers, reproduced
        // deliberately: the test exists so that "fixing" it fails loudly.
        // Plausible coinbase nonce bytes, not a payment id by intent.
        let coinbase_nonce = bytes("011b6e909787d90042");
        assert_eq!(coinbase_nonce.len(), 9);
        let mut extra = vec![TAG_NONCE, 0x09];
        extra.extend(&coinbase_nonce);
        let parsed = parse(&extra);
        assert!(parsed.is_complete());
        assert_eq!(
            parsed.payment_id().map(|id| id.to_hex()),
            Some("1b6e909787d90042".to_owned()),
            "monerod reports this as an encrypted payment id, so we must too"
        );

        // The 8-byte coinbase nonces that really do start with 0x01 (three of
        // them in a 3,213-blob mainnet sample, e.g. `014fe07752fdfc00` at
        // height 1,578,021) are the near miss: wrong length, so not a payment
        // id.
        let mut extra = vec![TAG_NONCE, 0x08];
        extra.extend(bytes("011b6e909787d900"));
        assert_eq!(parse(&extra).payment_id(), None);
    }

    #[test]
    fn the_payment_id_getter_refuses_partial_results_but_the_pubkey_getter_does_not() {
        // The asymmetry is load-bearing for output compatibility: same blob,
        // two different answers about whether the decoded prefix counts.
        let key = "11".repeat(32);
        let pid = "cd".repeat(32);
        let extra = bytes(&format!("01{key}022100{pid}05ff"));
        let parsed = parse(&extra);
        assert!(!parsed.is_complete());
        assert_eq!(
            parsed.fields().len(),
            2,
            "both good fields survive the bad tail"
        );
        assert_eq!(parsed.tx_pub_key(), Some(hash(&key)));
        assert_eq!(parsed.tx_pub_key_explorer_compat(), Some(hash(&key)));
        assert_eq!(parsed.first_nonce().map(<[u8]>::len), Some(33));
        assert_eq!(
            parsed.payment_id(),
            None,
            "any parse failure voids the payment id"
        );
    }

    #[test]
    fn only_the_first_nonce_is_examined_for_a_payment_id() {
        let pid = "cd".repeat(32);
        let extra = bytes(&format!("0204deadbeef022100{pid}"));
        let parsed = parse(&extra);
        assert!(parsed.is_complete());
        assert_eq!(parsed.nonces().count(), 2);
        assert_eq!(
            parsed.payment_id(),
            None,
            "the second nonce is never looked at"
        );
    }

    // ----------------------------------------------------------- PaymentId8

    /// A real encrypted payment id: the eight bytes behind the `01` sub-tag of
    /// mainnet tx 32ee937d7824d7fd73956cd32906db2b42aec7c8df915ec4bc93abf71d5fbca2
    /// (`REAL_CORPUS[0]`).
    const REAL_PAYMENT_ID8: &str = "55e10418dec2fd58";

    #[test]
    fn a_payment_id8_round_trips_through_its_hex() {
        let id: PaymentId8 = REAL_PAYMENT_ID8.parse().expect("valid payment id");
        assert_eq!(id.to_string(), REAL_PAYMENT_ID8);
        assert_eq!(id.to_hex(), REAL_PAYMENT_ID8);
        // Debug renders the whole id: these land in log lines, where a
        // truncated or byte-array form is useless.
        assert_eq!(format!("{id:?}"), format!("PaymentId8({REAL_PAYMENT_ID8})"));
        // The bytes are the id, not a re-rendering of the string it came from.
        assert_eq!(
            id.as_bytes(),
            &[0x55, 0xe1, 0x04, 0x18, 0xde, 0xc2, 0xfd, 0x58]
        );
        assert_eq!(PaymentId8::from_bytes(*id.as_bytes()), id);
    }

    #[test]
    fn payment_id8_uppercase_hex_is_accepted_and_normalised_to_lowercase() {
        // Payment ids get pasted out of wallets and emails; rejecting uppercase
        // would be a gratuitous failure, but output must be canonical.
        let id: PaymentId8 = REAL_PAYMENT_ID8
            .to_uppercase()
            .parse()
            .expect("uppercase is valid hex");
        assert_eq!(id.to_string(), REAL_PAYMENT_ID8);
    }

    #[test]
    fn payment_id8_length_errors_are_precise() {
        assert_eq!(
            "".parse::<PaymentId8>(),
            Err(PaymentId8ParseError::WrongLength(0))
        );
        assert_eq!(
            REAL_PAYMENT_ID8[..15].parse::<PaymentId8>(),
            Err(PaymentId8ParseError::WrongLength(15))
        );
        assert_eq!(
            format!("{REAL_PAYMENT_ID8}0").parse::<PaymentId8>(),
            Err(PaymentId8ParseError::WrongLength(17))
        );
        // A 64-hex payment id is the other kind, and must not decode into this
        // type by truncation.
        assert_eq!(
            "cd".repeat(32).parse::<PaymentId8>(),
            Err(PaymentId8ParseError::WrongLength(64))
        );
    }

    #[test]
    fn payment_id8_non_hex_is_rejected() {
        let bad = format!("{}zz", &REAL_PAYMENT_ID8[..14]);
        assert_eq!(
            bad.parse::<PaymentId8>(),
            Err(PaymentId8ParseError::NotHex('z'))
        );
    }

    /// Multi-byte input must be rejected on length without panicking on a char
    /// boundary — `s.len()` is bytes, and slicing it would be a panic.
    #[test]
    fn payment_id8_multibyte_input_does_not_panic() {
        assert!("é".repeat(4).parse::<PaymentId8>().is_err());
        // Exactly 16 *bytes* of multi-byte text, twice over: both pass the
        // length gate, so both must fail on the alphabet check rather than
        // slicing mid-character.
        for text in ["é".repeat(8), "🙂".repeat(4)] {
            assert_eq!(text.len(), PAYMENT_ID8_HEX_LEN);
            assert!(matches!(
                text.parse::<PaymentId8>(),
                Err(PaymentId8ParseError::NotHex(_))
            ));
        }
    }

    #[test]
    fn payment_id8_serde_round_trips_through_a_json_string() {
        let id: PaymentId8 = REAL_PAYMENT_ID8.parse().expect("valid");
        let json = serde_json::to_string(&id).expect("serialises");
        assert_eq!(json, format!("\"{REAL_PAYMENT_ID8}\""));
        let back: PaymentId8 = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, id);
    }

    #[test]
    fn payment_id8_serde_rejects_a_malformed_id_rather_than_defaulting() {
        assert!(serde_json::from_str::<PaymentId8>("\"deadbeef\"").is_err());
        assert!(serde_json::from_str::<PaymentId8>("\"zzzzzzzzzzzzzzzz\"").is_err());
        assert!(serde_json::from_str::<PaymentId8>("123").is_err());
        assert!(serde_json::from_str::<PaymentId8>("null").is_err());
    }

    #[test]
    fn the_payment_id8_parsed_from_hex_equals_the_one_decoded_from_the_chain() {
        // The type and the parser have to agree about which eight bytes those
        // are, or the explorer's `payment_id8` field is a different number from
        // the one a user searches for.
        let parsed = parse(&bytes(REAL_CORPUS[0].0));
        let from_chain = parsed.payment_id().expect("an encrypted payment id");
        let from_hex: PaymentId8 = REAL_PAYMENT_ID8.parse().expect("valid");
        assert_eq!(from_chain, PaymentId::Encrypted(from_hex));
        assert_eq!(from_chain.to_hex(), REAL_PAYMENT_ID8);
    }

    // --------------------------------------------------------------- pubkeys

    #[test]
    fn the_explorer_returns_the_second_pubkey_when_two_exist() {
        let first = "11".repeat(32);
        let second = "22".repeat(32);
        let parsed = parse(&bytes(&format!("01{first}01{second}")));
        assert_eq!(
            parsed.tx_pub_key(),
            Some(hash(&first)),
            "monerod takes the first"
        );
        assert_eq!(
            parsed.tx_pub_key_explorer_compat(),
            Some(hash(&second)),
            "the explorer takes the second, and its pages show that value"
        );

        // Three pubkeys: still the second.
        let third = "33".repeat(32);
        let parsed = parse(&bytes(&format!("01{first}01{second}01{third}")));
        assert_eq!(parsed.tx_pub_key_explorer_compat(), Some(hash(&second)));

        // One pubkey: both agree.
        let parsed = parse(&bytes(&format!("01{first}")));
        assert_eq!(parsed.tx_pub_key_explorer_compat(), Some(hash(&first)));
    }

    #[test]
    fn a_short_pubkey_is_a_failure_not_a_truncated_field() {
        let parsed = parse(&bytes(&format!("01{}", "aa".repeat(31))));
        assert!(!parsed.is_complete());
        assert_eq!(
            parsed.error().map(|e| e.kind),
            Some(TxExtraErrorKind::TruncatedPubKey)
        );
        assert!(parsed.fields().is_empty());
    }

    // ---------------------------------------------------- additional pubkeys

    #[test]
    fn the_additional_pubkey_varint_counts_keys_not_bytes() {
        let key = "44".repeat(32);
        let two = parse(&bytes(&format!("0402{key}{key}")));
        assert!(two.is_complete());
        assert_eq!(two.additional_pub_keys().len(), 2);

        // A count of 2 with 40 bytes left passes monerod's weak bytes-versus-
        // elements check — 40 >= 2 — and only fails on the second key.
        let parsed = parse(&bytes(&format!("0402{key}{}", "44".repeat(8))));
        assert!(!parsed.is_complete());
        assert_eq!(
            parsed.error().map(|e| e.kind),
            Some(TxExtraErrorKind::TruncatedAdditionalKeys)
        );
        assert!(
            parsed.fields().is_empty(),
            "a half-read key list is not a field"
        );

        // Counts that exceed the bytes remaining never reach the key loop, so
        // 33 keys behind 32 bytes is rejected before anything is reserved.
        for count in ["21", "ff01"] {
            let parsed = parse(&bytes(&format!("04{count}{key}")));
            assert_eq!(
                parsed.error().map(|e| e.kind),
                Some(TxExtraErrorKind::LengthBeyondEnd)
            );
        }
    }

    #[test]
    fn a_huge_additional_pubkey_count_allocates_nothing() {
        // `04` + count 2^64-1 + 32 bytes. Reserving `count` keys would be a
        // 512 EiB request; the bytes-remaining check has to come first.
        let extra = bytes(&format!("04{}01{}", "ff".repeat(9), "44".repeat(32)));
        let parsed = parse(&extra);
        assert!(!parsed.is_complete());
        assert_eq!(
            parsed.error().map(|e| e.kind),
            Some(TxExtraErrorKind::LengthBeyondEnd)
        );
    }

    #[test]
    fn only_the_first_additional_pubkey_field_is_used() {
        let a = "44".repeat(32);
        let b = "55".repeat(32);
        let parsed = parse(&bytes(&format!("0401{a}0401{b}")));
        assert!(parsed.is_complete());
        assert_eq!(parsed.fields().len(), 2);
        assert_eq!(parsed.additional_pub_keys(), [hash(&a)]);
    }

    // ----------------------------------------------------------- merge mining

    #[test]
    fn merge_mining_depth_zero_is_the_common_form_and_consumes_exactly_35_bytes() {
        // `03 21 00 <32>`. An implementation that computes the depth varint's
        // length instead of reading it gets 0 for depth 0, concludes the blob
        // has a trailing byte, and desynchronises here.
        let root = "33".repeat(32);
        let parsed = parse(&bytes(&format!("032100{root}")));
        assert!(parsed.is_complete());
        assert_eq!(parsed.consumed(), 35);
        assert_eq!(parsed.merge_mining_tag(), Some((0, hash(&root))));

        // And the same blob followed by another field must still line up.
        let key = "11".repeat(32);
        let parsed = parse(&bytes(&format!("032100{root}01{key}")));
        assert!(parsed.is_complete(), "{:?}", parsed.error());
        assert_eq!(parsed.tx_pub_key(), Some(hash(&key)));
    }

    #[test]
    fn the_merge_mining_blob_must_be_consumed_exactly() {
        let root = "33".repeat(32);
        assert_eq!(
            parse(&bytes(&format!("03228001{root}"))).merge_mining_tag(),
            Some((128, hash(&root)))
        );

        for case in [
            format!("032000{root}"),     // one byte short
            format!("032200{root}ff"),   // one byte long
            format!("032300{root}ffff"), // two bytes long
            "030180".to_owned(),         // inner is a lone continuation byte
            format!("0300{root}"),       // an empty inner blob
        ] {
            let parsed = parse(&bytes(&case));
            assert!(!parsed.is_complete(), "{case}");
        }
    }

    #[test]
    fn a_merge_mining_depth_keeps_all_sixty_four_bits() {
        // `tx_extra_merge_mining_tag::depth` is a uint64_t and the varint can
        // carry every bit of one. Nothing on chain exercises this — mainnet has
        // only ever carried depth 0 or 1 — so a truncation to 32 bits would be
        // invisible to the real-blob corpus and to any expectation written as a
        // field count. These are the widths either side of the 2^32 boundary,
        // and the expected values are `tools/txextra-oracle/batch`'s.
        let root = "33".repeat(32);
        for (case, depth) in [
            (format!("0325ffffffff0f{root}"), u64::from(u32::MAX)),
            (format!("03258080808010{root}"), 1u64 << 32),
            (format!("03258180808010{root}"), (1u64 << 32) + 1),
            (
                format!("0329ef9bafcdf8acd19101{root}"),
                0x0123_4567_89ab_cdef,
            ),
            (format!("032a{}01{root}", "ff".repeat(9)), u64::MAX),
        ] {
            let parsed = parse(&bytes(&case));
            assert!(parsed.is_complete(), "{case}: {:?}", parsed.error());
            assert_eq!(
                parsed.merge_mining_tag(),
                Some((depth, hash(&root))),
                "{case}"
            );
        }
    }

    // ------------------------------------------------------- failure handling

    #[test]
    fn an_unknown_tag_keeps_everything_decoded_before_it() {
        let key = "11".repeat(32);
        let extra = bytes(&format!("01{key}05ff"));
        let parsed = parse(&extra);
        assert!(!parsed.is_complete());
        assert_eq!(parsed.fields(), [TxExtraField::PubKey(hash(&key))]);
        assert_eq!(parsed.consumed(), 33);
        assert_eq!(parsed.undecoded_len(), 2);
        assert_eq!(parsed.undecoded_tail(&extra), &bytes("05ff")[..]);
        assert_eq!(
            parsed.error().map(|e| (e.offset, e.kind)),
            Some((33, TxExtraErrorKind::UnknownTag(0x05)))
        );
    }

    #[test]
    fn the_undecoded_tail_checks_the_length_and_nothing_else() {
        // A pubkey tag with one byte behind it: nothing is consumed, so the
        // whole blob is the tail.
        let extra = bytes("0100");
        let parsed = parse(&extra);
        assert_eq!(parsed.consumed(), 0);
        assert_eq!(parsed.undecoded_len(), 2);
        assert_eq!(parsed.undecoded_tail(&extra), &extra[..]);

        // A blob of a different length yields nothing, rather than a tail of
        // the wrong length or a panic on an out-of-range index.
        assert!(parsed.undecoded_tail(&bytes("aabbcc")).is_empty());
        assert!(parsed.undecoded_tail(&[]).is_empty());

        // A different blob of the *same* length is returned verbatim: the
        // guard compares lengths and cannot compare identity. That is the
        // documented limit of it — the caller must hand back the slice it
        // parsed — and this asserts the real behaviour so the doc cannot drift
        // back into promising more.
        assert_eq!(parsed.undecoded_tail(&bytes("05ff")), &bytes("05ff")[..]);
    }

    #[test]
    fn the_error_offset_is_monerods_cursor_not_the_start_of_the_tail() {
        // They coincide for an unknown tag, which fails on the tag byte itself
        // without moving the cursor past it.
        let key = "11".repeat(32);
        let extra = bytes(&format!("01{key}05ff"));
        let parsed = parse(&extra);
        assert_eq!(parsed.error().map(|e| e.offset), Some(33));
        assert_eq!(parsed.consumed(), 33);

        // Everywhere else they differ, because the failing field has already
        // walked the cursor over bytes no field ended up owning. Rendering the
        // tail from `offset` would print one byte of a four-byte blob that
        // monerod rejected whole.
        let extra = bytes("000000ff");
        let parsed = parse(&extra);
        assert_eq!(parsed.error().map(|e| e.offset), Some(3));
        assert_eq!(parsed.consumed(), 0);
        assert_eq!(parsed.undecoded_tail(&extra), &extra[..]);
        assert_eq!(
            &extra[3..],
            &bytes("ff")[..],
            "what following `offset` would show"
        );
    }

    #[test]
    fn a_field_count_amplifying_blob_stays_linear() {
        // 2 bytes per field is the densest encoding there is, and monerod
        // imposes no field cap, so this really does decode to 30,000 fields.
        let extra = bytes(&"de00".repeat(30_000));
        let parsed = parse(&extra);
        assert!(parsed.is_complete());
        assert_eq!(parsed.fields().len(), 30_000);
        assert_eq!(parsed.consumed(), 60_000);
    }
    // ------------------------------------------------------ real fixture data

    /// Pull every `"extra"` byte array out of a fixture, including the ones
    /// nested inside the JSON-encoded strings monerod returns (`json` on a
    /// block, `as_json` on a transaction).
    fn collect_extras(value: &serde_json::Value, depth: u32, out: &mut Vec<Vec<u8>>) {
        if depth > 12 {
            return;
        }
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if key == "extra"
                        && let Some(array) = child.as_array()
                        && let Some(blob) = array
                            .iter()
                            .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                            .collect::<Option<Vec<u8>>>()
                    {
                        out.push(blob);
                    }
                    collect_extras(child, depth + 1, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_extras(item, depth + 1, out);
                }
            }
            serde_json::Value::String(text) if text.starts_with('{') => {
                if let Ok(inner) = serde_json::from_str::<serde_json::Value>(text) {
                    collect_extras(&inner, depth + 1, out);
                }
            }
            _ => {}
        }
    }

    fn fixture_extras() -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        for net in ["testnet", "mainnet"] {
            let dir = repo_root().join("fixtures").join(net);
            let entries = std::fs::read_dir(&dir).expect("fixtures directory exists");
            let mut paths: Vec<_> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .collect();
            paths.sort();
            for path in paths {
                let text = std::fs::read_to_string(&path).expect("fixture is readable");
                let value: serde_json::Value =
                    serde_json::from_str(&text).expect("fixture is valid JSON");
                let mut blobs = Vec::new();
                collect_extras(&value, 0, &mut blobs);
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                for blob in blobs {
                    found.push((format!("{net}/{name}"), blob));
                }
            }
        }
        found
    }

    #[test]
    fn every_extra_in_the_fixtures_decodes_whole() {
        let extras = fixture_extras();
        assert!(
            extras.len() >= 10,
            "expected the captured RPC fixtures to carry tx_extra blobs, found {}",
            extras.len()
        );
        for (source, extra) in &extras {
            let parsed = parse(extra);
            assert!(
                parsed.is_complete(),
                "{source}: {} failed at {:?}",
                crate::hex::encode(extra),
                parsed.error()
            );
            assert_eq!(parsed.consumed(), extra.len(), "{source}");
            assert!(
                parsed.tx_pub_key().is_some(),
                "{source}: every real tx has a pubkey"
            );
        }
    }

    #[test]
    fn the_testnet_transaction_fixture_decodes_to_one_pubkey() {
        let path = repo_root().join("fixtures/testnet/tx_as_json_parsed.json");
        let text = std::fs::read_to_string(&path).expect("fixture is readable");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let mut blobs = Vec::new();
        collect_extras(&value, 0, &mut blobs);
        assert_eq!(blobs.len(), 1);

        let parsed = parse(&blobs[0]);
        assert!(parsed.is_complete());
        assert_eq!(
            parsed.fields(),
            [TxExtraField::PubKey(hash(
                "495bbb2d69001caf7dfd13b662f3ea1b7c247e68b10750418652d5f3909c98d2"
            ))]
        );
        assert_eq!(parsed.payment_id(), None);
        assert!(parsed.additional_pub_keys().is_empty());
    }

    #[test]
    fn the_mainnet_block_fixture_coinbase_carries_a_miner_nonce() {
        let path = repo_root().join("fixtures/mainnet/get_block_ringct.json");
        let text = std::fs::read_to_string(&path).expect("fixture is readable");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let mut blobs = Vec::new();
        collect_extras(&value, 0, &mut blobs);
        assert_eq!(blobs.len(), 1);

        let parsed = parse(&blobs[0]);
        assert!(parsed.is_complete());
        assert_eq!(
            parsed.fields(),
            [
                TxExtraField::PubKey(hash(
                    "62add31b6d4a40902f842d083fb7ba177f02cd52a6a4d9684048bbd7d9873d73"
                )),
                TxExtraField::Nonce(bytes("000000068db94d60")),
            ]
        );
        // An 8-byte nonce is not a payment id however it starts.
        assert_eq!(parsed.payment_id(), None);
    }

    // -------------------------------------------------- real chain field data

    #[test]
    fn real_mainnet_fields_decode_to_the_right_values() {
        // tx 32ee937d…bca2: pubkey then an encrypted payment id.
        let parsed = parse(&bytes(REAL_CORPUS[0].0));
        assert_eq!(
            parsed.tx_pub_key(),
            Some(hash(
                "455fe610dfc1b1efec57b39885c28ac08defac0291ae19349a354d159473e00a"
            ))
        );
        assert_eq!(
            parsed.payment_id().map(|id| id.to_hex()),
            Some("55e10418dec2fd58".to_owned())
        );
        assert!(parsed.payment_id().unwrap().is_encrypted());

        // tx e8256130…3d2a: the nonce comes FIRST, the pubkey second.
        let parsed = parse(&bytes(REAL_CORPUS[1].0));
        assert_eq!(parsed.fields()[0].tag(), TAG_NONCE);
        assert_eq!(
            parsed.tx_pub_key(),
            Some(hash(
                "56268a40135e84463e9708968924dc93b9aaa2954b462f949f69c7363c2f43f9"
            ))
        );
        assert_eq!(
            parsed.payment_id(),
            Some(PaymentId::Long(hash(
                "2715536cb0e7c24faeb02b6659dbdae5d701da922cc1034846695b72157a4b65"
            )))
        );

        // tx f0d450ad…ce53: a 0xDE field, which is one raw tag byte.
        let parsed = parse(&bytes(REAL_CORPUS[2].0));
        assert_eq!(
            parsed.minergate_fields().next().map(crate::hex::encode),
            Some("6de0332d02832042ee8b7d7839bfc10d3b4e38307ea1cc14825b1fcac2df1021".to_owned())
        );

        // tx d257fc1b…5778: `01 <32> 04 04 <4x32>`.
        let parsed = parse(&bytes(REAL_CORPUS[3].0));
        assert_eq!(parsed.additional_pub_keys().len(), 4);
        assert_eq!(
            parsed.additional_pub_keys().first(),
            Some(&hash(
                "53da502b78b9e2a1ddc58541bdb16c90a5b204c02bf2998db5c1dbc7d25c2d5a"
            ))
        );
        assert_eq!(
            parsed.additional_pub_keys().last(),
            Some(&hash(
                "fb2d2a73b1addb2111245b7ed1ab5983af1ea7df377877ad2de3f5e0287ae7b5"
            ))
        );

        // tx d387fd49…7856: `01 <32> 04 10 <16x32>`, the largest count seen.
        let parsed = parse(&bytes(REAL_CORPUS[4].0));
        assert_eq!(parsed.additional_pub_keys().len(), 16);
        assert_eq!(parsed.consumed(), parsed.input_len());

        // tx 53752da9…6dd1: minergate field before the nonce that holds the
        // payment id — another blob where the first tag is not 0x01.
        let parsed = parse(&bytes(REAL_CORPUS[7].0));
        assert_eq!(
            parsed.payment_id(),
            Some(PaymentId::Long(hash(
                "f4abfe6034772fbd15ccba8a5e843481f78d2448023ec963086dd344f33f4816"
            )))
        );
        assert_eq!(parsed.minergate_fields().count(), 1);
    }

    #[test]
    fn real_mainnet_coinbases_decode_to_the_right_values() {
        // Coinbase at 500000: pubkey, 17-byte miner nonce, merge mining depth 1.
        let parsed = parse(&bytes(REAL_CORPUS[8].0));
        assert_eq!(parsed.first_nonce().map(<[u8]>::len), Some(17));
        assert_eq!(parsed.payment_id(), None);
        assert_eq!(
            parsed.merge_mining_tag(),
            Some((
                1,
                hash("65fd83daffbd2b088496463ed4cdc508b0dfd5a6610f22b47739136c073e918b")
            ))
        );

        // Coinbase at 73060: a 98-byte nonce with the miner's name in it, a
        // depth-0 merge-mining tag, and terminal padding.
        let parsed = parse(&bytes(REAL_CORPUS[9].0));
        let nonce = parsed.first_nonce().expect("nonce");
        assert_eq!(nonce.len(), 98);
        assert!(
            nonce.windows(9).any(|w| w == b"MinerGate"),
            "the nonce is arbitrary bytes, not a payment id"
        );
        assert_eq!(parsed.merge_mining_tag().map(|(depth, _)| depth), Some(0));
        assert_eq!(parsed.padding(), Some(10));
        assert_eq!(
            parsed.fields().last().map(TxExtraField::tag),
            Some(TAG_PADDING)
        );

        // Coinbase at 61190: pubkey and 38 zero bytes of padding.
        let parsed = parse(&bytes(REAL_CORPUS[10].0));
        assert_eq!(parsed.padding(), Some(39));
        assert_eq!(parsed.consumed(), 72);
    }

    // ------------------------------------------------------------- properties

    /// xorshift64*, so that a failing case is reproducible from its seed
    /// without a dev-dependency.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next_u64() % n }
        }

        fn byte(&mut self) -> u8 {
            (self.next_u64() >> 33) as u8
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.byte()).collect()
        }

        /// Between zero and `max - 1` random bytes.
        fn bytes_upto(&mut self, max: u64) -> Vec<u8> {
            let len = self.below(max) as usize;
            self.bytes(len)
        }
    }

    fn push_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn varint_len(value: u64) -> usize {
        let mut buf = Vec::new();
        push_varint(value, &mut buf);
        buf.len()
    }

    /// Canonical re-encoding of decoded fields, for the round-trip property.
    fn encode_fields(fields: &[TxExtraField]) -> Vec<u8> {
        let mut out = Vec::new();
        for field in fields {
            out.push(field.tag());
            match field {
                TxExtraField::Padding { size } => {
                    out.extend(std::iter::repeat_n(
                        0u8,
                        usize::from(size.saturating_sub(1)),
                    ));
                }
                TxExtraField::PubKey(key) => out.extend(key.as_bytes()),
                TxExtraField::Nonce(data) | TxExtraField::MinerGate(data) => {
                    push_varint(data.len() as u64, &mut out);
                    out.extend(data);
                }
                TxExtraField::MergeMining { depth, merkle_root } => {
                    push_varint((varint_len(*depth) + HASH_LEN) as u64, &mut out);
                    push_varint(*depth, &mut out);
                    out.extend(merkle_root.as_bytes());
                }
                TxExtraField::AdditionalPubKeys(keys) => {
                    push_varint(keys.len() as u64, &mut out);
                    for key in keys {
                        out.extend(key.as_bytes());
                    }
                }
            }
        }
        out
    }

    /// Everything that must hold for every input, valid or not.
    fn check_invariants(extra: &[u8]) -> ParsedTxExtra {
        let parsed = parse(extra);

        assert_eq!(parsed.input_len(), extra.len());
        assert!(parsed.consumed() <= extra.len());
        assert_eq!(parsed.is_complete(), parsed.error().is_none());
        if parsed.is_complete() {
            assert_eq!(parsed.consumed(), extra.len());
            assert_eq!(parsed.undecoded_len(), 0);
        } else {
            let error = parsed.error().expect("incomplete parses carry an error");
            assert!(error.offset <= extra.len());
        }
        assert_eq!(parsed.undecoded_tail(extra).len(), parsed.undecoded_len());
        // The tag byte guarantees progress, so a field can never cost less than
        // one input byte.
        assert!(parsed.fields().len() <= extra.len());

        for field in parsed.fields() {
            match field {
                TxExtraField::Padding { size } => assert!((1..=PADDING_MAX_COUNT).contains(size)),
                TxExtraField::Nonce(data) => assert!(data.len() as u64 <= NONCE_MAX_COUNT),
                TxExtraField::AdditionalPubKeys(keys) => {
                    assert!(keys.len() * HASH_LEN <= extra.len());
                }
                TxExtraField::MinerGate(data) => assert!(data.len() <= extra.len()),
                _ => {}
            }
        }

        // Accessors must be total too.
        let _ = parsed.tx_pub_key();
        let _ = parsed.tx_pub_key_explorer_compat();
        let _ = parsed.additional_pub_keys();
        let _ = parsed.payment_id();
        let _ = parsed.padding();
        let _ = parsed.merge_mining_tag();
        let _ = parsed.nonces().count();
        let _ = parsed.minergate_fields().count();

        // A blob that decoded whole must survive a canonical round trip. It is
        // not byte-identical — a length varint truncated at end-of-buffer
        // re-encodes as a zero — but the fields must be.
        if parsed.is_complete() {
            let reencoded = encode_fields(parsed.fields());
            let again = parse(&reencoded);
            assert!(
                again.is_complete(),
                "re-encoded blob no longer parses: {}",
                crate::hex::encode(&reencoded)
            );
            assert_eq!(again.fields(), parsed.fields());
        }

        parsed
    }

    fn random_field(rng: &mut Rng) -> TxExtraField {
        match rng.below(6) {
            0 => TxExtraField::Padding {
                size: (rng.below(u64::from(PADDING_MAX_COUNT)) + 1) as u16,
            },
            1 => TxExtraField::PubKey(Hash32::from_bytes(
                <[u8; HASH_LEN]>::try_from(rng.bytes(HASH_LEN).as_slice()).expect("32 bytes"),
            )),
            2 => TxExtraField::Nonce(rng.bytes_upto(NONCE_MAX_COUNT + 1)),
            3 => TxExtraField::MergeMining {
                // A mix of one-byte and ten-byte depth varints, because the
                // blob length depends on the depth's encoded width.
                depth: if rng.below(2) == 0 {
                    rng.below(4)
                } else {
                    rng.next_u64()
                },
                merkle_root: Hash32::from_bytes(
                    <[u8; HASH_LEN]>::try_from(rng.bytes(HASH_LEN).as_slice()).expect("32 bytes"),
                ),
            },
            4 => TxExtraField::AdditionalPubKeys(
                (0..rng.below(5))
                    .map(|_| {
                        Hash32::from_bytes(
                            <[u8; HASH_LEN]>::try_from(rng.bytes(HASH_LEN).as_slice())
                                .expect("32 bytes"),
                        )
                    })
                    .collect(),
            ),
            _ => TxExtraField::MinerGate(rng.bytes_upto(320)),
        }
    }

    /// A blob that must parse: valid fields, with the at-most-one-and-last
    /// padding rule respected.
    fn well_formed(rng: &mut Rng) -> Vec<TxExtraField> {
        let mut fields: Vec<TxExtraField> = (0..rng.below(5) + 1)
            .map(|_| random_field(rng))
            .filter(|f| f.tag() != TAG_PADDING)
            .collect();
        if rng.below(4) == 0 {
            fields.push(TxExtraField::Padding {
                size: (rng.below(u64::from(PADDING_MAX_COUNT)) + 1) as u16,
            });
        }
        fields
    }

    /// One generated blob, plus the fields it was built from when those are
    /// known.
    ///
    /// Most of the generators below produce damage, so there is nothing to
    /// expect beyond totality. The well-formed generator, though, chose the
    /// exact values it encoded, which makes it the only offline check here that
    /// is about *values* rather than shapes: `parse(encode(f))` has to give back
    /// `f`, key for key and depth for depth. Re-parsing our own output would
    /// not do — a parser that truncates every depth the same way agrees with
    /// itself perfectly.
    struct Generated {
        extra: Vec<u8>,
        expected: Option<Vec<TxExtraField>>,
    }

    impl Generated {
        const fn opaque(extra: Vec<u8>) -> Self {
            Self {
                extra,
                expected: None,
            }
        }
    }

    fn structured_input(rng: &mut Rng) -> Generated {
        Generated::opaque(match rng.below(6) {
            // Raw noise.
            0 => rng.bytes_upto(48),
            // Tag-led noise: far more likely to get several fields in.
            1 => {
                let tags = [
                    TAG_PADDING,
                    TAG_PUBKEY,
                    TAG_NONCE,
                    TAG_MERGE_MINING,
                    TAG_ADDITIONAL_PUBKEYS,
                    0x05,
                    TAG_MINERGATE,
                ];
                let mut out = Vec::new();
                for _ in 0..rng.below(4) + 1 {
                    out.push(tags[rng.below(tags.len() as u64) as usize]);
                    out.extend(rng.bytes_upto(40));
                }
                out
            }
            // Well formed. The only arm whose decoded values are known ahead of
            // the parse, so it returns early with them attached.
            2 => {
                let fields = well_formed(rng);
                return Generated {
                    extra: encode_fields(&fields),
                    expected: Some(fields),
                };
            }
            // Well formed, then damaged: truncated, extended, or one byte flipped.
            3 => {
                let mut out = encode_fields(&well_formed(rng));
                match rng.below(3) {
                    0 => {
                        let keep = rng.below(out.len() as u64 + 1) as usize;
                        out.truncate(keep);
                    }
                    1 => {
                        let tail = rng.bytes_upto(4);
                        out.extend(tail);
                        out.push(rng.byte());
                    }
                    _ => {
                        if !out.is_empty() {
                            let at = rng.below(out.len() as u64) as usize;
                            out[at] ^= 1 << rng.below(8);
                        }
                    }
                }
                out
            }
            // Varint torture: the length field is the dangerous part.
            4 => {
                let tags = [
                    TAG_NONCE,
                    TAG_MERGE_MINING,
                    TAG_ADDITIONAL_PUBKEYS,
                    TAG_MINERGATE,
                ];
                let mut out = vec![tags[rng.below(4) as usize]];
                match rng.below(6) {
                    0 => out.extend(std::iter::repeat_n(0x80u8, rng.below(12) as usize)),
                    1 => {
                        out.extend(std::iter::repeat_n(0xffu8, 9));
                        out.push(rng.byte());
                    }
                    2 => out.extend([0x80, 0x00]),
                    3 => push_varint(rng.next_u64(), &mut out),
                    4 => push_varint(rng.below(300), &mut out),
                    _ => out.push(rng.byte()),
                }
                out.extend(rng.bytes_upto(70));
                out
            }
            // Padding torture around the 254/255 boundary.
            _ => {
                let zeros = 250 + rng.below(8) as usize;
                let mut out = vec![TAG_PADDING];
                out.extend(std::iter::repeat_n(0u8, zeros));
                if rng.below(4) == 0 {
                    out.push(rng.byte() | 1);
                }
                out
            }
        })
    }

    /// The stand-in for a fuzz target.
    ///
    /// cargo-fuzz is not set up and cannot be installed offline: `cargo install
    /// cargo-fuzz --offline` fails with "could not find `cargo-fuzz` in
    /// registry `crates-io`", and libFuzzer needs a nightly toolchain, which is
    /// not among the installed ones. So the fuzzing lives here: a
    /// fixed-seed generator walks a large structured corpus, every input has to
    /// come back obeying [`check_invariants`], and every input that was built
    /// out of known fields has to decode back to exactly those fields — values
    /// included, not just tags and counts. Deterministic, so a failure is
    /// reproducible from the seed printed in the assertion.
    #[test]
    fn a_structured_random_corpus_stays_total_and_returns_the_values_it_was_built_from() {
        let mut complete = 0usize;
        let mut failed = 0usize;
        let mut value_checked = 0usize;
        let mut wide_depths = 0usize;
        let mut tags_seen = [false; 6];

        for seed in 1..=8u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            for case in 0..25_000 {
                let generated = structured_input(&mut rng);
                let extra = &generated.extra;
                let parsed = check_invariants(extra);
                if parsed.is_complete() {
                    complete += 1
                } else {
                    failed += 1
                }

                if let Some(expected) = &generated.expected {
                    value_checked += 1;
                    wide_depths += expected
                        .iter()
                        .filter(|f| {
                            matches!(f, TxExtraField::MergeMining { depth, .. } if *depth > u64::from(u32::MAX))
                        })
                        .count();
                    assert!(
                        parsed.is_complete(),
                        "seed {seed} case {case}: {:?}",
                        parsed.error()
                    );
                    assert_eq!(
                        parsed.fields(),
                        expected.as_slice(),
                        "seed {seed} case {case}: {} decoded to different values",
                        crate::hex::encode(extra)
                    );
                }

                for field in parsed.fields() {
                    let index = match field.tag() {
                        TAG_MINERGATE => 5,
                        other => usize::from(other),
                    };
                    if let Some(slot) = tags_seen.get_mut(index) {
                        *slot = true;
                    }
                }
            }
        }

        // A corpus that never reaches the interesting states would pass
        // vacuously, so assert the coverage too. `wide_depths` is the one that
        // keeps the value check honest: a merge-mining depth above 2^32 is the
        // only thing that can tell a u64 depth from a u32 one, and without it
        // the assertion above would hold for a parser that truncates every
        // depth it decodes.
        assert!(
            tags_seen.iter().all(|seen| *seen),
            "corpus missed a tag: {tags_seen:?}"
        );
        assert!(complete > 10_000, "only {complete} inputs parsed whole");
        assert!(failed > 10_000, "only {failed} inputs were rejected");
        assert!(
            value_checked > 10_000,
            "only {value_checked} inputs had known values"
        );
        assert!(
            wide_depths > 1_000,
            "only {wide_depths} depths exceeded 2^32"
        );
    }

    #[test]
    fn every_short_input_stays_total() {
        // Exhaustive over one and two bytes, and over three bytes behind every
        // tag that means something (plus one that does not). 524,544 cases.
        for first in 0..=u8::MAX {
            check_invariants(&[first]);
            for second in 0..=u8::MAX {
                check_invariants(&[first, second]);
            }
        }
        for tag in [
            TAG_PADDING,
            TAG_PUBKEY,
            TAG_NONCE,
            TAG_MERGE_MINING,
            TAG_ADDITIONAL_PUBKEYS,
            0x05,
            TAG_MINERGATE,
        ] {
            for second in 0..=u8::MAX {
                for third in 0..=u8::MAX {
                    check_invariants(&[tag, second, third]);
                }
            }
        }
    }

    // ----------------------------------------------------- opt-in cross-checks

    fn curl_json(url: &str, body: &str) -> Option<serde_json::Value> {
        let output = std::process::Command::new("curl")
            .args([
                "-s",
                "-m",
                "30",
                "-X",
                "POST",
                url,
                "-H",
                "Content-Type: application/json",
                "-d",
                body,
            ])
            .output()
            .ok()?;
        serde_json::from_slice(&output.stdout).ok()
    }

    fn live_block_extras(port: u16, height: u64) -> Vec<Vec<u8>> {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"0","method":"get_block","params":{{"height":{height}}}}}"#
        );
        let mut out = Vec::new();
        if let Some(value) = curl_json(&format!("http://127.0.0.1:{port}/json_rpc"), &body) {
            collect_extras(&value, 0, &mut out);
        }
        out
    }

    fn live_tx_extras(port: u16, hashes: &[String]) -> Vec<Vec<u8>> {
        let list = hashes
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(r#"{{"txs_hashes":[{list}],"decode_as_json":true}}"#);
        let mut out = Vec::new();
        if let Some(value) = curl_json(&format!("http://127.0.0.1:{port}/get_transactions"), &body)
        {
            collect_extras(&value, 0, &mut out);
        }
        out
    }

    fn live_block_tx_hashes(port: u16, height: u64) -> Vec<String> {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"0","method":"get_block","params":{{"height":{height}}}}}"#
        );
        let Some(value) = curl_json(&format!("http://127.0.0.1:{port}/json_rpc"), &body) else {
            return Vec::new();
        };
        let Some(text) = value.pointer("/result/json").and_then(|v| v.as_str()) else {
            return Vec::new();
        };
        let Ok(block) = serde_json::from_str::<serde_json::Value>(text) else {
            return Vec::new();
        };
        block
            .get("tx_hashes")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The whole of the testnet chain's tx_extra surface: the 14 non-coinbase
    /// transactions and the coinbases of the blocks holding them.
    #[test]
    #[ignore = "needs the local testnet node on 127.0.0.1:28081"]
    fn live_testnet_extras_all_decode() {
        const HEIGHTS: [u64; 14] = [
            3640, 3733, 3815, 3900, 3989, 4074, 4157, 4240, 4325, 4418, 4502, 4590, 5636, 134_721,
        ];
        let mut decoded = 0usize;
        for height in HEIGHTS {
            let mut extras = live_block_extras(28081, height);
            let hashes = live_block_tx_hashes(28081, height);
            assert!(
                !hashes.is_empty(),
                "block {height} should hold a transaction"
            );
            extras.extend(live_tx_extras(28081, &hashes));
            assert!(!extras.is_empty(), "block {height} returned no extra");
            for extra in &extras {
                let parsed = parse(extra);
                assert!(
                    parsed.is_complete(),
                    "{}: {:?}",
                    crate::hex::encode(extra),
                    parsed.error()
                );
                // The testnet chain predates everything but the pubkey tag.
                assert_eq!(parsed.fields().len(), 1);
                assert!(parsed.tx_pub_key().is_some());
                decoded += 1;
            }
        }
        assert!(decoded >= 28, "decoded only {decoded} testnet extras");
    }

    /// A walk over live mainnet, which is where the interesting tags live.
    #[test]
    #[ignore = "needs the local mainnet node on 127.0.0.1:18081"]
    fn live_mainnet_extras_all_decode() {
        let mut decoded = 0usize;
        let mut failures = Vec::new();
        let mut height = 61_190u64;
        for _ in 0..40 {
            let mut extras = live_block_extras(18081, height);
            let hashes = live_block_tx_hashes(18081, height);
            if !hashes.is_empty() {
                extras.extend(live_tx_extras(18081, &hashes));
            }
            for extra in &extras {
                let parsed = parse(extra);
                if !parsed.is_complete() {
                    failures.push(crate::hex::encode(extra));
                }
                decoded += 1;
            }
            height = height.wrapping_mul(2_654_435_761) % 2_000_000 + 1;
        }
        assert!(decoded > 40, "decoded only {decoded} mainnet extras");
        assert!(
            failures.is_empty(),
            "{} failed: {failures:?}",
            failures.len()
        );
    }

    /// Run one batch of blobs through the C++ oracle and compare its rendering
    /// of each against [`oracle_line`], returning (compared, mismatched).
    ///
    /// Batched rather than one-shot so that a long soak is bounded in memory:
    /// at 50 million inputs, holding them all would cost gigabytes.
    fn compare_against_oracle(oracle: &Path, inputs: &[Vec<u8>]) -> (usize, usize) {
        use std::io::Write as _;

        // Named per process: a second test run sharing one fixed path would
        // feed this one somebody else's blobs and report their mismatches.
        let path = std::env::temp_dir().join(format!(
            "oxblocks-txextra-difffuzz-{}.hex",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).expect("temp file");
        for extra in inputs {
            writeln!(file, "{}", crate::hex::encode(extra)).expect("write");
        }
        drop(file);

        let stdin = std::fs::File::open(&path).expect("temp file reopens");
        let output = std::process::Command::new(oracle)
            .stdin(stdin)
            .output()
            .expect("oracle runs");
        let stdout = String::from_utf8(output.stdout).expect("oracle output is utf-8");
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), inputs.len());

        let mut mismatches = 0usize;
        for (extra, expected) in inputs.iter().zip(lines) {
            let ours = oracle_line(extra);
            if ours != expected {
                mismatches += 1;
                if mismatches <= 10 {
                    println!(
                        "MISMATCH {}\n  ours: {ours}\n  cpp:  {expected}",
                        crate::hex::encode(extra)
                    );
                }
            }
        }
        (inputs.len(), mismatches)
    }

    /// Differential test against the C++ parser itself.
    ///
    /// `tools/txextra-oracle/batch` is a verbatim copy of monerod's
    /// `parse_tx_extra` compiled against Monero's own serialization headers. It
    /// is not built by cargo, so this is opt-in; when it is present, this is the
    /// only test here that can catch a shared misreading of the spec.
    ///
    /// Both sides render every decoded value (see [`oracle_line`]), so a
    /// disagreement about a depth, a key or a nonce byte is a mismatch and not
    /// just a coincidence of field counts.
    ///
    /// `OXBLOCKS_TXEXTRA_DIFF_SEEDS` sets how many 25,000-input generations to
    /// run; the default of 4 keeps an opt-in run at a few seconds, and a soak
    /// is `OXBLOCKS_TXEXTRA_DIFF_SEEDS=2000` for 50 million inputs.
    #[test]
    #[ignore = "needs tools/txextra-oracle/batch (see tools/txextra-oracle/build.sh)"]
    fn differential_against_the_cpp_oracle() {
        let oracle = repo_root().join("tools/txextra-oracle/batch");
        assert!(
            oracle.exists(),
            "build the oracle first: {}",
            oracle.display()
        );

        let seeds: u64 = std::env::var("OXBLOCKS_TXEXTRA_DIFF_SEEDS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(4);

        // The harness reads one hex blob per line, so an empty blob is not
        // expressible; it is covered by its own test.
        let corpus: Vec<Vec<u8>> = SYNTHETIC_CORPUS
            .iter()
            .chain(REAL_CORPUS.iter())
            .map(|(hex_str, _)| bytes(hex_str))
            .filter(|extra| !extra.is_empty())
            .collect();
        let (mut compared, mut mismatches) = compare_against_oracle(&oracle, &corpus);

        for seed in 1..=seeds {
            let mut rng = Rng::new(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let chunk: Vec<Vec<u8>> = (0..25_000)
                .map(|_| structured_input(&mut rng).extra)
                .filter(|extra| !extra.is_empty())
                .collect();
            let (n, bad) = compare_against_oracle(&oracle, &chunk);
            compared += n;
            mismatches += bad;
        }

        println!("compared {compared} inputs against the C++ parser");
        assert_eq!(mismatches, 0, "{mismatches} of {compared} inputs disagree");
    }

    /// The same differential, over bytes the chain actually contains.
    ///
    /// The generated corpus above is far broader, but it is a guess at what
    /// `tx_extra` looks like; this one cannot be. Values, not counts, so a
    /// pubkey or payment id rendered from the wrong 32 bytes is a mismatch.
    #[test]
    #[ignore = "needs the local mainnet node on 127.0.0.1:18081 and tools/txextra-oracle/batch"]
    fn live_mainnet_extras_match_the_cpp_oracle() {
        let oracle = repo_root().join("tools/txextra-oracle/batch");
        assert!(
            oracle.exists(),
            "build the oracle first: {}",
            oracle.display()
        );

        // The same walk as `live_mainnet_extras_all_decode`, which reaches the
        // eras with merge-mining, minergate and padding fields in them.
        let mut extras = Vec::new();
        let mut height = 61_190u64;
        for _ in 0..40 {
            extras.extend(live_block_extras(18081, height));
            let hashes = live_block_tx_hashes(18081, height);
            if !hashes.is_empty() {
                extras.extend(live_tx_extras(18081, &hashes));
            }
            height = height.wrapping_mul(2_654_435_761) % 2_000_000 + 1;
        }
        extras.retain(|extra| !extra.is_empty());
        assert!(
            extras.len() > 40,
            "collected only {} live extras",
            extras.len()
        );

        let (compared, mismatches) = compare_against_oracle(&oracle, &extras);
        println!("compared {compared} live mainnet extras against the C++ parser");
        assert_eq!(
            mismatches, 0,
            "{mismatches} of {compared} live extras disagree"
        );
    }

    // -----------------------------------------------------------------------
    // Mutation-derived regressions.
    //
    // Each test below exists because a mutation tester introduced wrong code at
    // this exact spot and the whole suite still passed. The mutation is named in
    // each comment. Assertions here must fail under it -- so they pin VALUES,
    // not shapes: every one of these survived precisely because the old
    // assertions checked a width, a count, or a mere presence.
    // -----------------------------------------------------------------------

    /// S1, S2, S3: the differential oracle compares decoded values only, so
    /// which error a failure reports, and where, is outside it entirely. Three
    /// separate arms could report the wrong offset or the wrong kind unnoticed.
    ///
    /// Every error-producing arm pins both here.
    #[test]
    fn every_failing_arm_pins_both_its_kind_and_its_offset() {
        let long_root = "33".repeat(32);
        let cases: Vec<(String, TxExtraErrorKind, usize)> = vec![
            // S1: nonce declares 16 bytes, one follows. Offset is the length
            // byte, not the tag.
            ("021000".to_owned(), TxExtraErrorKind::LengthBeyondEnd, 2),
            // S2: a public key one byte short.
            (
                format!("01{}", "aa".repeat(31)),
                TxExtraErrorKind::TruncatedPubKey,
                1,
            ),
            // S3: a merge-mining blob with one byte too many. Must be
            // MergeMiningBlob -- "not exactly a depth varint plus 32 bytes" --
            // and not the generic length error.
            (
                format!("032200{long_root}ff"),
                TxExtraErrorKind::MergeMiningBlob,
                36,
            ),
            ("000000ff".to_owned(), TxExtraErrorKind::PaddingNonZero, 3),
            ("ff".to_owned(), TxExtraErrorKind::UnknownTag(0xff), 0),
            (
                format!("0404{}", "aa".repeat(64)),
                TxExtraErrorKind::TruncatedAdditionalKeys,
                66,
            ),
        ];

        for (hex_str, kind, offset) in cases {
            let parsed = parse(&bytes(&hex_str));
            let err = parsed
                .error()
                .unwrap_or_else(|| panic!("{hex_str} should not parse"));
            assert_eq!(err.kind, kind, "wrong error kind for {hex_str}");
            assert_eq!(err.offset, offset, "wrong error offset for {hex_str}");
        }
    }

    /// S10: the rendered message is what an operator actually reads, and
    /// nothing asserted it. Dropping `{offset}` from the format string left
    /// every test passing.
    #[test]
    fn the_rendered_error_message_carries_both_the_reason_and_the_byte() {
        let err = parse(&bytes("021000")).error().expect("does not parse");
        let rendered = err.to_string();
        assert_eq!(
            rendered,
            "tx_extra: declared length runs past the end of the blob at byte 2"
        );

        // And each kind renders its own reason, so one cannot be swapped for
        // another without this failing.
        assert_eq!(
            parse(&bytes("ff"))
                .error()
                .expect("does not parse")
                .to_string(),
            "tx_extra: unknown field tag 0xff at byte 0"
        );
    }

    /// S4: `merge_mining_tag()` takes the *first* 0x03 field, matching
    /// monerod's `find_tx_extra_field_by_type`. Switching it to `.last()`
    /// survived because no vector anywhere contained two merge-mining fields.
    #[test]
    fn the_merge_mining_tag_is_the_first_one_when_several_exist() {
        let first = "33".repeat(32);
        let second = "44".repeat(32);
        let parsed = parse(&bytes(&format!("032100{first}032100{second}")));

        assert_eq!(parsed.merge_mining_tags().count(), 2, "both must parse");
        let (depth, root) = parsed.merge_mining_tag().expect("a tag is present");
        assert_eq!(depth, 0);
        assert_eq!(
            root.to_hex(),
            first,
            "monerod returns the first merge-mining field; .last() must fail here"
        );
    }

    /// S5: `minergate_fields()` documents "in order". Reversing the iterator
    /// survived because the only multi-field vector held three *identical*
    /// empty payloads, which makes order unobservable.
    #[test]
    fn minergate_fields_come_back_in_the_order_they_appear() {
        let parsed = parse(&bytes("de02aaaade02bbbb"));
        let seen: Vec<String> = parsed.minergate_fields().map(crate::hex::encode).collect();
        assert_eq!(
            seen,
            vec!["aaaa".to_owned(), "bbbb".to_owned()],
            "distinct payloads, so a reversed iterator cannot hide"
        );
    }

    /// S6, the most damaging survivor: adding one line to `pub_keys()` made it
    /// yield additional (0x04) keys too, so `tx_pub_key_explorer_compat()`
    /// returned an additional key instead of the transaction public key -- on
    /// real mainnet data, and the entire workspace suite still passed.
    ///
    /// That value is what the transaction page prints.
    #[test]
    fn the_tx_public_key_is_never_confused_with_an_additional_one() {
        // mainnet tx d257fc1b…5778, laid out `01 <key> 04 04 <4 keys>`.
        let parsed = parse(&bytes(REAL_CORPUS[3].0));

        let expected_tx_key = "776265b0e273694de887932cc21bc18942e59a3c2ca6f78b3a8fc5986b7fe47f";
        let first_additional = "53da502b78b9e2a1ddc58541bdb16c90a5b204c02bf2998db5c1dbc7d25c2d5a";

        let keys: Vec<String> = parsed.pub_keys().map(Hash32::to_hex).collect();
        assert_eq!(
            keys,
            vec![expected_tx_key.to_owned()],
            "pub_keys() covers 0x01 only; this document has exactly one"
        );

        assert_eq!(
            parsed.tx_pub_key_explorer_compat().map(Hash32::to_hex),
            Some(expected_tx_key.to_owned())
        );
        assert_eq!(
            parsed.tx_pub_key().map(Hash32::to_hex),
            Some(expected_tx_key.to_owned())
        );

        // The additional keys are reachable, but only through their own
        // accessor, and the first of them is explicitly not the tx key.
        assert_eq!(parsed.additional_pub_keys().len(), 4);
        assert_eq!(parsed.additional_pub_keys()[0].to_hex(), first_additional);
        assert_ne!(expected_tx_key, first_additional);
    }

    /// S7, S8: every existing test compared a `PaymentId::Long` by enum
    /// equality, so its two renderings were unasserted. Truncating either to 16
    /// characters -- a payment id a user could never match against their own --
    /// passed.
    #[test]
    fn a_long_payment_id_renders_all_sixty_four_characters() {
        // mainnet tx e8256130…3d2a carries an unencrypted 32-byte payment id.
        let parsed = parse(&bytes(REAL_CORPUS[1].0));
        let id = parsed.payment_id().expect("a payment id is present");

        let expected = "2715536cb0e7c24faeb02b6659dbdae5d701da922cc1034846695b72157a4b65";
        assert!(!id.is_encrypted());
        assert_eq!(id.to_hex(), expected);
        assert_eq!(id.to_hex().len(), 64);
        // Display and to_hex are separate code paths and must not diverge.
        assert_eq!(format!("{id}"), expected);
    }

    /// The encrypted form renders its own 16, so the two variants cannot be
    /// collapsed into one another.
    #[test]
    fn an_encrypted_payment_id_renders_all_sixteen_characters() {
        let parsed = parse(&bytes(REAL_CORPUS[0].0));
        let id = parsed.payment_id().expect("a payment id is present");
        assert!(id.is_encrypted());
        assert_eq!(id.to_hex(), "55e10418dec2fd58");
        assert_eq!(format!("{id}"), "55e10418dec2fd58");
    }

    /// S9: `TxExtraField`'s Debug is only ever seen inside assertion failure
    /// messages, so nothing checked it -- including the property its own doc
    /// comment calls load-bearing. Rendering a nonce as `[222, 173, 190, 239]`
    /// passed the whole suite.
    #[test]
    fn debug_renders_byte_payloads_as_hex_not_as_decimal_lists() {
        let parsed = parse(&bytes("0204deadbeef"));
        let rendered = format!("{:?}", parsed.fields());
        assert_eq!(rendered, "[Nonce(deadbeef)]");
        assert!(
            !rendered.contains("222"),
            "a nonce printed as decimal integers cannot be compared \
             against anything an operator has to hand"
        );
    }
}
