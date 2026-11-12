//! The vocabulary the web layer uses to ask about the chain: what a block is
//! identified by, what a resolved ring member looks like, and how a lookup can
//! fail.
//!
//! Deliberately free of anything monerod-specific, so these types describe the
//! question rather than the daemon that answers it.
//! [`crate::rpc_source::RpcChainSource`] is the one thing that answers them.

use crate::hash::Hash32;

/// How a block was asked for.
///
/// monerod's `get_block` takes *either* a height or a hash and silently prefers
/// the hash when both are set, so the two are kept mutually exclusive here
/// rather than as two optional fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockId {
    Height(u64),
    Hash(Hash32),
}

/// Why a path argument is not a block identifier.
///
/// Carries which shape was attempted so each front end can word its own
/// message; the dispatch itself is shared, because two copies of it had
/// already drifted apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockIdError {
    /// Short enough to be a height, but not a number.
    NotAHeight,
    /// The right length for a hash, but not hex.
    NotAHash,
    /// Neither shape.
    Unrecognised,
}

impl BlockId {
    /// Parse a path argument: eight digits or fewer is a height, exactly 64
    /// hex characters is a hash, anything else is rejected.
    ///
    /// Nothing is stripped or repaired first, so `1,23` is an error rather
    /// than height 123.
    ///
    /// The eight-character bound is on the *text* rather than the value --
    /// `99999999` parses and `100000000` does not, which will matter around
    /// block 100,000,000 and not before.
    pub fn parse(arg: &str) -> Result<Self, BlockIdError> {
        if arg.len() == crate::hash::HASH_HEX_LEN {
            arg.parse::<Hash32>()
                .map(Self::Hash)
                .map_err(|_| BlockIdError::NotAHash)
        } else if arg.len() <= 8 {
            crate::fmt::decimal(arg)
                .map(Self::Height)
                .ok_or(BlockIdError::NotAHeight)
        } else {
            Err(BlockIdError::Unrecognised)
        }
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Height(h) => write!(f, "{h}"),
            Self::Hash(h) => write!(f, "{h}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("no block {0}")]
    BlockNotFound(BlockId),

    /// The daemon could not be reached, or is still syncing. Callers should
    /// treat this as temporary.
    #[error("monerod is unavailable: {0}")]
    Unavailable(String),

    /// The call needs an unrestricted daemon and this one is restricted.
    ///
    /// monerod blocks `get_alternate_chains`, `get_coinbase_tx_sum` and
    /// `/get_alt_blocks_hashes` under
    /// `--restricted-rpc`, so these pages are unavailable by configuration
    /// rather than broken.
    #[error("{0} requires an unrestricted monerod")]
    NeedsUnrestricted(&'static str),

    /// The daemon answered, but not with the shape the call expects.
    #[error("the daemon's answer to {what} could not be read: {detail}")]
    BadAnswer { what: &'static str, detail: String },

    /// A range of blocks holds more than one request may fetch. See
    /// [`crate::rpc_source::MAX_RANGE_KIB`].
    #[error("blocks {start} to {end} hold {kib} KiB, more than one request may fetch")]
    RangeTooLarge { start: u64, end: u64, kib: u64 },

    /// The explorer is holding as much as it may, and the request waited
    /// its turn for too long. Callers should treat this as temporary.
    #[error("the explorer is busy: {0}")]
    Busy(&'static str),

    #[error(transparent)]
    Rpc(#[from] monerod_rpc::RpcError),
}

impl ChainError {
    /// Whether retrying later might succeed.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Unavailable(_) | Self::Busy(_) => true,
            Self::Rpc(e) => e.is_transient(),
            _ => false,
        }
    }

    /// Whether this is the caller's fault (a bad hash, a height past the tip)
    /// rather than ours. Drives 4xx versus 5xx at the web layer.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::BlockNotFound(_))
    }

    /// A message safe to return to an unauthenticated client.
    ///
    /// [`Display`] must not be: it includes the transport error, which
    /// carries the daemon's URL. Before this existed, an unreachable daemon
    /// answered a public request with
    /// `error sending request for url (http://127.0.0.1:19999/json_rpc)`,
    /// disclosing the address of an internal service. In a deployment where
    /// the daemon is on an internal hostname, that is network topology handed
    /// to anyone who can make a request while the node happens to be down.
    ///
    /// Log [`Display`] instead; it is intended for the operator, who is
    /// allowed to know where their own daemon is.
    ///
    /// [`Display`]: std::fmt::Display
    #[must_use]
    pub fn public_message(&self) -> String {
        match self {
            // These name only what the caller already asked for.
            Self::BlockNotFound(id) => format!("no block {id}"),
            Self::NeedsUnrestricted(what) => {
                format!("{what} requires an unrestricted monerod")
            }
            Self::BadAnswer { what, .. } => {
                format!("the daemon's answer to {what} could not be read")
            }
            Self::RangeTooLarge { start, end, kib } => format!(
                "blocks {start} to {end} hold {} MiB, more than one request may fetch; \
                 ask for fewer blocks",
                kib.div_ceil(1024)
            ),
            Self::Busy(what) => format!("the explorer is busy with {what}; try again shortly"),
            // These carry internals. Say what happened, not where.
            Self::Unavailable(_) | Self::Rpc(monerod_rpc::RpcError::Transport { .. }) => {
                "the explorer could not reach its daemon".to_owned()
            }
            Self::Rpc(_) => "the explorer's daemon gave an answer it could not use".to_owned(),
        }
    }
}

/// One ring member, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingMember {
    /// The global (or per-denomination, pre-RingCT) output index this offset
    /// resolved to.
    pub index: u64,
    pub block_height: u64,
    pub public_key: Hash32,
    pub tx_hash: Hash32,
}

/// A transaction input together with its resolved ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInput {
    /// Zero for RingCT, the denomination for pre-RingCT.
    pub amount: u64,
    pub key_image: Hash32,
    /// Empty when the ring could not be resolved, and for every input of an
    /// FCMP++ transaction, which proves membership in the curve tree as of its
    /// reference block instead of naming a ring. `ring_unavailable` tells the two apart.
    ///
    /// monerod fails an entire `/get_outs` batch if any one index is out of
    /// range, so one unresolvable input must not blank the whole page. That
    /// input's ring is dropped and the rest are rendered.
    pub ring: Vec<RingMember>,
    /// True when the ring is not being reported: either monerod refused the
    /// lookup, or the endpoint deliberately did not ask for one. Rendered as
    /// `"mixins": null` rather than `[]`, because an empty list would claim
    /// the input has no ring members.
    pub ring_unavailable: bool,
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

    #[test]
    fn block_id_renders_the_way_a_user_typed_it() {
        assert_eq!(BlockId::Height(1234).to_string(), "1234");
        let h: Hash32 = "d29c51c4354a396f370335035540fc94372bd277c2f65b50cc5bd2608a92c69c"
            .parse()
            .unwrap();
        assert_eq!(
            BlockId::Hash(h).to_string(),
            "d29c51c4354a396f370335035540fc94372bd277c2f65b50cc5bd2608a92c69c"
        );
    }

    #[test]
    fn parsing_dispatches_on_the_shape_of_the_argument() {
        assert_eq!(BlockId::parse("0"), Ok(BlockId::Height(0)));
        assert_eq!(BlockId::parse("2000000"), Ok(BlockId::Height(2_000_000)));
        assert_eq!(BlockId::parse("99999999"), Ok(BlockId::Height(99_999_999)));

        let hash = "dc2ef85b049311814742f543469e3ec1b8d589e68434d9f220ce41072c69c39e";
        assert!(matches!(BlockId::parse(hash), Ok(BlockId::Hash(_))));
        // Uppercase is accepted.
        assert!(matches!(
            BlockId::parse(&hash.to_uppercase()),
            Ok(BlockId::Hash(_))
        ));
    }

    #[test]
    fn parsing_rejects_each_wrong_shape_distinctly() {
        assert_eq!(BlockId::parse("abc"), Err(BlockIdError::NotAHeight));
        assert_eq!(BlockId::parse(""), Err(BlockIdError::NotAHeight));
        // 64 characters, not all hex.
        assert_eq!(BlockId::parse(&"z".repeat(64)), Err(BlockIdError::NotAHash));
        // Neither a height nor a hash length. Two copies of this dispatch had
        // already disagreed here: one tried to parse anything longer than 8 as
        // a hash, the other required exactly 64.
        assert_eq!(
            BlockId::parse(&"a".repeat(9)),
            Err(BlockIdError::Unrecognised)
        );
        assert_eq!(
            BlockId::parse(&"a".repeat(63)),
            Err(BlockIdError::Unrecognised)
        );
        assert_eq!(
            BlockId::parse(&"a".repeat(65)),
            Err(BlockIdError::Unrecognised)
        );
        // 100000000 is nine characters, so it is too long to be a height.
        assert_eq!(BlockId::parse("100000000"), Err(BlockIdError::Unrecognised));
    }

    #[test]
    fn not_found_is_distinguished_from_unavailable() {
        let nf = ChainError::BlockNotFound(BlockId::Height(9));
        assert!(nf.is_not_found());
        assert!(!nf.is_transient());

        let un = ChainError::Unavailable("syncing".into());
        assert!(!un.is_not_found());
        assert!(
            un.is_transient(),
            "a syncing node must read as retry-later, not as a missing block"
        );
    }

    /// The leak this method exists to prevent.
    #[test]
    fn a_public_message_never_carries_the_daemon_address() {
        let transport = ChainError::Unavailable(
            "error sending request for url (http://monerod.internal:18081/json_rpc)".to_owned(),
        );

        let public = transport.public_message();
        assert!(!public.contains("monerod.internal"));
        assert!(!public.contains("18081"));
        assert!(!public.contains("http"));

        // The operator still gets the detail, through Display.
        assert!(transport.to_string().contains("monerod.internal"));
    }

    /// A not-found message may name what was asked for: the caller supplied it.
    #[test]
    fn a_public_message_may_echo_what_was_asked_for() {
        let e = ChainError::BlockNotFound(BlockId::Height(12345));
        assert!(e.public_message().contains("12345"));
    }

    #[test]
    fn a_restricted_daemon_is_neither_not_found_nor_transient() {
        // Retrying will not help, and the resource does exist -- it is a
        // deployment choice, and the message should say so.
        let e = ChainError::NeedsUnrestricted("the mempool");
        assert!(!e.is_not_found());
        assert!(!e.is_transient());
        assert!(e.to_string().contains("unrestricted"));
    }
}
