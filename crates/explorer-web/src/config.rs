//! Command line configuration.

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};

/// Which palette the stylesheet carries.
///
/// A per-reader toggle would need a cookie or a script, and this explorer
/// serves neither, so the choice is the operator's: `auto` hands it back to
/// the reader's browser, the other two pin it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Theme {
    /// Follow the reader's `prefers-color-scheme`.
    #[default]
    Auto,
    Light,
    Dark,
}

/// Default bounds on the k-anonymous endpoints.
///
/// Every one of these is a trade between how well a caller hides and what the
/// request costs the daemon, so an operator who knows their own chain and
/// hardware should be able to move it.
pub const DEFAULT_POSTFIX_MIN: usize = 2;
pub const DEFAULT_POSTFIX_MAX: usize = 12;
pub const DEFAULT_BLOCK_RANGE: u64 = 100;
pub const DEFAULT_RECENT_BLOCKS: u64 = 30;

/// A transaction hash written out, and so the longest postfix that can match
/// anything at all.
const HASH_TEXT_LEN: usize = 64;

/// The bounds the k-anonymous endpoints enforce.
///
/// Carried on the shared state rather than read from constants, so that the
/// endpoints and the documentation page cannot disagree about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub postfix_min: usize,
    pub postfix_max: usize,
    pub block_range: u64,
    pub recent_blocks: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            postfix_min: DEFAULT_POSTFIX_MIN,
            postfix_max: DEFAULT_POSTFIX_MAX,
            block_range: DEFAULT_BLOCK_RANGE,
            recent_blocks: DEFAULT_RECENT_BLOCKS,
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "oxblocks",
    version,
    about = "A memory-safe Monero block explorer for monerod",
    long_about = None
)]
pub struct Config {
    /// monerod RPC URL. Must be an UNRESTRICTED daemon.
    ///
    /// Under `--restricted-rpc` monerod blocks get_alternate_chains and
    /// get_alt_blocks_hashes, which removes the alt-block pages.
    #[arg(
        long,
        env = "OXBLOCKS_DAEMON_URL",
        default_value = "http://127.0.0.1:18081"
    )]
    pub daemon_url: String,

    /// SHA-256 of the daemon's TLS certificate, in hex, colons allowed.
    ///
    /// For an `https://` daemon whose certificate no public CA signed, as
    /// monerod's own is: that certificate is trusted, and no other.
    #[arg(long, env = "OXBLOCKS_DAEMON_CERT_SHA256", value_parser = sha256_hex)]
    pub daemon_cert_sha256: Option<[u8; 32]>,

    /// Address to listen on.
    #[arg(long, env = "OXBLOCKS_BIND", default_value = "127.0.0.1:8081")]
    pub bind: SocketAddr,

    /// Seconds to wait on a single monerod RPC call.
    #[arg(long, env = "OXBLOCKS_RPC_TIMEOUT", default_value_t = 30)]
    pub rpc_timeout_secs: u64,

    /// Seconds before an inbound HTTP request is abandoned.
    ///
    /// Held below the RPC timeout on purpose: a request that has already
    /// outlived its own deadline should not keep an RPC call alive.
    #[arg(long, env = "OXBLOCKS_REQUEST_TIMEOUT", default_value_t = 25)]
    pub request_timeout_secs: u64,

    /// Maximum number of requests processed concurrently, across every route.
    ///
    /// This is the backpressure valve. Every request costs RPC calls,
    /// so an unbounded server would turn a traffic spike into a self-inflicted
    /// denial of service against its own daemon. A request that finds every
    /// slot taken waits for one within its timeout, and is answered 504 when
    /// the timeout passes first. At least 1: with none, every request would
    /// wait out its timeout.
    #[arg(
        long,
        env = "OXBLOCKS_MAX_CONCURRENT",
        default_value_t = 128,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub max_concurrent: usize,

    /// Maximum RPC calls in flight against monerod at once.
    ///
    /// The other half of `--max-concurrent`, and the one that protects the
    /// daemon rather than this process. monerod answers RPC on a bounded
    /// thread pool shared with its peer-to-peer duties, so a burst of requests
    /// here degrades the node itself. Requests that cannot get a slot queue in
    /// front of the daemon rather than stampeding it, and the inbound request
    /// timeout eventually sheds them. At least 1.
    ///
    /// Keep it under monerod's own per-address connection limit, past which
    /// it drops connections: `--rpc-max-connections-per-private-ip`, 25 by
    /// default, or `--rpc-max-connections-per-public-ip`, 3 by default, for
    /// a daemon reached over a public address.
    #[arg(
        long,
        env = "OXBLOCKS_MAX_INFLIGHT_RPC",
        default_value_t = explorer_core::DEFAULT_MAX_INFLIGHT_RPC,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub max_inflight_rpc: usize,

    /// Maximum accepted request body size, in bytes.
    ///
    /// Every route is a GET. This exists to make that explicit rather than
    /// relying on it.
    #[arg(long, env = "OXBLOCKS_MAX_BODY", default_value_t = 8 * 1024)]
    pub max_body_bytes: usize,

    /// Largest answer accepted from monerod, in MiB.
    ///
    /// A decoded answer takes several times its size in memory, and up to
    /// `--max-inflight-rpc` are read at once, so against a daemon you do not
    /// run, lower this. The largest real answers are `/get_transactions` for
    /// a batch of big transactions. Calls whose answers are always small have
    /// a ceiling of 1 MiB whatever this is.
    #[arg(
        long,
        env = "OXBLOCKS_MAX_RESPONSE_MIB",
        default_value_t = monerod_rpc::DEFAULT_MAX_RESPONSE_BYTES / (1024 * 1024),
        value_parser = clap::value_parser!(u64).range(1..=4096)
    )]
    pub max_response_mib: u64,

    /// Shortest transaction-hash postfix `/api/transaction/private` accepts.
    ///
    /// A shorter postfix hides the caller in a larger set and makes the daemon
    /// scan more of its transaction index to build it. The expected-match band
    /// still applies, so lowering this alone does not make a wider set servable.
    #[arg(
        long,
        env = "OXBLOCKS_POSTFIX_MIN",
        default_value_t = DEFAULT_POSTFIX_MIN,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=HASH_TEXT_LEN as u64)
    )]
    pub postfix_min: usize,

    /// Longest transaction-hash postfix `/api/transaction/private` accepts.
    ///
    /// A longer postfix names fewer transactions, so past some length it
    /// identifies one rather than hiding it. The expected-match band refuses
    /// that on its own; this is the flat ceiling beside it.
    #[arg(
        long,
        env = "OXBLOCKS_POSTFIX_MAX",
        default_value_t = DEFAULT_POSTFIX_MAX,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=HASH_TEXT_LEN as u64)
    )]
    pub postfix_max: usize,

    /// Most blocks `/api/blocks/<start>/<end>` serves in one request.
    ///
    /// The width of the set a caller hides in, and the cost of the request.
    /// Every block costs a `get_block` and its transactions are fetched whole
    /// before any are summarised, so the bytes grow with the blocks. Measured
    /// against mainnet, 100 blocks takes about 10 seconds and holds about
    /// 40 MiB, and that multiplies by `--max-concurrent`. Raise this and the
    /// memory ceiling together, or not at all.
    #[arg(
        long,
        env = "OXBLOCKS_MAX_BLOCK_RANGE",
        default_value_t = DEFAULT_BLOCK_RANGE,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_block_range: u64,

    /// How many blocks back `/api/transactions/recent` reaches.
    ///
    /// Every caller gets the same window, which is what makes asking for it
    /// reveal nothing. A wider window costs more per request; the unconfirmed
    /// pool is returned beside it either way and is not bounded by this.
    #[arg(
        long,
        env = "OXBLOCKS_RECENT_BLOCKS",
        default_value_t = DEFAULT_RECENT_BLOCKS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub recent_blocks: u64,

    /// Colour scheme: auto, light or dark.
    #[arg(long, env = "OXBLOCKS_THEME", value_enum, default_value = "auto")]
    pub theme: Theme,

    /// Log filter, e.g. "info", "oxblocks=debug,tower_http=debug".
    #[arg(long, env = "OXBLOCKS_LOG", default_value = "info")]
    pub log: String,
}

/// 32 bytes from 64 hex digits, optionally separated by colons.
fn sha256_hex(text: &str) -> Result<[u8; 32], String> {
    let digits: Vec<u8> = text.bytes().filter(|&b| b != b':').collect();
    let bad = || format!("not a SHA-256 in hex: {text}");
    if digits.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

impl Config {
    /// The configured bounds, or why they cannot be used.
    ///
    /// clap checks each one on its own. This is the pair that only makes sense
    /// together.
    pub fn limits(&self) -> Result<Limits, String> {
        if self.daemon_cert_sha256.is_some() && !self.daemon_url.starts_with("https://") {
            return Err("--daemon-cert-sha256 pins a certificate, which only an \
                 https:// --daemon-url presents"
                .to_owned());
        }
        if self.postfix_min > self.postfix_max {
            return Err(format!(
                "--postfix-min {} is above --postfix-max {}, which accepts no \
                 postfix at all",
                self.postfix_min, self.postfix_max
            ));
        }
        Ok(Limits {
            postfix_min: self.postfix_min,
            postfix_max: self.postfix_max,
            block_range: self.max_block_range,
            recent_blocks: self.recent_blocks,
        })
    }

    pub fn rpc_timeout(&self) -> Duration {
        Duration::from_secs(self.rpc_timeout_secs)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_mib * 1024 * 1024
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

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Config::command().debug_assert();
    }

    #[test]
    fn defaults_point_at_a_loopback_unrestricted_daemon() {
        let c = Config::parse_from(["oxblocks"]);
        assert_eq!(c.daemon_url, "http://127.0.0.1:18081");
        assert_eq!(c.bind.to_string(), "127.0.0.1:8081");
    }

    /// The response ceiling is the client's own unless lowered, and is
    /// given in MiB within bounds.
    #[test]
    fn the_response_ceiling_is_in_mib() {
        let c = Config::parse_from(["oxblocks"]);
        assert_eq!(
            c.max_response_bytes(),
            monerod_rpc::DEFAULT_MAX_RESPONSE_BYTES
        );
        let c = Config::parse_from(["oxblocks", "--max-response-mib", "16"]);
        assert_eq!(c.max_response_bytes(), 16 << 20);
        for bad in ["0", "4097"] {
            assert!(Config::try_parse_from(["oxblocks", "--max-response-mib", bad]).is_err());
        }
    }

    /// A pin is 32 bytes of hex, as `openssl x509 -fingerprint -sha256`
    /// prints it or bare, and only for a daemon reached over TLS.
    #[test]
    fn a_certificate_pin_is_a_sha256_for_an_https_daemon() {
        let hex = "ab".repeat(32);
        let colons = vec!["AB"; 32].join(":");
        for pin in [&hex, &colons] {
            let c = Config::parse_from([
                "oxblocks",
                "--daemon-url",
                "https://node:18081",
                "--daemon-cert-sha256",
                pin,
            ]);
            assert_eq!(c.daemon_cert_sha256, Some([0xab; 32]));
            assert!(c.limits().is_ok());
        }
        for bad in ["ab", &"zz".repeat(32), &"ab".repeat(33)] {
            assert!(
                Config::try_parse_from(["oxblocks", "--daemon-cert-sha256", bad]).is_err(),
                "{bad}"
            );
        }
        let plain = Config::parse_from(["oxblocks", "--daemon-cert-sha256", &hex]);
        assert!(plain.limits().is_err());
    }

    /// The request deadline must stay under the RPC deadline, or a client
    /// that has already given up still pins an RPC call open.
    #[test]
    fn request_timeout_is_shorter_than_rpc_timeout_by_default() {
        let c = Config::parse_from(["oxblocks"]);
        assert!(c.request_timeout() < c.rpc_timeout());
    }

    /// The daemon-side ceiling has to be reachable from the command line: it
    /// is the knob an operator turns when their node is shared with something
    /// else, and it was previously settable only from a test.
    #[test]
    fn the_inflight_rpc_ceiling_is_configurable_and_defaults_to_the_library_value() {
        let c = Config::parse_from(["oxblocks"]);
        assert_eq!(c.max_inflight_rpc, explorer_core::DEFAULT_MAX_INFLIGHT_RPC);
        let c = Config::parse_from(["oxblocks", "--max-inflight-rpc", "4"]);
        assert_eq!(c.max_inflight_rpc, 4);
    }

    /// `auto` is the only default that respects a reader's own setting; the
    /// other two exist for an operator who wants one look regardless.
    #[test]
    fn the_theme_defaults_to_the_readers_own_preference() {
        assert_eq!(Config::parse_from(["oxblocks"]).theme, Theme::Auto);
        assert_eq!(
            Config::parse_from(["oxblocks", "--theme", "light"]).theme,
            Theme::Light
        );
        assert_eq!(
            Config::parse_from(["oxblocks", "--theme", "dark"]).theme,
            Theme::Dark
        );
        assert!(Config::try_parse_from(["oxblocks", "--theme", "sepia"]).is_err());
    }

    /// The defaults are the bounds the endpoints shipped with, so an operator
    /// who sets nothing gets what the documentation describes.
    #[test]
    fn the_k_anonymity_bounds_default_to_the_shipped_values() {
        let c = Config::parse_from(["oxblocks"]);
        assert_eq!(c.limits(), Ok(Limits::default()));
        assert_eq!(
            Limits::default(),
            Limits {
                postfix_min: 2,
                postfix_max: 12,
                block_range: 100,
                recent_blocks: 30,
            }
        );
    }

    #[test]
    fn each_k_anonymity_bound_is_settable() {
        let c = Config::parse_from([
            "oxblocks",
            "--postfix-min",
            "3",
            "--postfix-max",
            "8",
            "--max-block-range",
            "25",
            "--recent-blocks",
            "5",
        ]);
        assert_eq!(
            c.limits(),
            Ok(Limits {
                postfix_min: 3,
                postfix_max: 8,
                block_range: 25,
                recent_blocks: 5,
            })
        );
    }

    /// A bound that would refuse every request, or accept one that cannot
    /// match anything, is refused at startup rather than at the first call.
    #[test]
    fn a_bound_that_serves_nothing_is_rejected() {
        for bad in [
            vec!["--postfix-min", "0"],
            vec!["--postfix-max", "0"],
            // A hash is 64 characters, so a longer postfix matches nothing.
            vec!["--postfix-max", "65"],
            vec!["--max-block-range", "0"],
            vec!["--recent-blocks", "0"],
        ] {
            let args: Vec<&str> = ["oxblocks"].into_iter().chain(bad.clone()).collect();
            assert!(
                Config::try_parse_from(&args).is_err(),
                "{bad:?} was accepted"
            );
        }

        // The pair only makes sense together, so clap cannot catch this one.
        let crossed = Config::parse_from(["oxblocks", "--postfix-min", "8", "--postfix-max", "4"]);
        assert!(crossed.limits().is_err());
    }

    #[test]
    fn a_bad_bind_address_is_rejected_rather_than_defaulted() {
        assert!(Config::try_parse_from(["oxblocks", "--bind", "not-an-address"]).is_err());
        // A limit of none would leave every request waiting out its timeout.
        for flag in ["--max-concurrent", "--max-inflight-rpc"] {
            assert!(
                Config::try_parse_from(["oxblocks", flag, "0"]).is_err(),
                "{flag}"
            );
            assert!(
                Config::try_parse_from(["oxblocks", flag, "1"]).is_ok(),
                "{flag}"
            );
        }
    }
}
