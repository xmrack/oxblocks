//! Errors produced while talking to monerod.

/// The `status` string that monerod puts on most non-JSON-RPC responses.
///
/// monerod does not use HTTP status codes to signal application failure: a
/// perfectly successful HTTP 200 can carry `"status": "Failed"`. Anything that
/// only checks the HTTP status silently treats failures as success, so every
/// response goes through here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// The daemon is still syncing and declined to answer.
    Busy,
    Failed,
    NotMining,
    Other(String),
}

/// How much of an unrecognised status is kept, in characters.
///
/// The string is remote input on its way into logs and error pages, so it is
/// bounded, and control characters are replaced so that it stays on one line.
const MAX_STATUS_CHARS: usize = 64;

/// At most `max` characters of `raw`, each control character replaced by
/// `?`: text from the daemon, on its way into an error message and a log
/// line, where a newline or an escape sequence would forge or garble one.
#[must_use]
pub(crate) fn printable(raw: &str, max: usize) -> String {
    raw.chars()
        .take(max)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The most characters of a parser's reason kept: it can quote what the
/// daemon sent, at any length.
pub(crate) const MAX_DECODE_DETAIL: usize = 256;

/// A parser's reason for refusing what the daemon sent, fit for a log line.
#[must_use]
pub(crate) fn decode_detail(e: &serde_json::Error) -> String {
    printable(&e.to_string(), MAX_DECODE_DETAIL)
}

impl RpcError {
    /// [`Self::Decode`], for `context`'s answer refused as `e`.
    #[must_use]
    pub(crate) fn decode(context: &'static str, e: &serde_json::Error) -> Self {
        Self::Decode {
            context,
            detail: decode_detail(e),
        }
    }
}

impl Status {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "OK" => Self::Ok,
            "BUSY" => Self::Busy,
            "Failed" => Self::Failed,
            "NOT MINING" => Self::NotMining,
            other => Self::Other(printable(other, MAX_STATUS_CHARS)),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => f.write_str("OK"),
            Self::Busy => f.write_str("BUSY"),
            Self::Failed => f.write_str("Failed"),
            Self::NotMining => f.write_str("NOT MINING"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

/// Why a request never produced a response, so callers can tell a daemon that
/// is briefly unreachable from one that answered with something unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// The connection could not be established.
    Connect,
    /// The deadline passed with no answer.
    Timeout,
    Other,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("could not reach monerod for {context}: {message}")]
    Transport {
        context: &'static str,
        kind: TransportKind,
        message: String,
    },

    /// The response exceeded the ceiling this client will accumulate.
    #[error("monerod's response to {context} was {len} bytes, which is too large")]
    ResponseTooLarge { context: &'static str, len: u64 },

    /// The request body could not be built. Not reachable from remote input:
    /// the bodies are this crate's own structs.
    #[error("could not encode the request for {context}: {source}")]
    Encode {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },

    /// monerod answered the JSON-RPC envelope with an `error` member.
    #[error("monerod rejected {method}: {message} (code {code})")]
    JsonRpc {
        method: &'static str,
        code: i64,
        message: String,
    },

    /// A non-JSON-RPC endpoint answered with a non-OK `status`.
    #[error("monerod answered {endpoint} with status {status}")]
    Status {
        endpoint: &'static str,
        status: Status,
    },

    /// monerod answered with a non-success HTTP status. Distinct from
    /// [`RpcError::Status`]: this is the transport refusing, not the daemon
    /// reporting. A 401 here means `--rpc-login` is set and we have no credentials.
    #[error("monerod answered {context} with HTTP {status}: {body}")]
    Http {
        context: &'static str,
        status: u16,
        body: String,
    },

    /// The parser's reason, which can quote the daemon's text, comes through
    /// [`printable`].
    /// TLS could not be set up as configured.
    #[error("TLS could not be set up: {0}")]
    Tls(String),

    /// The user agent cannot be sent as a header.
    #[error("the user agent cannot be sent: {0}")]
    BadUserAgent(String),

    #[error("could not decode monerod's response to {context}: {detail}")]
    Decode {
        context: &'static str,
        detail: String,
    },

    /// A `.bin` endpoint answered with a body that is not portable storage.
    #[error("could not decode monerod's binary response to {context}: {source}")]
    BinaryDecode {
        context: &'static str,
        #[source]
        source: crate::epee::EpeeError,
    },

    /// monerod answered, but the payload did not contain what the call promises.
    #[error("monerod's response to {context} had no {field} field")]
    Missing {
        context: &'static str,
        field: &'static str,
    },

    /// A request could not be written in epee's binary format. Not reachable
    /// from remote input: the requests are this crate's own.
    #[error("could not encode the binary request for {context}: {source}")]
    BinaryEncode {
        context: &'static str,
        #[source]
        source: crate::epee::EpeeError,
    },

    #[error("{0} is not a usable monerod URL: {1}")]
    BadUrl(String, String),
}

impl RpcError {
    /// Whether retrying the same call later might succeed.
    ///
    /// `BUSY` means the daemon is syncing, which is the normal state of a node
    /// during initial sync, so callers generally want to back off rather than
    /// surface a hard failure.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Status { status, .. } => matches!(status, Status::Busy),
            Self::Transport { kind, .. } => {
                matches!(kind, TransportKind::Timeout | TransportKind::Connect)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_the_status_strings_monerod_actually_sends() {
        assert_eq!(Status::parse("OK"), Status::Ok);
        assert_eq!(Status::parse("BUSY"), Status::Busy);
        assert_eq!(Status::parse("Failed"), Status::Failed);
        assert_eq!(Status::parse("NOT MINING"), Status::NotMining);
        assert!(Status::parse("OK").is_ok());
        assert!(!Status::parse("Failed").is_ok());
    }

    #[test]
    fn unknown_status_is_preserved_rather_than_coerced_to_ok() {
        // A future monerod status we do not know about must never read as success.
        let s = Status::parse("SOMETHING_NEW");
        assert!(!s.is_ok());
        assert_eq!(s.to_string(), "SOMETHING_NEW");
    }

    #[test]
    fn an_unknown_status_is_kept_short_and_on_one_line() {
        let long = format!("A\nB\u{1b}[31m{}", "x".repeat(10_000));
        let Status::Other(kept) = Status::parse(&long) else {
            panic!("an unknown status is Other");
        };
        assert_eq!(kept.chars().count(), MAX_STATUS_CHARS);
        assert!(kept.starts_with("A?B?[31m"), "{kept:?}");
        assert!(!kept.chars().any(char::is_control));
    }

    /// A daemon that is down or slow is worth retrying; one that answered with
    /// something unusable is not, and nor is a response too large to hold.
    #[test]
    fn only_connect_and_timeout_failures_are_worth_retrying() {
        for kind in [TransportKind::Connect, TransportKind::Timeout] {
            let e = RpcError::Transport {
                context: "get_info",
                kind,
                message: "…".to_owned(),
            };
            assert!(e.is_transient(), "{kind:?} should be retryable");
        }
        let other = RpcError::Transport {
            context: "get_info",
            kind: TransportKind::Other,
            message: "…".to_owned(),
        };
        assert!(!other.is_transient());
        assert!(
            !RpcError::ResponseTooLarge {
                context: "get_transactions",
                len: u64::MAX,
            }
            .is_transient(),
            "a response that big will be just as big next time"
        );
    }

    /// A parser's reason quotes the daemon's text: kept to one line and a
    /// bounded length however much it quotes.
    #[test]
    fn a_decode_error_neither_forges_a_line_nor_runs_on() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        enum Kind {
            A,
        }
        let forged = serde_json::from_str::<Kind>("\"x\\nINFO forged \\u001b[31m\"").unwrap_err();
        let e = RpcError::decode("get_info", &forged).to_string();
        assert!(e.contains("x?INFO forged ?[31m"), "{e}");
        assert!(!e.chars().any(char::is_control), "{e}");

        let long = format!("\"{}\"", "y".repeat(100_000));
        let huge = serde_json::from_str::<u64>(&long).unwrap_err();
        let e = RpcError::decode("get_info", &huge).to_string();
        assert!(e.len() < MAX_DECODE_DETAIL + 100, "{}", e.len());
    }

    #[test]
    fn busy_is_transient_but_failed_is_not() {
        let busy = RpcError::Status {
            endpoint: "/get_transactions",
            status: Status::Busy,
        };
        let failed = RpcError::Status {
            endpoint: "/get_transactions",
            status: Status::Failed,
        };
        assert!(busy.is_transient());
        assert!(!failed.is_transient());
    }
}
