//! Transport for the monerod daemon RPC.
//!
//! monerod exposes three calling conventions and they fail differently:
//!
//! * `POST /json_rpc` — a JSON-RPC 2.0 envelope. Failures arrive as an `error`
//!   member alongside HTTP 200.
//! * `POST /<endpoint>` — a bare JSON body (`/get_transactions`, `/get_outs`,
//!   …). Failures arrive as a `"status"` string alongside HTTP 200.
//! * `POST /<endpoint>.bin` — the same, in epee's binary format rather than
//!   JSON. Used for the one figure monerod reports only in binary; see
//!   [`crate::epee`].
//!
//! All are normalised into [`RpcError`] here so that callers never have to
//! remember which convention a given call uses.

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes};
use hyper::header::{ACCEPT, CONTENT_TYPE, HeaderValue, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;

use crate::error::{RpcError, Status, TransportKind};
use crate::url::BaseUrl;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How much of a failing response body is kept for the error message.
///
/// This is remote input on its way into logs, so it is bounded. monerod's own
/// error bodies are far shorter than this.
const MAX_ERROR_BODY: usize = 256;

/// The most of a failing response's body that is read, to take
/// [`MAX_ERROR_BODY`] characters from.
const MAX_ERROR_BODY_READ: u64 = 64 * 1024;

/// The largest response this client will accumulate, unless told otherwise.
///
/// hyper hands back a stream; without a ceiling, a daemon that answered with
/// an endless body would grow this process until it died. `/get_transactions`
/// over a wide block range is the largest legitimate response and is nowhere
/// near this.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(feature = "tls")]
type Connector = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
#[cfg(not(feature = "tls"))]
type Connector = hyper_util::client::legacy::connect::HttpConnector;

/// A connection to one monerod daemon.
///
/// Cheap to clone: the underlying connection pool is shared.
#[derive(Debug, Clone)]
pub struct Client {
    http: HyperClient<Connector, Full<Bytes>>,
    base: BaseUrl,
    timeout: Duration,
    max_response_bytes: u64,
    user_agent: Option<HeaderValue>,
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    base: String,
    timeout: Duration,
    max_response_bytes: u64,
    user_agent: Option<String>,
}

impl ClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// The ceiling on a single response body.
    pub fn max_response_bytes(mut self, bytes: u64) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    pub fn build(self) -> Result<Client, RpcError> {
        let base = BaseUrl::parse(&self.base)
            .map_err(|e| RpcError::BadUrl(crate::url::shown(&self.base), e))?;

        let user_agent = self
            .user_agent
            .map(|ua| {
                HeaderValue::from_str(&ua)
                    .map_err(|e| RpcError::BadUrl(ua.clone(), format!("bad user agent: {e}")))
            })
            .transpose()?;

        // Nothing here follows redirects: hyper's client does not, and there
        // is no legitimate redirect for monerod to send. Anything sitting
        // between this client and the configured URL -- a proxy, a
        // misconfiguration, a compromised daemon -- therefore cannot point it
        // at a host the operator never named.
        Ok(Client {
            http: HyperClient::builder(TokioExecutor::new()).build(connector()),
            base,
            timeout: self.timeout,
            max_response_bytes: self.max_response_bytes,
            user_agent,
        })
    }
}

impl Client {
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base: base_url.into(),
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            user_agent: None,
        }
    }

    pub fn new(base_url: impl Into<String>) -> Result<Self, RpcError> {
        Self::builder(base_url).build()
    }

    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }

    /// Reads a response body, refusing one that never ends.
    ///
    /// Frame by frame with a running total, rather than collecting and then
    /// measuring: a chunked response declares no length, so measuring what
    /// arrived would mean the memory had already been taken before the limit
    /// was consulted. This stops at the first frame that crosses it.
    async fn collect_body(
        response: hyper::Response<hyper::body::Incoming>,
        context: &'static str,
        max_bytes: u64,
    ) -> Result<Bytes, RpcError> {
        let too_large = |len| RpcError::ResponseTooLarge { context, len };

        // A declared length over the ceiling is refused before reading at all.
        if let Some(len) = response.body().size_hint().exact()
            && len > max_bytes
        {
            return Err(too_large(len));
        }

        let mut body = response.into_body();
        let mut buf: Vec<u8> = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| RpcError::Transport {
                context,
                kind: TransportKind::Other,
                message: e.to_string(),
            })?;
            let Some(chunk) = frame.data_ref() else {
                continue;
            };
            let total = (buf.len() as u64).saturating_add(chunk.len() as u64);
            if total > max_bytes {
                return Err(too_large(total));
            }
            buf.extend_from_slice(chunk);
        }
        Ok(Bytes::from(buf))
    }

    /// POST a body to `path` as JSON and return the answer's bytes.
    async fn post(
        &self,
        path: &str,
        context: &'static str,
        body: &impl Serialize,
    ) -> Result<Bytes, RpcError> {
        let payload =
            serde_json::to_vec(body).map_err(|source| RpcError::Encode { context, source })?;
        self.exchange(
            path,
            context,
            "application/json",
            payload,
            self.max_response_bytes,
        )
        .await
    }

    /// POST `payload` to `path` and return the body of a successful answer.
    async fn exchange(
        &self,
        path: &str,
        context: &'static str,
        media_type: &'static str,
        payload: Vec<u8>,
        max_bytes: u64,
    ) -> Result<Bytes, RpcError> {
        let uri = self
            .base
            .join(path)
            .map_err(|e| RpcError::BadUrl(format!("{}{path}", self.base.as_str()), e))?;

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, HeaderValue::from_static(media_type))
            .header(ACCEPT, HeaderValue::from_static(media_type))
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| RpcError::BadUrl(path.to_owned(), e.to_string()))?;
        if let Some(ua) = &self.user_agent {
            request.headers_mut().insert(USER_AGENT, ua.clone());
        }

        // One deadline across the whole exchange -- connect, send, read the
        // head, read the body -- rather than one per stage, which would let a
        // daemon that stalls in each stage in turn take twice as long as the
        // operator configured.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let expired = |stage: &str| RpcError::Transport {
            context,
            kind: TransportKind::Timeout,
            message: format!("{stage} within {:?}", self.timeout),
        };

        let sent = tokio::time::timeout_at(deadline, self.http.request(request))
            .await
            .map_err(|_| expired("no response"))?;

        let response = sent.map_err(|e| RpcError::Transport {
            context,
            kind: if e.is_connect() {
                TransportKind::Connect
            } else {
                TransportKind::Other
            },
            message: e.to_string(),
        })?;

        let http_status = response.status();
        if !http_status.is_success() {
            // Keep a bounded slice of the body: monerod's error pages are short,
            // but this is remote input and it ends up in logs. Only that much
            // is read, not the whole answer up to `max_bytes`.
            let read = tokio::time::timeout_at(
                deadline,
                Self::collect_body(response, context, MAX_ERROR_BODY_READ),
            )
            .await
            .map_err(|_| expired("body not read"))?;
            let body = match read {
                Ok(bytes) => {
                    crate::error::printable(&String::from_utf8_lossy(&bytes), MAX_ERROR_BODY)
                }
                Err(_) => "<error body too large to read>".to_owned(),
            };
            return Err(RpcError::Http {
                context,
                status: http_status.as_u16(),
                body,
            });
        }

        tokio::time::timeout_at(deadline, Self::collect_body(response, context, max_bytes))
            .await
            .map_err(|_| expired("body not read"))?
    }

    /// Call a JSON-RPC 2.0 method on `/json_rpc`.
    pub async fn json_rpc<P, R>(
        &self,
        method: &'static str,
        params: Option<P>,
    ) -> Result<R, RpcError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        #[derive(Serialize)]
        struct Envelope<P> {
            jsonrpc: &'static str,
            id: &'static str,
            method: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            params: Option<P>,
        }

        /// The envelope of the answer. `result` and `error` are kept as text
        /// and parsed once, each into the type that reads it: parsing into a
        /// `serde_json::Value` holds the answer in memory many times over.
        #[derive(Deserialize)]
        struct Reply<'a> {
            #[serde(borrow, default)]
            error: Option<&'a RawValue>,
            #[serde(borrow, default)]
            result: Option<&'a RawValue>,
        }

        /// What is read of an `error`: anything else in it is skipped
        /// without being kept, and an `error` of another shape still fails
        /// the call, with no code or message.
        #[derive(Deserialize, Default)]
        struct Fault {
            #[serde(default)]
            code: Option<i64>,
            #[serde(default)]
            message: Option<String>,
        }

        let bytes = self
            .post(
                "json_rpc",
                method,
                &Envelope {
                    jsonrpc: "2.0",
                    id: "0",
                    method,
                    params,
                },
            )
            .await?;
        let reply: Reply<'_> =
            serde_json::from_slice(&bytes).map_err(|source| RpcError::Decode {
                context: method,
                source,
            })?;

        if let Some(error) = reply.error {
            let fault: Fault = serde_json::from_str(error.get()).unwrap_or_default();
            return Err(RpcError::JsonRpc {
                method,
                code: fault.code.unwrap_or(0),
                message: fault.message.map_or_else(
                    || "<no message>".to_owned(),
                    |m| crate::error::printable(&m, MAX_ERROR_BODY),
                ),
            });
        }
        let result = reply.result.ok_or(RpcError::Missing {
            context: method,
            field: "result",
        })?;

        // Several JSON-RPC results carry a `status` of their own in addition to
        // the envelope. An `error`-free response with `"status": "Failed"` is
        // still a failure.
        Self::check_status(result.get().as_bytes(), method)?;

        serde_json::from_str(result.get()).map_err(|source| RpcError::Decode {
            context: method,
            source,
        })
    }

    /// Call one of the bare (non-JSON-RPC) endpoints, e.g. `/get_transactions`.
    ///
    /// `endpoint` is given without a leading slash.
    pub async fn endpoint<B, R>(&self, endpoint: &'static str, body: &B) -> Result<R, RpcError>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let bytes = self.post(endpoint, endpoint, body).await?;
        Self::check_status(&bytes, endpoint)?;
        serde_json::from_slice(&bytes).map_err(|source| RpcError::Decode {
            context: endpoint,
            source,
        })
    }

    /// Call a binary endpoint, e.g. `/get_path_by_unified_id.bin`, and return
    /// the root entries named in `wanted`.
    ///
    /// `endpoint` is given without a leading slash and with its `.bin`. The
    /// answer is held to `max_bytes`, and to the client's general ceiling if
    /// that is lower: each binary answer has a size its caller can bound,
    /// and it is far smaller than the largest JSON one.
    ///
    /// Every binary answer monerod writes carries `status`, so the answer
    /// must have one, it must be UTF-8 text, and it must be `OK`.
    pub async fn binary(
        &self,
        endpoint: &'static str,
        fields: &[(&str, crate::epee::Field<'_>)],
        wanted: &[&str],
        max_bytes: u64,
    ) -> Result<crate::epee::Root, RpcError> {
        let payload = crate::epee::encode(fields).map_err(|source| RpcError::BinaryEncode {
            context: endpoint,
            source,
        })?;
        let bytes = self
            .exchange(
                endpoint,
                endpoint,
                "application/octet-stream",
                payload,
                max_bytes.min(self.max_response_bytes),
            )
            .await?;
        let mut keep: Vec<&str> = wanted.to_vec();
        if !keep.contains(&"status") {
            keep.push("status");
        }
        let root =
            crate::epee::read_root(&bytes, &keep).map_err(|source| RpcError::BinaryDecode {
                context: endpoint,
                source,
            })?;
        Self::check_binary_status(&root, endpoint)?;
        Ok(root)
    }

    /// The binary form of [`Self::check_status`], which requires `status`.
    fn check_binary_status(
        root: &crate::epee::Root,
        endpoint: &'static str,
    ) -> Result<(), RpcError> {
        if root.get("status").is_none() {
            return Err(RpcError::Missing {
                context: endpoint,
                field: "status",
            });
        }
        let status = root
            .text("status")
            .map_or_else(|| Status::parse("<unreadable status>"), Status::parse);
        if status.is_ok() {
            Ok(())
        } else {
            Err(RpcError::Status { endpoint, status })
        }
    }

    /// Reject a JSON object whose `status` is present and not `OK`.
    ///
    /// A missing `status` is tolerated: not every result carries one, and
    /// absence is not failure. Only `status` is read; the rest of the object
    /// is walked past without being kept.
    fn check_status(json: &[u8], context: &'static str) -> Result<(), RpcError> {
        #[derive(Deserialize)]
        struct WithStatus<'a> {
            #[serde(borrow, default)]
            status: Option<std::borrow::Cow<'a, str>>,
        }
        // Anything but an object with a string `status` has no status to
        // fail on; whether it is the answer expected is for its own parse.
        let Ok(WithStatus { status: Some(raw) }) = serde_json::from_slice(json) else {
            return Ok(());
        };
        let status = Status::parse(&raw);
        if status.is_ok() {
            Ok(())
        } else {
            Err(RpcError::Status {
                endpoint: context,
                status,
            })
        }
    }
}

/// The connector, with TLS when the feature is on.
///
/// `https_or_http` rather than `https_only`: the overwhelmingly common
/// deployment is a loopback daemon over plain HTTP, and requiring TLS there
/// would break it. The scheme in the configured URL decides.
#[cfg(feature = "tls")]
fn connector() -> Connector {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.enforce_http(false);
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http)
}

#[cfg(not(feature = "tls"))]
fn connector() -> Connector {
    hyper_util::client::legacy::connect::HttpConnector::new()
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

    /// A one-shot loopback server that cannot outlive the test.
    ///
    /// `TcpListener::accept` has no timeout, so a blocking server thread waits
    /// for a client that a broken build may never send -- turning a failing
    /// assertion into a hung test, which in CI is a job timeout with no
    /// message. Everything here is bounded: accept, read and join.
    struct Peer {
        port: u16,
        handle: std::thread::JoinHandle<Vec<u8>>,
    }

    /// Serves `body` as a JSON 200, with the length computed rather than typed.
    fn serve_json(body: &str) -> Peer {
        serve_owned(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    /// Announces a body far over any sane ceiling, then sends almost none of
    /// it. Refusing on the declared length means never reading the rest.
    fn serve_declared_huge() -> Peer {
        serve_owned(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000000\r\n\r\n{}"
                .to_owned(),
        )
    }

    /// A chunked 200 that declares no length and sends more than it should.
    fn serve_chunked() -> Peer {
        let chunk = "x".repeat(512);
        let mut reply =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_owned();
        for _ in 0..8 {
            reply.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
        }
        reply.push_str("0\r\n\r\n");
        serve_owned(reply)
    }

    /// Sends a complete head promising a body that never arrives.
    fn serve_truncated_body() -> Peer {
        serve_owned(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{"
                .to_owned(),
        )
    }

    /// Accepts, then never answers -- the client's deadline is what ends it.
    fn serve_nothing() -> Peer {
        serve_owned(String::new())
    }

    fn serve(reply: &'static [u8]) -> Peer {
        serve_owned(String::from_utf8_lossy(reply).into_owned())
    }

    fn serve_owned(reply: String) -> Peer {
        serve_bytes(reply.into_bytes())
    }

    fn serve_bytes(reply: Vec<u8>) -> Peer {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port is available");
        let port = listener.local_addr().expect("bound").port();
        listener
            .set_nonblocking(true)
            .expect("the listener can be polled");

        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                if std::time::Instant::now() > deadline {
                    return Vec::new();
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return Vec::new(),
                }
            };
            socket
                .set_nonblocking(false)
                .expect("back to blocking for the exchange");
            let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
            let mut scratch = [0u8; 8192];
            let n = socket.read(&mut scratch).unwrap_or(0);
            let stall_after_writing = reply
                .windows(b"Content-Length: 4096".len())
                .any(|w| w == b"Content-Length: 4096");
            if reply.is_empty() {
                // Hold the connection open with no response, so the only thing
                // that can end the exchange is the client giving up.
                std::thread::sleep(Duration::from_secs(10));
            } else {
                let _ = socket.write_all(&reply);
                let _ = socket.flush();
                if stall_after_writing {
                    std::thread::sleep(Duration::from_secs(10));
                }
            }
            scratch.get(..n).unwrap_or_default().to_vec()
        });

        Peer { port, handle }
    }

    impl Peer {
        /// The request bytes the client actually sent, or empty if it never
        /// connected.
        fn request(self) -> String {
            String::from_utf8_lossy(&self.request_bytes()).into_owned()
        }

        fn request_bytes(self) -> Vec<u8> {
            self.handle.join().expect("the server thread finished")
        }
    }

    #[test]
    fn base_url_without_trailing_slash_still_resolves_under_its_path() {
        // The bug this guards: Url::join("json_rpc") against ".../mon" drops
        // "mon" and silently targets a different endpoint.
        let c = Client::new("http://127.0.0.1:18081/mon").expect("valid url");
        assert!(c.base_url().ends_with("/mon/"));
    }

    #[test]
    fn plain_host_is_accepted() {
        let c = Client::new("http://127.0.0.1:18081").expect("valid url");
        assert_eq!(c.base_url(), "http://127.0.0.1:18081/");
    }

    /// A redirect is an instruction to talk to somewhere the operator did not
    /// configure. monerod never sends one, so following one can only take this
    /// client somewhere it should not go.
    ///
    /// Answered by a real socket rather than by inspecting the builder: what
    /// matters is where the *request* ends up, and a redirect that was followed
    /// would show up here as a transport error against the unreachable port in
    /// the `Location` header instead of as the 302 itself.
    #[tokio::test]
    async fn a_redirect_is_reported_rather_than_followed() {
        // Port 1 is not listening, so a followed redirect would fail loudly.
        let peer = serve(
            b"HTTP/1.1 302 Found\r\n\
              Location: http://127.0.0.1:1/json_rpc\r\n\
              Content-Length: 0\r\n\r\n",
        );

        let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
        let outcome: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        assert!(!peer.request().is_empty(), "the client never connected");

        match outcome {
            Err(RpcError::Http { status, .. }) => assert_eq!(
                status, 302,
                "the redirect itself should come back as the answer"
            ),
            other => panic!("expected the 302 to be reported, got {other:?}"),
        }
    }

    /// The TLS stack must be usable at runtime, not merely linked.
    ///
    /// rustls 0.23 resolves its crypto provider at *run* time and panics with
    /// "no process-level CryptoProvider available" if none was installed. That
    /// is invisible to `cargo check` and to every test that only speaks plain
    /// HTTP, so it would first appear as a crash on an operator's first
    /// request to an https daemon.
    ///
    /// The peer here answers with garbage rather than a ServerHello, so the
    /// handshake fails -- which is the point: reaching a handshake failure
    /// means the TLS path ran.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn the_tls_connector_reaches_a_handshake_rather_than_panicking() {
        // Not a TLS record, so the client rejects it as a bad peer.
        let peer = serve(b"definitely not a ServerHello\r\n");

        let client = Client::builder(format!("https://127.0.0.1:{}", peer.port))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("valid url");
        let outcome: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        assert!(
            !peer.request().is_empty(),
            "no TLS ClientHello arrived, so the handshake was never attempted"
        );

        match outcome {
            Err(RpcError::Transport { .. }) => {}
            other => panic!("expected a transport failure from the handshake, got {other:?}"),
        }
    }

    /// A plain-HTTP daemon must still work when the TLS feature is on: the
    /// connector is `https_or_http`, and the configured scheme decides.
    #[tokio::test]
    async fn a_plain_http_daemon_is_reachable_with_tls_compiled_in() {
        let peer = serve_json(r#"{"id":"0","jsonrpc":"2.0","result":{"status":"OK","height":7}}"#);

        let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
        let got: serde_json::Value = client
            .json_rpc("get_info", None::<()>)
            .await
            .expect("the daemon answered");
        assert_eq!(got.get("height").and_then(|h| h.as_u64()), Some(7));
        assert!(!peer.request().is_empty(), "the client never connected");
    }

    /// An `error` is read for its code and message only: whatever else it
    /// holds is skipped, an `error` of another shape still fails the call,
    /// and a null one is no error.
    #[tokio::test]
    async fn an_error_is_read_for_its_code_and_message_only() {
        let fault = |body: &'static str| async move {
            let peer = serve_json(body);
            let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
            client
                .json_rpc::<(), serde_json::Value>("get_info", None)
                .await
        };

        match fault(r#"{"error":{"code":-2,"message":"no\nway","data":[0,0,0,[0,[0]]]}}"#).await {
            Err(RpcError::JsonRpc { code, message, .. }) => {
                assert_eq!(code, -2);
                assert!(
                    message.starts_with("no") && !message.contains('\n'),
                    "{message}"
                );
            }
            other => panic!("expected the daemon's error, got {other:?}"),
        }
        match fault(r#"{"error":[0,0,0]}"#).await {
            Err(RpcError::JsonRpc { code, message, .. }) => {
                assert_eq!((code, message.as_str()), (0, "<no message>"));
            }
            other => panic!("expected an error without details, got {other:?}"),
        }
        let answered = fault(r#"{"error":null,"result":{"status":"OK"}}"#)
            .await
            .expect("a null error is no error");
        assert_eq!(answered.get("status").and_then(|s| s.as_str()), Some("OK"));
    }

    /// The request monerod actually receives: a POST of JSON to the endpoint
    /// under the configured base path, with no redirect handling in between.
    #[tokio::test]
    async fn the_request_is_a_json_post_to_the_configured_path() {
        let peer = serve_json(r#"{"result":{}}"#);

        let client = Client::builder(format!("http://127.0.0.1:{}/mon", peer.port))
            .user_agent("oxblocks-test/1")
            .build()
            .expect("valid url");
        let _: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        let request = peer.request();

        assert!(
            request.starts_with("POST /mon/json_rpc HTTP/1.1"),
            "wrong method or path: {request}"
        );
        assert!(
            request.contains("content-type: application/json")
                || request.contains("Content-Type: application/json"),
            "no json content type: {request}"
        );
        assert!(
            request
                .to_lowercase()
                .contains("user-agent: oxblocks-test/1"),
            "the user agent was not sent: {request}"
        );
        assert!(
            request.contains(r#""method":"get_info""#),
            "the JSON-RPC body did not arrive: {request}"
        );
    }

    /// A daemon that accepts the connection and then says nothing must not
    /// pin the request open. The explorer's own request deadline is set below
    /// this one, so without it a stalled daemon would outlive the reader
    /// waiting on it.
    #[tokio::test]
    async fn a_daemon_that_never_answers_hits_the_deadline() {
        let peer = serve_nothing();
        let client = Client::builder(format!("http://127.0.0.1:{}", peer.port))
            .timeout(Duration::from_millis(250))
            .build()
            .expect("valid url");

        let started = std::time::Instant::now();
        let outcome: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        let waited = started.elapsed();

        match outcome {
            Err(e @ RpcError::Transport { .. }) => {
                assert!(e.is_transient(), "a timeout is worth retrying");
                assert!(
                    e.to_string().contains("get_info"),
                    "the failure should name the call: {e}"
                );
            }
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(
            waited < Duration::from_secs(5),
            "waited {waited:?}, so the configured deadline was not what stopped it"
        );
    }

    /// The head arriving is not the exchange finishing. A daemon that sends a
    /// Content-Length and then withholds the body would hang a request that
    /// only bounded the response head.
    #[tokio::test]
    async fn a_body_that_never_arrives_hits_the_same_deadline() {
        let peer = serve_truncated_body();
        let client = Client::builder(format!("http://127.0.0.1:{}", peer.port))
            .timeout(Duration::from_millis(250))
            .build()
            .expect("valid url");

        let started = std::time::Instant::now();
        let outcome: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        let waited = started.elapsed();

        assert!(
            matches!(outcome, Err(RpcError::Transport { .. })),
            "expected the body read to time out, got {outcome:?}"
        );
        assert!(
            waited < Duration::from_secs(5),
            "waited {waited:?}, so nothing bounded the body read"
        );
    }

    /// An oversized body is refused, whether or not it announced its size.
    ///
    /// The declared-length case is refused before a byte is read. The chunked
    /// case has no declared length, so it is refused at the first frame that
    /// crosses the ceiling -- which is the point: measuring after collecting
    /// would mean the memory had already been taken.
    #[tokio::test]
    async fn a_response_over_the_ceiling_is_refused() {
        for (label, peer) in [
            ("declared length", serve_json(&"x".repeat(4096))),
            ("chunked", serve_chunked()),
        ] {
            let client = Client::builder(format!("http://127.0.0.1:{}", peer.port))
                .timeout(Duration::from_secs(5))
                .max_response_bytes(1024)
                .build()
                .expect("valid url");
            let outcome: Result<serde_json::Value, _> =
                client.json_rpc("get_info", None::<()>).await;
            match outcome {
                Err(RpcError::ResponseTooLarge { len, .. }) => {
                    assert!(len > 1024, "{label}: refused at {len}, under the ceiling");
                }
                other => panic!("{label}: expected a size refusal, got {other:?}"),
            }
        }
    }

    /// A declared length over the ceiling is refused on the strength of the
    /// declaration, without reading the body it promises.
    ///
    /// Distinguishable from the streaming check because this peer announces
    /// ten megabytes and then sends two bytes: refusing on the header reports
    /// the declared size, while reading first would stall waiting for a body
    /// that never finishes arriving.
    #[tokio::test]
    async fn a_declared_length_over_the_ceiling_is_refused_before_reading() {
        let peer = serve_declared_huge();
        let client = Client::builder(format!("http://127.0.0.1:{}", peer.port))
            .timeout(Duration::from_millis(500))
            .max_response_bytes(1024)
            .build()
            .expect("valid url");

        let outcome: Result<serde_json::Value, _> = client.json_rpc("get_info", None::<()>).await;
        match outcome {
            Err(RpcError::ResponseTooLarge { len, .. }) => assert_eq!(
                len, 10_000_000,
                "the refusal should quote the declared length, not what arrived"
            ),
            other => panic!("expected refusal on the declared length, got {other:?}"),
        }
    }

    /// The same body, under the ceiling, is read normally -- so the size tests
    /// is measuring the limit rather than a transport that never works.
    #[tokio::test]
    async fn a_response_under_the_ceiling_is_read() {
        let peer = serve_json(r#"{"result":{"status":"OK","height":7}}"#);
        let client = Client::builder(format!("http://127.0.0.1:{}", peer.port))
            .max_response_bytes(1024)
            .build()
            .expect("valid url");
        let got: serde_json::Value = client
            .json_rpc("get_info", None::<()>)
            .await
            .expect("a small response is fine");
        assert_eq!(got.get("height").and_then(|h| h.as_u64()), Some(7));
    }

    #[test]
    fn nonsense_url_is_rejected_at_construction() {
        assert!(matches!(
            Client::new("not a url"),
            Err(RpcError::BadUrl(_, _))
        ));
    }

    #[test]
    fn non_ok_status_is_an_error_and_missing_status_is_not() {
        let status = |json: &str| Client::check_status(json.as_bytes(), "/get_outs");
        assert!(status(r#"{"status": "Failed"}"#).is_err());
        let err = status(r#"{"status": "BUSY", "height": 1}"#).expect_err("BUSY is not OK");
        assert!(err.is_transient());
        assert!(status(r#"{"height": 1, "status": "OK"}"#).is_ok());
        assert!(status(r#"{"height": 1}"#).is_ok());
        // No string status, nothing to fail on: the typed parse decides.
        assert!(status(r#"{"status": 7}"#).is_ok());
        assert!(status("[1, 2]").is_ok());
        // A status carrying control characters reaches the error printable.
        let err = status("{\"status\": \"bad\\nline\"}").expect_err("not OK");
        assert!(!err.to_string().contains('\n'), "{err}");

        // Binary: a status that is present but unreadable is a failure, not a
        // missing field.
        let root = |status: &[u8]| {
            let mut b = vec![
                0x01,
                0x11,
                0x01,
                0x01,
                0x01,
                0x01,
                0x02,
                0x01,
                0x01,
                1 << 2,
                6,
            ];
            b.extend_from_slice(b"status");
            b.push(10);
            b.push((status.len() as u8) << 2);
            b.extend_from_slice(status);
            crate::epee::read_root(&b, &["status"]).unwrap()
        };
        assert!(Client::check_binary_status(&root(b"OK"), "x.bin").is_ok());
        assert!(Client::check_binary_status(&root(b"OK\xff"), "x.bin").is_err());
    }

    /// A portable-storage root section holding `entries`, each a name, a type
    /// byte and the value's bytes.
    fn epee_doc(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut b = vec![0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];
        b.push((entries.len() as u8) << 2);
        for (name, ty, value) in entries {
            b.push(name.len() as u8);
            b.extend_from_slice(name.as_bytes());
            b.push(*ty);
            b.extend_from_slice(value);
        }
        b
    }

    fn epee_text(text: &str) -> Vec<u8> {
        let mut v = vec![(text.len() as u8) << 2];
        v.extend_from_slice(text.as_bytes());
        v
    }

    fn serve_binary(body: &[u8]) -> Peer {
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        reply.extend_from_slice(body);
        serve_bytes(reply)
    }

    const PROBE: [(&str, crate::epee::Field<'static>); 2] = [
        ("as_of_n_blocks", crate::epee::Field::U64(421)),
        ("unified_ids", crate::epee::Field::U64s(&[7])),
    ];

    #[tokio::test]
    async fn a_binary_call_posts_the_encoded_request_and_reads_the_answer() {
        let answer = epee_doc(&[
            ("n_leaf_tuples", 5, &62u64.to_le_bytes()),
            ("status", 10, &epee_text("OK")),
        ]);
        let peer = serve_binary(&answer);
        let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
        let root = client
            .binary(
                "get_path_by_unified_id.bin",
                &PROBE,
                &["n_leaf_tuples"],
                1024,
            )
            .await
            .expect("the answer is accepted");
        assert_eq!(root.unsigned("n_leaf_tuples"), Some(62));

        let sent = peer.request_bytes();
        let head_end = sent
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete head");
        let head = String::from_utf8_lossy(sent.get(..head_end).unwrap()).to_ascii_lowercase();
        assert!(
            head.starts_with("post /get_path_by_unified_id.bin "),
            "{head}"
        );
        assert!(
            head.contains("content-type: application/octet-stream"),
            "{head}"
        );
        assert_eq!(
            sent.get(head_end + 4..).unwrap(),
            crate::epee::encode(&PROBE).unwrap().as_slice(),
            "the body is the encoded request"
        );
    }

    #[tokio::test]
    async fn a_binary_answer_over_its_limit_is_refused() {
        let peer = serve_binary(&vec![0u8; 2048]);
        let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
        let outcome = client
            .binary("get_path_by_unified_id.bin", &PROBE, &[], 1024)
            .await;
        let _ = peer.request();
        assert!(
            matches!(outcome, Err(RpcError::ResponseTooLarge { len: 2048, .. })),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_binary_answer_that_failed_or_has_no_status_is_an_error() {
        let failed = epee_doc(&[
            ("n_leaf_tuples", 5, &0u64.to_le_bytes()),
            ("status", 10, &epee_text("Failed")),
        ]);
        let silent = epee_doc(&[("n_leaf_tuples", 5, &62u64.to_le_bytes())]);
        for (body, want_status) in [(failed, true), (silent, false)] {
            let peer = serve_binary(&body);
            let client = Client::new(format!("http://127.0.0.1:{}", peer.port)).expect("valid url");
            let outcome = client
                .binary(
                    "get_path_by_unified_id.bin",
                    &PROBE,
                    &["n_leaf_tuples"],
                    1024,
                )
                .await;
            let _ = peer.request();
            if want_status {
                assert!(
                    matches!(
                        outcome,
                        Err(RpcError::Status {
                            status: Status::Failed,
                            ..
                        })
                    ),
                    "{outcome:?}"
                );
            } else {
                assert!(
                    matches!(
                        outcome,
                        Err(RpcError::Missing {
                            field: "status",
                            ..
                        })
                    ),
                    "{outcome:?}"
                );
            }
        }
    }
}
