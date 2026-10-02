//! A stand-in monerod for tests: a loopback HTTP server that answers each
//! call with what the test says and records the calls it gets.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test support, where a panic is the failure"
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use monerod_rpc::Client;

use crate::RpcChainSource;

/// A loopback HTTP server answering like monerod for the few calls the
/// range and cache code makes, and recording each one. Bounded throughout:
/// the listener polls, every read has a timeout, and dropping it stops and
/// joins the thread, so a broken build fails instead of hanging.
pub struct FakeDaemon {
    port: u16,
    calls: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// An answer: its HTTP status and its body.
pub type Reply = (u16, Vec<u8>);

type Answer = dyn Fn(&str, &serde_json::Value) -> Reply + Send + Sync;

impl FakeDaemon {
    /// `answer` gets the method (for `/json_rpc`) or the endpoint, and the
    /// request body, and returns the whole response body.
    pub fn start(
        answer: impl Fn(&str, &serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    ) -> Self {
        Self::start_raw(move |what, body| (200, answer(what, body).to_string().into_bytes()))
    }

    /// As [`start`](Self::start), with `answer` giving the status and the
    /// raw body, for a binary call or a failing one. A binary request's body
    /// reads as its unsigned fields among [`BINARY_FIELDS`], an array as its
    /// one element when it has one; anything else in it reads as null.
    pub fn start_raw(
        answer: impl Fn(&str, &serde_json::Value) -> Reply + Send + Sync + 'static,
    ) -> Self {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let answer: Arc<Answer> = Arc::new(answer);
        let (c, st) = (Arc::clone(&calls), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, length) = loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (None, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (Some(i + 4), length);
                    }
                };
                let Some(start) = head_end else { continue };
                while buf.len() < start + length {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request_line = String::from_utf8_lossy(&buf[..start]).to_string();
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .trim_start_matches('/')
                    .to_owned();
                let raw = &buf[start..start + length];
                let body: serde_json::Value =
                    serde_json::from_slice(raw).unwrap_or_else(|_| binary_body(raw));
                let what = if path == "json_rpc" {
                    body["method"].as_str().unwrap_or("").to_owned()
                } else {
                    path
                };
                let (status, reply) = answer(&what, &body);
                c.lock().unwrap().push((what, body));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(&reply);
            }
        });
        Self {
            port,
            calls,
            stop,
            handle: Some(handle),
        }
    }

    pub fn source(&self) -> RpcChainSource {
        RpcChainSource::new(Client::new(format!("http://127.0.0.1:{}", self.port)).unwrap())
    }

    pub fn count(&self, what: &str) -> usize {
        self.bodies(what).len()
    }

    /// The request bodies of every `what` call, in the order they came.
    pub fn bodies(&self, what: &str) -> Vec<serde_json::Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c == what)
            .map(|(_, b)| b.clone())
            .collect()
    }
}

/// The binary request fields the fake reads.
pub const BINARY_FIELDS: &[&str] = &["as_of_n_blocks", "unified_ids"];

fn binary_body(raw: &[u8]) -> serde_json::Value {
    use monerod_rpc::epee::{Value, read_root};
    let Ok(root) = read_root(raw, BINARY_FIELDS) else {
        return serde_json::Value::Null;
    };
    root.entries()
        .iter()
        .filter_map(|(k, v)| match v {
            Value::Unsigned(n) => Some((k.clone(), serde_json::json!(n))),
            _ => None,
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
