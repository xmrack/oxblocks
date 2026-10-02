//! The response envelope.
//!
//! The body is the JSend-ish object that xmrblocks clients expect:
//!
//! ```text
//! {"data": <object>, "status": "success"}
//! {"data": {"title": "<message>"}, "status": "fail"}
//! {"data": null, "message": "<message>", "status": "error"}
//! ```
//!
//! The HTTP status says the same thing as the envelope: 400 for input this
//! explorer will not parse, 404 for something the chain does not hold, 5xx
//! when the fault is ours or the daemon's. A client that reads the `status`
//! member instead sees the same three shapes either way.
//!
//! The error form carries `"data": null`, not `{}`.

use axum::body::Bytes;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Which body shape an answer takes.
///
/// `fail` is the caller's fault, a hash that will not parse or a height past
/// the tip. `error` is ours or the daemon's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Fail,
    Error,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub outcome: Outcome,
    pub status: StatusCode,
    pub message: String,
    /// `/api/transactions` fills its `blocks` array before the step that can
    /// fail, so its error form carries whatever blocks it had. That partial
    /// value goes here.
    pub partial: Option<serde_json::Value>,
}

impl ApiError {
    fn new(outcome: Outcome, status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            outcome,
            status,
            message: message.into(),
            partial: None,
        }
    }

    /// Answers 400: the argument is not something this explorer will read.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(Outcome::Fail, StatusCode::BAD_REQUEST, message)
    }

    /// Answers 404: the argument was well formed and the chain does not hold
    /// it.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Outcome::Fail, StatusCode::NOT_FOUND, message)
    }

    /// Answers 502: the daemon could not be reached, or answered with
    /// something this explorer cannot use.
    pub fn daemon(message: impl Into<String>) -> Self {
        Self::new(Outcome::Error, StatusCode::BAD_GATEWAY, message)
    }

    /// Answers 503: this deployment cannot serve the endpoint at all, because
    /// of how its daemon is built or configured.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(Outcome::Error, StatusCode::SERVICE_UNAVAILABLE, message)
    }

    /// Answers 500: our own bug.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Outcome::Error, StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    #[must_use]
    pub fn with_partial(mut self, partial: serde_json::Value) -> Self {
        self.partial = Some(partial);
        self
    }

    fn to_value(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        match self.outcome {
            Outcome::Fail => {
                let mut data = serde_json::Map::new();
                data.insert(
                    "title".to_owned(),
                    serde_json::Value::String(self.message.clone()),
                );
                out.insert("data".to_owned(), serde_json::Value::Object(data));
                out.insert(
                    "status".to_owned(),
                    serde_json::Value::String("fail".to_owned()),
                );
            }
            Outcome::Error => {
                out.insert(
                    "data".to_owned(),
                    self.partial.clone().unwrap_or(serde_json::Value::Null),
                );
                out.insert(
                    "message".to_owned(),
                    serde_json::Value::String(self.message.clone()),
                );
                out.insert(
                    "status".to_owned(),
                    serde_json::Value::String("error".to_owned()),
                );
            }
        }
        serde_json::Value::Object(out)
    }
}

#[derive(Debug, Clone)]
pub struct ApiOk<T>(pub T);

/// Headers on every JSON response.
fn api_headers() -> [(HeaderName, HeaderValue); 3] {
    [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ),
        (
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        ),
        (
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type"),
        ),
    ]
}

fn render(status: StatusCode, value: &serde_json::Value) -> Response {
    // `dump()` with no arguments is compact, and serde_json's default writer
    // matches: no spaces after `,` or `:`.
    let (status, body) = match serde_json::to_string(value) {
        Ok(body) => (status, body),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"data":null,"message":"serialisation failed","status":"error"}"#.to_owned(),
        ),
    };
    (status, api_headers(), body).into_response()
}

/// The success envelope around `data`, written out.
///
/// Straight from `data`, not through a `serde_json::Value`, which would hold
/// the whole answer again as a tree only to sort its keys. The bytes are the
/// same because every struct an answer is built from declares its fields in
/// byte order (see `shapes`), and a `Value` inside one, as the raw endpoints
/// carry, writes its keys sorted. Debug builds check that on every answer.
pub fn ok_body<T: Serialize>(data: &T) -> Result<Bytes, ApiError> {
    #[derive(Serialize)]
    struct Envelope<'a, T> {
        data: &'a T,
        status: &'static str,
    }
    let body = serde_json::to_vec(&Envelope {
        data,
        status: "success",
    })
    .map_err(|e| ApiError::internal(format!("could not render: {e}")))?;
    #[cfg(debug_assertions)]
    {
        let sorted = serde_json::from_slice::<serde_json::Value>(&body)
            .and_then(|v| serde_json::to_vec(&v))
            .map_err(|e| ApiError::internal(format!("could not reread: {e}")))?;
        debug_assert!(
            sorted == body,
            "an answer's keys are not in byte order:\n{}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(Bytes::from(body))
}

/// A success answer whose body is already written.
pub fn ok_response(body: Bytes) -> Response {
    (StatusCode::OK, api_headers(), body).into_response()
}

impl<T: Serialize> IntoResponse for ApiOk<T> {
    fn into_response(self) -> Response {
        match ok_body(&self.0) {
            Ok(body) => ok_response(body),
            Err(e) => e.into_response(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        render(self.status, &self.to_value())
    }
}

/// axum's `Path`, refusing a path it cannot read in this API's envelope
/// rather than in axum's plain text.
pub struct ApiPath<T>(pub T);

/// axum's `Query`, likewise.
pub struct ApiQuery<T>(pub T);

/// A refusal by axum's own extractor, as this API's `fail`. Its text can
/// quote the request, so it is bounded as any echoed argument is.
fn refused(text: &str) -> ApiError {
    ApiError::bad_request(crate::api::handlers::echo(text))
}

impl<S, T> axum::extract::FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, ApiError> {
        axum::extract::Path::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(t)| Self(t))
            .map_err(|e| refused(&e.body_text()))
    }
}

impl<S, T> axum::extract::FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, ApiError> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(t)| Self(t))
            .map_err(|e| refused(&e.body_text()))
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

    fn body_of(r: Response) -> String {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async move {
                let bytes = axum::body::to_bytes(r.into_body(), 64 * 1024)
                    .await
                    .unwrap();
                String::from_utf8(bytes.to_vec()).unwrap()
            })
    }

    /// The message is echoed as written, apostrophe-free "Cant" included.
    #[test]
    fn a_failure_is_data_title() {
        let r = ApiError::bad_request("Cant parse tx hash: abc").into_response();
        assert_eq!(
            body_of(r),
            r#"{"data":{"title":"Cant parse tx hash: abc"},"status":"fail"}"#
        );
    }

    /// The status code is the part that is ours. A refused request must not
    /// come back as 200, or every proxy, cache and monitor in the path is told
    /// it succeeded.
    #[test]
    fn the_status_code_says_what_happened() {
        for (expected, built) in [
            (StatusCode::BAD_REQUEST, ApiError::bad_request("x")),
            (StatusCode::NOT_FOUND, ApiError::not_found("x")),
            (StatusCode::BAD_GATEWAY, ApiError::daemon("x")),
            (StatusCode::SERVICE_UNAVAILABLE, ApiError::unsupported("x")),
            (StatusCode::INTERNAL_SERVER_ERROR, ApiError::internal("x")),
        ] {
            assert_eq!(built.clone().into_response().status(), expected);
            assert!(built.status.is_client_error() || built.status.is_server_error());
        }
        assert_eq!(ApiOk(7).into_response().status(), StatusCode::OK);
    }

    /// Which body shape goes with which code: a 4xx is the caller's fault and
    /// carries `fail`, a 5xx is ours and carries `error`.
    #[test]
    fn the_code_and_the_body_agree_on_whose_fault_it_is() {
        for built in [ApiError::bad_request("x"), ApiError::not_found("x")] {
            assert_eq!(built.outcome, Outcome::Fail);
            assert!(
                built.status.is_client_error(),
                "{} is not 4xx",
                built.status
            );
        }
        for built in [
            ApiError::daemon("x"),
            ApiError::unsupported("x"),
            ApiError::internal("x"),
        ] {
            assert_eq!(built.outcome, Outcome::Error);
            assert!(
                built.status.is_server_error(),
                "{} is not 5xx",
                built.status
            );
        }
    }

    /// `data` is null on the error form, not `{}`.
    #[test]
    fn an_error_carries_a_null_data_and_a_message() {
        let r = ApiError::internal("boom").into_response();
        assert_eq!(
            body_of(r),
            r#"{"data":null,"message":"boom","status":"error"}"#
        );
    }

    /// `/api/transactions` returns whatever blocks it had collected before the
    /// failure.
    #[test]
    fn an_error_can_carry_partially_built_data() {
        let r = ApiError::daemon("Cant get block: 99")
            .with_partial(serde_json::json!({"blocks": [{"height": 100}]}))
            .into_response();
        assert_eq!(
            body_of(r),
            r#"{"data":{"blocks":[{"height":100}]},"message":"Cant get block: 99","status":"error"}"#
        );
    }

    #[test]
    fn success_wraps_the_payload_and_sets_the_cors_headers() {
        #[derive(Serialize)]
        struct Payload {
            // Declared alphabetically on purpose; see `keys_are_alphabetical`.
            api: u64,
            height: u64,
        }
        let r = ApiOk(Payload {
            api: 65539,
            height: 7,
        })
        .into_response();

        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            r.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert_eq!(
            body_of(r),
            r#"{"data":{"api":65539,"height":7},"status":"success"}"#
        );
    }

    /// Keys are emitted in byte-ascending order, recursively. serde emits
    /// struct fields in *declaration* order, so every response struct must
    /// declare its fields alphabetically. This checks the envelope itself.
    /// The response shapes are covered by
    /// `shapes::tests::declaration_order_is_alphabetical`.
    #[test]
    fn envelope_keys_are_alphabetical() {
        let e = ApiError::internal("x").into_response();
        let body = body_of(e);
        let keys: Vec<&str> = ["data", "message", "status"].into();
        let mut last = 0usize;
        for k in keys {
            let at = body.find(&format!("\"{k}\"")).expect("key present");
            assert!(at >= last, "{k} is out of alphabetical order");
            last = at;
        }
    }

    /// The check behind writing answers straight from their structs: a
    /// struct out of byte order is caught rather than sent in another order
    /// than the sorted answer it replaces.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not in byte order")]
    fn an_answer_out_of_byte_order_is_caught() {
        #[derive(Serialize)]
        struct Backwards {
            b: u8,
            a: u8,
        }
        let _ = ok_body(&Backwards { b: 1, a: 2 });
    }

    #[test]
    fn a_sorted_answer_is_written_as_the_sorted_envelope() {
        #[derive(Serialize)]
        struct Sorted {
            a: u8,
            b: serde_json::Value,
        }
        let body = ok_body(&Sorted {
            a: 1,
            b: serde_json::json!({"z": 1, "y": [2]}),
        })
        .unwrap();
        assert_eq!(
            &body[..],
            br#"{"data":{"a":1,"b":{"y":[2],"z":1}},"status":"success"}"#
        );
    }
}
