//! The loopback listener the portal redirects the browser to after a login, with a one-time code
//! (or an error) for the client service.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::portal::LoginError;

/// What the portal sent back through the browser.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Callback {
    Code(String),
    Error(LoginError),
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    error: Option<LoginError>,
    state: Option<String>,
}

struct Listener {
    tx: mpsc::Sender<Callback>,
    /// The login's state, which the portal echoes: anything else didn't come from it.
    state: String,
}

const DONE_HTML: &str = "<!doctype html><meta charset=\"utf-8\"><title>Drawbridge</title>\
<p>Login received. You can close this window and return to your terminal.</p>";
const FAILED_HTML: &str = "<!doctype html><meta charset=\"utf-8\"><title>Drawbridge</title>\
<p>The login did not complete. See your terminal for details.</p>";

/// Serves `listener` until the returned task is aborted, passing the first callback carrying
/// `state` to the receiver.
pub(super) fn serve(
    listener: TcpListener,
    state: String,
) -> (mpsc::Receiver<Callback>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(1);
    let app = Router::new()
        .route("/", get(callback))
        .with_state(Arc::new(Listener { tx, state }));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (rx, task)
}

async fn callback(
    State(listener): State<Arc<Listener>>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if q.state.as_deref() != Some(listener.state.as_str()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (callback, page) = match (q.code, q.error) {
        (Some(code), None) => (Callback::Code(code), DONE_HTML),
        (None, Some(error)) => (Callback::Error(error), FAILED_HTML),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    // The service takes the first; a repeat (e.g. a reload of this page) is dropped.
    let _ = listener.tx.try_send(callback);
    let mut response = Html(page).into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CONTENT_SECURITY_POLICY, "default-src 'none'"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn get(port: u16, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn passes_codes_and_errors_on() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (mut rx, task) = serve(listener, "st".into());

        // Without this login's state nothing gets through, so it can't be aborted or stalled.
        for path in [
            "/?code=forged",
            "/?error=login_failed",
            "/?code=x&state=other",
        ] {
            assert!(get(port, path).await.starts_with("HTTP/1.1 400"), "{path}");
        }
        let page = get(port, "/?code=abc&state=st").await;
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("Login received"));
        assert_eq!(rx.recv().await, Some(Callback::Code("abc".into())));

        get(port, "/?error=login_failed&state=st").await;
        assert_eq!(
            rx.recv().await,
            Some(Callback::Error(LoginError::LoginFailed))
        );

        assert!(get(port, "/?state=st").await.starts_with("HTTP/1.1 400"));
        assert!(
            get(port, "/?error=bogus&state=st")
                .await
                .starts_with("HTTP/1.1 400")
        );
        assert!(get(port, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        task.abort();
    }
}
