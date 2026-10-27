//! Cleartext HTTP host rules: every request on a connection is checked by host and path.
//!
//! hyper serves the client side. A denied request resets the connection: the stream sits in an
//! [`Io`] whose drop sets `SO_LINGER 0` once [`Io::reset`] is flagged, so dropping hyper's
//! connection future sends the RST.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{CONNECTION, HOST, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use super::droplog::Drop;
use super::{Grant, Proxy, Verdict};
use crate::firewall::ruleset::Mode;
use crate::policy::Proto;
use crate::session::SessionView;

/// The largest request head the proxy accepts (hyper's buffer limit).
const MAX_HEAD: usize = 16 * 1024;

/// The HTTP/2 prior-knowledge (h2c) connection preface.
const H2C_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type Body = BoxBody<Bytes, hyper::Error>;

/// Serves the HTTP connection `client` from `peer` to `dst`; `head` holds the bytes already read.
pub(super) async fn serve(
    proxy: Arc<Proxy>,
    mut client: TcpStream,
    peer: SocketAddr,
    dst: SocketAddr,
    mut head: Vec<u8>,
) {
    match tokio::time::timeout(proxy.timeout, read_preface(&mut client, &mut head)).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            proxy
                .log
                .record(drop_line(peer, dst, None, None, Some("h2c")));
            if proxy.mode == Mode::Enforcing {
                return super::reset(client);
            }
            // Permissive: pass h2c through untouched.
            return match TcpStream::connect(dst).await {
                Ok(upstream) => {
                    super::splice(client, upstream, &head, None, proxy.sessions.clone()).await;
                }
                Err(_) => super::reset(client),
            };
        }
        Ok(Err(_)) => return,
        Err(_) => {
            proxy
                .log
                .record(drop_line(peer, dst, None, None, Some("timeout")));
            return super::reset(client);
        }
    }

    let reset = Arc::new(AtomicBool::new(false));
    let answering = Arc::new(AtomicBool::new(false));
    let io = Io {
        head,
        pos: 0,
        stream: client,
        reset: reset.clone(),
        answering: answering.clone(),
        upgraded: false,
    };
    let conn = Arc::new(Conn {
        proxy: proxy.clone(),
        peer,
        dst,
        reset,
        answering,
        denied: Notify::new(),
        upstream: tokio::sync::Mutex::new(None),
        session: Mutex::new(None),
        upgraded: Mutex::new(None),
    });
    let service = {
        let conn = conn.clone();
        hyper::service::service_fn(move |req| conn.clone().request(req))
    };
    let served = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(proxy.timeout)
        .max_buf_size(MAX_HEAD)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    let mut served = Box::pin(served);
    let ended = session_ended(&conn, proxy.sessions.clone());
    tokio::select! {
        res = &mut served => {
            if let Err(e) = res {
                let reason = if e.is_timeout() {
                    "timeout"
                } else if e.is_parse_too_large() {
                    "oversized"
                } else {
                    "malformed"
                };
                tracing::debug!("proxy: HTTP from {peer} failed: {e}");
                if e.is_timeout() || e.is_parse_too_large() {
                    proxy.log.record(drop_line(peer, dst, None, None, Some(reason)));
                }
                conn.reset.store(true, Ordering::SeqCst);
            }
        }
        () = conn.denied.notified() => {}
        () = ended => {
            tracing::debug!("proxy: session for {peer} ended; closing its HTTP connection");
            conn.reset.store(true, Ordering::SeqCst);
        }
    }
    // Dropping hyper's connection (and so the `Io`) sends the RST if one was flagged.
    drop(served);

    let upgraded = conn.upgraded.lock().unwrap().take();
    if let Some(mut task) = upgraded {
        let ended = session_ended(&conn, proxy.sessions.clone());
        tokio::select! {
            _ = &mut task => {}
            () = ended => {
                conn.reset.store(true, Ordering::SeqCst);
                task.abort();
            }
        }
    }
}

/// Reads until `head` either starts with the h2c preface (`false`) or can't (`true`).
async fn read_preface(client: &mut TcpStream, head: &mut Vec<u8>) -> io::Result<bool> {
    loop {
        let n = head.len().min(H2C_PREFACE.len());
        if head[..n] != H2C_PREFACE[..n] {
            return Ok(true);
        }
        if n == H2C_PREFACE.len() {
            return Ok(false);
        }
        let mut chunk = [0; 64];
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.extend_from_slice(&chunk[..read]);
    }
}

/// Resolves once a session that allowed a request on `conn` is gone from the view.
async fn session_ended(conn: &Conn, mut sessions: watch::Receiver<Arc<SessionView>>) {
    loop {
        if sessions.changed().await.is_err() {
            return std::future::pending().await;
        }
        let granted = *conn.session.lock().unwrap();
        if let Some((ip, id)) = granted
            && sessions.borrow_and_update().get(&ip).map(|(i, _)| *i) != Some(id)
        {
            return;
        }
    }
}

fn drop_line(
    src: SocketAddr,
    dst: SocketAddr,
    host: Option<String>,
    path: Option<String>,
    reason: Option<&'static str>,
) -> Drop {
    Drop {
        src: src.ip(),
        dst,
        proto: "http",
        host,
        path,
        reason,
    }
}

/// One client connection's state, shared with its requests.
struct Conn {
    proxy: Arc<Proxy>,
    peer: SocketAddr,
    dst: SocketAddr,
    reset: Arc<AtomicBool>,
    /// Set while a response from [`Conn::request`] is on its way out (see [`Io::poll_write`]).
    answering: Arc<AtomicBool>,
    /// Notified when a request is denied with a RST.
    denied: Notify,
    /// The upstream connection, opened by the first forwarded request.
    upstream: tokio::sync::Mutex<Option<SendRequest<Incoming>>>,
    /// The latest session that allowed a request here; its end closes the connection.
    session: Mutex<Option<(IpAddr, u32)>>,
    /// Splices the two sides once an Upgrade succeeded.
    upgraded: Mutex<Option<JoinHandle<()>>>,
}

impl Conn {
    async fn request(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<Body>, Infallible> {
        // An absolute-form authority overrides the Host header, as hyper and upstreams read it.
        let host = match req.uri().authority() {
            Some(a) => Some(a.as_str().rsplit('@').next().unwrap_or_default().to_owned()),
            None => req
                .headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        };
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        let verdict = match host.as_deref() {
            _ if req.method() == Method::CONNECT => Err("connect"),
            None => Err("no-host"),
            Some(host) => {
                let view = self.proxy.sessions.borrow().clone();
                Ok(self.proxy.authorise(
                    &view,
                    self.peer.ip(),
                    self.dst,
                    Proto::Http,
                    host,
                    Some(&path),
                ))
            }
        };
        let enforcing = self.proxy.mode == Mode::Enforcing;
        match verdict {
            Ok(Verdict::Allow(grant)) => {
                if let Grant::Session { ip, id } = grant {
                    *self.session.lock().unwrap() = Some((ip, id));
                }
            }
            Ok(Verdict::PathDenied) => {
                self.log(host, Some(path), None);
                if enforcing {
                    return Ok(self.answer(not_found(&req)));
                }
            }
            Ok(Verdict::Deny) => {
                self.log(host, None, None);
                if enforcing {
                    return self.deny().await;
                }
            }
            Err(reason) => {
                self.log(host, None, Some(reason));
                if enforcing {
                    return self.deny().await;
                }
            }
        }
        self.forward(req).await
    }

    fn answer(&self, resp: Response<Body>) -> Response<Body> {
        self.answering.store(true, Ordering::SeqCst);
        resp
    }

    fn log(&self, host: Option<String>, path: Option<String>, reason: Option<&'static str>) {
        self.proxy
            .log
            .record(drop_line(self.peer, self.dst, host, path, reason));
    }

    /// Flags the connection for a RST and never answers, so nothing reaches the client.
    async fn deny(&self) -> Result<Response<Body>, Infallible> {
        self.reset.store(true, Ordering::SeqCst);
        self.denied.notify_one();
        std::future::pending().await
    }

    async fn forward(&self, mut req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        let client_upgrade = hyper::upgrade::on(&mut req);
        let mut upstream = self.upstream.lock().await;
        if upstream.as_ref().is_none_or(|s| s.is_closed()) {
            match self.connect().await {
                Some(sender) => *upstream = Some(sender),
                None => return self.deny().await,
            }
        }
        let sender = upstream.as_mut().expect("connected above");
        let mut resp = match sender.send_request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(
                    "proxy: forwarding {} to {} failed: {e}",
                    self.peer,
                    self.dst
                );
                return self.deny().await;
            }
        };
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            let task = tokio::spawn(async move {
                if let (Ok(client), Ok(upstream)) = tokio::join!(client_upgrade, upstream_upgrade) {
                    let _ = tokio::io::copy_bidirectional(
                        &mut TokioIo::new(client),
                        &mut TokioIo::new(upstream),
                    )
                    .await;
                }
            });
            *self.upgraded.lock().unwrap() = Some(task);
        }
        Ok(self.answer(resp.map(BodyExt::boxed)))
    }

    async fn connect(&self) -> Option<SendRequest<Incoming>> {
        let peer = self.peer;
        let dst = self.dst;
        let stream = match tokio::time::timeout(self.proxy.timeout, TcpStream::connect(dst)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::debug!("proxy: connecting {peer} to {dst} failed: {e}");
                return None;
            }
            Err(_) => {
                tracing::debug!("proxy: connecting {peer} to {dst} timed out");
                return None;
            }
        };
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .ok()?;
        tokio::spawn(conn.with_upgrades());
        Some(sender)
    }
}

/// `404 Not Found`, closing the connection if the request asked to.
fn not_found(req: &Request<Incoming>) -> Response<Body> {
    let mut resp = Response::new(Empty::new().map_err(|e| match e {}).boxed());
    *resp.status_mut() = StatusCode::NOT_FOUND;
    let close = req.headers().get_all(CONNECTION).iter().any(|v| {
        v.to_str()
            .is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
    });
    if close {
        resp.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    resp
}

/// The client stream with the bytes the proxy read before hyper took over replayed first.
struct Io {
    head: Vec<u8>,
    pos: usize,
    stream: TcpStream,
    reset: Arc<AtomicBool>,
    answering: Arc<AtomicBool>,
    /// Whether a `101 Switching Protocols` went out.
    upgraded: bool,
}

impl std::ops::Drop for Io {
    fn drop(&mut self) {
        if self.reset.load(Ordering::SeqCst)
            && let Err(e) = self.stream.set_zero_linger()
        {
            tracing::debug!("proxy: setting SO_LINGER failed: {e}");
        }
    }
}

impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.head.len() {
            let n = (self.head.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.head[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // hyper answers a request it can't parse (an oversized head gets 431) on its own. A
        // response head the service didn't produce is one of those: refuse it, so the
        // connection fails and is reset instead.
        // After a 101, the bytes are the upgraded protocol's.
        if !self.upgraded && buf.starts_with(b"HTTP/1.") {
            if !self.answering.swap(false, Ordering::SeqCst) {
                self.reset.store(true, Ordering::SeqCst);
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            self.upgraded = buf[8..].starts_with(b" 101 ");
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::super::tests::{Harness, assert_reset, harness_for};
    use super::*;
    use crate::firewall::ruleset::Mode;

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

    async fn http(mode: Mode) -> Harness {
        harness_for(mode, false, "http", "ok.test/pub").await
    }

    /// Reads from `stream` until `buf` ends with a blank line (a request or response head).
    async fn read_head(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
                .await
                .expect("no head in time")
                .unwrap();
            assert_ne!(
                n,
                0,
                "closed before a head: {:?}",
                String::from_utf8_lossy(&buf)
            );
            buf.push(byte[0]);
        }
        String::from_utf8(buf).unwrap()
    }

    /// Reads a response with a 2-byte (or empty, for a 404) body.
    async fn read_response(stream: &mut TcpStream) -> String {
        let head = read_head(stream).await;
        let len = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .map_or(0, |n| n.trim().parse().unwrap());
        let mut body = vec![0; len];
        stream.read_exact(&mut body).await.unwrap();
        head + &String::from_utf8(body).unwrap()
    }

    #[tokio::test]
    async fn allowed_request_is_forwarded() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /pub/x HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let (mut up, _) = h.upstream.accept().await.unwrap();
        let req = read_head(&mut up).await;
        assert!(req.starts_with("GET /pub/x HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("host: ok.test\r\n"), "{req}");
        up.write_all(OK).await.unwrap();
        let resp = read_response(&mut client).await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("ok"),
            "{resp}"
        );
    }

    #[tokio::test]
    async fn denied_host_is_reset() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: nope.test\r\n\r\n")
            .await
            .unwrap();
        assert_reset(&mut client).await;
    }

    async fn accept(h: &Harness) -> TcpStream {
        tokio::time::timeout(Duration::from_secs(5), h.upstream.accept())
            .await
            .expect("not forwarded")
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn denied_path_gets_404_and_the_connection_stays_open() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /private HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"), "{resp}");
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        let req = read_head(&mut up).await;
        assert!(req.starts_with("GET /pub HTTP/1.1\r\n"), "{req}");
        up.write_all(OK).await.unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn denied_path_with_connection_close_closes() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /private HTTP/1.1\r\nhost: ok.test\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 404"));
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn a_later_denied_host_on_a_keep_alive_connection_is_reset() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        read_head(&mut up).await;
        up.write_all(OK).await.unwrap();
        read_response(&mut client).await;
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: nope.test\r\n\r\n")
            .await
            .unwrap();
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn absolute_form_authority_is_the_host() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET http://nope.test/pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        assert_reset(&mut client).await;
    }

    async fn assert_request_reset(req: &[u8]) {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client.write_all(req).await.unwrap();
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn connect_is_reset() {
        assert_request_reset(b"CONNECT ok.test:443 HTTP/1.1\r\nhost: ok.test:443\r\n\r\n").await;
    }

    #[tokio::test]
    async fn missing_host_is_reset() {
        assert_request_reset(b"GET /pub HTTP/1.0\r\n\r\n").await;
    }

    #[tokio::test]
    async fn h2c_preface_is_reset() {
        assert_request_reset(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
    }

    #[tokio::test]
    async fn oversized_head_is_reset() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        let big = format!(
            "GET /pub HTTP/1.1\r\nhost: ok.test\r\nx: {}\r\n\r\n",
            "a".repeat(20_000)
        );
        let _ = client.write_all(big.as_bytes()).await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn incomplete_head_is_reset_after_the_timeout() {
        assert_request_reset(b"GET /pub HTTP/1.1\r\nhost: ok").await;
    }

    #[tokio::test]
    async fn upgrade_is_spliced() {
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /pub/ws HTTP/1.1\r\nhost: ok.test\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        let req = read_head(&mut up).await;
        assert!(req.contains("upgrade: websocket"), "{req}");
        up.write_all(b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 101"));
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        up.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        up.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn permissive_forwards_a_denied_host() {
        let h = http(Mode::Permissive).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /private HTTP/1.1\r\nhost: nope.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        assert!(read_head(&mut up).await.starts_with("GET /private"));
        up.write_all(OK).await.unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn session_end_closes_the_connection() {
        let mut h = harness_for(Mode::Enforcing, true, "http", "ok.test").await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        read_head(&mut up).await;
        up.write_all(OK).await.unwrap();
        read_response(&mut client).await;
        h.sessions
            .take()
            .unwrap()
            .send_replace(Arc::new(SessionView::new()));
        assert_reset(&mut client).await;
    }
}
