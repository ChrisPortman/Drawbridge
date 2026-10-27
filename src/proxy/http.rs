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

use super::droplog::{Denial, DenyReason};
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
                .record(drop_line(peer, dst, None, None, Some(DenyReason::H2c)));
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
                .record(drop_line(peer, dst, None, None, Some(DenyReason::Timeout)));
            return super::reset(client);
        }
    }

    let reset = Arc::new(AtomicBool::new(false));
    let answering = Arc::new(Answering::default());
    let idle = Arc::new(AtomicBool::new(false));
    let io = Io {
        head,
        pos: 0,
        stream: client,
        reset: reset.clone(),
        answering: answering.clone(),
        idle: idle.clone(),
        in_response: false,
        response_flushed: false,
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
        upstream_conn: Mutex::new(None),
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
            match res {
                // hyper's header timeout also runs between requests: an idle keep-alive
                // connection did nothing wrong, so it just closes.
                Err(e) if e.is_timeout() && idle.load(Ordering::SeqCst) => {
                    tracing::debug!("proxy: closing idle HTTP connection from {peer}");
                }
                Err(e) => {
                let reason = if e.is_timeout() {
                    DenyReason::Timeout
                } else if e.is_parse_too_large() {
                    DenyReason::Oversized
                } else {
                    DenyReason::Malformed
                };
                tracing::debug!("proxy: HTTP from {peer} failed: {e}");
                if e.is_timeout() || e.is_parse_too_large() {
                    proxy.log.record(drop_line(peer, dst, None, None, Some(reason)));
                }
                conn.reset.store(true, Ordering::SeqCst);
                }
                Ok(()) => {}
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
    if let Some(task) = upgraded {
        let ended = session_ended(&conn, proxy.sessions.clone());
        tokio::select! {
            () = task => {}
            () = ended => conn.reset.store(true, Ordering::SeqCst),
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
    reason: Option<DenyReason>,
) -> Denial {
    Denial {
        src: src.ip(),
        dst,
        proto: Proto::Http,
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
    /// Tells the [`Io`] about the responses [`Conn::request`] produces.
    answering: Arc<Answering>,
    /// Notified when a request is denied with a RST.
    denied: Notify,
    /// The upstream connection, opened by the first forwarded request.
    upstream: tokio::sync::Mutex<Option<SendRequest<Incoming>>>,
    /// The latest session that allowed a request here; its end closes the connection.
    session: Mutex<Option<(IpAddr, u32)>>,
    /// Splices the two sides once an Upgrade succeeded.
    upgraded: Mutex<Option<AbortOnDrop>>,
    /// Drives the upstream connection, opened with `upstream`.
    upstream_conn: Mutex<Option<AbortOnDrop>>,
}

/// A spawned task that is aborted when this is dropped, so it can't outlive the connection
/// (whose task the proxy aborts on shutdown) that spawned it.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Future for AbortOnDrop {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx).map(|_| ())
    }
}

impl Conn {
    async fn request(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<Body>, Infallible> {
        let host = request_host(&req);
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        let verdict = match &host {
            _ if req.method() == Method::CONNECT => Err(DenyReason::Connect),
            Err(reason) => Err(*reason),
            Ok(host) => {
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
        let host = host.ok();
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

    /// Marks `resp` as the service's, so the [`Io`] lets it out.
    fn answer(&self, resp: Response<Body>) -> Response<Body> {
        let a = &self.answering;
        a.body_done.store(false, Ordering::SeqCst);
        a.upgrade
            .store(resp.status() == StatusCode::SWITCHING_PROTOCOLS, Ordering::SeqCst);
        a.head_next.store(true, Ordering::SeqCst);
        let done = a.clone();
        resp.map(|body| TrackedBody { body, done }.boxed())
    }

    fn log(&self, host: Option<String>, path: Option<String>, reason: Option<DenyReason>) {
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
            *self.upgraded.lock().unwrap() = Some(AbortOnDrop(task));
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
        let task = tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        *self.upstream_conn.lock().unwrap() = Some(AbortOnDrop(task));
        Some(sender)
    }
}

/// The host a request is for: its absolute-form authority (without userinfo) or its Host header.
/// A request that names two hosts (two Host headers, or an authority that disagrees with the
/// Host header) is `ambiguous-host`: upstreams differ on which one wins.
fn request_host(req: &Request<Incoming>) -> Result<String, DenyReason> {
    let mut headers = req.headers().get_all(HOST).iter();
    let header = match (headers.next(), headers.next()) {
        (_, Some(_)) => return Err(DenyReason::AmbiguousHost),
        (Some(v), None) => Some(v.to_str().map_err(|_| DenyReason::NoHost)?),
        (None, None) => None,
    };
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().rsplit('@').next().unwrap_or_default());
    match (authority, header) {
        (Some(a), Some(h)) if !a.eq_ignore_ascii_case(h) => Err(DenyReason::AmbiguousHost),
        (Some(host), _) | (None, Some(host)) => Ok(host.to_owned()),
        (None, None) => Err(DenyReason::NoHost),
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

/// What [`Conn::answer`] tells the [`Io`] about the service's responses.
#[derive(Default)]
struct Answering {
    /// The next write starts a response head the service produced.
    head_next: AtomicBool,
    /// That response is a `101 Switching Protocols`.
    upgrade: AtomicBool,
    /// hyper has finished with (or dropped) that response's body.
    body_done: AtomicBool,
}

/// A response body that tells [`Answering::body_done`] when hyper is done with it.
struct TrackedBody {
    body: Body,
    done: Arc<Answering>,
}

impl hyper::body::Body for TrackedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let polled = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(None) = polled {
            self.done.body_done.store(true, Ordering::SeqCst);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl Drop for TrackedBody {
    fn drop(&mut self) {
        self.done.body_done.store(true, Ordering::SeqCst);
    }
}

/// The client stream with the bytes the proxy read before hyper took over replayed first.
///
/// hyper answers a request it can't parse (an oversized head gets 431) on its own. The `Io`
/// refuses any write that isn't part of a response the service produced, so the connection
/// fails and is reset instead. A response lasts from its head until its body is done, flushed,
/// and the client has sent more (hyper only parses, and so only fails on, a next request then).
struct Io {
    head: Vec<u8>,
    pos: usize,
    stream: TcpStream,
    reset: Arc<AtomicBool>,
    answering: Arc<Answering>,
    /// Whether the writes belong to a response the service produced.
    in_response: bool,
    /// Whether that response's body is done and everything written is flushed.
    response_flushed: bool,
    /// Set when a response head goes out, cleared when the client sends more: whether the
    /// connection is waiting for a next request that hasn't started.
    idle: Arc<AtomicBool>,
    /// Whether a `101 Switching Protocols` went out.
    upgraded: bool,
}

impl Drop for Io {
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
        let filled = buf.filled().len();
        let polled = Pin::new(&mut self.stream).poll_read(cx, buf);
        if buf.filled().len() > filled {
            self.idle.store(false, Ordering::SeqCst);
            if self.response_flushed {
                self.in_response = false;
            }
        }
        polled
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // After a 101, the bytes are the upgraded protocol's.
        if !self.upgraded {
            if self.answering.head_next.swap(false, Ordering::SeqCst) {
                self.in_response = true;
                self.response_flushed = false;
                self.upgraded = self.answering.upgrade.load(Ordering::SeqCst);
                self.idle.store(true, Ordering::SeqCst);
            } else if !self.in_response {
                self.reset.store(true, Ordering::SeqCst);
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let flushed = Pin::new(&mut self.stream).poll_flush(cx);
        if let Poll::Ready(Ok(())) = flushed
            && self.answering.body_done.load(Ordering::SeqCst)
        {
            self.response_flushed = true;
        }
        flushed
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
    async fn an_idle_keep_alive_connection_is_closed_without_a_reset() {
        // hyper's header timeout also runs while waiting for the next request; an idle client
        // did nothing wrong, so it gets a FIN, not a RST.
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /private HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 404"));
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
            .await
            .expect("not closed in time")
            .expect("closed with a reset");
        assert!(rest.is_empty());
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
    async fn a_second_host_header_is_reset() {
        // Upstreams disagree on which of two Host headers wins.
        assert_request_reset(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\nhost: nope.test\r\n\r\n")
            .await;
    }

    #[tokio::test]
    async fn an_authority_that_differs_from_the_host_header_is_reset() {
        // An upstream that ignores the absolute form would route by the Host header.
        assert_request_reset(b"GET http://ok.test/pub HTTP/1.1\r\nhost: nope.test\r\n\r\n").await;
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
    async fn oversized_head_after_a_response_is_reset() {
        // The 431 hyper writes on its own comes after a response the service produced.
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /private HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 404"));
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

    /// Reads from `stream` until it closes, failing if it is still open after 5s.
    async fn assert_closes(stream: &mut TcpStream) {
        let mut buf = [0; 64];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                .await
                .expect("still open")
            {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn aborting_the_connection_closes_an_upgraded_splice() {
        // Aborting the proxy aborts its connections; their splices must not outlive them.
        let h = http(Mode::Enforcing).await;
        let (mut client, task) = h.connect_task().await;
        client
            .write_all(b"GET /pub/ws HTTP/1.1\r\nhost: ok.test\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        read_head(&mut up).await;
        up.write_all(b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 101"));
        task.abort();
        assert_closes(&mut up).await;
        assert_closes(&mut client).await;
    }

    #[tokio::test]
    async fn aborting_the_connection_closes_the_upstream() {
        let h = http(Mode::Enforcing).await;
        let (mut client, task) = h.connect_task().await;
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        read_head(&mut up).await;
        up.write_all(OK).await.unwrap();
        read_response(&mut client).await;
        task.abort();
        assert_closes(&mut up).await;
    }

    #[tokio::test]
    async fn a_body_that_looks_like_a_response_head_is_forwarded() {
        // Only a response the service produced may go out, but a body chunk that happens to
        // start like a head is part of one.
        let h = http(Mode::Enforcing).await;
        let mut client = h.connect().await;
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        let mut up = accept(&h).await;
        read_head(&mut up).await;
        up.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\n")
            .await
            .unwrap();
        // Let the head go out on its own before the body.
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        up.write_all(b"HTTP/1.").await.unwrap();
        let mut body = [0; 7];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut body))
            .await
            .expect("no body in time")
            .expect("body forwarded");
        assert_eq!(&body, b"HTTP/1.");
        // And the connection is still usable.
        client
            .write_all(b"GET /pub HTTP/1.1\r\nhost: ok.test\r\n\r\n")
            .await
            .unwrap();
        read_head(&mut up).await;
        up.write_all(OK).await.unwrap();
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
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
