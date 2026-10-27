//! Transparent proxy for host rules (ADR 0004).
//!
//! nftables redirects flows that a host rule covers to [`ProxyConfig`]'s listener. The proxy
//! reads the connection's original destination, decides from the TLS SNI whether a client or
//! session host rule allows it, and either splices it to that destination or resets it.

mod droplog;
mod http;
pub(crate) mod sni;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnetwork::IpNetwork;
use nix::sys::socket::{getsockopt, setsockopt, sockopt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::firewall::ruleset::Mode;
use crate::policy::{Allow, Policy, Proto};
use crate::session::SessionView;
use droplog::{Denial, DenyReason, DropLog};
use sni::ClientHello;

/// How long a client has to send its ClientHello, and the proxy to connect upstream.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The listener's accept backlog.
const LISTEN_BACKLOG: u32 = 1024;

/// How long to wait before accepting again after an accept failed (out of file descriptors,
/// say), so a persistent failure doesn't spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// The most connections the proxy serves at once. Each takes two file descriptors (client and
/// upstream), so the process's `LimitNOFILE` must leave room for them and the portal.
const MAX_CONNECTIONS: usize = 4096;

/// The most connections the proxy serves at once from one source address, so one client can't
/// take every slot.
const MAX_PER_SOURCE: usize = 256;

/// Binds the proxy's dual-stack listener on `[::]:<port>` (`IPV6_V6ONLY=0`).
pub(crate) fn bind(port: u16) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v6()?;
    setsockopt(&socket, sockopt::Ipv6V6Only, &false)?;
    socket.set_reuseaddr(true)?;
    socket.bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))?;
    socket.listen(LISTEN_BACKLOG)
}

/// Everything the proxy needs; [`ProxyConfig::run`] serves it.
pub(crate) struct ProxyConfig {
    proxy: Proxy,
    listener: TcpListener,
}

impl ProxyConfig {
    /// `listener` comes from [`bind`]; `sessions` from the session manager (or
    /// [`crate::session::idle_view`] without a portal).
    pub(crate) fn new(
        policy: &Policy,
        sessions: watch::Receiver<Arc<SessionView>>,
        mode: Mode,
        listener: TcpListener,
    ) -> Self {
        ProxyConfig {
            proxy: Proxy::new(policy, sessions, mode),
            listener,
        }
    }

    /// Accepts and serves connections until aborted. Aborting it also drops every connection
    /// it serves.
    pub(crate) async fn run(self) {
        let proxy = Arc::new(self.proxy);
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let orig = original_dst(&stream, peer);
                        let local = stream.local_addr().ok();
                        conns.spawn(proxy.clone().admit(stream, peer, orig, local));
                    }
                    Err(e) => {
                        tracing::warn!("proxy accept failed: {e}");
                        tokio::time::sleep(ACCEPT_RETRY).await;
                    }
                },
                Some(_) = conns.join_next() => {}
            }
        }
    }
}

/// The destination the client aimed at before nftables redirected it, if it was redirected.
fn original_dst(stream: &TcpStream, peer: SocketAddr) -> Option<SocketAddr> {
    let fd = stream.as_fd();
    if canonical(peer).is_ipv4() {
        let sin = getsockopt(&fd, sockopt::OriginalDst).ok()?;
        Some(SocketAddr::V4(std::net::SocketAddrV4::new(
            u32::from_be(sin.sin_addr.s_addr).into(),
            u16::from_be(sin.sin_port),
        )))
    } else {
        let sin6 = getsockopt(&fd, sockopt::Ip6tOriginalDst).ok()?;
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            sin6.sin6_addr.s6_addr.into(),
            u16::from_be(sin6.sin6_port),
            0,
            0,
        )))
    }
}

/// `addr` with a v4-mapped IPv6 address turned back into IPv4.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// What the host rules say about a connection or request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow(Grant),
    /// A rule allows the host, but none allows the path (HTTP only).
    PathDenied,
    Deny,
}

impl Verdict {
    fn grant(self) -> Option<Grant> {
        match self {
            Verdict::Allow(grant) => Some(grant),
            _ => None,
        }
    }
}

/// Why a host rule allows a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// A client rule: holds for as long as the connection lasts.
    Client,
    /// The rules of the session `id` on `ip`: holds while that session lives.
    Session { ip: IpAddr, id: u32 },
}

struct Proxy {
    /// Each client's CIDR with its host rules (clients without any are left out).
    clients: Vec<(IpNetwork, Vec<Allow>)>,
    sessions: watch::Receiver<Arc<SessionView>>,
    mode: Mode,
    log: DropLog,
    timeout: Duration,
    limits: Arc<Limits>,
}

/// Counts the connections the proxy serves, in total and per source address.
struct Limits {
    total: usize,
    per_source: usize,
    open: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// One connection's slot in [`Limits`], released on drop.
struct Slot {
    limits: Arc<Limits>,
    src: IpAddr,
}

impl Limits {
    fn new(total: usize, per_source: usize) -> Self {
        Limits {
            total,
            per_source,
            open: Mutex::new((0, HashMap::new())),
        }
    }

    /// A slot for a connection from `src`, or `None` when it would go over either limit.
    fn acquire(limits: &Arc<Limits>, src: IpAddr) -> Option<Slot> {
        let mut open = limits.open.lock().unwrap_or_else(|e| e.into_inner());
        let (total, by_source) = &mut *open;
        let from_src = by_source.entry(src).or_default();
        if *total >= limits.total || *from_src >= limits.per_source {
            if *from_src == 0 {
                by_source.remove(&src);
            }
            return None;
        }
        *total += 1;
        *from_src += 1;
        Some(Slot {
            limits: limits.clone(),
            src,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.limits.open.lock().unwrap_or_else(|e| e.into_inner());
        let (total, by_source) = &mut *open;
        *total -= 1;
        if let Some(n) = by_source.get_mut(&self.src) {
            *n -= 1;
            if *n == 0 {
                by_source.remove(&self.src);
            }
        }
    }
}

impl Proxy {
    fn new(policy: &Policy, sessions: watch::Receiver<Arc<SessionView>>, mode: Mode) -> Self {
        let clients = policy
            .clients
            .iter()
            .map(|c| {
                let hosts = c.allow.iter().filter(|a| a.is_host_rule()).cloned();
                (c.cidr, hosts.collect::<Vec<_>>())
            })
            .filter(|(_, allow)| !allow.is_empty())
            .collect();
        Proxy {
            clients,
            sessions,
            mode,
            log: DropLog::new(mode),
            timeout: TIMEOUT,
            limits: Arc::new(Limits::new(MAX_CONNECTIONS, MAX_PER_SOURCE)),
        }
    }

    /// Whether `src` may reach `dst` with `proto` for `host` (and, for HTTP, `path`): the union
    /// of the client rules whose CIDR contains `src` and the rules of `src`'s live session in
    /// `view`. Client rules win, because they don't end with a session.
    fn authorise(
        &self,
        view: &SessionView,
        src: IpAddr,
        dst: SocketAddr,
        proto: Proto,
        host: &str,
        path: Option<&str>,
    ) -> Verdict {
        let src = src.to_canonical();
        let dst = canonical(dst);
        let mut path_denied = false;
        let mut allows = |rules: &[Allow]| match rules_allow(rules, dst, proto, host, path) {
            Some(true) => true,
            Some(false) => {
                path_denied = true;
                false
            }
            None => false,
        };
        for (cidr, rules) in &self.clients {
            if cidr.contains(src) && allows(rules) {
                return Verdict::Allow(Grant::Client);
            }
        }
        if let Some((id, rules)) = view.get(&src)
            && allows(rules)
        {
            return Verdict::Allow(Grant::Session { ip: src, id: *id });
        }
        if path_denied {
            Verdict::PathDenied
        } else {
            Verdict::Deny
        }
    }

    /// Serves one accepted connection from `peer` if the connection limits allow it, and resets
    /// it otherwise. Over the limit is enforced in permissive mode too: it protects the gateway.
    async fn admit(
        self: Arc<Self>,
        client: TcpStream,
        peer: SocketAddr,
        orig: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) {
        let src = peer.ip().to_canonical();
        let Some(_slot) = Limits::acquire(&self.limits, src) else {
            if let Some(dst) = orig {
                self.log.record(Denial {
                    src,
                    dst: canonical(dst),
                    proto: Proto::Tcp,
                    host: None,
                    path: None,
                    reason: Some(DenyReason::Limit),
                });
            }
            return reset(client);
        };
        self.handle(client, peer, orig, local).await;
    }

    /// Serves one accepted connection from `peer`.
    async fn handle(
        self: Arc<Self>,
        mut client: TcpStream,
        peer: SocketAddr,
        orig: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) {
        let peer = canonical(peer);
        let local = local.map(canonical);
        let dst = match orig.map(canonical) {
            Some(dst) if !is_proxy_itself(dst, local) => dst,
            _ => {
                tracing::debug!("proxy: {peer} has no original destination; resetting");
                return reset(client);
            }
        };

        let mut buf = Vec::with_capacity(1024);
        let hello = tokio::time::timeout(self.timeout, read_hello(&mut client, &mut buf)).await;
        let (host, reason) = match hello {
            Err(_) => (None, Some(DenyReason::Timeout)),
            Ok(Err(_)) | Ok(Ok(None)) => return,
            // Anything that doesn't open with a TLS handshake record is taken for HTTP.
            Ok(Ok(Some(_))) if buf.first() != Some(&sni::CONTENT_HANDSHAKE) => {
                return http::serve(self, client, peer, dst, buf).await;
            }
            Ok(Ok(Some(hello))) => match hello {
                ClientHello::Sni(host) => (Some(host), None),
                ClientHello::NoSni => (None, Some(DenyReason::NoSni)),
                ClientHello::Ech => (None, Some(DenyReason::Ech)),
                ClientHello::NotTls => (None, Some(DenyReason::NotTls)),
                ClientHello::Malformed | ClientHello::NeedMore => {
                    (None, Some(DenyReason::Malformed))
                }
            },
        };

        let mut sessions = self.sessions.clone();
        let grant = host.as_deref().and_then(|h| {
            self.authorise(
                &sessions.borrow_and_update(),
                peer.ip(),
                dst,
                Proto::Https,
                h,
                None,
            )
            .grant()
        });
        if grant.is_none() {
            self.log.record(Denial {
                src: peer.ip(),
                dst,
                proto: Proto::Https,
                host,
                path: None,
                reason,
            });
            if self.mode == Mode::Enforcing {
                return reset(client);
            }
        }

        let Some(upstream) = self.connect_upstream(peer, dst).await else {
            return reset(client);
        };
        splice(client, upstream, &buf, grant, sessions).await;
    }

    /// Connects to `dst` for `peer` within the timeout; failures are logged at debug.
    async fn connect_upstream(&self, peer: SocketAddr, dst: SocketAddr) -> Option<TcpStream> {
        match tokio::time::timeout(self.timeout, TcpStream::connect(dst)).await {
            Ok(Ok(upstream)) => Some(upstream),
            Ok(Err(e)) => {
                tracing::debug!("proxy: connecting {peer} to {dst} failed: {e}");
                None
            }
            Err(_) => {
                tracing::debug!("proxy: connecting {peer} to {dst} timed out");
                None
            }
        }
    }
}

/// Whether `dst` is the proxy's own listener: its accepted address, or any of the host's own
/// addresses on its port (the listener is bound to all of them). Connecting there would loop.
fn is_proxy_itself(dst: SocketAddr, local: Option<SocketAddr>) -> bool {
    let Some(local) = local else {
        return true;
    };
    // Only a local address can be bound (without IP_FREEBIND).
    dst == local || (dst.port() == local.port() && std::net::UdpSocket::bind((dst.ip(), 0)).is_ok())
}

/// `None` if no rule in `rules` allows `host` at `dst`; otherwise whether one also allows `path`
/// (always, when `path` is `None`).
fn rules_allow(
    rules: &[Allow],
    dst: SocketAddr,
    proto: Proto,
    host: &str,
    path: Option<&str>,
) -> Option<bool> {
    let mut host_allowed = false;
    let covering = rules.iter().filter(|r| {
        r.proto == proto
            && r.dest.iter().any(|d| d.contains(dst.ip()))
            && r.effective_ports()
                .iter()
                .any(|p| (p.lo..=p.hi).contains(&dst.port()))
    });
    for pattern in covering.flat_map(|r| &r.hosts) {
        if pattern.matches_host(host) {
            if path.is_none_or(|p| pattern.matches_path(p)) {
                return Some(true);
            }
            host_allowed = true;
        }
    }
    host_allowed.then_some(false)
}

/// Reads into `buf` until the ClientHello parser has a verdict. `None` if the client closed
/// first.
async fn read_hello(client: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<ClientHello>> {
    loop {
        match sni::parse(buf) {
            ClientHello::NeedMore => {}
            verdict => return Ok(Some(verdict)),
        }
        let mut chunk = [0; 4096];
        let want = (sni::MAX_INPUT - buf.len()).min(chunk.len());
        let n = client.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Sends `head` upstream, then copies both ways until either side closes, or until the session
/// behind a [`Grant::Session`] ends.
async fn splice(
    mut client: TcpStream,
    mut upstream: TcpStream,
    head: &[u8],
    grant: Option<Grant>,
    mut sessions: watch::Receiver<Arc<SessionView>>,
) {
    if upstream.write_all(head).await.is_err() {
        return reset(client);
    }
    let Some(Grant::Session { ip, id }) = grant else {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return;
    };
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
        () = session_gone(&mut sessions, || Some((ip, id))) => {
            tracing::debug!("proxy: session {id} on {ip} ended; closing its connection");
            reset(upstream);
            reset(client);
        }
    }
}

/// Resolves once the session `granted` names (when it names one) is no longer in the view:
/// ended, or replaced by another session on its IP. `granted` is read again at each change.
///
/// If the session manager drops its sender (it has stopped, at shutdown), this never resolves:
/// the proxy is aborted next, which closes every connection anyway.
async fn session_gone(
    sessions: &mut watch::Receiver<Arc<SessionView>>,
    granted: impl Fn() -> Option<(IpAddr, u32)>,
) {
    while sessions.changed().await.is_ok() {
        if let Some((ip, id)) = granted()
            && sessions.borrow_and_update().get(&ip).map(|(i, _)| *i) != Some(id)
        {
            return;
        }
    }
    std::future::pending().await
}

/// Closes `stream` with a TCP RST.
fn reset(stream: TcpStream) {
    if let Err(e) = stream.set_zero_linger() {
        tracing::debug!("proxy: setting SO_LINGER failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::idle_view;

    const SRC: &str = "10.0.0.5";

    fn policy(yaml: &str) -> Policy {
        Policy::parse(yaml).unwrap()
    }

    fn allow(yaml: &str) -> Arc<[Allow]> {
        policy(&format!(
            "clients:\n  - cidr: 0.0.0.0/0\n    allow:\n{yaml}"
        ))
        .clients
        .remove(0)
        .allow
        .into()
    }

    const CLIENT_POLICY: &str = "
clients:
  - cidr: 10.0.0.0/24
    allow:
      - { dest: [192.0.2.1/32], proto: https, hosts: [a.test] }
      - { dest: [192.0.2.0/24], proto: tcp, ports: [443] }
  - cidr: 10.0.0.5/32
    allow:
      - { dest: [192.0.2.2/32], proto: https, ports: [8443], hosts: [\"*.b.test\"] }
";

    fn auth(proxy: &Proxy, view: &SessionView, dst: &str, host: &str) -> Option<Grant> {
        proxy
            .authorise(
                view,
                SRC.parse().unwrap(),
                dst.parse().unwrap(),
                Proto::Https,
                host,
                None,
            )
            .grant()
    }

    #[test]
    fn client_rules_union_with_dest_and_port_checks() {
        let proxy = Proxy::new(&policy(CLIENT_POLICY), idle_view(), Mode::Enforcing);
        let view = SessionView::new();
        assert_eq!(
            auth(&proxy, &view, "192.0.2.1:443", "a.test"),
            Some(Grant::Client)
        );
        assert_eq!(
            auth(&proxy, &view, "192.0.2.2:8443", "x.b.test"),
            Some(Grant::Client)
        );
        // Wrong host, dest outside the matching rule, wrong port.
        assert_eq!(auth(&proxy, &view, "192.0.2.1:443", "x.b.test"), None);
        assert_eq!(auth(&proxy, &view, "192.0.2.2:443", "a.test"), None);
        assert_eq!(auth(&proxy, &view, "192.0.2.2:443", "x.b.test"), None);
        // An IP rule for the same dest and port doesn't allow a host.
        assert_eq!(auth(&proxy, &view, "192.0.2.3:443", "a.test"), None);
        // Another source, and a v4-mapped one.
        let other = proxy
            .authorise(
                &view,
                "10.0.1.5".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                Proto::Https,
                "a.test",
                None,
            )
            .grant();
        assert_eq!(other, None);
        let mapped = proxy
            .authorise(
                &view,
                "::ffff:10.0.0.5".parse().unwrap(),
                "[::ffff:192.0.2.1]:443".parse().unwrap(),
                Proto::Https,
                "a.test",
                None,
            )
            .grant();
        assert_eq!(mapped, Some(Grant::Client));
    }

    #[test]
    fn session_rules_are_added_and_carry_the_session_id() {
        let proxy = Proxy::new(&policy(CLIENT_POLICY), idle_view(), Mode::Enforcing);
        let rules = allow("      - { dest: [198.51.100.0/24], proto: https, hosts: [c.test] }");
        let ip: IpAddr = SRC.parse().unwrap();
        let mut view = SessionView::new();
        assert_eq!(auth(&proxy, &view, "198.51.100.1:443", "c.test"), None);
        view.insert(ip, (7, rules.clone()));
        assert_eq!(
            auth(&proxy, &view, "198.51.100.1:443", "c.test"),
            Some(Grant::Session { ip, id: 7 })
        );
        assert_eq!(
            auth(&proxy, &view, "192.0.2.1:443", "a.test"),
            Some(Grant::Client)
        );
        view.insert(ip, (8, rules));
        assert_eq!(
            auth(&proxy, &view, "198.51.100.1:443", "c.test"),
            Some(Grant::Session { ip, id: 8 })
        );
    }

    #[test]
    fn http_rules_do_not_allow_https() {
        let proxy = Proxy::new(
            &policy(
                "clients:\n  - cidr: 10.0.0.0/24\n    allow:\n      - { dest: [192.0.2.1/32], proto: http, ports: [443], hosts: [a.test] }\n",
            ),
            idle_view(),
            Mode::Enforcing,
        );
        assert_eq!(
            auth(&proxy, &SessionView::new(), "192.0.2.1:443", "a.test"),
            None
        );
    }

    #[test]
    fn http_rules_check_the_path() {
        let proxy = Proxy::new(
            &policy(
                "clients:\n  - cidr: 10.0.0.0/24\n    allow:\n      - { dest: [192.0.2.1/32], proto: http, hosts: [a.test/pub, b.test] }\n",
            ),
            idle_view(),
            Mode::Enforcing,
        );
        let view = SessionView::new();
        let check = |host: &str, path: &str| {
            proxy.authorise(
                &view,
                SRC.parse().unwrap(),
                "192.0.2.1:80".parse().unwrap(),
                Proto::Http,
                host,
                Some(path),
            )
        };
        assert_eq!(check("a.test", "/pub/x"), Verdict::Allow(Grant::Client));
        assert_eq!(check("b.test", "/anything"), Verdict::Allow(Grant::Client));
        assert_eq!(check("a.test", "/private"), Verdict::PathDenied);
        assert_eq!(check("c.test", "/pub"), Verdict::Deny);
    }

    // Flows over loopback: the test plays nftables by handing `handle` the upstream listener's
    // address as the original destination.

    pub(super) struct Harness {
        proxy: Arc<Proxy>,
        pub(super) upstream: TcpListener,
        pub(super) sessions: Option<watch::Sender<Arc<SessionView>>>,
    }

    async fn harness(mode: Mode, session: bool) -> Harness {
        harness_for(mode, session, "https", "ok.test").await
    }

    /// A proxy whose client (or, with `session`, session) rule allows `proto` to `hosts` on the
    /// upstream listener.
    pub(super) async fn harness_for(
        mode: Mode,
        session: bool,
        proto: &str,
        hosts: &str,
    ) -> Harness {
        // SO_REUSEPORT lets a test hold the port once the listener is gone (see
        // `upstream_failure_is_reset`).
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseport(true).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let upstream = socket.listen(16).unwrap();
        let port = upstream.local_addr().unwrap().port();
        let rule = format!(
            "      - {{ dest: [127.0.0.1/32], proto: {proto}, ports: [{port}], hosts: [{hosts}] }}\n"
        );
        let (tx, rx) = watch::channel(Arc::new(SessionView::new()));
        let yaml = if session {
            let mut view = SessionView::new();
            view.insert("127.0.0.1".parse().unwrap(), (5, allow(&rule)));
            tx.send_replace(Arc::new(view));
            String::from("clients: []\n")
        } else {
            format!("clients:\n  - cidr: 127.0.0.0/8\n    allow:\n{rule}")
        };
        let mut proxy = Proxy::new(&policy(&yaml), rx, mode);
        proxy.timeout = Duration::from_millis(300);
        Harness {
            proxy: Arc::new(proxy),
            upstream,
            sessions: Some(tx),
        }
    }

    impl Harness {
        /// Connects a client through the proxy to the upstream listener.
        pub(super) async fn connect(&self) -> TcpStream {
            self.connect_task().await.0
        }

        /// [`Harness::connect`], also returning the task serving the connection.
        pub(super) async fn connect_task(&self) -> (TcpStream, tokio::task::JoinHandle<()>) {
            let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(front.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, peer) = front.accept().await.unwrap();
            let orig = self.upstream.local_addr().ok();
            let local = stream.local_addr().ok();
            let task = tokio::spawn(self.proxy.clone().admit(stream, peer, orig, local));
            (client, task)
        }
    }

    pub(super) async fn assert_reset(client: &mut TcpStream) {
        let mut buf = [0; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no reset in time")
            .expect_err("expected a reset");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    async fn send_hello(client: &mut TcpStream, sni: Option<&str>) -> Vec<u8> {
        let hello = sni::tests::client_hello(sni);
        client.write_all(&hello).await.unwrap();
        hello
    }

    #[tokio::test]
    async fn allowed_sni_is_spliced() {
        let h = harness(Mode::Enforcing, false).await;
        let mut client = h.connect().await;
        let hello = send_hello(&mut client, Some("ok.test")).await;
        let (mut up, _) = h.upstream.accept().await.unwrap();
        let mut got = vec![0; hello.len()];
        up.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello);
        up.write_all(b"pong").await.unwrap();
        let mut back = [0; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    #[tokio::test]
    async fn denied_sni_is_reset() {
        let h = harness(Mode::Enforcing, false).await;
        let mut client = h.connect().await;
        send_hello(&mut client, Some("nope.test")).await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn no_sni_is_reset() {
        let h = harness(Mode::Enforcing, false).await;
        let mut client = h.connect().await;
        send_hello(&mut client, None).await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn silent_client_is_reset_after_the_timeout() {
        let h = harness(Mode::Enforcing, false).await;
        let mut client = h.connect().await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn missing_original_destination_is_reset() {
        let h = harness(Mode::Enforcing, false).await;
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(front.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = front.accept().await.unwrap();
        let local = stream.local_addr().ok();
        // Aimed at the proxy itself.
        tokio::spawn(h.proxy.clone().handle(stream, peer, local, local));
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn another_local_address_on_the_proxy_port_is_reset() {
        // A redirected flow aimed at one of the gateway's own addresses on the proxy's port
        // would loop back into the proxy, even where a rule allows that address.
        // Listening on every address, as the proxy does.
        let front = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = front.local_addr().unwrap().port();
        let rule = format!(
            "      - {{ dest: [127.0.0.0/8], proto: https, ports: [{port}], hosts: [ok.test] }}\n"
        );
        let yaml = format!("clients:\n  - cidr: 127.0.0.0/8\n    allow:\n{rule}");
        let proxy = Arc::new(Proxy::new(&policy(&yaml), idle_view(), Mode::Enforcing));
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (stream, peer) = front.accept().await.unwrap();
        let local = stream.local_addr().ok();
        let orig = Some(SocketAddr::new("127.0.0.2".parse().unwrap(), port));
        tokio::spawn(proxy.handle(stream, peer, orig, local));
        send_hello(&mut client, Some("ok.test")).await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn upstream_failure_is_reset() {
        let h = harness(Mode::Enforcing, false).await;
        let mut client = h.connect().await;
        // Keep the port bound but not listening, so connecting to it is refused. A freed port
        // could be taken by a parallel test, or by the proxy's own connect as its source port.
        let hold = TcpSocket::new_v4().unwrap();
        hold.set_reuseport(true).unwrap();
        hold.bind(h.upstream.local_addr().unwrap()).unwrap();
        drop(h.upstream);
        send_hello(&mut client, Some("ok.test")).await;
        assert_reset(&mut client).await;
    }

    #[tokio::test]
    async fn permissive_splices_a_denied_sni() {
        let h = harness(Mode::Permissive, false).await;
        let mut client = h.connect().await;
        let hello = send_hello(&mut client, Some("nope.test")).await;
        let (mut up, _) = h.upstream.accept().await.unwrap();
        let mut got = vec![0; hello.len()];
        up.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello);
    }

    #[tokio::test]
    async fn session_end_closes_the_connection() {
        let mut h = harness(Mode::Enforcing, true).await;
        let mut client = h.connect().await;
        send_hello(&mut client, Some("ok.test")).await;
        let (mut up, _) = h.upstream.accept().await.unwrap();
        let mut buf = [0; 1];
        up.read_exact(&mut buf).await.unwrap();
        // A change that keeps the session doesn't cut it.
        let tx = h.sessions.take().unwrap();
        tx.send_modify(|_| {});
        up.write_all(b"x").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        // Replaced by another session on the same IP.
        tx.send_modify(|v| {
            let mut view = (**v).clone();
            view.get_mut(&"127.0.0.1".parse::<IpAddr>().unwrap())
                .unwrap()
                .0 = 6;
            *v = Arc::new(view);
        });
        assert_reset(&mut client).await;
    }

    #[test]
    fn limits_cap_connections_globally_and_per_source() {
        let limits = Arc::new(Limits::new(3, 2));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let a1 = Limits::acquire(&limits, a).expect("first from a");
        let _a2 = Limits::acquire(&limits, a).expect("second from a");
        assert!(Limits::acquire(&limits, a).is_none(), "over a's limit");
        let _b1 = Limits::acquire(&limits, b).expect("first from b");
        assert!(
            Limits::acquire(&limits, b).is_none(),
            "over the global limit"
        );
        drop(a1);
        assert!(Limits::acquire(&limits, b).is_some(), "a's slot freed");
    }

    #[tokio::test]
    async fn over_the_source_limit_is_reset() {
        let mut h = harness(Mode::Enforcing, false).await;
        Arc::get_mut(&mut h.proxy).unwrap().limits = Arc::new(Limits::new(16, 1));
        let mut first = h.connect().await;
        send_hello(&mut first, Some("ok.test")).await;
        let (_up, _) = h.upstream.accept().await.unwrap();
        let mut second = h.connect().await;
        assert_reset(&mut second).await;
        // The first is still served.
        drop(first);
    }

    #[tokio::test]
    async fn bind_is_dual_stack() {
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert!(canonical(peer).is_ipv4());
    }
}
