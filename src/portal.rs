//! The login portal: an HTTPS site on the gateway that sends the browser through the OIDC flow,
//! provisions the session for its source IP, and keeps it alive while the page stays open.
//!
//! - `GET /`: the confirmation page for a live session, otherwise a redirect to `/login`.
//! - `GET /login[?silent=1]`: starts an authorization request (`prompt=none` when silent).
//! - `GET /callback`: completes it and provisions access.
//! - `GET /api/session`: the session as JSON, polled by the page to schedule re-authentication.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_server::Server;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use serde::Deserialize;
use tokio::task::{JoinError, JoinSet};
use tracing::{info, warn};

mod oidc;

pub(crate) use oidc::OidcConfig;
// `pub` so `cli` can re-export it: it is the type of a public CLI field.
pub use oidc::Secret;

use crate::session::{SessionError, SessionHandle, unix_secs};
use oidc::{Authenticator, Oidc, OidcError, PendingLogin};

/// Holds the session token. `__Host-` makes browsers insist on Secure, Path=/ and no Domain.
const SESSION_COOKIE: &str = "__Host-drawbridge_session";
/// Ties a callback to the browser that started the login, against login CSRF.
const LOGIN_COOKIE: &str = "__Host-drawbridge_login";
/// How long a started login may take to come back.
const LOGIN_TTL: Duration = Duration::from_secs(600);
/// Logins in flight across all clients, and per client (see [`client_prefix`]), bounding memory.
const MAX_PENDING: usize = 10_000;
const MAX_PENDING_PER_CLIENT: usize = 16;
/// Provider errors to a `prompt=none` request that just mean the user must interact.
const INTERACTION_ERRORS: [&str; 4] = [
    "login_required",
    "interaction_required",
    "consent_required",
    "account_selection_required",
];

const INDEX_HTML: &str = include_str!("portal/index.html");
const MESSAGE_HTML: &str = include_str!("portal/message.html");

struct Pending {
    login: PendingLogin,
    silent: bool,
    ip: IpAddr,
    started: Instant,
}

/// What the portal needs to start.
#[derive(Debug)]
pub(crate) struct PortalConfig {
    pub(crate) oidc: OidcConfig,
    pub(crate) tls_cert: PathBuf,
    pub(crate) tls_key: PathBuf,
    pub(crate) listen: Vec<SocketAddr>,
}

/// Why the portal couldn't start, or stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PortalError {
    #[error(
        "loading TLS certificate {cert} and key {key}",
        cert = .cert.display(),
        key = .key.display()
    )]
    Tls {
        cert: PathBuf,
        key: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("contacting OIDC issuer {issuer}")]
    Oidc {
        issuer: String,
        #[source]
        source: OidcError,
    },
    #[error("binding portal listener {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("portal listener {addr} stopped")]
    Stopped { addr: SocketAddr },
    #[error("portal listener {addr} failed")]
    Failed {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("portal task panicked")]
    Panicked(#[source] JoinError),
}

/// A portal ready to serve: TLS loaded, the OIDC provider discovered and the TLS servers built
/// on bound listeners. Everything fallible happens here, before the firewall is touched, so
/// [`serve`](Self::serve) can't fail and leave the table provisioned without a portal.
pub(crate) struct Prepared {
    oidc: Oidc,
    servers: Vec<(SocketAddr, Server<SocketAddr, RustlsAcceptor>)>,
    handle: axum_server::Handle<SocketAddr>,
}

impl Prepared {
    /// Loads the TLS files, discovers the OIDC provider (network I/O) and binds every listener.
    /// Installs rustls's ring crypto provider for the process if none is set.
    pub(crate) async fn new(config: PortalConfig) -> Result<Self, PortalError> {
        // rustls needs a process-wide crypto provider; `Err` only means one is installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = RustlsConfig::from_pem_file(&config.tls_cert, &config.tls_key)
            .await
            .map_err(|source| PortalError::Tls {
                cert: config.tls_cert.clone(),
                key: config.tls_key.clone(),
                source,
            })?;
        let issuer = config.oidc.issuer.clone();
        let oidc = Oidc::discover(config.oidc)
            .await
            .map_err(|source| PortalError::Oidc { issuer, source })?;
        let handle = axum_server::Handle::new();
        let servers = config
            .listen
            .iter()
            .map(|&addr| {
                let bind = || {
                    let listener = TcpListener::bind(addr)?;
                    listener.set_nonblocking(true)?;
                    let bound = listener.local_addr()?;
                    let server = axum_server::from_tcp_rustls(listener, tls.clone())?;
                    Ok((bound, server.handle(handle.clone())))
                };
                bind().map_err(|source| PortalError::Bind { addr, source })
            })
            .collect::<Result<_, _>>()?;
        Ok(Prepared {
            oidc,
            servers,
            handle,
        })
    }

    /// Starts serving on every listener, provisioning logins through `sessions`.
    pub(crate) fn serve(self, sessions: SessionHandle) -> Servers {
        let app = router(Portal::new(self.oidc, sessions))
            .into_make_service_with_connect_info::<SocketAddr>();
        let mut tasks = JoinSet::new();
        for (addr, server) in self.servers {
            let app = app.clone();
            tasks.spawn(async move { (addr, server.serve(app).await) });
            info!(%addr, "portal listening");
        }
        Servers {
            tasks,
            handle: self.handle,
        }
    }
}

/// The running portal listeners. The default has none.
#[derive(Default)]
pub(crate) struct Servers {
    tasks: JoinSet<(SocketAddr, io::Result<()>)>,
    handle: axum_server::Handle<SocketAddr>,
}

impl Servers {
    /// Waits for a listener to stop, which is always a failure. Returns `None` at once when there
    /// are no listeners. Cancel-safe.
    pub(crate) async fn stopped(&mut self) -> Option<PortalError> {
        Some(match self.tasks.join_next().await? {
            Ok((addr, Ok(()))) => PortalError::Stopped { addr },
            Ok((addr, Err(source))) => PortalError::Failed { addr, source },
            Err(e) => PortalError::Panicked(e),
        })
    }

    /// Stops accepting, gives open connections `drain` to finish, and waits for every listener.
    pub(crate) async fn shutdown(mut self, drain: Duration) {
        self.handle.graceful_shutdown(Some(drain));
        while self.tasks.join_next().await.is_some() {}
    }
}

struct Portal<A> {
    auth: A,
    sessions: SessionHandle,
    pending: Mutex<HashMap<String, Pending>>,
}

impl<A: Authenticator> Portal<A> {
    fn new(auth: A, sessions: SessionHandle) -> Arc<Self> {
        Arc::new(Portal {
            auth,
            sessions,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Records a started login under its `state`. When a client, or everyone together, has too
    /// many in flight, the oldest is dropped: abandoned attempts (closed tabs, reloads) and
    /// floods then can't stop anyone else from logging in.
    fn add_pending(&self, state: String, pending: Pending) {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, p| p.started.elapsed() < LOGIN_TTL);
        let client = client_prefix(pending.ip);
        let from_client = map
            .values()
            .filter(|p| client_prefix(p.ip) == client)
            .count();
        if from_client >= MAX_PENDING_PER_CLIENT {
            evict_oldest(&mut map, |p| client_prefix(p.ip) == client);
        }
        if map.len() >= MAX_PENDING {
            evict_oldest(&mut map, |_| true);
        }
        map.insert(state, pending);
    }

    fn take_pending(&self, state: &str) -> Option<Pending> {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(state)
            .filter(|p| p.started.elapsed() < LOGIN_TTL)
    }
}

fn evict_oldest(map: &mut HashMap<String, Pending>, filter: impl Fn(&Pending) -> bool) {
    let oldest = map
        .iter()
        .filter(|(_, p)| filter(p))
        .min_by_key(|(_, p)| p.started)
        .map(|(s, _)| s.clone());
    if let Some(state) = oldest {
        map.remove(&state);
    }
}

/// What counts as one client for login limits: an IPv4 address, or an IPv6 /64, since a single
/// IPv6 client often holds a whole /64.
fn client_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
    }
}

fn router<A: Authenticator>(portal: Arc<Portal<A>>) -> Router {
    Router::new()
        .route("/", get(index::<A>))
        .route("/login", get(login::<A>))
        .route("/callback", get(callback::<A>))
        .route("/api/session", get(session::<A>))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(portal)
}

async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// The client's address, with IPv4-mapped IPv6 unwrapped so it matches the firewall's view.
fn client_ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> IpAddr {
    addr.ip().to_canonical()
}

async fn live_session<A: Authenticator>(
    portal: &Portal<A>,
    jar: &CookieJar,
    ip: IpAddr,
) -> Option<crate::session::SessionInfo> {
    let token = jar.get(SESSION_COOKIE)?.value().to_string();
    portal.sessions.status(token, ip).await
}

async fn index<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    jar: CookieJar,
) -> Response {
    match live_session(&portal, &jar, client_ip(conn)).await {
        Some(_) => Html(INDEX_HTML).into_response(),
        None => Redirect::to("/login").into_response(),
    }
}

#[derive(serde::Serialize)]
struct SessionJson {
    #[serde(flatten)]
    info: crate::session::SessionInfo,
    /// Lets the page schedule re-authentication without trusting the browser's clock.
    server_now: u64,
}

async fn session<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    jar: CookieJar,
) -> Response {
    match live_session(&portal, &jar, client_ip(conn)).await {
        Some(info) => Json(SessionJson {
            info,
            server_now: unix_secs(SystemTime::now()),
        })
        .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    silent: Option<String>,
}

async fn login<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    Query(q): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let silent = q.silent.is_some_and(|s| s == "1");
    let req = portal.auth.authorize(silent);
    let pending = Pending {
        login: req.pending,
        silent,
        ip: client_ip(conn),
        started: Instant::now(),
    };
    portal.add_pending(req.state.clone(), pending);
    let cookie = Cookie::build((LOGIN_COOKIE, req.state))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(LOGIN_TTL.as_secs() as i64))
        .build();
    (jar.add(cookie), Redirect::to(&req.url)).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

async fn callback<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    Query(q): Query<CallbackQuery>,
    jar: CookieJar,
) -> Response {
    let ip = client_ip(conn);
    let restart = || {
        message(
            StatusCode::BAD_REQUEST,
            "Login expired",
            "This login could not be completed. <a href=\"/login\">Start again</a>.",
        )
    };
    let Some(state) = q.state else {
        return restart();
    };
    // The state must come back to the browser, and the address, that started the login.
    let browser_ok = jar.get(LOGIN_COOKIE).is_some_and(|c| c.value() == state);
    let Some(pending) = portal.take_pending(&state) else {
        return restart();
    };
    if !browser_ok || pending.ip != ip {
        warn!(%ip, "login callback from a different browser or address");
        return restart();
    }
    let jar = jar.remove(Cookie::build(LOGIN_COOKIE).path("/"));

    if let Some(error) = q.error {
        if pending.silent && INTERACTION_ERRORS.contains(&error.as_str()) {
            return (jar, Redirect::to("/login")).into_response();
        }
        warn!(%ip, error, "provider refused the login");
        return message(
            StatusCode::UNAUTHORIZED,
            "Login failed",
            "The identity provider did not complete the login. <a href=\"/login\">Try again</a>.",
        );
    }
    let Some(code) = q.code else {
        return restart();
    };

    let identity = match portal.auth.complete(code, pending.login).await {
        Ok(identity) => identity,
        Err(e) => {
            warn!(%ip, error = %format!("{e:#}"), "login verification failed");
            return message(
                StatusCode::UNAUTHORIZED,
                "Login failed",
                "Your login could not be verified. <a href=\"/login\">Try again</a>.",
            );
        }
    };
    let username = identity.username.clone();
    match portal
        .sessions
        .login(ip, identity.username, identity.expires_at)
        .await
    {
        Ok(token) => {
            // No Max-Age: the cookie lasts until the browser closes, and the server enforces
            // the token's expiry regardless.
            let cookie = Cookie::build((SESSION_COOKIE, token))
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .path("/")
                .build();
            (jar.add(cookie), Redirect::to("/")).into_response()
        }
        Err(SessionError::NoPolicy(_)) => {
            info!(%ip, username, "login refused: no policy for user");
            message(
                StatusCode::FORBIDDEN,
                "No access",
                &format!(
                    "You are signed in as <b>{}</b>, but no access is configured for this account.",
                    escape(&username)
                ),
            )
        }
        Err(e) => {
            warn!(%ip, username, error = %format!("{e:#}"), "provisioning failed");
            message(
                StatusCode::SERVICE_UNAVAILABLE,
                "Access not provisioned",
                "The gateway could not provision your access. <a href=\"/login\">Try again</a>.",
            )
        }
    }
}

/// A small HTML page. `body_html` is inserted as-is, so escape anything not written here.
fn message(status: StatusCode, title: &str, body_html: &str) -> Response {
    let page = MESSAGE_HTML
        .replace("{{title}}", &escape(title))
        .replace("{{body}}", body_html);
    (status, Html(page)).into_response()
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use openidconnect::{Nonce, PkceCodeVerifier};
    use tower::ServiceExt;

    use super::oidc::{AuthRequest, Identity, OidcError};
    use super::*;
    use crate::policy::Policy;
    use crate::session::{NoopEnforcer, SessionTable};

    /// Authorizes with a fixed state; `complete` succeeds for code `ok-<user>`.
    struct Stub {
        silent_seen: AtomicBool,
    }

    impl Authenticator for Stub {
        fn authorize(&self, silent: bool) -> AuthRequest {
            self.silent_seen.store(silent, Ordering::SeqCst);
            AuthRequest {
                url: "https://idp.example/auth?state=st".into(),
                state: "st".into(),
                pending: PendingLogin {
                    nonce: Nonce::new("n".into()),
                    pkce_verifier: PkceCodeVerifier::new("v".into()),
                },
            }
        }

        async fn complete(
            &self,
            code: String,
            _pending: PendingLogin,
        ) -> Result<Identity, OidcError> {
            let user = code.strip_prefix("ok-").ok_or(OidcError::NoIdToken)?;
            Ok(Identity {
                username: user.into(),
                expires_at: SystemTime::now() + Duration::from_secs(300),
            })
        }
    }

    const CLIENT: &str = "192.168.60.7:40000";

    fn app() -> (Router, Arc<Portal<Stub>>) {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        let (handle, _task) = crate::session::spawn(SessionTable::new(
            Arc::new(policy),
            NoopEnforcer,
            Duration::ZERO,
        ));
        let portal = Portal::new(
            Stub {
                silent_seen: AtomicBool::new(false),
            },
            handle,
        );
        (router(portal.clone()), portal)
    }

    async fn get(app: &Router, from: &str, uri: &str, cookie: Option<&str>) -> Response {
        let mut req = Request::get(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        app.clone()
            .layer(MockConnectInfo(from.parse::<SocketAddr>().unwrap()))
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn location(r: &Response) -> &str {
        r.headers()[header::LOCATION].to_str().unwrap()
    }

    /// The `name=value` pair of the Set-Cookie header for `name`.
    fn set_cookie(r: &Response, name: &str) -> String {
        r.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|v| v.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} cookie"))
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn body(r: Response) -> String {
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    /// Runs `/login` then `/callback` with `code`, returning the callback response.
    async fn log_in(app: &Router, from: &str, code: &str) -> Response {
        let r = get(app, from, "/login", None).await;
        let login = set_cookie(&r, LOGIN_COOKIE);
        get(
            app,
            from,
            &format!("/callback?state=st&code={code}"),
            Some(&login),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn index_without_session_redirects_to_login() {
        let (app, _) = app();
        let r = get(&app, CLIENT, "/", None).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&r), "/login");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_redirects_to_provider_with_state_cookie() {
        let (app, portal) = app();
        let r = get(&app, CLIENT, "/login?silent=1", None).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert!(location(&r).starts_with("https://idp.example/auth"));
        assert_eq!(set_cookie(&r, LOGIN_COOKIE), format!("{LOGIN_COOKIE}=st"));
        assert!(portal.auth.silent_seen.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_login_provisions_session() {
        let (app, _) = app();
        let r = log_in(&app, CLIENT, "ok-alice").await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&r), "/");
        let session = set_cookie(&r, SESSION_COOKIE);
        let raw = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|v| v.starts_with(SESSION_COOKIE))
            .unwrap();
        assert!(raw.contains("HttpOnly") && raw.contains("Secure") && raw.contains("SameSite=Lax"));

        let r = get(&app, CLIENT, "/", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = get(&app, CLIENT, "/api/session", Some(&session)).await;
        let json: serde_json::Value = serde_json::from_str(&body(r).await).unwrap();
        assert_eq!(json["username"], "alice");
        assert!(json["expires_at"].as_u64().unwrap() > json["server_now"].as_u64().unwrap());

        // The cookie is useless from another address.
        let r = get(&app, "192.168.60.8:40000", "/api/session", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn user_without_policy_is_forbidden_and_name_escaped() {
        let (app, _) = app();
        let r = log_in(&app, CLIENT, "ok-%3Cbob%3E").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(
            r.headers()
                .get(header::SET_COOKIE)
                .is_none_or(|c| { !c.to_str().unwrap().starts_with(SESSION_COOKIE) })
        );
        let text = body(r).await;
        assert!(
            text.contains("&lt;bob&gt;") && !text.contains("<bob>"),
            "{text}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn callback_requires_login_cookie_and_same_address() {
        let (app, _) = app();
        get(&app, CLIENT, "/login", None).await;
        let r = get(&app, CLIENT, "/callback?state=st&code=ok-alice", None).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);

        let r = get(&app, CLIENT, "/login", None).await;
        let login = set_cookie(&r, LOGIN_COOKIE);
        let r = get(
            &app,
            "192.168.60.8:40000",
            "/callback?state=st&code=ok-alice",
            Some(&login),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // The state is single-use, even after a rejected attempt.
        let r = get(
            &app,
            CLIENT,
            "/callback?state=st&code=ok-alice",
            Some(&login),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_login_required_falls_back_to_interactive() {
        let (app, _) = app();
        let r = get(&app, CLIENT, "/login?silent=1", None).await;
        let login = set_cookie(&r, LOGIN_COOKIE);
        let r = get(
            &app,
            CLIENT,
            "/callback?state=st&error=login_required",
            Some(&login),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&r), "/login");

        let r = get(&app, CLIENT, "/login", None).await;
        let login = set_cookie(&r, LOGIN_COOKIE);
        let r = get(
            &app,
            CLIENT,
            "/callback?state=st&error=login_required",
            Some(&login),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_verification_is_unauthorized() {
        let (app, _) = app();
        let r = log_in(&app, CLIENT, "forged").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    fn pending(ip: &str) -> Pending {
        Pending {
            login: PendingLogin {
                nonce: Nonce::new("n".into()),
                pkce_verifier: PkceCodeVerifier::new("v".into()),
            },
            silent: false,
            ip: ip.parse().unwrap(),
            started: Instant::now(),
        }
    }

    #[test]
    fn pending_logins_are_bounded_per_client() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let (_, portal) = app();
        // One IPv6 client rotating through its /64 counts once.
        for i in 0..MAX_PENDING_PER_CLIENT + 4 {
            portal.add_pending(format!("s{i}"), pending(&format!("fd00:60::{i:x}")));
        }
        portal.add_pending("other".into(), pending("fd00:61::1"));
        let map = portal.pending.lock().unwrap();
        assert_eq!(map.len(), MAX_PENDING_PER_CLIENT + 1);
        assert!(!map.contains_key("s0"), "the oldest attempt is evicted");
        assert!(map.contains_key("other"));
    }

    #[test]
    fn client_prefix_groups_ipv6_by_64() {
        let p = |s: &str| client_prefix(s.parse().unwrap()).to_string();
        assert_eq!(p("fd00:60::1:2:3:4"), "fd00:60::");
        assert_eq!(p("192.168.60.7"), "192.168.60.7");
    }

    #[test]
    fn escapes_html() {
        assert_eq!(
            escape("<a href=\"x\">'&"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;"
        );
    }
}
