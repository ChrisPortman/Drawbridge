//! The login portal: an HTTPS site on the gateway that sends the browser through the OIDC flow,
//! provisions the session for its source IP, and keeps it alive while the page stays open (or the
//! client service runs).
//!
//! - `GET /`: the confirmation page for a live session, otherwise a redirect to `/login`.
//! - `GET /login[?silent=1]`: starts an authorization request (`prompt=none` when silent).
//!   `?cli_port=N&cli_challenge=C` starts one for the client service, which receives a one-time
//!   code on `http://127.0.0.1:N/` instead of a cookie.
//! - `GET /callback`: completes it and provisions access.
//! - `GET /api/session`: the session as JSON, polled by the page to schedule a refresh.
//! - `POST /api/session/refresh`: extends the session with the provider's refresh token.
//! - `DELETE /api/session`: ends the session at once.
//! - `POST /api/cli/token`: swaps the one-time code and PKCE verifier for the session token.
//!
//! Requests that change a session must carry [`REQUEST_HEADER`], against cross-site requests.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_server::Server;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use openidconnect::{PkceCodeChallenge, PkceCodeVerifier};
use serde::Deserialize;
use tokio::task::{JoinError, JoinSet};
use tracing::{info, warn};

mod api;
mod oidc;

pub(crate) use api::{
    ApiError, CliTokenJson, CliTokenRequest, ErrorCode, LoginError, REQUEST_HEADER, SESSION_COOKIE,
    SessionJson,
};
pub(crate) use oidc::OidcConfig;
// `pub` so `cli` can re-export it: it is the type of a public CLI field.
pub use oidc::Secret;

use crate::session::{
    RefreshError, RefreshOutcome, SessionError, SessionHandle, SessionInfo, new_token, unix_secs,
};
use oidc::{Authenticator, LoggedIn, Oidc, OidcError, PendingLogin, RefreshFailure};

/// Ties a callback to the browser that started the login, against login CSRF.
const LOGIN_COOKIE: &str = "__Host-drawbridge_login";
/// How long a started login may take to come back. The client service's unit allows as long.
pub(crate) const LOGIN_TTL: Duration = Duration::from_secs(600);
/// How long the client service has to redeem its one-time code.
const CLI_CODE_TTL: Duration = Duration::from_secs(60);
/// Logins in flight across all clients, and per client (see [`client_prefix`]), bounding memory.
/// The same bounds apply to unredeemed one-time codes.
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
    cli: Option<CliLogin>,
}

/// A login started by the client service: where its loopback listener is, and the S256
/// challenge of the verifier it will redeem the code with.
struct CliLogin {
    port: u16,
    challenge: String,
    /// Echoed to the loopback listener, which ignores callbacks without it.
    state: String,
}

/// A verified login waiting for the client service to redeem its one-time code. Access is
/// provisioned only then, so a login nobody redeems leaves nothing open.
struct CliGrant {
    login: LoggedIn,
    challenge: String,
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
    pending: Bounded<Pending>,
    grants: Bounded<CliGrant>,
}

impl<A: Authenticator> Portal<A> {
    fn new(auth: A, sessions: SessionHandle) -> Arc<Self> {
        Arc::new(Portal {
            auth,
            sessions,
            pending: Bounded::new(LOGIN_TTL),
            grants: Bounded::new(CLI_CODE_TTL),
        })
    }
}

/// An entry in a [`Bounded`] store: what it holds, and the client that created it, when.
struct Entry<T> {
    value: T,
    ip: IpAddr,
    started: Instant,
}

/// Single-use entries that expire after `ttl`. When a client, or everyone together, has too many,
/// the oldest is dropped: abandoned attempts (closed tabs, reloads) and floods then can't stop
/// anyone else from logging in.
struct Bounded<T> {
    map: Mutex<HashMap<String, Entry<T>>>,
    ttl: Duration,
}

impl<T> Bounded<T> {
    fn new(ttl: Duration) -> Self {
        Bounded {
            map: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn add(&self, key: String, ip: IpAddr, value: T) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| e.started.elapsed() < self.ttl);
        let client = client_prefix(ip);
        let from_client = map
            .values()
            .filter(|e| client_prefix(e.ip) == client)
            .count();
        if from_client >= MAX_PENDING_PER_CLIENT {
            evict_oldest(&mut map, |e| client_prefix(e.ip) == client);
        }
        if map.len() >= MAX_PENDING {
            evict_oldest(&mut map, |_| true);
        }
        let started = Instant::now();
        map.insert(key, Entry { value, ip, started });
    }

    /// Removes the entry under `key`, returning it if it hasn't expired.
    fn take(&self, key: &str) -> Option<Entry<T>> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(key).filter(|e| e.started.elapsed() < self.ttl)
    }
}

fn evict_oldest<T>(map: &mut HashMap<String, Entry<T>>, filter: impl Fn(&Entry<T>) -> bool) {
    let oldest = map
        .iter()
        .filter(|(_, e)| filter(e))
        .min_by_key(|(_, e)| e.started)
        .map(|(k, _)| k.clone());
    if let Some(key) = oldest {
        map.remove(&key);
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
        .route("/api/session", get(session::<A>).delete(logout::<A>))
        .route("/api/session/refresh", post(refresh::<A>))
        .route("/api/cli/token", post(cli_token::<A>))
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

fn session_token(jar: &CookieJar) -> Option<String> {
    Some(jar.get(SESSION_COOKIE)?.value().to_string())
}

async fn live_session<A: Authenticator>(
    portal: &Portal<A>,
    jar: &CookieJar,
    ip: IpAddr,
) -> Option<SessionInfo> {
    portal.sessions.status(session_token(jar)?, ip).await
}

/// A JSON error response, `{"error": code}`.
fn api_error(status: StatusCode, error: ErrorCode) -> Response {
    let body = Json(ApiError { error });
    (status, body).into_response()
}

/// The answer to a state-changing request without [`REQUEST_HEADER`]: such a request may come
/// from another site, so it does nothing.
fn missing_request_header(headers: &HeaderMap) -> Option<Response> {
    let ok = headers.get(REQUEST_HEADER).is_some_and(|v| v == "1");
    (!ok).then(|| api_error(StatusCode::FORBIDDEN, ErrorCode::MissingRequestHeader))
}

fn session_json(info: SessionInfo) -> SessionJson {
    SessionJson {
        info,
        server_now: unix_secs(SystemTime::now()),
    }
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

async fn session<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    jar: CookieJar,
) -> Response {
    match live_session(&portal, &jar, client_ip(conn)).await {
        Some(info) => Json(session_json(info)).into_response(),
        None => api_error(StatusCode::UNAUTHORIZED, ErrorCode::NoSession),
    }
}

async fn refresh<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    if let Some(refused) = missing_request_header(&headers) {
        return refused;
    }
    let ip = client_ip(conn);
    let Some(token) = session_token(&jar) else {
        return api_error(StatusCode::UNAUTHORIZED, ErrorCode::NoSession);
    };
    let lease = match portal.sessions.begin_refresh(token.clone(), ip).await {
        Ok(lease) => lease,
        Err(e) => return refresh_error(e),
    };
    // A task of its own, so the leased (and maybe rotated) refresh token gets back to the session
    // even if the client disconnects mid-request and this handler is dropped.
    let task = tokio::spawn(async move {
        let outcome = match portal.auth.refresh(lease.refresh_token).await {
            Ok(LoggedIn {
                identity,
                refresh_token,
            }) => RefreshOutcome::Refreshed {
                username: identity.username,
                expires_at: identity.expires_at,
                refresh_token,
            },
            Err(RefreshFailure::Rejected(e)) => {
                let error = format!("{e:#}");
                warn!(%ip, error, "refresh token rejected; refresh disabled for this session");
                RefreshOutcome::Rejected
            }
            Err(RefreshFailure::Unreachable(e)) => {
                warn!(%ip, error = %format!("{e:#}"), "refresh failed; provider unreachable");
                RefreshOutcome::Unreachable
            }
        };
        portal
            .sessions
            .finish_refresh(token, ip, lease.id, outcome)
            .await
    });
    match task.await {
        Ok(Ok(info)) => Json(session_json(info)).into_response(),
        Ok(Err(e)) => refresh_error(e),
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::InternalError),
    }
}

/// 401 means there is no session; 409 that it can't be refreshed (the page falls back to a
/// silent re-authentication); 503 that a later attempt may work.
fn refresh_error(e: RefreshError) -> Response {
    let (status, code, retry_after) = match e {
        RefreshError::NoSession => (StatusCode::UNAUTHORIZED, ErrorCode::NoSession, None),
        RefreshError::Unavailable => (StatusCode::CONFLICT, ErrorCode::RefreshUnavailable, None),
        RefreshError::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::RefreshInProgress,
            Some("2"),
        ),
        RefreshError::Transient | RefreshError::Closed => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ProviderUnavailable,
            Some("5"),
        ),
    };
    let mut response = api_error(status, code);
    if let Some(secs) = retry_after {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static(secs));
    }
    response
}

async fn logout<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    if let Some(refused) = missing_request_header(&headers) {
        return refused;
    }
    let ip = client_ip(conn);
    let Some(token) = session_token(&jar) else {
        return api_error(StatusCode::UNAUTHORIZED, ErrorCode::NoSession);
    };
    if portal.sessions.logout(token, ip).await {
        let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/"));
        (jar, StatusCode::NO_CONTENT).into_response()
    } else {
        api_error(StatusCode::UNAUTHORIZED, ErrorCode::NoSession)
    }
}

async fn cli_token<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<CliTokenRequest>, JsonRejection>,
) -> Response {
    if let Some(refused) = missing_request_header(&headers) {
        return refused;
    }
    let Ok(Json(req)) = body else {
        return api_error(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
    };
    let ip = client_ip(conn);
    // Taken before any check, so a code can be tried once.
    let Some(grant) = portal.grants.take(&req.code) else {
        return api_error(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCode);
    };
    if s256(req.verifier).is_none_or(|c| c != grant.value.challenge) {
        warn!(%ip, "client token request with the wrong verifier");
        return api_error(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCode);
    }
    if grant.ip != ip {
        warn!(%ip, login_ip = %grant.ip, "client token request from another address");
        return api_error(StatusCode::UNAUTHORIZED, ErrorCode::AddressMismatch);
    }
    let token = match provision(&portal, ip, grant.value.login).await {
        Ok(token) => token,
        Err(Failure::NoAccess(_)) => return api_error(StatusCode::FORBIDDEN, ErrorCode::NoAccess),
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::ProvisioningFailed,
            );
        }
    };
    match portal.sessions.status(token.clone(), ip).await {
        Some(info) => Json(CliTokenJson {
            token,
            session: session_json(info),
        })
        .into_response(),
        // Ended between provisioning and here: only by a session manager shutting down.
        None => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ProvisioningFailed,
        ),
    }
}

/// The S256 challenge of a PKCE `verifier`, or `None` if it isn't one (RFC 7636: 43 to 128
/// unreserved characters). Checked first, because the library panics on a bad length.
fn s256(verifier: String) -> Option<String> {
    let valid = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    let verifier = PkceCodeVerifier::new(verifier);
    valid.then(|| {
        PkceCodeChallenge::from_code_verifier_sha256(&verifier)
            .as_str()
            .to_string()
    })
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    silent: Option<String>,
    #[serde(default)]
    cli_port: Option<String>,
    #[serde(default)]
    cli_challenge: Option<String>,
    #[serde(default)]
    cli_state: Option<String>,
}

/// The client service's loopback port, S256 challenge and state, if valid. The port is
/// unprivileged, so the redirect can't target a system service; the challenge is a base64url
/// SHA-256; the state is 16 to 128 base64url characters, so it needs no escaping in the redirect.
fn cli_login(port: &str, challenge: &str, state: &str) -> Option<CliLogin> {
    let port: u16 = port.parse().ok().filter(|&p| p >= 1024)?;
    let base64url = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let well_formed = challenge.len() == 43
        && base64url(challenge)
        && (16..=128).contains(&state.len())
        && base64url(state);
    well_formed.then(|| CliLogin {
        port,
        challenge: challenge.to_string(),
        state: state.to_string(),
    })
}

async fn login<A: Authenticator>(
    State(portal): State<Arc<Portal<A>>>,
    conn: ConnectInfo<SocketAddr>,
    Query(q): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let silent = q.silent.is_some_and(|s| s == "1");
    let cli = match (q.cli_port, q.cli_challenge, q.cli_state) {
        (None, None, None) => None,
        (Some(port), Some(challenge), Some(state)) if !silent => {
            match cli_login(&port, &challenge, &state) {
                Some(cli) => Some(cli),
                None => return bad_cli_login(),
            }
        }
        _ => return bad_cli_login(),
    };
    let req = portal.auth.authorize(silent);
    let pending = Pending {
        login: req.pending,
        silent,
        cli,
    };
    portal
        .pending
        .add(req.state.clone(), client_ip(conn), pending);
    let cookie = Cookie::build((LOGIN_COOKIE, req.state))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(LOGIN_TTL.as_secs() as i64))
        .build();
    (jar.add(cookie), Redirect::to(&req.url)).into_response()
}

fn bad_cli_login() -> Response {
    message(
        StatusCode::BAD_REQUEST,
        "Invalid login request",
        "This command-line login link is malformed. Run <code>drawbridge client login</code> \
         again.",
    )
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

/// Why a validated callback didn't provision a session.
enum Failure {
    Refused,
    Unverified,
    NoAccess(String),
    Unavailable,
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
    let Some(pending) = portal.pending.take(&state) else {
        return restart();
    };
    if !browser_ok || pending.ip != ip {
        warn!(%ip, "login callback from a different browser or address");
        return restart();
    }
    let pending = pending.value;
    let jar = jar.remove(Cookie::build(LOGIN_COOKIE).path("/"));

    if let Some(error) = &q.error
        && pending.silent
        && INTERACTION_ERRORS.contains(&error.as_str())
    {
        return (jar, Redirect::to("/login")).into_response();
    }
    let verified = verify(&portal, ip, q.error, q.code, pending.login).await;

    // From here the login is known to be this client's, so a client service's loopback port can
    // be trusted with the outcome.
    if let Some(cli) = pending.cli {
        return cli_redirect(&portal, jar, ip, cli, verified);
    }
    let provisioned = match verified {
        Ok(login) => provision(&portal, ip, login).await,
        Err(failure) => Err(failure),
    };
    match provisioned {
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
        Err(Failure::Refused) => message(
            StatusCode::UNAUTHORIZED,
            "Login failed",
            "The identity provider did not complete the login. <a href=\"/login\">Try again</a>.",
        ),
        Err(Failure::Unverified) => message(
            StatusCode::UNAUTHORIZED,
            "Login failed",
            "Your login could not be verified. <a href=\"/login\">Try again</a>.",
        ),
        Err(Failure::NoAccess(username)) => message(
            StatusCode::FORBIDDEN,
            "No access",
            &format!(
                "You are signed in as <b>{}</b>, but no access is configured for this account.",
                escape(&username)
            ),
        ),
        Err(Failure::Unavailable) => message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Access not provisioned",
            "The gateway could not provision your access. <a href=\"/login\">Try again</a>.",
        ),
    }
}

/// Sends the outcome of a client service's login to its loopback listener: a one-time code it
/// redeems for the session, or the failure. The login is known to be this client's by now, so its
/// port can be trusted with the outcome.
fn cli_redirect<A: Authenticator>(
    portal: &Portal<A>,
    jar: CookieJar,
    ip: IpAddr,
    cli: CliLogin,
    verified: Result<LoggedIn, Failure>,
) -> Response {
    let outcome = match verified {
        Ok(login) => {
            let code = new_token();
            let grant = CliGrant {
                login,
                challenge: cli.challenge,
            };
            portal.grants.add(code.clone(), ip, grant);
            format!("code={code}")
        }
        Err(_) => format!("error={}", LoginError::LoginFailed.as_str()),
    };
    let url = format!(
        "http://127.0.0.1:{}/?{outcome}&state={}",
        cli.port, cli.state
    );
    (jar, Redirect::to(&url)).into_response()
}

/// Completes a validated callback: redeems the code with the provider and verifies the login.
async fn verify<A: Authenticator>(
    portal: &Portal<A>,
    ip: IpAddr,
    error: Option<String>,
    code: Option<String>,
    login: PendingLogin,
) -> Result<LoggedIn, Failure> {
    if let Some(error) = error {
        warn!(%ip, error, "provider refused the login");
        return Err(Failure::Refused);
    }
    let code = code.ok_or(Failure::Refused)?;
    portal.auth.complete(code, login).await.map_err(|e| {
        warn!(%ip, error = %format!("{e:#}"), "login verification failed");
        Failure::Unverified
    })
}

/// Provisions a verified login's session from `ip`, returning its token.
async fn provision<A: Authenticator>(
    portal: &Portal<A>,
    ip: IpAddr,
    login: LoggedIn,
) -> Result<String, Failure> {
    let LoggedIn {
        identity,
        refresh_token,
    } = login;
    let username = identity.username.clone();
    portal
        .sessions
        .login(ip, identity.username, identity.expires_at, refresh_token)
        .await
        .map_err(|e| match e {
            SessionError::NoPolicy(_) => {
                info!(%ip, username, "login refused: no policy for user");
                Failure::NoAccess(username.clone())
            }
            e => {
                warn!(%ip, username, error = %format!("{e:#}"), "provisioning failed");
                Failure::Unavailable
            }
        })
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
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use openidconnect::Nonce;
    use tower::ServiceExt;

    use super::oidc::{AuthRequest, Identity, OidcError};
    use super::*;
    use crate::policy::Policy;
    use crate::session::{NoopEnforcer, SessionTable};

    /// Authorizes with a fixed state. `complete` succeeds for code `ok-<user>`, issuing refresh
    /// token `rt-<user>-1`, or for `ok-<user>:<refresh token>` (none if empty). `refresh` rotates
    /// `rt-<user>-<n>` to `n + 1`, rejects `revoked`, logs in as bob for `other`, and fails as
    /// unreachable while `down` is set.
    struct Stub {
        silent_seen: AtomicBool,
        down: AtomicBool,
    }

    fn identity(user: &str) -> Identity {
        Identity {
            username: user.into(),
            expires_at: SystemTime::now() + Duration::from_secs(300),
        }
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
        ) -> Result<LoggedIn, OidcError> {
            let rest = code.strip_prefix("ok-").ok_or(OidcError::NoIdToken)?;
            let (user, refresh) = match rest.split_once(':') {
                Some((user, "")) => (user, None),
                Some((user, rt)) => (user, Some(rt.to_string())),
                None => (rest, Some(format!("rt-{rest}-1"))),
            };
            Ok(LoggedIn {
                identity: identity(user),
                refresh_token: refresh.map(Secret::new),
            })
        }

        async fn refresh(&self, refresh_token: Secret) -> Result<LoggedIn, RefreshFailure> {
            if self.down.load(Ordering::SeqCst) {
                return Err(RefreshFailure::Unreachable(OidcError::NoIdToken));
            }
            let (user, next) = match refresh_token.expose() {
                "revoked" => return Err(RefreshFailure::Rejected(OidcError::NoIdToken)),
                "other" => ("bob".to_string(), None),
                rt => {
                    let (user, n) = rt
                        .strip_prefix("rt-")
                        .and_then(|r| r.rsplit_once('-'))
                        .expect("stub refresh token");
                    let n: u32 = n.parse().unwrap();
                    (user.to_string(), Some(format!("rt-{user}-{}", n + 1)))
                }
            };
            Ok(LoggedIn {
                identity: identity(&user),
                refresh_token: next.map(Secret::new),
            })
        }
    }

    const CLIENT: &str = "192.168.60.7:40000";
    const OTHER: &str = "192.168.60.8:40000";

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
                down: AtomicBool::new(false),
            },
            handle,
        );
        (router(portal.clone()), portal)
    }

    async fn send(app: &Router, from: &str, req: Request<Body>) -> Response {
        app.clone()
            .layer(MockConnectInfo(from.parse::<SocketAddr>().unwrap()))
            .oneshot(req)
            .await
            .unwrap()
    }

    async fn get(app: &Router, from: &str, uri: &str, cookie: Option<&str>) -> Response {
        let mut req = Request::get(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        send(app, from, req.body(Body::empty()).unwrap()).await
    }

    /// A state-changing API request; `marked` adds the required request header.
    async fn api(
        app: &Router,
        from: &str,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        marked: bool,
        json: Option<serde_json::Value>,
    ) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        if marked {
            req = req.header(REQUEST_HEADER, "1");
        }
        let body = match json {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        send(app, from, req.body(body).unwrap()).await
    }

    async fn refresh_as(app: &Router, from: &str, cookie: Option<&str>) -> Response {
        api(
            app,
            from,
            Method::POST,
            "/api/session/refresh",
            cookie,
            true,
            None,
        )
        .await
    }

    fn location(r: &Response) -> &str {
        r.headers()[header::LOCATION].to_str().unwrap()
    }

    /// The Set-Cookie header for `name`, if any.
    fn raw_set_cookie(r: &Response, name: &str) -> Option<String> {
        r.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|v| v.starts_with(&format!("{name}=")))
    }

    /// The `name=value` pair of the Set-Cookie header for `name`.
    fn set_cookie(r: &Response, name: &str) -> String {
        raw_set_cookie(r, name)
            .unwrap_or_else(|| panic!("no {name} cookie"))
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn body(r: Response) -> String {
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    async fn json(r: Response) -> serde_json::Value {
        serde_json::from_str(&body(r).await).unwrap()
    }

    /// Runs `/login<query>` then `/callback` with `code`, returning the callback response.
    async fn log_in_with(app: &Router, from: &str, query: &str, code: &str) -> Response {
        let r = get(app, from, &format!("/login{query}"), None).await;
        let login = set_cookie(&r, LOGIN_COOKIE);
        get(
            app,
            from,
            &format!("/callback?state=st&code={code}"),
            Some(&login),
        )
        .await
    }

    async fn log_in(app: &Router, from: &str, code: &str) -> Response {
        log_in_with(app, from, "", code).await
    }

    /// Logs in through the browser flow and returns the session cookie pair.
    async fn session_cookie(app: &Router, code: &str) -> String {
        let r = log_in(app, CLIENT, code).await;
        set_cookie(&r, SESSION_COOKIE)
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
        let raw = raw_set_cookie(&r, SESSION_COOKIE).unwrap();
        assert!(raw.contains("HttpOnly") && raw.contains("Secure") && raw.contains("SameSite=Lax"));

        let r = get(&app, CLIENT, "/", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = get(&app, CLIENT, "/api/session", Some(&session)).await;
        let json = json(r).await;
        assert_eq!(json["username"], "alice");
        assert!(json["expires_at"].as_u64().unwrap() > json["server_now"].as_u64().unwrap());

        // The cookie is useless from another address.
        let r = get(&app, OTHER, "/api/session", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn user_without_policy_is_forbidden_and_name_escaped() {
        let (app, _) = app();
        let r = log_in(&app, CLIENT, "ok-%3Cbob%3E").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(raw_set_cookie(&r, SESSION_COOKIE).is_none());
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
            OTHER,
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

    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_extends_with_header_and_cookie_from_the_same_address() {
        let (app, _) = app();
        let session = session_cookie(&app, "ok-alice").await;
        let r = api(
            &app,
            CLIENT,
            Method::POST,
            "/api/session/refresh",
            Some(&session),
            false,
            None,
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(r).await["error"], "missing_request_header");
        assert_eq!(
            refresh_as(&app, CLIENT, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            refresh_as(&app, OTHER, Some(&session)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // Twice, so the second uses the rotated refresh token.
        for _ in 0..2 {
            let r = refresh_as(&app, CLIENT, Some(&session)).await;
            assert_eq!(r.status(), StatusCode::OK);
            let json = json(r).await;
            assert_eq!(json["username"], "alice");
            assert!(json["expires_at"].as_u64() > json["server_now"].as_u64());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_without_a_usable_token_is_a_conflict() {
        let (app, _) = app();
        let session = session_cookie(&app, "ok-alice:").await;
        let r = refresh_as(&app, CLIENT, Some(&session)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(json(r).await["error"], "refresh_unavailable");

        let (app, _) = self::app();
        let session = session_cookie(&app, "ok-alice:revoked").await;
        for _ in 0..2 {
            let r = refresh_as(&app, CLIENT, Some(&session)).await;
            assert_eq!(r.status(), StatusCode::CONFLICT);
        }
        // The session itself lives on.
        let r = get(&app, CLIENT, "/api/session", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::OK);

        let (app, _) = self::app();
        let session = session_cookie(&app, "ok-alice:other").await;
        let r = refresh_as(&app, CLIENT, Some(&session)).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_with_the_provider_down_is_retryable() {
        let (app, portal) = app();
        let session = session_cookie(&app, "ok-alice").await;
        portal.auth.down.store(true, Ordering::SeqCst);
        let r = refresh_as(&app, CLIENT, Some(&session)).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers()[header::RETRY_AFTER], "5");
        assert_eq!(json(r).await["error"], "provider_unavailable");
        portal.auth.down.store(false, Ordering::SeqCst);
        let r = refresh_as(&app, CLIENT, Some(&session)).await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_ends_the_session() {
        let (app, _) = app();
        let session = session_cookie(&app, "ok-alice").await;
        let delete = |from, marked| {
            let session = session.clone();
            let app = app.clone();
            async move {
                let uri = "/api/session";
                api(
                    &app,
                    from,
                    Method::DELETE,
                    uri,
                    Some(&session),
                    marked,
                    None,
                )
                .await
            }
        };
        assert_eq!(delete(CLIENT, false).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(delete(OTHER, true).await.status(), StatusCode::UNAUTHORIZED);
        let r = delete(CLIENT, true).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert_eq!(set_cookie(&r, SESSION_COOKIE), format!("{SESSION_COOKIE}="));
        let r = get(&app, CLIENT, "/api/session", Some(&session)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            delete(CLIENT, true).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// A PKCE verifier and the challenge the client service would send with it.
    fn pkce() -> (String, String) {
        let verifier = "v".repeat(43);
        let challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
        (verifier, challenge.as_str().to_string())
    }

    const CLI_STATE: &str = "state-0123456789abcdef";

    fn cli_query(challenge: &str) -> String {
        format!("?cli_port=40123&cli_challenge={challenge}&cli_state={CLI_STATE}")
    }

    /// Logs in for the client service listening on port 40123, returning the one-time code.
    async fn cli_log_in(app: &Router, challenge: &str) -> String {
        cli_log_in_as(app, challenge, "ok-alice").await
    }

    async fn cli_log_in_as(app: &Router, challenge: &str, login: &str) -> String {
        let r = log_in_with(app, CLIENT, &cli_query(challenge), login).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert!(raw_set_cookie(&r, SESSION_COOKIE).is_none());
        let rest = location(&r)
            .strip_prefix("http://127.0.0.1:40123/?code=")
            .unwrap_or_else(|| panic!("redirect to {}", location(&r)));
        let (code, state) = rest.split_once("&state=").expect("state echoed");
        assert_eq!(state, CLI_STATE);
        assert!(code.len() == 64 && code.bytes().all(|b| b.is_ascii_hexdigit()));
        code.to_string()
    }

    async fn redeem(app: &Router, from: &str, code: &str, verifier: &str) -> Response {
        let body = serde_json::json!({"code": code, "verifier": verifier});
        api(
            app,
            from,
            Method::POST,
            "/api/cli/token",
            None,
            true,
            Some(body),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_login_parameters_are_validated() {
        let (app, _) = app();
        let (_, challenge) = pkce();
        let st = format!("cli_state={CLI_STATE}");
        for query in [
            format!("cli_port=0&cli_challenge={challenge}&{st}"),
            format!("cli_port=80&cli_challenge={challenge}&{st}"),
            format!("cli_port=70000&cli_challenge={challenge}&{st}"),
            format!("cli_port=abc&cli_challenge={challenge}&{st}"),
            format!("cli_port=40123&cli_challenge={}&{st}", &challenge[1..]),
            format!("cli_port=40123&cli_challenge={}.&{st}", &challenge[1..]),
            format!("cli_port=40123&cli_challenge={challenge}"),
            format!("cli_port=40123&cli_challenge={challenge}&cli_state=short"),
            format!("cli_port=40123&{st}"),
            format!("cli_challenge={challenge}&{st}"),
            format!("silent=1&cli_port=40123&cli_challenge={challenge}&{st}"),
        ] {
            let r = get(&app, CLIENT, &format!("/login?{query}"), None).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{query}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_login_hands_the_token_over_once() {
        let (app, _) = app();
        let (verifier, challenge) = pkce();
        let code = cli_log_in(&app, &challenge).await;
        let r = redeem(&app, CLIENT, &code, &verifier).await;
        assert_eq!(r.status(), StatusCode::OK);
        let json = json(r).await;
        assert_eq!(json["username"], "alice");
        let token = json["token"].as_str().unwrap();
        let cookie = format!("{SESSION_COOKIE}={token}");
        let r = get(&app, CLIENT, "/api/session", Some(&cookie)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = redeem(&app, CLIENT, &code, &verifier).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(self::json(r).await["error"], "invalid_code");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_token_needs_verifier_address_header_and_time() {
        let (app, portal) = app();
        let (verifier, challenge) = pkce();
        // A wrong verifier burns the code.
        let code = cli_log_in(&app, &challenge).await;
        let r = redeem(&app, CLIENT, &code, "wrong").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let code = cli_log_in(&app, &challenge).await;
        let r = redeem(&app, CLIENT, &code, &"w".repeat(43)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let r = redeem(&app, CLIENT, &code, &verifier).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        let code = cli_log_in(&app, &challenge).await;
        let r = redeem(&app, OTHER, &code, &verifier).await;
        assert_eq!(json(r).await["error"], "address_mismatch");

        let code = cli_log_in(&app, &challenge).await;
        let body = serde_json::json!({"code": code, "verifier": verifier});
        let r = api(
            &app,
            CLIENT,
            Method::POST,
            "/api/cli/token",
            None,
            false,
            Some(body),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let bad = serde_json::json!({"code": code});
        let r = api(
            &app,
            CLIENT,
            Method::POST,
            "/api/cli/token",
            None,
            true,
            Some(bad),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);

        let code = cli_log_in(&app, &challenge).await;
        let stale = Instant::now().checked_sub(CLI_CODE_TTL).unwrap();
        portal
            .grants
            .map
            .lock()
            .unwrap()
            .get_mut(&code)
            .unwrap()
            .started = stale;
        let r = redeem(&app, CLIENT, &code, &verifier).await;
        assert_eq!(json(r).await["error"], "invalid_code");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_login_failures_go_to_the_loopback() {
        let (app, _) = app();
        let (_, challenge) = pkce();
        let query = cli_query(&challenge);
        let r = log_in_with(&app, CLIENT, &query, "forged").await;
        assert_eq!(
            location(&r),
            format!("http://127.0.0.1:40123/?error=login_failed&state={CLI_STATE}")
        );
        // A callback that can't be tied to the login never reaches the loopback.
        get(&app, CLIENT, &format!("/login{query}"), None).await;
        let r = get(&app, CLIENT, "/callback?state=st&code=ok-alice", None).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    fn pending() -> Pending {
        Pending {
            login: PendingLogin {
                nonce: Nonce::new("n".into()),
                pkce_verifier: PkceCodeVerifier::new("v".into()),
            },
            silent: false,
            cli: None,
        }
    }

    #[test]
    fn stores_are_bounded_per_client() {
        let store = Bounded::new(LOGIN_TTL);
        // One IPv6 client rotating through its /64 counts once.
        for i in 0..MAX_PENDING_PER_CLIENT + 4 {
            let ip = format!("fd00:60::{i:x}").parse().unwrap();
            store.add(format!("s{i}"), ip, pending());
        }
        store.add("other".into(), "fd00:61::1".parse().unwrap(), pending());
        let map = store.map.lock().unwrap();
        assert_eq!(map.len(), MAX_PENDING_PER_CLIENT + 1);
        assert!(!map.contains_key("s0"), "the oldest attempt is evicted");
        assert!(map.contains_key("other"));
    }

    #[test]
    fn busy_refresh_asks_to_retry_soon() {
        let r = refresh_error(RefreshError::Busy);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers()[header::RETRY_AFTER], "2");
    }

    #[test]
    fn cli_logins_need_an_unprivileged_port_and_a_state() {
        let (_, challenge) = pkce();
        assert!(cli_login("1023", &challenge, CLI_STATE).is_none());
        for port in ["1024", "65535"] {
            assert!(cli_login(port, &challenge, CLI_STATE).is_some(), "{port}");
        }
        for state in ["short", &"s".repeat(129), "state-with/slash-0123"] {
            assert!(cli_login("40123", &challenge, state).is_none(), "{state}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_access_is_decided_when_the_code_is_redeemed() {
        let (app, _) = app();
        let (verifier, challenge) = pkce();
        // bob has no policy: the callback can't tell, the redemption refuses.
        let code = cli_log_in_as(&app, &challenge, "ok-bob").await;
        let r = redeem(&app, CLIENT, &code, &verifier).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(r).await["error"], "no_access");
    }

    #[test]
    fn s256_rejects_what_is_not_a_verifier() {
        let (verifier, challenge) = pkce();
        assert_eq!(s256(verifier), Some(challenge));
        assert!(s256("v".repeat(128)).is_some());
        for bad in [
            "v".repeat(42),
            "v".repeat(129),
            format!("{}/", "v".repeat(42)),
        ] {
            assert_eq!(s256(bad.clone()), None, "{bad}");
        }
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
