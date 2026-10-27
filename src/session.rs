//! Authenticated sessions: which user is logged in from which source IP, until when, and keeping
//! the firewall's per-session chains in step.
//!
//! [`SessionTable`] is the state machine; [`spawn`] runs it in a task that serialises
//! every change and removes sessions as their tokens expire.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::RngExt;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use crate::firewall::ruleset::{RuleSpec, Ruleset, SessionRules};
use crate::firewall::{Firewall, FirewallError};
use crate::policy::{Allow, Policy, Proto};
use crate::portal::Secret;

/// How long to wait before retrying a failed firewall rebuild.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// How long a refresh may hold its session's refresh token before another may take it: longer
/// than the provider's HTTP connect and request timeouts together.
const REFRESH_LEASE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("no access policy for user {0:?}")]
    NoPolicy(String),
    #[error("the login has already expired")]
    Expired,
    #[error("failed to provision access")]
    Firewall(#[from] FirewallError),
    #[error("session manager is not running")]
    Closed,
}

/// Why a session can't be refreshed now.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RefreshError {
    #[error("no live session for this token and address")]
    NoSession,
    /// No usable refresh token: the provider issued none or refused it. Permanent.
    #[error("the session can't be refreshed")]
    Unavailable,
    #[error("a refresh of this session is already in progress")]
    Busy,
    /// The provider couldn't be reached; the refresh token is kept for another attempt.
    #[error("the identity provider is unreachable")]
    Transient,
    #[error("session manager is not running")]
    Closed,
}

/// A session's refresh token, handed out for one refresh at a time.
#[derive(Debug)]
pub(crate) struct RefreshLease {
    pub(crate) id: u64,
    pub(crate) refresh_token: Secret,
}

/// What the provider said to a refresh.
#[derive(Debug)]
pub(crate) enum RefreshOutcome {
    Refreshed {
        username: String,
        expires_at: SystemTime,
        /// A rotated refresh token, replacing the leased one.
        refresh_token: Option<Secret>,
    },
    Rejected,
    Unreachable,
}

/// Applies session changes to the firewall. [`Kernel`] is the real one.
pub(crate) trait Enforcer: Send + 'static {
    /// Incremental change; see [`Firewall::update_sessions`].
    fn update(
        &mut self,
        added: &[SessionRules],
        removed: &[u32],
        live: &[SessionRules],
    ) -> impl Future<Output = Result<(), FirewallError>> + Send;
    /// Atomically rebuilds the whole table with exactly the `live` sessions.
    fn rebuild(
        &mut self,
        live: &[SessionRules],
    ) -> impl Future<Output = Result<(), FirewallError>> + Send;
}

/// Enforces through the kernel, rebuilding from the static `base` ruleset.
pub(crate) struct Kernel {
    pub(crate) firewall: Firewall,
    pub(crate) base: Ruleset,
}

impl Enforcer for Kernel {
    async fn update(
        &mut self,
        added: &[SessionRules],
        removed: &[u32],
        live: &[SessionRules],
    ) -> Result<(), FirewallError> {
        self.firewall.update_sessions(added, removed, live).await
    }

    async fn rebuild(&mut self, live: &[SessionRules]) -> Result<(), FirewallError> {
        let mut ruleset = self.base.clone();
        ruleset.sessions = live.to_vec();
        self.firewall.apply(&ruleset).await
    }
}

/// Accepts every change; for tests of code built on sessions.
#[cfg(test)]
pub(crate) struct NoopEnforcer;

#[cfg(test)]
impl Enforcer for NoopEnforcer {
    async fn update(
        &mut self,
        _: &[SessionRules],
        _: &[u32],
        _: &[SessionRules],
    ) -> Result<(), FirewallError> {
        Ok(())
    }

    async fn rebuild(&mut self, _: &[SessionRules]) -> Result<(), FirewallError> {
        Ok(())
    }
}

/// No `Debug`: it holds the session token.
#[derive(Clone)]
struct Session {
    username: String,
    /// Opaque bearer token held in the browser's session cookie (or the client service).
    token: String,
    expires_at: SystemTime,
    rules: SessionRules,
    /// The user's host rules for this IP's address family, as published in the view.
    host_rules: Arc<[Allow]>,
    /// The provider's refresh token; it never leaves the gateway.
    refresh: Option<Secret>,
    /// The refresh in flight, if any.
    refreshing: Option<Lease>,
}

#[derive(Debug, Clone)]
struct Lease {
    id: u64,
    started: SystemTime,
}

/// What `/api/session` reports about a live session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionInfo {
    pub(crate) username: String,
    /// Seconds since the Unix epoch.
    pub(crate) expires_at: u64,
    /// What the session may reach, one entry per rule, e.g. `10.0.1.0/24 tcp/443`.
    pub(crate) access: Vec<String>,
}

/// What the host-rule proxy needs to know about live sessions: per source IP, the session id
/// and the user's host rules (`http` and `https` allows), with `dest` narrowed to the IP's
/// address family. Rules left with no dest are omitted.
pub(crate) type SessionView = HashMap<IpAddr, (u32, Arc<[Allow]>)>;

/// A view that never changes, for when no portal (and so no session) runs.
pub(crate) fn idle_view() -> watch::Receiver<Arc<SessionView>> {
    watch::channel(Arc::default()).1
}

pub(crate) struct SessionTable<E> {
    policy: Arc<Policy>,
    enforcer: E,
    by_ip: HashMap<IpAddr, Session>,
    /// Session ids double as `ct mark`s, so they start at a random value: connections marked by
    /// an earlier run then can't pass as a new session's.
    next_id: u32,
    /// The kernel may not match `by_ip` (an update failed, or its outcome is unknown); the next
    /// change, or the retry timer, rebuilds the table from `by_ip`.
    dirty: bool,
    /// Upper bound on how long one login keeps access; zero means the token's expiry alone.
    max_ttl: Duration,
    next_lease: u64,
    /// Republished after every change to `by_ip`.
    view: watch::Sender<Arc<SessionView>>,
}

impl<E: Enforcer> SessionTable<E> {
    pub(crate) fn new(policy: Arc<Policy>, enforcer: E, max_ttl: Duration) -> Self {
        SessionTable {
            policy,
            enforcer,
            by_ip: HashMap::new(),
            next_id: rand::rng().random(),
            dirty: false,
            max_ttl,
            next_lease: 0,
            view: watch::Sender::new(Arc::default()),
        }
    }

    /// Follows the [`SessionView`], which every change to the table republishes.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<SessionView>> {
        self.view.subscribe()
    }

    fn publish(&self) {
        let view = self
            .by_ip
            .iter()
            .map(|(&ip, s)| (ip, (s.rules.id, s.host_rules.clone())))
            .collect();
        self.view.send_replace(Arc::new(view));
    }

    /// Provisions `username` from `ip` until `expires_at` (capped at `max_ttl` from `now`) and
    /// returns the session token. `refresh` is the provider's refresh token, if it issued one.
    ///
    /// A login matching the session already held by `ip` extends it and keeps its token, so
    /// several browsers on one host can share it. A different user from `ip` replaces it.
    pub(crate) async fn login(
        &mut self,
        ip: IpAddr,
        username: &str,
        expires_at: SystemTime,
        refresh: Option<Secret>,
        now: SystemTime,
    ) -> Result<String, SessionError> {
        let expires_at = capped(self.max_ttl, expires_at, now);
        if expires_at <= now {
            return Err(SessionError::Expired);
        }
        if let Some(s) = self.by_ip.get_mut(&ip)
            && s.username == username
        {
            s.expires_at = expires_at;
            if refresh.is_some() {
                // A refresh in flight now finishes without effect: this token supersedes it.
                s.refresh = refresh;
                s.refreshing = None;
            }
            info!(%ip, username, via = "login", "session extended");
            return Ok(s.token.clone());
        }
        if self.policy.user(username).is_none() {
            return Err(SessionError::NoPolicy(username.to_string()));
        }
        let id = self.allocate_id();
        let rules = SessionRules::for_user(&self.policy, id, username, ip).expect("checked above");
        let host_rules = host_rules(&self.policy, username, ip);
        let session = Session {
            username: username.to_string(),
            host_rules,
            token: new_token(),
            expires_at,
            rules,
            refresh,
            refreshing: None,
        };
        let token = session.token.clone();
        let added = [session.rules.clone()];
        let replaced = self.by_ip.insert(ip, session);
        let removed: Vec<u32> = replaced.iter().map(|s| s.rules.id).collect();
        if let Err(e) = self.sync(&added, &removed).await {
            // Only what was in force before is kept: either the kernel rejected the change and
            // still enforces it, or the retry timer rebuilds to it.
            let new = self.by_ip.remove(&ip);
            if let Some(old) = replaced {
                self.by_ip.insert(ip, old);
            }
            debug_assert!(new.is_some());
            return Err(e.into());
        }
        if let Some(old) = &replaced {
            info!(%ip, username = old.username, "session replaced");
        }
        self.publish();
        info!(%ip, username, id = added[0].id, "session provisioned");
        Ok(token)
    }

    /// The session `token` names, if it is live and belongs to `ip`.
    pub(crate) fn status(&self, token: &str, ip: IpAddr, now: SystemTime) -> Option<SessionInfo> {
        self.live_session(token, ip, now).map(Session::info)
    }

    fn live_session(&self, token: &str, ip: IpAddr, now: SystemTime) -> Option<&Session> {
        self.by_ip.get(&ip).filter(|s| s.is_live(token, now))
    }

    /// Hands out the refresh token of the session `token` names, for the caller to redeem with
    /// the provider and report back through [`finish_refresh`](Self::finish_refresh). One
    /// refresh per session runs at a time, so a rotated token can't be redeemed twice.
    pub(crate) fn begin_refresh(
        &mut self,
        token: &str,
        ip: IpAddr,
        now: SystemTime,
    ) -> Result<RefreshLease, RefreshError> {
        let s = self
            .by_ip
            .get_mut(&ip)
            .filter(|s| s.is_live(token, now))
            .ok_or(RefreshError::NoSession)?;
        let refresh_token = s.refresh.clone().ok_or(RefreshError::Unavailable)?;
        if let Some(lease) = &s.refreshing
            && now < lease.started + REFRESH_LEASE_TTL
        {
            return Err(RefreshError::Busy);
        }
        let id = self.next_lease;
        self.next_lease += 1;
        s.refreshing = Some(Lease { id, started: now });
        Ok(RefreshLease { id, refresh_token })
    }

    /// Applies the provider's answer to the refresh `lease` of the session `token` names. A
    /// refresh extends the session exactly as a re-login does. Its outcome is discarded if the
    /// session has since ended or expired, or a re-login has replaced its refresh token.
    pub(crate) fn finish_refresh(
        &mut self,
        token: &str,
        ip: IpAddr,
        lease: u64,
        outcome: RefreshOutcome,
        now: SystemTime,
    ) -> Result<SessionInfo, RefreshError> {
        let max_ttl = self.max_ttl;
        let s = self
            .by_ip
            .get_mut(&ip)
            .filter(|s| s.is_live(token, now))
            .ok_or(RefreshError::NoSession)?;
        if s.refreshing.as_ref().is_none_or(|l| l.id != lease) {
            return Ok(s.info());
        }
        s.refreshing = None;
        match outcome {
            RefreshOutcome::Refreshed {
                username,
                expires_at,
                refresh_token,
            } => {
                let expires_at = capped(max_ttl, expires_at, now);
                if username != s.username || expires_at <= now {
                    warn!(
                        %ip,
                        username = s.username,
                        refreshed_as = username,
                        "refresh returned another user or an expired token; refresh disabled"
                    );
                    s.refresh = None;
                    return Err(RefreshError::Unavailable);
                }
                s.expires_at = expires_at;
                if refresh_token.is_some() {
                    s.refresh = refresh_token;
                }
                info!(%ip, username, via = "refresh", "session extended");
                Ok(s.info())
            }
            RefreshOutcome::Rejected => {
                s.refresh = None;
                Err(RefreshError::Unavailable)
            }
            RefreshOutcome::Unreachable => Err(RefreshError::Transient),
        }
    }

    /// Ends the session `token` names at once. Returns whether there was one.
    pub(crate) async fn logout(&mut self, token: &str, ip: IpAddr, now: SystemTime) -> bool {
        if self.live_session(token, ip, now).is_none() {
            return false;
        }
        let s = self.by_ip.remove(&ip).expect("checked above");
        info!(%ip, username = s.username, "session ended");
        self.publish();
        // Like an expiry, the session is gone from the state either way; a failed update leaves
        // the table dirty and the retry timer removes it from the kernel.
        if let Err(e) = self.sync(&[], &[s.rules.id]).await {
            error!(error = %format!("{e:#}"), "failed to deprovision ended session; will retry");
        }
        true
    }

    /// Removes every session expired by `now`.
    pub(crate) async fn expire(&mut self, now: SystemTime) {
        let expired: Vec<IpAddr> = self
            .by_ip
            .iter()
            .filter(|(_, s)| s.expires_at <= now)
            .map(|(&ip, _)| ip)
            .collect();
        if expired.is_empty() {
            return;
        }
        let mut removed = Vec::new();
        for ip in expired {
            let s = self.by_ip.remove(&ip).expect("collected above");
            info!(%ip, username = s.username, "session expired");
            removed.push(s.rules.id);
        }
        self.publish();
        if let Err(e) = self.sync(&[], &removed).await {
            error!(error = %format!("{e:#}"), "failed to deprovision expired sessions; will retry");
        }
    }

    /// Retries a rebuild after an earlier failure. Returns whether the kernel is now in sync.
    pub(crate) async fn retry(&mut self) -> bool {
        if self.dirty {
            match self.enforcer.rebuild(&self.live()).await {
                Ok(()) => {
                    info!("firewall resynchronised");
                    self.dirty = false;
                }
                Err(e) => warn!(error = %format!("{e:#}"), "firewall rebuild failed; will retry"),
            }
        }
        !self.dirty
    }

    /// When the next session expires, or sooner if a rebuild is pending.
    pub(crate) fn next_wakeup(&self, now: SystemTime) -> Option<Duration> {
        let expiry = self
            .by_ip
            .values()
            .map(|s| s.expires_at.duration_since(now).unwrap_or_default())
            .min();
        let retry = self.dirty.then_some(RETRY_INTERVAL);
        expiry.into_iter().chain(retry).min()
    }

    /// The next id that is nonzero (0 means unmarked) and not held by a live session.
    fn allocate_id(&mut self) -> u32 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if id != 0 && self.by_ip.values().all(|s| s.rules.id != id) {
                return id;
            }
        }
    }

    fn live(&self) -> Vec<SessionRules> {
        let mut live: Vec<_> = self.by_ip.values().map(|s| s.rules.clone()).collect();
        live.sort_by_key(|r| r.id);
        live
    }

    /// Brings the kernel in line with `by_ip`, which already reflects `added` and `removed`.
    /// Falls back to a full rebuild; if that fails too, leaves the table marked dirty.
    async fn sync(&mut self, added: &[SessionRules], removed: &[u32]) -> Result<(), FirewallError> {
        let live = self.live();
        if !self.dirty {
            match self.enforcer.update(added, removed, &live).await {
                Ok(()) => return Ok(()),
                Err(e) => warn!(error = %format!("{e:#}"), "session update failed; rebuilding"),
            }
        }
        match self.enforcer.rebuild(&live).await {
            Ok(()) => {
                self.dirty = false;
                Ok(())
            }
            Err(e) => {
                self.dirty = true;
                Err(e)
            }
        }
    }
}

impl Session {
    fn is_live(&self, token: &str, now: SystemTime) -> bool {
        self.token == token && self.expires_at > now
    }

    fn info(&self) -> SessionInfo {
        SessionInfo {
            username: self.username.clone(),
            expires_at: unix_secs(self.expires_at),
            access: self.rules.rules.iter().map(RuleSpec::describe).collect(),
        }
    }
}

/// `username`'s host rules, with `dest` narrowed to `ip`'s address family.
fn host_rules(policy: &Policy, username: &str, ip: IpAddr) -> Arc<[Allow]> {
    let Some(user) = policy.user(username) else {
        return Arc::new([]);
    };
    user.allow
        .iter()
        .filter(|a| matches!(a.proto, Proto::Http | Proto::Https))
        .filter_map(|a| {
            let dest: Vec<_> = a
                .dest
                .iter()
                .filter(|d| d.is_ipv4() == ip.is_ipv4())
                .copied()
                .collect();
            (!dest.is_empty()).then(|| Allow { dest, ..a.clone() })
        })
        .collect()
}

/// `expires_at`, capped at `max_ttl` from `now` (zero means no cap).
fn capped(max_ttl: Duration, expires_at: SystemTime, now: SystemTime) -> SystemTime {
    if max_ttl.is_zero() {
        expires_at
    } else {
        expires_at.min(now + max_ttl)
    }
}

/// 256 random bits, hex-encoded.
pub(crate) fn new_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

enum Command {
    Login {
        ip: IpAddr,
        username: String,
        expires_at: SystemTime,
        refresh: Option<Secret>,
        reply: oneshot::Sender<Result<String, SessionError>>,
    },
    Status {
        token: String,
        ip: IpAddr,
        reply: oneshot::Sender<Option<SessionInfo>>,
    },
    BeginRefresh {
        token: String,
        ip: IpAddr,
        reply: oneshot::Sender<Result<RefreshLease, RefreshError>>,
    },
    FinishRefresh {
        token: String,
        ip: IpAddr,
        lease: u64,
        outcome: RefreshOutcome,
        reply: oneshot::Sender<Result<SessionInfo, RefreshError>>,
    },
    Logout {
        token: String,
        ip: IpAddr,
        reply: oneshot::Sender<bool>,
    },
}

/// Talks to the task started by [`spawn`].
#[derive(Clone)]
pub(crate) struct SessionHandle {
    tx: mpsc::Sender<Command>,
}

impl SessionHandle {
    pub(crate) async fn login(
        &self,
        ip: IpAddr,
        username: String,
        expires_at: SystemTime,
        refresh: Option<Secret>,
    ) -> Result<String, SessionError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Login {
                ip,
                username,
                expires_at,
                refresh,
                reply,
            })
            .await
            .map_err(|_| SessionError::Closed)?;
        rx.await.map_err(|_| SessionError::Closed)?
    }

    pub(crate) async fn status(&self, token: String, ip: IpAddr) -> Option<SessionInfo> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Status { token, ip, reply })
            .await
            .ok()?;
        rx.await.ok()?
    }

    pub(crate) async fn begin_refresh(
        &self,
        token: String,
        ip: IpAddr,
    ) -> Result<RefreshLease, RefreshError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::BeginRefresh { token, ip, reply })
            .await
            .map_err(|_| RefreshError::Closed)?;
        rx.await.map_err(|_| RefreshError::Closed)?
    }

    pub(crate) async fn finish_refresh(
        &self,
        token: String,
        ip: IpAddr,
        lease: u64,
        outcome: RefreshOutcome,
    ) -> Result<SessionInfo, RefreshError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::FinishRefresh {
                token,
                ip,
                lease,
                outcome,
                reply,
            })
            .await
            .map_err(|_| RefreshError::Closed)?;
        rx.await.map_err(|_| RefreshError::Closed)?
    }

    /// Ends the session at once. Returns whether there was one; `false` too if the session
    /// manager has stopped, which removes every session anyway.
    pub(crate) async fn logout(&self, token: String, ip: IpAddr) -> bool {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Command::Logout { token, ip, reply })
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

/// Runs `table` in a task until every [`SessionHandle`] is dropped. The receiver follows its
/// [`SessionView`].
pub(crate) fn spawn<E: Enforcer>(
    table: SessionTable<E>,
) -> (
    SessionHandle,
    watch::Receiver<Arc<SessionView>>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel(64);
    let view = table.subscribe();
    (SessionHandle { tx }, view, tokio::spawn(run(table, rx)))
}

async fn run<E: Enforcer>(mut table: SessionTable<E>, mut rx: mpsc::Receiver<Command>) {
    loop {
        // An hour stands in for "nothing scheduled"; the loop just re-evaluates.
        let wait = table
            .next_wakeup(SystemTime::now())
            .unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(Command::Login { ip, username, expires_at, refresh, reply }) => {
                    let result = table
                        .login(ip, &username, expires_at, refresh, SystemTime::now())
                        .await;
                    let _ = reply.send(result);
                }
                Some(Command::Status { token, ip, reply }) => {
                    let _ = reply.send(table.status(&token, ip, SystemTime::now()));
                }
                Some(Command::BeginRefresh { token, ip, reply }) => {
                    let _ = reply.send(table.begin_refresh(&token, ip, SystemTime::now()));
                }
                Some(Command::FinishRefresh { token, ip, lease, outcome, reply }) => {
                    let now = SystemTime::now();
                    let _ = reply.send(table.finish_refresh(&token, ip, lease, outcome, now));
                }
                Some(Command::Logout { token, ip, reply }) => {
                    let ended = table.logout(&token, ip, SystemTime::now()).await;
                    let _ = reply.send(ended);
                }
                None => break,
            },
            () = tokio::time::sleep(wait) => {
                table.expire(SystemTime::now()).await;
                table.retry().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records calls and fails on demand.
    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        fail_update: bool,
        fail_rebuild: bool,
    }

    impl Enforcer for Fake {
        async fn update(
            &mut self,
            added: &[SessionRules],
            removed: &[u32],
            live: &[SessionRules],
        ) -> Result<(), FirewallError> {
            let ids = |s: &[SessionRules]| s.iter().map(|r| r.id).collect::<Vec<_>>();
            self.calls.push(format!(
                "update +{:?} -{removed:?} ={:?}",
                ids(added),
                ids(live)
            ));
            if self.fail_update {
                return Err(crate::firewall::NftError::Timeout {
                    after: Duration::ZERO,
                }
                .into());
            }
            Ok(())
        }

        async fn rebuild(&mut self, live: &[SessionRules]) -> Result<(), FirewallError> {
            let ids: Vec<_> = live.iter().map(|r| r.id).collect();
            self.calls.push(format!("rebuild ={ids:?}"));
            if self.fail_rebuild {
                return Err(crate::firewall::NftError::Timeout {
                    after: Duration::ZERO,
                }
                .into());
            }
            Ok(())
        }
    }

    fn table() -> SessionTable<Fake> {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        let mut t = SessionTable::new(Arc::new(policy), Fake::default(), Duration::ZERO);
        t.next_id = 1;
        t
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    const IP: &str = "192.168.60.7";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn login_provisions_and_reports_status() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert_eq!(t.enforcer.calls, ["update +[1] -[] =[1]"]);
        let info = t.status(&token, ip(IP), at(150)).unwrap();
        assert_eq!(info.username, "alice");
        assert_eq!(info.expires_at, 200);
        assert_eq!(info.access, ["10.0.1.0/24 tcp/22", "10.0.1.0/24 tcp/443"]);
    }

    #[tokio::test]
    async fn status_requires_matching_token_ip_and_time() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert!(t.status("wrong", ip(IP), at(150)).is_none());
        assert!(t.status(&token, ip("192.168.60.8"), at(150)).is_none());
        assert!(t.status(&token, ip(IP), at(200)).is_none());
    }

    #[tokio::test]
    async fn relogin_extends_without_touching_the_firewall() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        let again = t
            .login(ip(IP), "alice", at(300), None, at(180))
            .await
            .unwrap();
        assert_eq!(token, again);
        assert_eq!(t.enforcer.calls.len(), 1);
        assert_eq!(t.status(&token, ip(IP), at(250)).unwrap().expires_at, 300);
    }

    #[tokio::test]
    async fn other_user_replaces_session_atomically() {
        let mut t = table();
        let mut policy = (*t.policy).clone();
        policy.users.push(crate::policy::User {
            username: "bob".into(),
            allow: policy.users[0].allow.clone(),
        });
        t.policy = Arc::new(policy);
        let alice = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        let bob = t
            .login(ip(IP), "bob", at(200), None, at(110))
            .await
            .unwrap();
        assert_ne!(alice, bob);
        assert_eq!(t.enforcer.calls[1], "update +[2] -[1] =[2]");
        assert!(t.status(&alice, ip(IP), at(120)).is_none());
    }

    #[tokio::test]
    async fn unknown_user_and_expired_login_are_refused() {
        let mut t = table();
        assert!(matches!(
            t.login(ip(IP), "mallory", at(200), None, at(100)).await,
            Err(SessionError::NoPolicy(_))
        ));
        assert!(matches!(
            t.login(ip(IP), "alice", at(100), None, at(100)).await,
            Err(SessionError::Expired)
        ));
        assert!(t.enforcer.calls.is_empty());
    }

    #[tokio::test]
    async fn expires_in_deadline_order() {
        let mut t = table();
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        t.login(ip("fd00:60::7"), "alice", at(300), None, at(100))
            .await
            .unwrap();
        assert_eq!(t.next_wakeup(at(150)), Some(Duration::from_secs(50)));
        t.expire(at(250)).await;
        assert_eq!(t.enforcer.calls.last().unwrap(), "update +[] -[1] =[2]");
        assert_eq!(t.next_wakeup(at(250)), Some(Duration::from_secs(50)));
        t.expire(at(300)).await;
        assert_eq!(t.enforcer.calls.last().unwrap(), "update +[] -[2] =[]");
        assert_eq!(t.next_wakeup(at(300)), None);
    }

    #[tokio::test]
    async fn failed_update_falls_back_to_rebuild() {
        let mut t = table();
        t.enforcer.fail_update = true;
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert_eq!(t.enforcer.calls, ["update +[1] -[] =[1]", "rebuild =[1]"]);
    }

    #[tokio::test]
    async fn failed_rebuild_rolls_back_and_retries() {
        let mut t = table();
        t.enforcer.fail_update = true;
        t.enforcer.fail_rebuild = true;
        assert!(matches!(
            t.login(ip(IP), "alice", at(200), None, at(100)).await,
            Err(SessionError::Firewall(_))
        ));
        assert_eq!(t.next_wakeup(at(100)), Some(RETRY_INTERVAL));
        assert!(!t.retry().await);
        t.enforcer.fail_rebuild = false;
        assert!(t.retry().await);
        // The rebuild restores the state before the failed login: no sessions.
        assert_eq!(t.enforcer.calls.last().unwrap(), "rebuild =[]");
        assert_eq!(t.next_wakeup(at(100)), None);
    }

    #[tokio::test]
    async fn dirty_table_skips_incremental_updates() {
        let mut t = table();
        t.dirty = true;
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert_eq!(t.enforcer.calls, ["rebuild =[1]"]);
        assert!(!t.dirty);
    }

    #[tokio::test]
    async fn max_ttl_caps_logins_and_extensions() {
        let mut t = table();
        t.max_ttl = Duration::from_secs(60);
        let token = t
            .login(ip(IP), "alice", at(1000), None, at(100))
            .await
            .unwrap();
        assert_eq!(t.status(&token, ip(IP), at(110)).unwrap().expires_at, 160);
        t.login(ip(IP), "alice", at(1000), None, at(150))
            .await
            .unwrap();
        assert_eq!(t.status(&token, ip(IP), at(155)).unwrap().expires_at, 210);
        // A token expiring sooner than the cap still wins.
        t.login(ip(IP), "alice", at(220), None, at(200))
            .await
            .unwrap();
        assert_eq!(t.status(&token, ip(IP), at(205)).unwrap().expires_at, 220);
    }

    #[tokio::test]
    async fn ids_skip_zero_and_live_sessions() {
        let mut t = table();
        t.next_id = u32::MAX;
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        // The counter wraps, skipping 0.
        assert_eq!(t.allocate_id(), 1);
        // u32::MAX is still held by alice's session, so it is skipped too.
        t.next_id = u32::MAX;
        assert_eq!(t.allocate_id(), 1);
    }

    #[tokio::test]
    async fn tokens_are_unique_hex() {
        let a = new_token();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, new_token());
    }

    fn rt(s: &str) -> Option<Secret> {
        Some(Secret::new(s.into()))
    }

    fn refreshed(user: &str, exp: u64, token: Option<Secret>) -> RefreshOutcome {
        RefreshOutcome::Refreshed {
            username: user.into(),
            expires_at: at(exp),
            refresh_token: token,
        }
    }

    #[tokio::test]
    async fn refresh_extends_and_rotates_the_refresh_token() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt-1"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(180)).unwrap();
        assert_eq!(lease.refresh_token.expose(), "rt-1");
        let info = t
            .finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("alice", 300, rt("rt-2")),
                at(181),
            )
            .unwrap();
        assert_eq!(info.expires_at, 300);
        // The rotated token is used next time, and the firewall was never touched.
        let lease = t.begin_refresh(&token, ip(IP), at(280)).unwrap();
        assert_eq!(lease.refresh_token.expose(), "rt-2");
        // A provider that doesn't rotate leaves the token as it was.
        t.finish_refresh(
            &token,
            ip(IP),
            lease.id,
            refreshed("alice", 400, None),
            at(281),
        )
        .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(380)).unwrap();
        assert_eq!(lease.refresh_token.expose(), "rt-2");
        assert_eq!(t.enforcer.calls.len(), 1);
    }

    #[tokio::test]
    async fn refresh_is_capped_by_max_ttl() {
        let mut t = table();
        t.max_ttl = Duration::from_secs(60);
        let token = t
            .login(ip(IP), "alice", at(1000), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(150)).unwrap();
        let info = t
            .finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("alice", 1000, None),
                at(150),
            )
            .unwrap();
        assert_eq!(info.expires_at, 210);
    }

    #[tokio::test]
    async fn refresh_as_another_user_disables_refresh() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(150)).unwrap();
        assert_eq!(
            t.finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("bob", 300, None),
                at(150)
            ),
            Err(RefreshError::Unavailable)
        );
        let info = t.status(&token, ip(IP), at(150)).unwrap();
        assert_eq!((info.username.as_str(), info.expires_at), ("alice", 200));
        assert_eq!(
            t.begin_refresh(&token, ip(IP), at(151)).unwrap_err(),
            RefreshError::Unavailable
        );
    }

    #[tokio::test]
    async fn rejected_refresh_drops_the_token_and_unreachable_keeps_it() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(150)).unwrap();
        assert_eq!(
            t.finish_refresh(
                &token,
                ip(IP),
                lease.id,
                RefreshOutcome::Unreachable,
                at(150)
            ),
            Err(RefreshError::Transient)
        );
        let lease = t.begin_refresh(&token, ip(IP), at(155)).unwrap();
        assert_eq!(
            t.finish_refresh(&token, ip(IP), lease.id, RefreshOutcome::Rejected, at(155)),
            Err(RefreshError::Unavailable)
        );
        assert_eq!(
            t.begin_refresh(&token, ip(IP), at(156)).unwrap_err(),
            RefreshError::Unavailable
        );
        // The session itself runs on to its expiry.
        assert!(t.status(&token, ip(IP), at(199)).is_some());
    }

    #[tokio::test]
    async fn begin_refresh_checks_session_token_and_lease() {
        let mut t = table();
        let none = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert_eq!(
            t.begin_refresh(&none, ip(IP), at(150)).unwrap_err(),
            RefreshError::Unavailable
        );
        let other = "fd00:60::7";
        let token = t
            .login(ip(other), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        for (tok, from, now) in [
            ("wrong", other, 150),
            (&*token, IP, 150),
            (&*token, other, 200),
        ] {
            assert_eq!(
                t.begin_refresh(tok, ip(from), at(now)).unwrap_err(),
                RefreshError::NoSession,
                "{tok} {from} {now}"
            );
        }
        let first = t.begin_refresh(&token, ip(other), at(150)).unwrap();
        assert_eq!(
            t.begin_refresh(&token, ip(other), at(160)).unwrap_err(),
            RefreshError::Busy
        );
        // An abandoned lease can be taken over once it is old enough, and then the first
        // one's answer no longer applies.
        let second = t.begin_refresh(&token, ip(other), at(180)).unwrap();
        assert_ne!(first.id, second.id);
        let info = t
            .finish_refresh(
                &token,
                ip(other),
                first.id,
                refreshed("alice", 400, None),
                at(181),
            )
            .unwrap();
        assert_eq!(info.expires_at, 200);
    }

    #[tokio::test]
    async fn relogin_supersedes_a_refresh_in_flight() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt-1"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(150)).unwrap();
        t.login(ip(IP), "alice", at(250), rt("login"), at(151))
            .await
            .unwrap();
        let info = t
            .finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("alice", 400, rt("rt-2")),
                at(152),
            )
            .unwrap();
        assert_eq!(info.expires_at, 250, "the stale refresh changes nothing");
        assert_eq!(
            t.begin_refresh(&token, ip(IP), at(153))
                .unwrap()
                .refresh_token
                .expose(),
            "login"
        );
        // A re-login without a refresh token keeps the one held.
        t.login(ip(IP), "alice", at(260), None, at(154))
            .await
            .unwrap();
        let held = t.by_ip[&ip(IP)].refresh.as_ref().map(Secret::expose);
        assert_eq!(held, Some("login"));
    }

    #[tokio::test]
    async fn refresh_after_logout_or_replacement_is_discarded() {
        let mut t = table();
        let mut policy = (*t.policy).clone();
        policy.users.push(crate::policy::User {
            username: "bob".into(),
            allow: policy.users[0].allow.clone(),
        });
        t.policy = Arc::new(policy);
        let alice = t
            .login(ip(IP), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&alice, ip(IP), at(150)).unwrap();
        let bob = t
            .login(ip(IP), "bob", at(200), rt("rt-bob"), at(151))
            .await
            .unwrap();
        assert_eq!(
            t.finish_refresh(
                &alice,
                ip(IP),
                lease.id,
                refreshed("alice", 400, None),
                at(152)
            ),
            Err(RefreshError::NoSession)
        );
        let lease = t.begin_refresh(&bob, ip(IP), at(153)).unwrap();
        assert!(t.logout(&bob, ip(IP), at(154)).await);
        assert_eq!(
            t.finish_refresh(&bob, ip(IP), lease.id, refreshed("bob", 400, None), at(155)),
            Err(RefreshError::NoSession)
        );
    }

    #[tokio::test]
    async fn logout_removes_the_session_through_an_update() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        assert!(!t.logout("wrong", ip(IP), at(150)).await);
        assert!(!t.logout(&token, ip("192.168.60.8"), at(150)).await);
        assert_eq!(t.enforcer.calls.len(), 1);
        assert!(t.logout(&token, ip(IP), at(150)).await);
        assert_eq!(t.enforcer.calls[1], "update +[] -[1] =[]");
        assert!(t.status(&token, ip(IP), at(150)).is_none());
        assert_eq!(t.next_wakeup(at(150)), None);
    }

    #[tokio::test]
    async fn failed_logout_stays_removed_and_retries() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        t.enforcer.fail_update = true;
        t.enforcer.fail_rebuild = true;
        assert!(t.logout(&token, ip(IP), at(150)).await);
        assert!(t.status(&token, ip(IP), at(150)).is_none());
        assert_eq!(t.next_wakeup(at(150)), Some(RETRY_INTERVAL));
        t.enforcer.fail_rebuild = false;
        assert!(t.retry().await);
        assert_eq!(t.enforcer.calls.last().unwrap(), "rebuild =[]");
    }

    #[tokio::test]
    async fn refresh_to_an_expired_token_disables_refresh() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(150)).unwrap();
        assert_eq!(
            t.finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("alice", 150, None),
                at(150)
            ),
            Err(RefreshError::Unavailable)
        );
        assert_eq!(t.status(&token, ip(IP), at(150)).unwrap().expires_at, 200);
    }

    #[tokio::test]
    async fn expired_sessions_neither_refresh_nor_log_out() {
        let mut t = table();
        let token = t
            .login(ip(IP), "alice", at(200), rt("rt"), at(100))
            .await
            .unwrap();
        let lease = t.begin_refresh(&token, ip(IP), at(190)).unwrap();
        // Past its expiry, before the expiry timer has removed it.
        assert_eq!(
            t.finish_refresh(
                &token,
                ip(IP),
                lease.id,
                refreshed("alice", 400, None),
                at(201)
            ),
            Err(RefreshError::NoSession)
        );
        assert!(!t.logout(&token, ip(IP), at(201)).await);
    }

    const HOST_POLICY: &str = r#"
users:
  - username: alice
    allow:
      - dest: [10.0.1.0/24]
        proto: tcp
        ports: [22]
      - dest: [10.0.2.0/24, "fd00:2::/64"]
        proto: https
        hosts: [example.com]
      - dest: ["fd00:3::/64"]
        proto: http
        hosts: [example.org]
  - username: bob
    allow:
      - dest: [10.0.4.0/24]
        proto: http
        hosts: [bob.example]
"#;

    fn host_table() -> SessionTable<Fake> {
        let policy = Policy::parse(HOST_POLICY).unwrap();
        let mut t = SessionTable::new(Arc::new(policy), Fake::default(), Duration::ZERO);
        t.next_id = 1;
        t
    }

    /// The view's entry for `ip`: session id and each host rule as `dests proto hosts`.
    fn entry(view: &SessionView, ip: IpAddr) -> Option<(u32, Vec<String>)> {
        let (id, rules) = view.get(&ip)?;
        let rules = rules
            .iter()
            .map(|a| {
                let dests: Vec<_> = a.dest.iter().map(ToString::to_string).collect();
                let hosts: Vec<_> = a.hosts.iter().map(ToString::to_string).collect();
                format!("{} {} {}", dests.join(","), a.proto, hosts.join(","))
            })
            .collect();
        Some((*id, rules))
    }

    #[tokio::test]
    async fn view_holds_the_login_families_host_rules() {
        let mut t = host_table();
        let view = t.subscribe();
        assert!(view.borrow().is_empty());
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        t.login(ip("fd00:60::7"), "alice", at(200), None, at(100))
            .await
            .unwrap();
        let v = view.borrow().clone();
        assert_eq!(v.len(), 2);
        assert_eq!(
            entry(&v, ip(IP)),
            Some((1, vec!["10.0.2.0/24 https example.com".into()]))
        );
        assert_eq!(
            entry(&v, ip("fd00:60::7")),
            Some((
                2,
                vec![
                    "fd00:2::/64 https example.com".into(),
                    "fd00:3::/64 http example.org".into()
                ]
            ))
        );
    }

    #[tokio::test]
    async fn view_keeps_the_id_on_extend_and_changes_it_on_replace() {
        let mut t = host_table();
        let view = t.subscribe();
        t.login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        t.login(ip(IP), "alice", at(300), None, at(150))
            .await
            .unwrap();
        assert_eq!(entry(&view.borrow(), ip(IP)).unwrap().0, 1);
        t.login(ip(IP), "bob", at(300), None, at(160))
            .await
            .unwrap();
        assert_eq!(
            entry(&view.borrow(), ip(IP)),
            Some((2, vec!["10.0.4.0/24 http bob.example".into()]))
        );
        t.login(ip(IP), "alice", at(300), None, at(170))
            .await
            .unwrap();
        assert_eq!(entry(&view.borrow(), ip(IP)).unwrap().0, 3);
    }

    #[tokio::test]
    async fn view_drops_sessions_on_logout_and_expiry() {
        let mut t = host_table();
        let view = t.subscribe();
        let token = t
            .login(ip(IP), "alice", at(200), None, at(100))
            .await
            .unwrap();
        t.login(ip("fd00:60::7"), "alice", at(300), None, at(100))
            .await
            .unwrap();
        assert!(t.logout(&token, ip(IP), at(150)).await);
        assert!(entry(&view.borrow(), ip(IP)).is_none());
        assert!(entry(&view.borrow(), ip("fd00:60::7")).is_some());
        t.expire(at(300)).await;
        assert!(view.borrow().is_empty());
    }

    #[tokio::test]
    async fn view_is_unchanged_by_a_refused_login() {
        let mut t = host_table();
        t.enforcer.fail_update = true;
        t.enforcer.fail_rebuild = true;
        let view = t.subscribe();
        assert!(
            t.login(ip(IP), "alice", at(200), None, at(100))
                .await
                .is_err()
        );
        assert!(view.borrow().is_empty());
    }

    #[tokio::test]
    async fn spawn_publishes_and_an_idle_view_stays_empty() {
        let (handle, mut view, _task) = spawn(host_table());
        handle
            .login(
                ip(IP),
                "alice".into(),
                SystemTime::now() + Duration::from_secs(3600),
                None,
            )
            .await
            .unwrap();
        view.wait_for(|v| v.contains_key(&ip(IP))).await.unwrap();
        assert!(idle_view().borrow().is_empty());
    }
}
