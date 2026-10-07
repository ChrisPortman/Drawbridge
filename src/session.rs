//! Authenticated sessions: which user is logged in from which source IP, until when, and keeping
//! the firewall's per-session chains in step.
//!
//! [`SessionTable`] is the synchronous state machine; [`spawn`] runs it in a task that serialises
//! every change and removes sessions as their tokens expire.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::RngExt;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::firewall::ruleset::{RuleSpec, Ruleset, SessionRules};
use crate::firewall::{self, FirewallError};
use crate::policy::{Policy, Proto};

/// How long to wait before retrying a failed firewall rebuild.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

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

/// Applies session changes to the firewall. [`Kernel`] is the real one.
pub(crate) trait Enforcer: Send + 'static {
    /// Incremental change; see [`firewall::update_sessions`].
    fn update(
        &mut self,
        added: &[SessionRules],
        removed: &[u32],
        live: &[SessionRules],
    ) -> Result<(), FirewallError>;
    /// Atomically rebuilds the whole table with exactly the `live` sessions.
    fn rebuild(&mut self, live: &[SessionRules]) -> Result<(), FirewallError>;
}

/// Enforces through the kernel, rebuilding from the static `base` ruleset.
pub(crate) struct Kernel {
    pub(crate) base: Ruleset,
}

impl Enforcer for Kernel {
    fn update(
        &mut self,
        added: &[SessionRules],
        removed: &[u32],
        live: &[SessionRules],
    ) -> Result<(), FirewallError> {
        firewall::update_sessions(added, removed, live)
    }

    fn rebuild(&mut self, live: &[SessionRules]) -> Result<(), FirewallError> {
        let mut ruleset = self.base.clone();
        ruleset.sessions = live.to_vec();
        firewall::apply(&ruleset)
    }
}

/// Accepts every change; for tests of code built on sessions.
#[cfg(test)]
pub(crate) struct NoopEnforcer;

#[cfg(test)]
impl Enforcer for NoopEnforcer {
    fn update(
        &mut self,
        _: &[SessionRules],
        _: &[u32],
        _: &[SessionRules],
    ) -> Result<(), FirewallError> {
        Ok(())
    }

    fn rebuild(&mut self, _: &[SessionRules]) -> Result<(), FirewallError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Session {
    username: String,
    /// Opaque bearer token held in the browser's session cookie.
    token: String,
    expires_at: SystemTime,
    rules: SessionRules,
}

/// What `/api/session` reports about a live session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SessionInfo {
    username: String,
    /// Seconds since the Unix epoch.
    expires_at: u64,
    /// What the session may reach, one entry per rule, e.g. `10.0.1.0/24 tcp/443`.
    access: Vec<String>,
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
        }
    }

    /// Provisions `username` from `ip` until `expires_at` (capped at `max_ttl` from `now`) and
    /// returns the session token.
    ///
    /// A login matching the session already held by `ip` extends it and keeps its token, so
    /// several browsers on one host can share it. A different user from `ip` replaces it.
    pub(crate) fn login(
        &mut self,
        ip: IpAddr,
        username: &str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<String, SessionError> {
        let expires_at = if self.max_ttl.is_zero() {
            expires_at
        } else {
            expires_at.min(now + self.max_ttl)
        };
        if expires_at <= now {
            return Err(SessionError::Expired);
        }
        if let Some(s) = self.by_ip.get_mut(&ip)
            && s.username == username
        {
            s.expires_at = expires_at;
            info!(%ip, username, "session extended");
            return Ok(s.token.clone());
        }
        if self.policy.user(username).is_none() {
            return Err(SessionError::NoPolicy(username.to_string()));
        }
        let id = self.allocate_id();
        let rules = SessionRules::for_user(&self.policy, id, username, ip).expect("checked above");
        let session = Session {
            username: username.to_string(),
            token: new_token(),
            expires_at,
            rules,
        };
        let token = session.token.clone();
        let added = [session.rules.clone()];
        let replaced = self.by_ip.insert(ip, session);
        let removed: Vec<u32> = replaced.iter().map(|s| s.rules.id).collect();
        if let Err(e) = self.sync(&added, &removed) {
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
        info!(%ip, username, id = added[0].id, "session provisioned");
        Ok(token)
    }

    /// The session `token` names, if it is live and belongs to `ip`.
    pub(crate) fn status(&self, token: &str, ip: IpAddr, now: SystemTime) -> Option<SessionInfo> {
        let s = self.by_ip.get(&ip)?;
        (s.token == token && s.expires_at > now).then(|| SessionInfo {
            username: s.username.clone(),
            expires_at: unix_secs(s.expires_at),
            access: s.rules.rules.iter().map(describe).collect(),
        })
    }

    /// Removes every session expired by `now`.
    pub(crate) fn expire(&mut self, now: SystemTime) {
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
        if let Err(e) = self.sync(&[], &removed) {
            error!(error = %format!("{e:#}"), "failed to deprovision expired sessions; will retry");
        }
    }

    /// Retries a rebuild after an earlier failure. Returns whether the kernel is now in sync.
    pub(crate) fn retry(&mut self) -> bool {
        if self.dirty {
            match self.enforcer.rebuild(&self.live()) {
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
    fn sync(&mut self, added: &[SessionRules], removed: &[u32]) -> Result<(), FirewallError> {
        let live = self.live();
        if !self.dirty {
            match self.enforcer.update(added, removed, &live) {
                Ok(()) => return Ok(()),
                Err(e) => warn!(error = %format!("{e:#}"), "session update failed; rebuilding"),
            }
        }
        match self.enforcer.rebuild(&live) {
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

/// 256 random bits, hex-encoded.
fn new_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn describe(rule: &RuleSpec) -> String {
    match (rule.proto, rule.ports) {
        (Proto::Any, _) => format!("{} any", rule.dst),
        (proto, Some(ports)) => format!("{} {proto}/{ports}", rule.dst),
        (proto, None) => format!("{} {proto}", rule.dst),
    }
}

enum Command {
    Login {
        ip: IpAddr,
        username: String,
        expires_at: SystemTime,
        reply: oneshot::Sender<Result<String, SessionError>>,
    },
    Status {
        token: String,
        ip: IpAddr,
        reply: oneshot::Sender<Option<SessionInfo>>,
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
    ) -> Result<String, SessionError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Login {
                ip,
                username,
                expires_at,
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
}

/// Runs `table` in a task until every [`SessionHandle`] is dropped.
pub(crate) fn spawn<E: Enforcer>(
    table: SessionTable<E>,
) -> (SessionHandle, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    (SessionHandle { tx }, tokio::spawn(run(table, rx)))
}

async fn run<E: Enforcer>(mut table: SessionTable<E>, mut rx: mpsc::Receiver<Command>) {
    loop {
        // An hour stands in for "nothing scheduled"; the loop just re-evaluates.
        let wait = table
            .next_wakeup(SystemTime::now())
            .unwrap_or(Duration::from_secs(3600));
        tokio::select! {
            cmd = rx.recv() => match cmd {
                // Netlink calls block briefly (up to the ack timeout); keep them off the
                // runtime's other worker threads.
                Some(Command::Login { ip, username, expires_at, reply }) => {
                    let result = tokio::task::block_in_place(|| {
                        table.login(ip, &username, expires_at, SystemTime::now())
                    });
                    let _ = reply.send(result);
                }
                Some(Command::Status { token, ip, reply }) => {
                    let _ = reply.send(table.status(&token, ip, SystemTime::now()));
                }
                None => break,
            },
            () = tokio::time::sleep(wait) => tokio::task::block_in_place(|| {
                table.expire(SystemTime::now());
                table.retry();
            }),
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
        fn update(
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
                return Err(crate::firewall::NetlinkError::Timeout.into());
            }
            Ok(())
        }

        fn rebuild(&mut self, live: &[SessionRules]) -> Result<(), FirewallError> {
            let ids: Vec<_> = live.iter().map(|r| r.id).collect();
            self.calls.push(format!("rebuild ={ids:?}"));
            if self.fail_rebuild {
                return Err(crate::firewall::NetlinkError::Timeout.into());
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

    #[test]
    fn login_provisions_and_reports_status() {
        let mut t = table();
        let token = t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        assert_eq!(t.enforcer.calls, ["update +[1] -[] =[1]"]);
        let info = t.status(&token, ip(IP), at(150)).unwrap();
        assert_eq!(info.username, "alice");
        assert_eq!(info.expires_at, 200);
        assert_eq!(info.access, ["10.0.1.0/24 tcp/22", "10.0.1.0/24 tcp/443"]);
    }

    #[test]
    fn status_requires_matching_token_ip_and_time() {
        let mut t = table();
        let token = t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        assert!(t.status("wrong", ip(IP), at(150)).is_none());
        assert!(t.status(&token, ip("192.168.60.8"), at(150)).is_none());
        assert!(t.status(&token, ip(IP), at(200)).is_none());
    }

    #[test]
    fn relogin_extends_without_touching_the_firewall() {
        let mut t = table();
        let token = t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        let again = t.login(ip(IP), "alice", at(300), at(180)).unwrap();
        assert_eq!(token, again);
        assert_eq!(t.enforcer.calls.len(), 1);
        assert_eq!(t.status(&token, ip(IP), at(250)).unwrap().expires_at, 300);
    }

    #[test]
    fn other_user_replaces_session_atomically() {
        let mut t = table();
        let mut policy = (*t.policy).clone();
        policy.users.push(crate::policy::User {
            username: "bob".into(),
            allow: policy.users[0].allow.clone(),
        });
        t.policy = Arc::new(policy);
        let alice = t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        let bob = t.login(ip(IP), "bob", at(200), at(110)).unwrap();
        assert_ne!(alice, bob);
        assert_eq!(t.enforcer.calls[1], "update +[2] -[1] =[2]");
        assert!(t.status(&alice, ip(IP), at(120)).is_none());
    }

    #[test]
    fn unknown_user_and_expired_login_are_refused() {
        let mut t = table();
        assert!(matches!(
            t.login(ip(IP), "mallory", at(200), at(100)),
            Err(SessionError::NoPolicy(_))
        ));
        assert!(matches!(
            t.login(ip(IP), "alice", at(100), at(100)),
            Err(SessionError::Expired)
        ));
        assert!(t.enforcer.calls.is_empty());
    }

    #[test]
    fn expires_in_deadline_order() {
        let mut t = table();
        t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        t.login(ip("fd00:60::7"), "alice", at(300), at(100))
            .unwrap();
        assert_eq!(t.next_wakeup(at(150)), Some(Duration::from_secs(50)));
        t.expire(at(250));
        assert_eq!(t.enforcer.calls.last().unwrap(), "update +[] -[1] =[2]");
        assert_eq!(t.next_wakeup(at(250)), Some(Duration::from_secs(50)));
        t.expire(at(300));
        assert_eq!(t.enforcer.calls.last().unwrap(), "update +[] -[2] =[]");
        assert_eq!(t.next_wakeup(at(300)), None);
    }

    #[test]
    fn failed_update_falls_back_to_rebuild() {
        let mut t = table();
        t.enforcer.fail_update = true;
        t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        assert_eq!(t.enforcer.calls, ["update +[1] -[] =[1]", "rebuild =[1]"]);
    }

    #[test]
    fn failed_rebuild_rolls_back_and_retries() {
        let mut t = table();
        t.enforcer.fail_update = true;
        t.enforcer.fail_rebuild = true;
        assert!(matches!(
            t.login(ip(IP), "alice", at(200), at(100)),
            Err(SessionError::Firewall(_))
        ));
        assert_eq!(t.next_wakeup(at(100)), Some(RETRY_INTERVAL));
        assert!(!t.retry());
        t.enforcer.fail_rebuild = false;
        assert!(t.retry());
        // The rebuild restores the state before the failed login: no sessions.
        assert_eq!(t.enforcer.calls.last().unwrap(), "rebuild =[]");
        assert_eq!(t.next_wakeup(at(100)), None);
    }

    #[test]
    fn dirty_table_skips_incremental_updates() {
        let mut t = table();
        t.dirty = true;
        t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        assert_eq!(t.enforcer.calls, ["rebuild =[1]"]);
        assert!(!t.dirty);
    }

    #[test]
    fn max_ttl_caps_logins_and_extensions() {
        let mut t = table();
        t.max_ttl = Duration::from_secs(60);
        let token = t.login(ip(IP), "alice", at(1000), at(100)).unwrap();
        assert_eq!(t.status(&token, ip(IP), at(110)).unwrap().expires_at, 160);
        t.login(ip(IP), "alice", at(1000), at(150)).unwrap();
        assert_eq!(t.status(&token, ip(IP), at(155)).unwrap().expires_at, 210);
        // A token expiring sooner than the cap still wins.
        t.login(ip(IP), "alice", at(220), at(200)).unwrap();
        assert_eq!(t.status(&token, ip(IP), at(205)).unwrap().expires_at, 220);
    }

    #[test]
    fn ids_skip_zero_and_live_sessions() {
        let mut t = table();
        t.next_id = u32::MAX;
        t.login(ip(IP), "alice", at(200), at(100)).unwrap();
        // The counter wraps, skipping 0.
        assert_eq!(t.allocate_id(), 1);
        // u32::MAX is still held by alice's session, so it is skipped too.
        t.next_id = u32::MAX;
        assert_eq!(t.allocate_id(), 1);
    }

    #[test]
    fn tokens_are_unique_hex() {
        let a = new_token();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, new_token());
    }
}
