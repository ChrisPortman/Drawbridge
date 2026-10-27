//! Deduplicated `drawbridge drop:` lines for what the proxy denies, in nft-log style.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::firewall::ruleset::Mode;

/// How long a logged key stays quiet, matching the firewall's drop log.
pub(crate) const WINDOW: Duration = Duration::from_secs(10);

/// How many keys the log remembers, as the firewall's drop-log sets do. Once full, new keys go
/// unlogged until the window frees some, so a client can't grow the map without bound.
const MAX_KEYS: usize = 65_536;

/// One denied (or, in permissive mode, would-be denied) request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Drop {
    pub(crate) src: IpAddr,
    pub(crate) dst: SocketAddr,
    /// `http` or `https`.
    pub(crate) proto: &'static str,
    pub(crate) host: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) reason: Option<&'static str>,
}

impl fmt::Display for Drop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SRC={} DST={} PROTO={} DPT={} HOST={}",
            self.src,
            self.dst.ip(),
            self.proto,
            self.dst.port(),
            Escaped(self.host.as_deref().unwrap_or("-"))
        )?;
        if let Some(path) = &self.path {
            write!(f, " PATH={}", Escaped(path))?;
        }
        if let Some(reason) = self.reason {
            write!(f, " REASON={reason}")?;
        }
        Ok(())
    }
}

/// A client-supplied field (Host header, SNI, path), with every byte outside printable ASCII,
/// and space and backslash, written as `\xNN`, so it can't forge fields or lines.
struct Escaped<'a>(&'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in self.0.as_bytes() {
            if b.is_ascii_graphic() && b != b'\\' {
                write!(f, "{}", char::from(b))?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

/// Logs each distinct [`Drop`] at most once per [`WINDOW`].
#[derive(Debug)]
pub(crate) struct DropLog {
    mode: Mode,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    seen: HashMap<Drop, Instant>,
    last_sweep: Instant,
}

impl DropLog {
    pub(crate) fn new(mode: Mode) -> Self {
        DropLog {
            mode,
            state: Mutex::new(State {
                seen: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Logs `drop` at info unless it was logged within the window.
    pub(crate) fn record(&self, drop: Drop) {
        if let Some(line) = self.record_at(drop, Instant::now()) {
            tracing::info!("{line}");
        }
    }

    /// The line to log for `drop` at `now`, or `None` while its key is within the window.
    /// Sweeps expired keys at most once per window.
    fn record_at(&self, drop: Drop, now: Instant) -> Option<String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if now.saturating_duration_since(state.last_sweep) >= WINDOW {
            state
                .seen
                .retain(|_, at| now.saturating_duration_since(*at) < WINDOW);
            state.last_sweep = now;
        }
        if let Some(at) = state.seen.get(&drop)
            && now.saturating_duration_since(*at) < WINDOW
        {
            return None;
        }
        if state.seen.len() >= MAX_KEYS {
            state
                .seen
                .retain(|_, at| now.saturating_duration_since(*at) < WINDOW);
            if state.seen.len() >= MAX_KEYS {
                tracing::debug!("proxy drop log full; not logging {drop}");
                return None;
            }
        }
        let prefix = match self.mode {
            Mode::Enforcing => "drawbridge drop: ",
            Mode::Permissive => "drawbridge would-drop: ",
        };
        let line = format!("{prefix}{drop}");
        state.seen.insert(drop, now);
        Some(line)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drop(host: Option<&str>) -> Drop {
        Drop {
            src: "10.0.0.5".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
            proto: "https",
            host: host.map(str::to_string),
            path: None,
            reason: None,
        }
    }

    #[test]
    fn line_format() {
        let log = DropLog::new(Mode::Enforcing);
        let now = Instant::now();
        assert_eq!(
            log.record_at(drop(Some("example.com")), now).unwrap(),
            "drawbridge drop: SRC=10.0.0.5 DST=192.0.2.1 PROTO=https DPT=443 HOST=example.com"
        );
        let mut d = drop(None);
        d.proto = "http";
        d.path = Some("/admin".into());
        d.reason = Some("no-sni");
        assert_eq!(
            log.record_at(d, now).unwrap(),
            "drawbridge drop: SRC=10.0.0.5 DST=192.0.2.1 PROTO=http DPT=443 HOST=- PATH=/admin REASON=no-sni"
        );
    }

    #[test]
    fn untrusted_fields_are_escaped() {
        // A Host header or SNI could otherwise forge fields or whole lines.
        let log = DropLog::new(Mode::Enforcing);
        let mut d = drop(Some("a.test PATH=/x\nforged é"));
        d.path = Some("/p\\q".into());
        assert_eq!(
            log.record_at(d, Instant::now()).unwrap(),
            "drawbridge drop: SRC=10.0.0.5 DST=192.0.2.1 PROTO=https DPT=443 HOST=a.test\\x20PATH=/x\\x0aforged\\x20\\xc3\\xa9 PATH=/p\\x5cq"
        );
    }

    #[test]
    fn stops_logging_new_keys_once_full() {
        let log = DropLog::new(Mode::Enforcing);
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert!(
                log.record_at(drop(Some(&format!("{i}.test"))), t0)
                    .is_some()
            );
        }
        assert!(log.record_at(drop(Some("full.test")), t0).is_none());
        assert_eq!(log.len(), MAX_KEYS);
        // Expired keys make room again.
        assert!(
            log.record_at(drop(Some("full.test")), t0 + WINDOW)
                .is_some()
        );
    }

    #[test]
    fn permissive_prefix() {
        let log = DropLog::new(Mode::Permissive);
        let line = log.record_at(drop(None), Instant::now()).unwrap();
        assert!(line.starts_with("drawbridge would-drop: SRC="), "{line}");
    }

    #[test]
    fn deduplicates_per_key_within_the_window() {
        let log = DropLog::new(Mode::Enforcing);
        let t0 = Instant::now();
        assert!(log.record_at(drop(Some("a.test")), t0).is_some());
        assert!(
            log.record_at(drop(Some("a.test")), t0 + Duration::from_secs(9))
                .is_none()
        );
        assert!(
            log.record_at(drop(Some("b.test")), t0 + Duration::from_secs(9))
                .is_some()
        );
        assert!(log.record_at(drop(Some("a.test")), t0 + WINDOW).is_some());
    }

    #[test]
    fn sweeps_expired_keys() {
        let log = DropLog::new(Mode::Enforcing);
        let t0 = Instant::now();
        log.record_at(drop(Some("a.test")), t0);
        log.record_at(drop(Some("b.test")), t0);
        assert_eq!(log.len(), 2);
        log.record_at(drop(Some("c.test")), t0 + WINDOW * 2);
        assert_eq!(log.len(), 1);
    }
}
