//! Allow-list policy file: YAML schema, loading and validation.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use ipnetwork::IpNetwork;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file {}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse policy")]
    Parse(#[from] serde_norway::Error),
    #[error("{section}[{index}].allow[{rule}]: {msg}")]
    Invalid {
        section: Section,
        index: usize,
        rule: usize,
        msg: String,
    },
    #[error("users[{index}]: {msg}")]
    InvalidUser { index: usize, msg: String },
}

/// The top-level policy list an [`PolicyError::Invalid`] entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Clients,
    Users,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Section::Clients => "clients",
            Section::Users => "users",
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub clients: Vec<Client>,
    /// Allow lists for users who authenticate through the portal, applied to their source IP.
    #[serde(default)]
    pub users: Vec<User>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub cidr: IpNetwork,
    #[serde(default)]
    pub allow: Vec<Allow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Matched exactly against the configured OIDC username claim.
    pub username: String,
    #[serde(default)]
    pub allow: Vec<Allow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    pub dest: Vec<IpNetwork>,
    pub proto: Proto,
    /// Empty means any port, or the protocol's default port for `http` and `https`.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// What a host rule (`http` or `https`) allows clients to request at `dest`.
    #[serde(default)]
    pub hosts: Vec<HostPattern>,
}

impl Allow {
    /// The destination ports this entry allows: `ports`, or 80 for `http` and 443 for `https`
    /// when it is empty. Empty means any port.
    pub fn effective_ports(&self) -> Vec<PortSpec> {
        let default = match self.proto {
            Proto::Http => 80,
            Proto::Https => 443,
            _ => return self.ports.clone(),
        };
        if self.ports.is_empty() {
            vec![PortSpec {
                lo: default,
                hi: default,
            }]
        } else {
            self.ports.clone()
        }
    }
}

/// A `hosts` entry of a host rule: a hostname, exact or with a leading `*.` wildcard, and for
/// `http` an optional path prefix (`example.com/some/path`). Stored lowercased, without a
/// trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct HostPattern {
    /// The hostname without the `*.` of a wildcard.
    host: String,
    wildcard: bool,
    /// Starts with `/` when present.
    path: Option<String>,
}

impl HostPattern {
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }

    /// Whether `host` (a TLS SNI or HTTP `Host` header) is allowed. Case-insensitive; a trailing
    /// dot and a `:port` are ignored. A wildcard matches one or more labels, never the apex.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = match host.rsplit_once(':') {
            Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => host,
        };
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if !self.wildcard {
            return host == self.host;
        }
        host.strip_suffix(&self.host)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|prefix| !prefix.is_empty() && !prefix.starts_with('.'))
    }

    /// Whether a request target `path` is allowed: the query is dropped, then the pattern's path
    /// must be a whole-segment prefix (`/a/b` matches `/a/b/c`, not `/a/bc`). No path allows all.
    ///
    /// Anything an upstream might normalise differently from this byte-wise prefix match never
    /// matches: dot segments (plain, percent-encoded or hidden behind `;` parameters), a
    /// backslash, a fragment, and an encoded `/`, `\`, `%`, `?` or `#`.
    pub(crate) fn matches_path(&self, path: &str) -> bool {
        const AMBIGUOUS: [&str; 6] = ["\\", "%2f", "%5c", "%25", "%3f", "%23"];
        let Some(prefix) = &self.path else {
            return true;
        };
        if path.contains('#') {
            return false;
        }
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        let lower = path.to_ascii_lowercase();
        if AMBIGUOUS.iter().any(|a| lower.contains(a)) {
            return false;
        }
        let climbs = lower.split('/').any(|segment| {
            let name = segment.split(';').next().unwrap_or_default();
            let name = name.replace("%2e", ".");
            name == "." || name == ".."
        });
        if climbs {
            return false;
        }
        let prefix = format!("{}/", prefix.trim_end_matches('/'));
        format!("{path}/").starts_with(&prefix)
    }
}

/// Checks a pattern's path: `/`-separated segments of unreserved and sub-delimiter characters
/// (no `;`, `%`, `?`, `#` or `\`), none empty (no `//`), `.` or `..`. A trailing `/` is allowed.
fn validate_pattern_path(s: &str, path: &str) -> Result<(), String> {
    let body = path.strip_prefix('/').unwrap_or(path);
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Ok(());
    }
    for segment in body.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(format!(
                "host {s:?} has an empty, \".\" or \"..\" path segment"
            ));
        }
        if let Some(c) = segment
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || "-._~!$&'()*+,=:@".contains(*c)))
        {
            return Err(format!("host {s:?} has an invalid path character {c:?}"));
        }
    }
    Ok(())
}

impl TryFrom<String> for HostPattern {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::str::FromStr for HostPattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, path) = match s.find('/') {
            Some(i) => (&s[..i], Some(s[i..].to_string())),
            None => (s, None),
        };
        if host.is_empty() {
            return Err(format!("host {s:?} is empty"));
        }
        if let Some(path) = &path {
            validate_pattern_path(s, path)?;
        }
        if host.contains(':') {
            return Err(format!("host {s:?} may not have a port"));
        }
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        let (wildcard, name) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, host.as_str()),
        };
        for label in name.split('.') {
            if label.is_empty() {
                return Err(format!("host {s:?} has an empty label"));
            }
            if label.contains('*') {
                return Err(format!(
                    "host {s:?}: a wildcard is only allowed as a leading \"*.\""
                ));
            }
            if let Some(c) = label
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
            {
                return Err(format!("host {s:?} has an invalid character {c:?}"));
            }
        }
        Ok(HostPattern {
            host: name.to_string(),
            wildcard,
            path,
        })
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.host)?;
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
    /// A host rule matched on the HTTP `Host` header (and optionally the path).
    Http,
    /// A host rule matched on the TLS SNI.
    Https,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Any => "any",
            Proto::Http => "http",
            Proto::Https => "https",
        })
    }
}

/// An inclusive destination port range; a single port has `lo == hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawPort")]
pub struct PortSpec {
    pub lo: u16,
    pub hi: u16,
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawPort {
    // Wider than u16 so out-of-range numbers get a specific message rather than serde's
    // generic "did not match any variant".
    Num(i64),
    Str(String),
}

fn port_from_i64(p: i64) -> Result<u16, String> {
    u16::try_from(p).map_err(|_| format!("port {p} is out of range (1-65535)"))
}

impl TryFrom<RawPort> for PortSpec {
    type Error = String;

    fn try_from(raw: RawPort) -> Result<Self, Self::Error> {
        let (lo, hi) = match raw {
            RawPort::Num(p) => {
                let p = port_from_i64(p)?;
                (p, p)
            }
            RawPort::Str(s) => {
                let parse = |v: &str| {
                    v.trim()
                        .parse::<i64>()
                        .map_err(|_| format!("invalid port {s:?}"))
                        .and_then(port_from_i64)
                };
                match s.split_once('-') {
                    Some((lo, hi)) => (parse(lo)?, parse(hi)?),
                    None => {
                        let p = parse(&s)?;
                        (p, p)
                    }
                }
            }
        };
        if lo == 0 {
            return Err("port 0 is not allowed".into());
        }
        if lo > hi {
            return Err(format!("port range {lo}-{hi} is reversed"));
        }
        Ok(PortSpec { lo, hi })
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parses and validates a policy document.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let policy: Policy = serde_norway::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        for (ci, client) in self.clients.iter().enumerate() {
            for (ri, allow) in client.allow.iter().enumerate() {
                let invalid = |msg| invalid(Section::Clients, ci, ri, msg);
                validate_allow(allow).map_err(invalid)?;
                for dest in &allow.dest {
                    if dest.is_ipv4() != client.cidr.is_ipv4() {
                        return Err(invalid(format!(
                            "dest {dest} is a different address family from client {}",
                            client.cidr
                        )));
                    }
                }
            }
        }
        // A user's address family is only known at login, so their dests may mix families.
        let mut seen = HashSet::new();
        for (ui, user) in self.users.iter().enumerate() {
            let invalid_user = |msg: &str| PolicyError::InvalidUser {
                index: ui,
                msg: msg.into(),
            };
            if user.username.is_empty() {
                return Err(invalid_user("username must not be empty"));
            }
            if !seen.insert(user.username.as_str()) {
                return Err(invalid_user(&format!(
                    "duplicate username {:?}",
                    user.username
                )));
            }
            for (ri, allow) in user.allow.iter().enumerate() {
                validate_allow(allow).map_err(|msg| invalid(Section::Users, ui, ri, msg))?;
            }
        }
        Ok(())
    }

    /// The allow list for `username`, or `None` if the policy doesn't name them.
    pub fn user(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }
}

fn invalid(section: Section, index: usize, rule: usize, msg: String) -> PolicyError {
    PolicyError::Invalid {
        section,
        index,
        rule,
        msg,
    }
}

/// Checks that apply to an allow entry wherever it appears.
fn validate_allow(allow: &Allow) -> Result<(), String> {
    if allow.dest.is_empty() {
        return Err("dest must not be empty".into());
    }
    let host_rule = matches!(allow.proto, Proto::Http | Proto::Https);
    if !allow.ports.is_empty() && !matches!(allow.proto, Proto::Tcp | Proto::Udp) && !host_rule {
        return Err(format!(
            "ports are only valid with tcp, udp, http or https, not {}",
            allow.proto
        ));
    }
    if host_rule && allow.hosts.is_empty() {
        return Err(format!("hosts are required for {}", allow.proto));
    }
    if !host_rule && !allow.hosts.is_empty() {
        return Err(format!(
            "hosts are only valid with http or https, not {}",
            allow.proto
        ));
    }
    for host in &allow.hosts {
        if allow.proto == Proto::Https && host.has_path() {
            return Err(format!("https host {host} may not have a path"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-client, one-rule policy with the given client CIDR and allow-entry fields.
    fn policy(cidr: &str, allow_fields: &str) -> String {
        format!("clients:\n  - cidr: {cidr}\n    allow:\n      - {allow_fields}\n")
    }

    fn tcp_ports(ports: &str) -> String {
        policy(
            "10.0.0.1/32",
            &format!("dest: [10.1.0.0/16]\n        proto: tcp\n        ports: [{ports}]"),
        )
    }

    /// The full error chain, as `main` prints it with `{:#}`.
    fn err(text: &str) -> String {
        let e = Policy::parse(text).unwrap_err();
        let mut msg = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(s) = source {
            msg = format!("{msg}: {s}");
            source = s.source();
        }
        msg
    }

    #[test]
    fn parses_example() {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        assert_eq!(policy.clients.len(), 2);
        let allow = &policy.clients[0].allow[0];
        assert_eq!(allow.proto, Proto::Tcp);
        assert_eq!(
            allow.ports,
            vec![
                PortSpec { lo: 443, hi: 443 },
                PortSpec { lo: 8000, hi: 8100 }
            ]
        );
    }

    #[test]
    fn ports_optional() {
        let p = Policy::parse(&policy(
            "10.0.0.1/32",
            "dest: [10.1.0.0/16]\n        proto: any",
        ))
        .unwrap();
        assert!(p.clients[0].allow[0].ports.is_empty());
    }

    #[test]
    fn accepts_port_boundaries() {
        for (ports, expected) in [
            ("1", PortSpec { lo: 1, hi: 1 }),
            (
                "65535",
                PortSpec {
                    lo: 65535,
                    hi: 65535,
                },
            ),
            ("\"80-80\"", PortSpec { lo: 80, hi: 80 }),
            ("\" 80 - 90 \"", PortSpec { lo: 80, hi: 90 }),
            ("1-65535", PortSpec { lo: 1, hi: 65535 }),
        ] {
            let p = Policy::parse(&tcp_ports(ports)).unwrap();
            assert_eq!(p.clients[0].allow[0].ports, [expected], "{ports}");
        }
    }

    #[test]
    fn rejects_bad_ports() {
        for (ports, expected) in [
            ("0", "port 0 is not allowed"),
            ("\"0-10\"", "port 0 is not allowed"),
            ("9000-8000", "port range 9000-8000 is reversed"),
            ("70000", "port 70000 is out of range"),
            ("\"70000\"", "port 70000 is out of range"),
            ("-1", "port -1 is out of range"),
            ("\"abc\"", "invalid port \"abc\""),
        ] {
            let e = err(&tcp_ports(ports));
            assert!(e.contains(expected), "{ports}: {e}");
        }
    }

    #[test]
    fn error_detail_is_not_repeated() {
        let e = err(&tcp_ports("0"));
        assert_eq!(e.matches("port 0 is not allowed").count(), 1, "{e}");
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(err("clients: []\nextra: 1\n").contains("unknown field"));
    }

    #[test]
    fn rejects_ports_without_tcp_or_udp() {
        for proto in ["icmp", "any"] {
            let e = err(&policy(
                "10.0.0.1/32",
                &format!("dest: [10.1.0.0/16]\n        proto: {proto}\n        ports: [1]"),
            ));
            assert!(
                e.contains("clients[0].allow[0]") && e.contains("only valid with tcp, udp"),
                "{proto}: {e}"
            );
        }
    }

    #[test]
    fn rejects_empty_dest() {
        let e = err(&policy("10.0.0.1/32", "dest: []\n        proto: tcp"));
        assert!(e.contains("dest must not be empty"), "{e}");
    }

    #[test]
    fn rejects_mixed_family() {
        for (cidr, dest) in [
            ("10.0.0.1/32", "\"fd00::/64\""),
            ("\"fd00::1/128\"", "10.1.0.0/16"),
        ] {
            let e = err(&policy(
                cidr,
                &format!("dest: [{dest}]\n        proto: tcp"),
            ));
            assert!(
                e.contains("different address family"),
                "{cidr} -> {dest}: {e}"
            );
        }
    }

    #[test]
    fn parses_example_users() {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        let alice = policy.user("alice").expect("alice in example");
        assert_eq!(alice.allow[0].dest.len(), 2);
        assert!(
            policy.user("Alice").is_none(),
            "usernames are case-sensitive"
        );
    }

    #[test]
    fn user_dests_may_mix_families() {
        Policy::parse(
            "users:\n  - username: a\n    allow:\n      - dest: [10.0.0.0/8, \"fd00::/8\"]\n        proto: any\n",
        )
        .unwrap();
    }

    #[test]
    fn user_errors_name_the_entry() {
        for (text, expected) in [
            (
                "users:\n  - username: a\n  - username: a\n",
                "users[1]: duplicate username \"a\"",
            ),
            (
                "users:\n  - username: \"\"\n",
                "users[0]: username must not be empty",
            ),
            (
                "users:\n  - username: a\n    allow:\n      - dest: []\n        proto: tcp\n",
                "users[0].allow[0]: dest must not be empty",
            ),
            (
                "users:\n  - username: a\n    allow:\n      - dest: [10.0.0.0/8]\n        proto: icmp\n        ports: [1]\n",
                "users[0].allow[0]: ports are only valid",
            ),
            (
                "users:\n  - username: a\n    groups: [x]\n",
                "unknown field",
            ),
        ] {
            let e = err(text);
            assert!(e.contains(expected), "{text}: {e}");
        }
    }

    #[test]
    fn missing_file_names_the_path() {
        let e = Policy::load(Path::new("/nonexistent/policy.yaml")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "failed to read policy file /nonexistent/policy.yaml"
        );
    }

    fn host_rule(proto: &str, extra: &str) -> String {
        policy(
            "10.0.0.1/32",
            &format!("dest: [10.1.0.1/32]\n        proto: {proto}{extra}"),
        )
    }

    #[test]
    fn parses_host_rules() {
        let p = Policy::parse(&host_rule(
            "http",
            "\n        hosts: [Example.COM., \"*.example.org/a/b\"]",
        ))
        .unwrap();
        let allow = &p.clients[0].allow[0];
        assert_eq!(allow.proto, Proto::Http);
        assert_eq!(allow.hosts[0].to_string(), "example.com");
        assert_eq!(allow.hosts[1].to_string(), "*.example.org/a/b");
        let p = Policy::parse(&host_rule("https", "\n        hosts: [example.com]")).unwrap();
        assert_eq!(p.clients[0].allow[0].proto, Proto::Https);
    }

    #[test]
    fn effective_ports_default_by_proto() {
        let ports = |proto: &str, extra: &str| {
            Policy::parse(&host_rule(
                proto,
                &format!("\n        hosts: [a.com]{extra}"),
            ))
            .unwrap()
            .clients[0]
                .allow[0]
                .effective_ports()
        };
        assert_eq!(ports("http", ""), [PortSpec { lo: 80, hi: 80 }]);
        assert_eq!(ports("https", ""), [PortSpec { lo: 443, hi: 443 }]);
        assert_eq!(
            ports("https", "\n        ports: [8443]"),
            [PortSpec { lo: 8443, hi: 8443 }]
        );
        let tcp = Policy::parse(&tcp_ports("22")).unwrap();
        assert_eq!(
            tcp.clients[0].allow[0].effective_ports(),
            [PortSpec { lo: 22, hi: 22 }]
        );
        let any = Policy::parse(&policy(
            "10.0.0.1/32",
            "dest: [10.1.0.0/16]\n        proto: any",
        ))
        .unwrap();
        assert!(any.clients[0].allow[0].effective_ports().is_empty());
    }

    #[test]
    fn host_rule_validation_names_the_entry() {
        for (proto, extra, expected) in [
            (
                "http",
                "",
                "clients[0].allow[0]: hosts are required for http",
            ),
            (
                "https",
                "\n        hosts: []",
                "clients[0].allow[0]: hosts are required for https",
            ),
            (
                "tcp",
                "\n        hosts: [a.com]",
                "clients[0].allow[0]: hosts are only valid with http or https, not tcp",
            ),
            (
                "https",
                "\n        hosts: [a.com/x]",
                "clients[0].allow[0]: https host a.com/x may not have a path",
            ),
        ] {
            let e = err(&host_rule(proto, extra));
            assert!(e.contains(expected), "{proto}{extra}: {e}");
        }
        let e = err(
            "users:\n  - username: a\n    allow:\n      - dest: [10.0.0.0/8]\n        proto: http\n",
        );
        assert!(
            e.contains("users[0].allow[0]: hosts are required for http"),
            "{e}"
        );
    }

    #[test]
    fn rejects_bad_host_patterns() {
        for (host, expected) in [
            ("a.com:80", "may not have a port"),
            ("a..com", "empty label"),
            ("\".a.com\"", "empty label"),
            ("\"\"", "empty"),
            ("\"*\"", "wildcard"),
            ("\"a.*.com\"", "wildcard"),
            ("\"*a.com\"", "wildcard"),
            ("\"*.*.com\"", "wildcard"),
            ("\"a.com?x\"", "invalid character"),
            ("\"a.com/a/../b\"", "path"),
            ("\"a.com/a/./b\"", "path"),
            ("\"a.com/a//b\"", "path"),
            ("\"a.com/a?x\"", "path"),
            ("\"a.com/a#x\"", "path"),
            ("\"a.com/a%2fb\"", "path"),
            ("\"a.com/a\\\\b\"", "path"),
            ("\"a.com/a;x\"", "path"),
        ] {
            let e = err(&host_rule("http", &format!("\n        hosts: [{host}]")));
            assert!(e.contains(expected), "{host}: {e}");
        }
    }

    #[test]
    fn rejects_unknown_field_in_allow() {
        let e = err(&host_rule(
            "http",
            "\n        hosts: [a.com]\n        paths: [/x]",
        ));
        assert!(e.contains("unknown field"), "{e}");
    }

    fn pattern(s: &str) -> HostPattern {
        s.parse().unwrap()
    }

    #[test]
    fn matches_host() {
        let exact = pattern("Example.com.");
        for host in [
            "example.com",
            "EXAMPLE.COM",
            "example.com.",
            "example.com:8080",
            "Example.Com.:443",
        ] {
            assert!(exact.matches_host(host), "{host}");
        }
        for host in ["www.example.com", "example.org", "xexample.com", ""] {
            assert!(!exact.matches_host(host), "{host}");
        }
        let wild = pattern("*.example.com");
        for host in ["a.example.com", "a.b.example.com", "A.Example.COM.:80"] {
            assert!(wild.matches_host(host), "{host}");
        }
        for host in [
            "example.com",
            "aexample.com",
            ".example.com",
            "example.com.evil",
        ] {
            assert!(!wild.matches_host(host), "{host}");
        }
    }

    #[test]
    fn matches_path() {
        let p = pattern("a.com/a/b");
        for path in ["/a/b", "/a/b/", "/a/b/c", "/a/b?x=1", "/a/b/c?y"] {
            assert!(p.matches_path(path), "{path}");
        }
        for path in ["/a/bc", "/a", "/", "/a/bc?/a/b/", "/x/a/b"] {
            assert!(!p.matches_path(path), "{path}");
        }
        // Dot segments (plain or percent-encoded) and backslashes could climb out of the prefix
        // at the upstream, so they never match.
        for path in [
            "/a/b/../c",
            "/a/b/..",
            "/a/b/%2e%2E/c",
            "/a/b/.%2e",
            "/a/b/./c",
            "/a/b/..\\c",
        ] {
            assert!(!p.matches_path(path), "{path}");
        }
        assert!(p.matches_path("/a/b/..x/c"));
        assert!(p.matches_path("/a/b/c;v=1"));
        // Path parameters are not stripped before the prefix match, so this one is conservative.
        assert!(!p.matches_path("/a/b;v=1/c"));
        assert!(p.matches_path("/a/b/c%20d"));
        // Encodings an upstream may decode into a separator, a dot segment or a query/fragment
        // delimiter, and `;` path parameters hiding a dot segment, never match.
        for path in [
            "/a/b/..;/c",
            "/a/b/.;x/c",
            "/a/b/%2e%2e%2fc",
            "/a/b/%2E%2E%2Fc",
            "/a/b/..%5cc",
            "/a/b/%252e%252e/c",
            "/a/b%3f/x",
            "/a/b%23x",
            "/a/b#x",
            "/a/b/c#/../d",
        ] {
            assert!(!p.matches_path(path), "{path}");
        }
        let any = pattern("a.com");
        for path in ["/", "/anything", "/x?y"] {
            assert!(any.matches_path(path), "{path}");
        }
    }
}
