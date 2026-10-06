//! Allow-list policy file: YAML schema, loading and validation.

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
    #[error("clients[{client}].allow[{rule}]: {msg}")]
    Invalid {
        client: usize,
        rule: usize,
        msg: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub clients: Vec<Client>,
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
pub struct Allow {
    pub dest: Vec<IpNetwork>,
    pub proto: Proto,
    /// Empty means any port.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Any => "any",
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
                let invalid = |msg: String| PolicyError::Invalid {
                    client: ci,
                    rule: ri,
                    msg,
                };
                if allow.dest.is_empty() {
                    return Err(invalid("dest must not be empty".into()));
                }
                if !allow.ports.is_empty() && !matches!(allow.proto, Proto::Tcp | Proto::Udp) {
                    return Err(invalid(format!(
                        "ports are only valid with tcp or udp, not {}",
                        allow.proto
                    )));
                }
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
        Ok(())
    }
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
                e.contains("clients[0].allow[0]") && e.contains("only valid with tcp or udp"),
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
    fn missing_file_names_the_path() {
        let e = Policy::load(Path::new("/nonexistent/policy.yaml")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "failed to read policy file /nonexistent/policy.yaml"
        );
    }
}
