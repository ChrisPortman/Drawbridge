//! Allow-list policy file: YAML schema, loading and validation.

use std::fmt;
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse policy: {0}")]
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
    Num(u16),
    Str(String),
}

impl TryFrom<RawPort> for PortSpec {
    type Error = String;

    fn try_from(raw: RawPort) -> Result<Self, Self::Error> {
        let (lo, hi) = match raw {
            RawPort::Num(p) => (p, p),
            RawPort::Str(s) => {
                let parse = |v: &str| {
                    v.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port {s:?}"))
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
            path: path.display().to_string(),
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

    fn err(text: &str) -> String {
        Policy::parse(text).unwrap_err().to_string()
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
        let p = Policy::parse(
            "clients:\n  - cidr: 10.0.0.1/32\n    allow:\n      - dest: [10.1.0.0/16]\n        proto: any\n",
        )
        .unwrap();
        assert!(p.clients[0].allow[0].ports.is_empty());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(err("clients: []\nextra: 1\n").contains("unknown field"));
    }

    #[test]
    fn rejects_ports_on_icmp() {
        let e = err(
            "clients:\n  - cidr: 10.0.0.1/32\n    allow:\n      - dest: [10.1.0.0/16]\n        proto: icmp\n        ports: [1]\n",
        );
        assert!(
            e.contains("clients[0].allow[0]") && e.contains("only valid with tcp or udp"),
            "{e}"
        );
    }

    #[test]
    fn rejects_empty_dest() {
        let e = err(
            "clients:\n  - cidr: 10.0.0.1/32\n    allow:\n      - dest: []\n        proto: tcp\n",
        );
        assert!(e.contains("dest must not be empty"), "{e}");
    }

    #[test]
    fn rejects_mixed_family() {
        let e = err(
            "clients:\n  - cidr: 10.0.0.1/32\n    allow:\n      - dest: [\"fd00::/64\"]\n        proto: tcp\n",
        );
        assert!(e.contains("different address family"), "{e}");
    }

    #[test]
    fn rejects_bad_ports() {
        for bad in ["0", "9000-8000", "70000", "\"abc\""] {
            let e = err(&format!(
                "clients:\n  - cidr: 10.0.0.1/32\n    allow:\n      - dest: [10.1.0.0/16]\n        proto: tcp\n        ports: [{bad}]\n"
            ));
            assert!(e.contains("parse"), "{bad}: {e}");
        }
    }
}
