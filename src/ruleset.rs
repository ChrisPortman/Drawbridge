//! Backend-independent description of the nftables ruleset derived from a [`Policy`].

use std::fmt;

use ipnetwork::IpNetwork;

use crate::policy::{Policy, PortSpec, Proto};

/// Name of the `inet` table owned by the gateway.
pub const TABLE: &str = "drawbridge";
/// Regular chain holding the per-client allow rules, jumped to from the base chains.
pub const FILTER_CHAIN: &str = "client_filter";

/// Linux `IFNAMSIZ` including the trailing NUL.
const IFNAMSIZ: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error("invalid external interface name {0:?}")]
    InterfaceName(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    pub external_iface: String,
    pub rules: Vec<RuleSpec>,
}

/// One accept rule: traffic from `src` to `dst` matching `proto` and optional destination ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    pub src: IpNetwork,
    pub dst: IpNetwork,
    pub proto: Proto,
    pub ports: Option<PortSpec>,
}

impl Ruleset {
    /// Expands the policy into one rule per client × allow entry × dest × port spec, in policy order.
    pub fn from_policy(policy: &Policy, external_iface: &str) -> Result<Self, RulesetError> {
        if external_iface.is_empty() || external_iface.len() >= IFNAMSIZ {
            return Err(RulesetError::InterfaceName(external_iface.to_string()));
        }
        let mut rules = Vec::new();
        for client in &policy.clients {
            let src = normalize(client.cidr);
            for allow in &client.allow {
                for &dest in &allow.dest {
                    let dst = normalize(dest);
                    let base = RuleSpec {
                        src,
                        dst,
                        proto: allow.proto,
                        ports: None,
                    };
                    if allow.ports.is_empty() {
                        rules.push(base);
                    } else {
                        rules.extend(allow.ports.iter().map(|&p| RuleSpec {
                            ports: Some(p),
                            ..base
                        }));
                    }
                }
            }
        }
        Ok(Ruleset {
            external_iface: external_iface.to_string(),
            rules,
        })
    }
}

/// Clears host bits so `192.168.1.5/24` becomes `192.168.1.0/24`.
fn normalize(net: IpNetwork) -> IpNetwork {
    IpNetwork::new(net.network(), net.prefix()).expect("prefix taken from a valid network")
}

impl fmt::Display for RuleSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = if self.src.is_ipv4() { "ip" } else { "ip6" };
        write!(f, "{family} saddr {} {family} daddr {}", self.src, self.dst)?;
        match (self.proto, self.ports) {
            (Proto::Tcp | Proto::Udp, Some(ports)) => write!(f, " {} dport {ports}", self.proto)?,
            (Proto::Tcp | Proto::Udp, None) => write!(f, " meta l4proto {}", self.proto)?,
            (Proto::Icmp, _) if self.src.is_ipv4() => write!(f, " meta l4proto icmp")?,
            (Proto::Icmp, _) => write!(f, " meta l4proto ipv6-icmp")?,
            (Proto::Any, _) => {}
        }
        write!(f, " counter accept")
    }
}

/// Renders the ruleset in `nft list` syntax, for `check` output and logging.
impl fmt::Display for Ruleset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "table inet {TABLE} {{")?;
        for hook in ["input", "forward"] {
            writeln!(f, "\tchain {hook} {{")?;
            writeln!(f, "\t\ttype filter hook {hook} priority 0; policy accept;")?;
            writeln!(
                f,
                "\t\tiifname \"{}\" jump {FILTER_CHAIN}",
                self.external_iface
            )?;
            writeln!(f, "\t}}")?;
        }
        writeln!(f, "\tchain {FILTER_CHAIN} {{")?;
        writeln!(f, "\t\tct state established,related accept")?;
        for rule in &self.rules {
            writeln!(f, "\t\t{rule}")?;
        }
        writeln!(f, "\t\tcounter drop")?;
        writeln!(f, "\t}}")?;
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Ruleset {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        Ruleset::from_policy(&policy, "wg0").unwrap()
    }

    #[test]
    fn expands_in_policy_order() {
        let rules: Vec<String> = example().rules.iter().map(ToString::to_string).collect();
        assert_eq!(
            rules,
            [
                "ip saddr 192.168.50.0/24 ip daddr 10.0.1.0/24 tcp dport 443 counter accept",
                "ip saddr 192.168.50.0/24 ip daddr 10.0.1.0/24 tcp dport 8000-8100 counter accept",
                "ip saddr 192.168.50.0/24 ip daddr 10.0.0.53/32 udp dport 53 counter accept",
                "ip6 saddr fd00:50::/64 ip6 daddr fd00:1::/64 meta l4proto ipv6-icmp counter accept",
            ]
        );
    }

    #[test]
    fn normalizes_host_bits() {
        let policy = Policy::parse(
            "clients:\n  - cidr: 10.0.0.7/24\n    allow:\n      - dest: [10.1.2.3/16]\n        proto: any\n",
        )
        .unwrap();
        let rs = Ruleset::from_policy(&policy, "wg0").unwrap();
        assert_eq!(
            rs.rules[0].to_string(),
            "ip saddr 10.0.0.0/24 ip daddr 10.1.0.0/16 counter accept"
        );
    }

    #[test]
    fn rejects_bad_interface_names() {
        let policy = Policy { clients: vec![] };
        assert!(Ruleset::from_policy(&policy, "").is_err());
        assert!(Ruleset::from_policy(&policy, "a-very-long-ifname").is_err());
    }

    #[test]
    fn renders_example() {
        assert_eq!(
            example().to_string(),
            include_str!("../tests/data/example.nft")
        );
    }
}
