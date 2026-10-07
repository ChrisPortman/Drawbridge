//! Backend-independent description of the nftables ruleset derived from a [`Policy`].

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnetwork::IpNetwork;

use crate::policy::{Allow, Policy, PolicyError, PortSpec, Proto};

/// Name of the `inet` table owned by the gateway.
pub const TABLE: &str = "drawbridge";
/// Regular chain holding the per-client allow rules, jumped to from the base chains.
pub const FILTER_CHAIN: &str = "client_filter";
/// Filter base chains that send external-interface traffic to [`FILTER_CHAIN`], named after the
/// netfilter hook each one attaches to.
pub(crate) const BASE_CHAINS: [&str; 2] = ["input", "forward"];
/// Regular chain dispatching each authenticated session's source IP to its own chain.
pub const SESSIONS_CHAIN: &str = "sessions";
/// Regular chain that accepts packets of connections whose session is still live. Every connection
/// a session accepts is tagged with `ct mark <session id>`, and `client_filter` sends marked packets
/// here by `goto`, before its `ct state established,related accept`. A packet matching no live
/// session falls off the end and, as `goto` left no return point in `client_filter`, goes back to
/// the base chain's default action.
pub const SESSION_FLOWS_CHAIN: &str = "session_flows";
/// Prefix of the per-session chains; the session id follows.
pub(crate) const SESSION_CHAIN_PREFIX: &str = "session_";
/// Priority of the base chains (`filter`).
pub(crate) const BASE_CHAIN_PRIORITY: i32 = 0;
/// Regular chain, jumped to by each base chain just before its default action, that logs the
/// packet once per [`LOG_WINDOW`] for each key (see [`LogSet`]). TCP and UDP continue by `goto`
/// in [`DROP_LOG_PORTS_CHAIN`], whose keys include the destination port.
pub(crate) const DROP_LOG_CHAIN: &str = "drop_log";
/// Regular chain logging TCP and UDP, reached by `goto` from [`DROP_LOG_CHAIN`].
pub(crate) const DROP_LOG_PORTS_CHAIN: &str = "drop_log_ports";
/// The protocols [`DROP_LOG_CHAIN`] sends to [`DROP_LOG_PORTS_CHAIN`].
pub(crate) const PORT_PROTOS: [Proto; 2] = [Proto::Tcp, Proto::Udp];
/// How long a logged key stays in its set, suppressing further log lines for it.
pub(crate) const LOG_WINDOW: Duration = Duration::from_secs(10);
/// Most keys each log set holds. Once full, new keys go unlogged (but still reach the default
/// action) until old ones expire, which bounds kernel memory under a scan.
pub(crate) const LOG_SET_SIZE: u32 = 65_536;
/// Most log lines per second from each log rule, after a burst of [`LOG_BURST`]. This bounds the
/// load a scan puts on the kernel log; keys it holds back are counted by [`MissRule`] and logged
/// on a later packet.
pub(crate) const LOG_RATE: u32 = 50;
pub(crate) const LOG_BURST: u32 = 100;

/// What happens to traffic from the external interface that nothing in the policy accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Drop it.
    #[default]
    Enforcing,
    /// Accept it, for rolling out onto a gateway already carrying traffic: the log shows what
    /// enforcing would drop.
    Permissive,
}

impl Mode {
    /// Prefix of the kernel log lines for traffic reaching the default action.
    pub(crate) fn log_prefix(self) -> &'static str {
        match self {
            Mode::Enforcing => "drawbridge drop: ",
            Mode::Permissive => "drawbridge would-drop: ",
        }
    }

    /// The base chains' default action, as an nft verdict.
    pub(crate) fn verdict(self) -> &'static str {
        match self {
            Mode::Enforcing => "drop",
            Mode::Permissive => "accept",
        }
    }
}

/// An IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// One field of a log set's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyField {
    SrcAddr,
    DstAddr,
    L4Proto,
    DstPort,
}

/// A set of recently logged keys: source, destination and layer 4 protocol, plus the destination
/// port when `ports` (TCP and UDP only). Each address family needs its own sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogSet {
    pub family: Family,
    pub ports: bool,
}

/// Every log set, in the order their rules appear within each chain: IPv4 first.
pub const LOG_SETS: [LogSet; 4] = [
    LogSet {
        family: Family::V4,
        ports: true,
    },
    LogSet {
        family: Family::V4,
        ports: false,
    },
    LogSet {
        family: Family::V6,
        ports: true,
    },
    LogSet {
        family: Family::V6,
        ports: false,
    },
];

impl LogSet {
    pub(crate) fn name(self) -> &'static str {
        match (self.family, self.ports) {
            (Family::V4, true) => "drop_seen4",
            (Family::V4, false) => "drop_seen4_proto",
            (Family::V6, true) => "drop_seen6",
            (Family::V6, false) => "drop_seen6_proto",
        }
    }

    /// The chain holding this set's log rule.
    pub(crate) fn chain(self) -> &'static str {
        if self.ports {
            DROP_LOG_PORTS_CHAIN
        } else {
            DROP_LOG_CHAIN
        }
    }

    /// The key's fields, in order. Both the nft rendering here and `nfraw`'s encoding follow it.
    pub(crate) fn key(self) -> &'static [KeyField] {
        use KeyField::*;
        if self.ports {
            &[SrcAddr, DstAddr, L4Proto, DstPort]
        } else {
            &[SrcAddr, DstAddr, L4Proto]
        }
    }

    /// The key as an nft concatenation, rendering each field with `render`.
    fn concat(self, render: impl Fn(Family, KeyField) -> &'static str) -> String {
        let fields: Vec<_> = self.key().iter().map(|&f| render(self.family, f)).collect();
        fields.join(" . ")
    }
}

/// The nft expression reading `field`.
fn key_expr(family: Family, field: KeyField) -> &'static str {
    match (family, field) {
        (Family::V4, KeyField::SrcAddr) => "ip saddr",
        (Family::V4, KeyField::DstAddr) => "ip daddr",
        (Family::V6, KeyField::SrcAddr) => "ip6 saddr",
        (Family::V6, KeyField::DstAddr) => "ip6 daddr",
        (_, KeyField::L4Proto) => "meta l4proto",
        (_, KeyField::DstPort) => "th dport",
    }
}

/// The nft data type of `field`.
fn key_type(family: Family, field: KeyField) -> &'static str {
    match (family, field) {
        (Family::V4, KeyField::SrcAddr | KeyField::DstAddr) => "ipv4_addr",
        (Family::V6, KeyField::SrcAddr | KeyField::DstAddr) => "ipv6_addr",
        (_, KeyField::L4Proto) => "inet_proto",
        (_, KeyField::DstPort) => "inet_service",
    }
}

/// The definition of a log set.
pub(crate) struct LogSetDef(pub(crate) LogSet);

impl fmt::Display for LogSetDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "set {} {{ type {}; size {LOG_SET_SIZE}; flags dynamic,timeout; timeout {}s; }}",
            self.0.name(),
            self.0.concat(key_type),
            LOG_WINDOW.as_secs()
        )
    }
}

/// The rule logging a packet whose key isn't in its set yet, within the rate limit, and adding
/// the key.
pub(crate) struct LogRule(pub(crate) LogSet, pub(crate) Mode);

impl fmt::Display for LogRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let LogRule(set, mode) = *self;
        let key = set.concat(key_expr);
        let name = set.name();
        write!(
            f,
            "{key} != @{name} limit rate {LOG_RATE}/second burst {LOG_BURST} packets \
             add @{name} {{ {key} }} counter log prefix \"{}\"",
            mode.log_prefix()
        )
    }
}

/// Follows a [`LogRule`], counting packets it didn't log although their key is new: over the rate
/// limit, or with the set full.
pub(crate) struct MissRule(pub(crate) LogSet);

impl fmt::Display for MissRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} != @{} counter",
            self.0.concat(key_expr),
            self.0.name()
        )
    }
}

/// Name of the chain holding session `id`'s rules.
pub(crate) fn session_chain(id: u32) -> String {
    format!("{SESSION_CHAIN_PREFIX}{id}")
}

/// Mirrors `libc::IFNAMSIZ` (including the trailing NUL) to keep this module kernel-free.
const IFNAMSIZ: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error(
        "invalid external interface name {0:?}: use 1-15 characters from A-Z, a-z, 0-9, '_', '.', '-'"
    )]
    InterfaceName(String),
    #[error("portal listen address {0} must be a specific address, not unspecified")]
    PortalAddr(SocketAddr),
    #[error("invalid policy")]
    Policy(#[from] PolicyError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    pub external_iface: String,
    /// Portal listen addresses. Every client may reach these, so unauthenticated users can log in.
    pub portal: Vec<SocketAddr>,
    /// Static per-client rules from the policy's `clients`.
    pub rules: Vec<RuleSpec>,
    /// Authenticated sessions, each in its own chain. Empty when built from a policy.
    pub sessions: Vec<SessionRules>,
    /// [`Mode::Enforcing`] when built from a policy.
    pub mode: Mode,
}

/// The rules for one authenticated session: traffic from `ip` jumps to its own `session_<id>`
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRules {
    /// Nonzero; also the `ct mark` of the session's connections.
    pub id: u32,
    pub ip: IpAddr,
    pub rules: Vec<RuleSpec>,
}

impl SessionRules {
    /// Expands `username`'s allow list for a session from `ip`, skipping dests of the other
    /// address family. Returns `None` if the policy has no entry for `username`.
    pub fn for_user(policy: &Policy, id: u32, username: &str, ip: IpAddr) -> Option<Self> {
        assert_ne!(id, 0, "session id 0 is the unmarked ct mark");
        let user = policy.user(username)?;
        let src = IpNetwork::from(ip);
        let mut rules = Vec::new();
        for allow in &user.allow {
            let same_family = allow.dest.iter().filter(|d| d.is_ipv4() == ip.is_ipv4());
            expand(&mut rules, src, allow, same_family.copied());
        }
        for rule in &mut rules {
            rule.mark = Some(id);
        }
        Some(SessionRules { id, ip, rules })
    }

    pub(crate) fn chain(&self) -> String {
        session_chain(self.id)
    }
}

/// One accept rule: traffic from `src` to `dst` matching `proto` and optional destination ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    pub src: IpNetwork,
    pub dst: IpNetwork,
    pub proto: Proto,
    pub ports: Option<PortSpec>,
    /// `ct mark` to tag accepted connections with (session rules only).
    pub mark: Option<u32>,
}

impl Ruleset {
    /// Validates the policy, then expands it into one rule per client × allow entry × dest × port
    /// spec, in policy order. `portal` addresses get an accept rule ahead of the client rules.
    pub fn from_policy(
        policy: &Policy,
        external_iface: &str,
        portal: &[SocketAddr],
    ) -> Result<Self, RulesetError> {
        if !is_valid_iface_name(external_iface) {
            return Err(RulesetError::InterfaceName(external_iface.to_string()));
        }
        // An unspecified address would need a rule opening every gateway address to clients.
        if let Some(&addr) = portal.iter().find(|a| a.ip().is_unspecified()) {
            return Err(RulesetError::PortalAddr(addr));
        }
        policy.validate()?;
        let mut rules = Vec::new();
        for client in &policy.clients {
            let src = normalize(client.cidr);
            for allow in &client.allow {
                expand(&mut rules, src, allow, allow.dest.iter().copied());
            }
        }
        Ok(Ruleset {
            external_iface: external_iface.to_string(),
            portal: portal.to_vec(),
            rules,
            sessions: Vec::new(),
            mode: Mode::Enforcing,
        })
    }
}

/// Appends one rule per dest × port spec of `allow`, from `src`.
fn expand(
    rules: &mut Vec<RuleSpec>,
    src: IpNetwork,
    allow: &Allow,
    dests: impl Iterator<Item = IpNetwork>,
) {
    for dest in dests {
        let base = RuleSpec {
            src,
            dst: normalize(dest),
            proto: allow.proto,
            ports: None,
            mark: None,
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

/// A conservative subset of what the kernel accepts (`dev_valid_name`): it rules out whitespace,
/// `/`, `:` and quotes, so the name is also safe to render unescaped.
fn is_valid_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < IFNAMSIZ
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Clears host bits so `192.168.1.5/24` becomes `192.168.1.0/24`.
fn normalize(net: IpNetwork) -> IpNetwork {
    IpNetwork::new(net.network(), net.prefix()).expect("prefix taken from a valid network")
}

impl fmt::Display for RuleSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = family(self.src.ip());
        write!(f, "{family} saddr {} {family} daddr {}", self.src, self.dst)?;
        match (self.proto, self.ports) {
            (Proto::Tcp | Proto::Udp, Some(ports)) => write!(f, " {} dport {ports}", self.proto)?,
            (Proto::Tcp | Proto::Udp, None) => write!(f, " meta l4proto {}", self.proto)?,
            (Proto::Icmp, _) if self.src.is_ipv4() => write!(f, " meta l4proto icmp")?,
            (Proto::Icmp, _) => write!(f, " meta l4proto ipv6-icmp")?,
            (Proto::Any, _) => {}
        }
        if let Some(mark) = self.mark {
            write!(f, " ct mark set {mark:#010x}")?;
        }
        write!(f, " counter accept")
    }
}

/// `ip`/`ip6`, the nft payload keyword for an address's family.
fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "ip" } else { "ip6" }
}

/// The portal accept rule for one listen address.
pub(crate) struct PortalRule(pub(crate) SocketAddr);

impl fmt::Display for PortalRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = self.0.ip();
        let port = self.0.port();
        write!(
            f,
            "{} daddr {ip} tcp dport {port} counter accept",
            family(ip)
        )
    }
}

/// The `sessions` chain rule sending a session's traffic to its chain.
pub(crate) struct DispatchRule<'a>(pub(crate) &'a SessionRules);

impl fmt::Display for DispatchRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        write!(f, "{} saddr {} jump {}", family(s.ip), s.ip, s.chain())
    }
}

/// The `session_flows` rule accepting a live session's connections.
pub(crate) struct FlowRule<'a>(pub(crate) &'a SessionRules);

impl fmt::Display for FlowRule<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        write!(
            f,
            "{} saddr {} ct mark {:#010x} accept",
            family(s.ip),
            s.ip,
            s.id
        )
    }
}

/// Renders the ruleset in `nft list` syntax, for `check` output and logging.
impl fmt::Display for Ruleset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iface = &self.external_iface;
        writeln!(f, "table inet {TABLE} {{")?;
        for set in LOG_SETS {
            writeln!(f, "\t{}", LogSetDef(set))?;
        }
        for hook in BASE_CHAINS {
            writeln!(f, "\tchain {hook} {{")?;
            writeln!(
                f,
                "\t\ttype filter hook {hook} priority {BASE_CHAIN_PRIORITY}; policy accept;"
            )?;
            writeln!(f, "\t\tiifname \"{iface}\" jump {FILTER_CHAIN}")?;
            writeln!(f, "\t\tiifname \"{iface}\" jump {DROP_LOG_CHAIN}")?;
            writeln!(f, "\t\tiifname \"{iface}\" counter {}", self.mode.verdict())?;
            writeln!(f, "\t}}")?;
        }
        writeln!(f, "\tchain {FILTER_CHAIN} {{")?;
        writeln!(f, "\t\tct mark != 0x00000000 goto {SESSION_FLOWS_CHAIN}")?;
        writeln!(f, "\t\tct state established,related accept")?;
        for &addr in &self.portal {
            writeln!(f, "\t\t{}", PortalRule(addr))?;
        }
        for rule in &self.rules {
            writeln!(f, "\t\t{rule}")?;
        }
        writeln!(f, "\t\tjump {SESSIONS_CHAIN}")?;
        writeln!(f, "\t}}")?;
        writeln!(f, "\tchain {SESSION_FLOWS_CHAIN} {{")?;
        for session in &self.sessions {
            writeln!(f, "\t\t{}", FlowRule(session))?;
        }
        writeln!(f, "\t}}")?;
        writeln!(f, "\tchain {SESSIONS_CHAIN} {{")?;
        for session in &self.sessions {
            writeln!(f, "\t\t{}", DispatchRule(session))?;
        }
        writeln!(f, "\t}}")?;
        for session in &self.sessions {
            writeln!(f, "\tchain {} {{", session.chain())?;
            for rule in &session.rules {
                writeln!(f, "\t\t{rule}")?;
            }
            writeln!(f, "\t}}")?;
        }
        for chain in [DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN] {
            writeln!(f, "\tchain {chain} {{")?;
            if chain == DROP_LOG_CHAIN {
                for proto in PORT_PROTOS {
                    writeln!(f, "\t\tmeta l4proto {proto} goto {DROP_LOG_PORTS_CHAIN}")?;
                }
            }
            for set in LOG_SETS.into_iter().filter(|s| s.chain() == chain) {
                writeln!(f, "\t\t{}", LogRule(set, self.mode))?;
                writeln!(f, "\t\t{}", MissRule(set))?;
            }
            writeln!(f, "\t}}")?;
        }
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_policy() -> Policy {
        Policy::parse(include_str!("../../examples/policy.yaml")).unwrap()
    }

    const PORTAL: &str = "192.168.50.1:8443";

    fn example() -> Ruleset {
        Ruleset::from_policy(&example_policy(), "wg0", &[PORTAL.parse().unwrap()]).unwrap()
    }

    fn rule_strings(rules: &[RuleSpec]) -> Vec<String> {
        rules.iter().map(ToString::to_string).collect()
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
        let rs = Ruleset::from_policy(&policy, "wg0", &[]).unwrap();
        assert_eq!(
            rs.rules[0].to_string(),
            "ip saddr 10.0.0.0/24 ip daddr 10.1.0.0/16 counter accept"
        );
    }

    #[test]
    fn accepts_interface_names_up_to_15_bytes() {
        let policy = Policy::default();
        for name in ["wg0", "eth0.100", "br-lan_1", "a23456789012345"] {
            assert!(Ruleset::from_policy(&policy, name, &[]).is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_bad_interface_names() {
        let policy = Policy::default();
        for name in [
            "",
            "a234567890123456", // 16 bytes: no room for the NUL
            ".",
            "..",
            "wg 0",
            "wg0 ",
            "wg/0",
            "wg:0",
            "wg\"0",
        ] {
            assert!(
                matches!(
                    Ruleset::from_policy(&policy, name, &[]),
                    Err(RulesetError::InterfaceName(_))
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn validates_policy() {
        let policy = Policy {
            users: vec![],
            clients: vec![crate::policy::Client {
                cidr: "10.0.0.1/32".parse().unwrap(),
                allow: vec![crate::policy::Allow {
                    dest: vec![],
                    proto: Proto::Tcp,
                    ports: vec![],
                }],
            }],
        };
        assert!(matches!(
            Ruleset::from_policy(&policy, "wg0", &[]),
            Err(RulesetError::Policy(_))
        ));
    }

    #[test]
    fn renders_remaining_protocol_branches() {
        let policy = Policy::parse(
            "clients:
  - cidr: 10.0.0.1/32
    allow:
      - dest: [10.1.0.0/16]
        proto: udp
      - dest: [10.1.0.0/16]
        proto: icmp
  - cidr: fd00::1/128
    allow:
      - dest: [\"fd01::/64\"]
        proto: tcp
        ports: [22]
",
        )
        .unwrap();
        let rules: Vec<String> = Ruleset::from_policy(&policy, "wg0", &[])
            .unwrap()
            .rules
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            rules,
            [
                "ip saddr 10.0.0.1/32 ip daddr 10.1.0.0/16 meta l4proto udp counter accept",
                "ip saddr 10.0.0.1/32 ip daddr 10.1.0.0/16 meta l4proto icmp counter accept",
                "ip6 saddr fd00::1/128 ip6 daddr fd01::/64 tcp dport 22 counter accept",
            ]
        );
    }

    #[test]
    fn rejects_unspecified_portal_addr() {
        for addr in ["0.0.0.0:443", "[::]:443"] {
            assert!(
                matches!(
                    Ruleset::from_policy(&Policy::default(), "wg0", &[addr.parse().unwrap()]),
                    Err(RulesetError::PortalAddr(_))
                ),
                "{addr}"
            );
        }
    }

    #[test]
    fn renders_ipv6_portal_rule() {
        assert_eq!(
            PortalRule("[fd00::1]:443".parse().unwrap()).to_string(),
            "ip6 daddr fd00::1 tcp dport 443 counter accept"
        );
    }

    #[test]
    fn session_rules_follow_the_login_family() {
        let policy = example_policy();
        let v4 =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        assert_eq!(
            rule_strings(&v4.rules),
            [
                "ip saddr 192.168.60.7/32 ip daddr 10.0.1.0/24 tcp dport 22 ct mark set 0x00000001 counter accept",
                "ip saddr 192.168.60.7/32 ip daddr 10.0.1.0/24 tcp dport 443 ct mark set 0x00000001 counter accept",
            ]
        );
        let v6 =
            SessionRules::for_user(&policy, 2, "alice", "fd00:60::7".parse().unwrap()).unwrap();
        assert_eq!(
            rule_strings(&v6.rules),
            [
                "ip6 saddr fd00:60::7/128 ip6 daddr fd00:1::/64 tcp dport 22 ct mark set 0x00000002 counter accept",
                "ip6 saddr fd00:60::7/128 ip6 daddr fd00:1::/64 tcp dport 443 ct mark set 0x00000002 counter accept",
            ]
        );
        assert_eq!(v6.chain(), "session_2");
    }

    #[test]
    fn unknown_user_has_no_session_rules() {
        let ip = "192.168.60.7".parse().unwrap();
        assert!(SessionRules::for_user(&example_policy(), 1, "mallory", ip).is_none());
    }

    #[test]
    fn renders_sessions() {
        let policy = example_policy();
        let mut rs = Ruleset::from_policy(&Policy::default(), "wg0", &[]).unwrap();
        rs.sessions = vec![
            SessionRules::for_user(&policy, 3, "alice", "192.168.60.7".parse().unwrap()).unwrap(),
            SessionRules::for_user(&policy, 4, "alice", "fd00:60::7".parse().unwrap()).unwrap(),
        ];
        let text = rs.to_string();
        let start = text.find("\tchain session_flows").unwrap();
        let end = text.find("\tchain drop_log ").unwrap();
        assert_eq!(
            &text[start..end],
            "\tchain session_flows {
\t\tip saddr 192.168.60.7 ct mark 0x00000003 accept
\t\tip6 saddr fd00:60::7 ct mark 0x00000004 accept
\t}
\tchain sessions {
\t\tip saddr 192.168.60.7 jump session_3
\t\tip6 saddr fd00:60::7 jump session_4
\t}
\tchain session_3 {
\t\tip saddr 192.168.60.7/32 ip daddr 10.0.1.0/24 tcp dport 22 ct mark set 0x00000003 counter accept
\t\tip saddr 192.168.60.7/32 ip daddr 10.0.1.0/24 tcp dport 443 ct mark set 0x00000003 counter accept
\t}
\tchain session_4 {
\t\tip6 saddr fd00:60::7/128 ip6 daddr fd00:1::/64 tcp dport 22 ct mark set 0x00000004 counter accept
\t\tip6 saddr fd00:60::7/128 ip6 daddr fd00:1::/64 tcp dport 443 ct mark set 0x00000004 counter accept
\t}
"
        );
    }

    #[test]
    fn permissive_accepts_and_logs_would_drop() {
        let enforcing = example().to_string();
        let mut rs = example();
        rs.mode = Mode::Permissive;
        let (drop, accept) = ("\"wg0\" counter drop", "\"wg0\" counter accept");
        let (logged, would) = ("\"drawbridge drop: \"", "\"drawbridge would-drop: \"");
        // One default action per base chain, one log rule per set.
        assert_eq!(enforcing.matches(drop).count(), BASE_CHAINS.len());
        assert_eq!(enforcing.matches(logged).count(), LOG_SETS.len());
        let expected = enforcing.replace(drop, accept).replace(logged, would);
        assert_eq!(rs.to_string(), expected);
    }

    #[test]
    fn log_set_keys_follow_family_and_ports() {
        let rendered: Vec<String> = LOG_SETS.map(|s| LogSetDef(s).to_string()).into();
        assert_eq!(
            rendered,
            [
                "set drop_seen4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service; size 65536; flags dynamic,timeout; timeout 10s; }",
                "set drop_seen4_proto { type ipv4_addr . ipv4_addr . inet_proto; size 65536; flags dynamic,timeout; timeout 10s; }",
                "set drop_seen6 { type ipv6_addr . ipv6_addr . inet_proto . inet_service; size 65536; flags dynamic,timeout; timeout 10s; }",
                "set drop_seen6_proto { type ipv6_addr . ipv6_addr . inet_proto; size 65536; flags dynamic,timeout; timeout 10s; }",
            ]
        );
        assert!(
            LOG_SETS
                .iter()
                .all(|s| (s.chain() == DROP_LOG_PORTS_CHAIN) == s.ports)
        );
    }

    #[test]
    fn renders_example() {
        assert_eq!(
            example().to_string(),
            include_str!("../../tests/data/example.nft")
        );
    }
}
