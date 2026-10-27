//! Pure conversion of a [`Ruleset`] and its [`SessionRules`] into `nft -j` documents, built from
//! the `nftables` crate's serde types: the apply, session update and teardown batches.
//!
//! Each document is one `nft -j -f` transaction. A kernel loaded from [`apply`] lists the same
//! ruleset as `tests/data/example.kernel.nft`.

// The nft runner that sends these documents lands separately (issue #21).
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use nftables::expr::{
    CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, Range,
};
use nftables::schema::{
    Chain, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetFlag, SetType,
    SetTypeValue, Table,
};
use nftables::stmt::{self, AnonymousCounter, JumpTarget, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use super::ruleset::{
    BASE_CHAIN_PRIORITY, BASE_CHAINS, DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN, FILTER_CHAIN, Family,
    KeyField, LOG_BURST, LOG_RATE, LOG_SET_SIZE, LOG_SETS, LOG_WINDOW, LogSet, Mode, PORT_PROTOS,
    RuleSpec, Ruleset, SESSION_FLOWS_CHAIN, SESSIONS_CHAIN, SessionRules, TABLE, session_chain,
};
use crate::policy::Proto;

/// IANA protocol numbers, as `meta l4proto` compares them.
const IPPROTO_ICMP: u32 = 1;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_ICMPV6: u32 = 58;

/// The batch atomically replacing the gateway table with one implementing `ruleset`. Adding then
/// deleting the table first clears any copy left behind by a previous run.
pub(crate) fn apply(ruleset: &Ruleset) -> Nftables<'static> {
    let mut cmds = apply_cmds(ruleset);
    cmds.extend(drop_log(ruleset.mode));
    document(cmds)
}

/// [`apply`] without the drop log's sets and the rules in its chains (the chains, and the base
/// chains' jumps to them, stay). If the kernel rejects [`apply`] but `nft -c` accepts this, the
/// drop log is to blame.
pub(crate) fn apply_without_drop_log(ruleset: &Ruleset) -> Nftables<'static> {
    document(apply_cmds(ruleset))
}

/// The batch installing `added` sessions, rewriting `sessions` and `session_flows` for the `live`
/// ones (which include `added`), and deleting the chains of the `removed` session ids. New chains
/// come first, so the dispatch rules can jump to them, and removed ones last, once nothing refers
/// to them. The table must already exist (see [`apply`]).
pub(crate) fn update_sessions(
    added: &[SessionRules],
    removed: &[u32],
    live: &[SessionRules],
) -> Nftables<'static> {
    let mut cmds = Vec::new();
    for session in added {
        session_chain_cmds(&mut cmds, session);
    }
    for name in [SESSIONS_CHAIN, SESSION_FLOWS_CHAIN] {
        cmds.push(NfCmd::Flush(FlushObject::Chain(chain(name))));
    }
    live_session_cmds(&mut cmds, live);
    for &id in removed {
        cmds.push(NfCmd::Delete(NfListObject::Chain(chain(&session_chain(
            id,
        )))));
    }
    document(cmds)
}

/// The batch deleting the gateway table. Adding it first makes the batch succeed whether or not
/// the table exists.
pub(crate) fn teardown() -> Nftables<'static> {
    document(vec![
        NfCmd::Add(NfListObject::Table(table())),
        NfCmd::Delete(NfListObject::Table(table())),
    ])
}

fn document(cmds: Vec<NfCmd<'static>>) -> Nftables<'static> {
    Nftables {
        objects: cmds.into_iter().map(NfObject::CmdObject).collect(),
    }
}

/// Everything in [`apply`] except the drop log.
fn apply_cmds(ruleset: &Ruleset) -> Vec<NfCmd<'static>> {
    let mut cmds = vec![
        NfCmd::Add(NfListObject::Table(table())),
        NfCmd::Delete(NfListObject::Table(table())),
        NfCmd::Add(NfListObject::Table(table())),
    ];
    // Jump targets must exist before the rules that reference them.
    for name in [
        FILTER_CHAIN,
        SESSION_FLOWS_CHAIN,
        SESSIONS_CHAIN,
        DROP_LOG_CHAIN,
        DROP_LOG_PORTS_CHAIN,
    ] {
        cmds.push(add_chain(chain(name)));
    }
    for session in &ruleset.sessions {
        session_chain_cmds(&mut cmds, session);
    }

    let iface = || match_eq(meta(MetaKey::Iifname), string(&ruleset.external_iface));
    let default = match ruleset.mode {
        Mode::Enforcing => Statement::Drop(None),
        Mode::Permissive => Statement::Accept(None),
    };
    for name in BASE_CHAINS {
        cmds.push(add_chain(Chain {
            _type: Some(NfChainType::Filter),
            hook: Some(hook(name)),
            prio: Some(BASE_CHAIN_PRIORITY),
            policy: Some(NfChainPolicy::Accept),
            ..chain(name)
        }));
        cmds.push(add_rule(name, vec![iface(), jump(FILTER_CHAIN)]));
        // Whatever comes back from client_filter is logged, then meets the default action.
        cmds.push(add_rule(name, vec![iface(), jump(DROP_LOG_CHAIN)]));
        cmds.push(add_rule(name, vec![iface(), counter(), default.clone()]));
    }

    // Marked connections belong to a session; once it has gone, they fall through to the default
    // action (see SESSION_FLOWS_CHAIN).
    cmds.push(add_rule(
        FILTER_CHAIN,
        vec![
            matches(Operator::NEQ, ct("mark"), Expression::Number(0)),
            Statement::Goto(target(SESSION_FLOWS_CHAIN)),
        ],
    ));
    cmds.push(add_rule(
        FILTER_CHAIN,
        vec![
            matches(
                Operator::IN,
                ct("state"),
                Expression::List(vec![string("established"), string("related")]),
            ),
            Statement::Accept(None),
        ],
    ));
    for &addr in &ruleset.portal {
        cmds.push(add_rule(FILTER_CHAIN, portal_rule(addr)));
    }
    for spec in &ruleset.rules {
        cmds.push(add_rule(FILTER_CHAIN, allow_rule(spec)));
    }
    cmds.push(add_rule(FILTER_CHAIN, vec![jump(SESSIONS_CHAIN)]));

    live_session_cmds(&mut cmds, &ruleset.sessions);
    cmds
}

/// The drop log's sets and the whole contents of its chains, which [`apply`] adds last.
fn drop_log(mode: Mode) -> Vec<NfCmd<'static>> {
    let mut cmds: Vec<_> = LOG_SETS.into_iter().map(log_set).collect();
    for proto in PORT_PROTOS {
        cmds.push(add_rule(
            DROP_LOG_CHAIN,
            vec![
                match_eq(meta(MetaKey::L4proto), Expression::Number(l4proto(proto))),
                Statement::Goto(target(DROP_LOG_PORTS_CHAIN)),
            ],
        ));
    }
    for chain in [DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN] {
        for set in LOG_SETS.into_iter().filter(|s| s.chain() == chain) {
            cmds.push(add_rule(chain, log_rule(set, mode)));
            cmds.push(add_rule(chain, vec![not_in_set(set), counter()]));
        }
    }
    cmds
}

/// A log set. nft adds the `dynamic` flag itself, from the `add @set` in the log rule, and
/// nftables 0.9.3 doesn't accept it in JSON.
fn log_set(set: LogSet) -> NfCmd<'static> {
    let types = set.key().iter().map(|&f| key_type(set.family, f)).collect();
    NfCmd::Add(NfListObject::Set(Box::new(Set {
        family: NfFamily::INet,
        table: TABLE.into(),
        name: set.name().into(),
        handle: None,
        set_type: SetTypeValue::Concatenated(Cow::Owned(types)),
        policy: None,
        flags: Some(HashSet::from([SetFlag::Timeout])),
        elem: None,
        timeout: Some(LOG_WINDOW.as_secs() as u32),
        gc_interval: None,
        size: Some(LOG_SET_SIZE),
        comment: None,
    })))
}

/// `<key> != @set limit rate 50/second burst 100 packets add @set { <key> } counter log prefix ..`.
fn log_rule(set: LogSet, mode: Mode) -> Vec<Statement<'static>> {
    vec![
        not_in_set(set),
        Statement::Limit(stmt::Limit {
            rate: LOG_RATE,
            rate_unit: Some("packets".into()),
            per: Some("second".into()),
            burst: Some(LOG_BURST),
            burst_unit: None,
            inv: None,
        }),
        Statement::Set(stmt::Set {
            op: stmt::SetOp::Add,
            elem: log_key(set),
            set: set_ref(set),
        }),
        counter(),
        Statement::Log(Some(stmt::Log {
            prefix: Some(mode.log_prefix().into()),
            ..stmt::Log::new(None)
        })),
    ]
}

/// `<key> != @set`.
fn not_in_set(set: LogSet) -> Statement<'static> {
    matches(
        Operator::NEQ,
        log_key(set),
        Expression::String(set_ref(set)),
    )
}

fn set_ref(set: LogSet) -> Cow<'static, str> {
    format!("@{}", set.name()).into()
}

/// The set's key, as a concatenation of the packet's fields.
fn log_key(set: LogSet) -> Expression<'static> {
    let fields = set.key().iter().map(|&f| key_expr(set.family, f)).collect();
    Expression::Named(NamedExpression::Concat(fields))
}

fn key_expr(family: Family, field: KeyField) -> Expression<'static> {
    let proto = match family {
        Family::V4 => "ip",
        Family::V6 => "ip6",
    };
    match field {
        KeyField::SrcAddr => payload(proto, "saddr"),
        KeyField::DstAddr => payload(proto, "daddr"),
        KeyField::L4Proto => meta(MetaKey::L4proto),
        KeyField::DstPort => payload("th", "dport"),
    }
}

fn key_type(family: Family, field: KeyField) -> SetType {
    match (family, field) {
        (Family::V4, KeyField::SrcAddr | KeyField::DstAddr) => SetType::Ipv4Addr,
        (Family::V6, KeyField::SrcAddr | KeyField::DstAddr) => SetType::Ipv6Addr,
        (_, KeyField::L4Proto) => SetType::InetProto,
        (_, KeyField::DstPort) => SetType::InetService,
    }
}

/// A session's chain and its rules.
fn session_chain_cmds(cmds: &mut Vec<NfCmd<'static>>, session: &SessionRules) {
    let name = session.chain();
    cmds.push(add_chain(chain(&name)));
    for spec in &session.rules {
        cmds.push(add_rule(&name, allow_rule(spec)));
    }
}

/// Fills the (empty) `sessions` and `session_flows` chains for the `live` sessions.
fn live_session_cmds(cmds: &mut Vec<NfCmd<'static>>, live: &[SessionRules]) {
    for session in live {
        let saddr = || match_eq(addr_field(session.ip, "saddr"), host(session.ip));
        cmds.push(add_rule(
            SESSIONS_CHAIN,
            vec![saddr(), jump(&session.chain())],
        ));
        cmds.push(add_rule(
            SESSION_FLOWS_CHAIN,
            vec![
                saddr(),
                match_eq(ct("mark"), Expression::Number(session.id)),
                Statement::Accept(None),
            ],
        ));
    }
}

/// `ip daddr <addr> tcp dport <port> counter accept`.
fn portal_rule(addr: SocketAddr) -> Vec<Statement<'static>> {
    vec![
        match_eq(addr_field(addr.ip(), "daddr"), host(addr.ip())),
        match_eq(
            payload("tcp", "dport"),
            Expression::Number(addr.port().into()),
        ),
        counter(),
        Statement::Accept(None),
    ]
}

fn allow_rule(spec: &RuleSpec) -> Vec<Statement<'static>> {
    let mut rule = vec![
        match_eq(addr_field(spec.src.ip(), "saddr"), network(spec.src)),
        match_eq(addr_field(spec.src.ip(), "daddr"), network(spec.dst)),
    ];
    match (spec.proto, spec.ports) {
        (Proto::Tcp | Proto::Udp, Some(p)) => {
            let ports = if p.lo == p.hi {
                Expression::Number(p.lo.into())
            } else {
                Expression::Range(Box::new(Range {
                    range: [
                        Expression::Number(p.lo.into()),
                        Expression::Number(p.hi.into()),
                    ],
                }))
            };
            rule.push(match_eq(payload(&spec.proto.to_string(), "dport"), ports));
        }
        (Proto::Icmp, _) if !spec.src.is_ipv4() => {
            rule.push(match_eq(
                meta(MetaKey::L4proto),
                Expression::Number(IPPROTO_ICMPV6),
            ));
        }
        (Proto::Tcp | Proto::Udp | Proto::Icmp, _) => {
            let proto = Expression::Number(l4proto(spec.proto));
            rule.push(match_eq(meta(MetaKey::L4proto), proto));
        }
        (Proto::Any, _) => {}
    }
    if let Some(mark) = spec.mark {
        rule.push(Statement::Mangle(stmt::Mangle {
            key: ct("mark"),
            value: Expression::Number(mark),
        }));
    }
    rule.push(counter());
    rule.push(Statement::Accept(None));
    rule
}

/// The IPv4 protocol number of `proto` (IPv6 ICMP rules use [`IPPROTO_ICMPV6`]).
fn l4proto(proto: Proto) -> u32 {
    match proto {
        Proto::Tcp => IPPROTO_TCP,
        Proto::Udp => IPPROTO_UDP,
        Proto::Icmp => IPPROTO_ICMP,
        Proto::Any => unreachable!("`any` matches every protocol"),
    }
}

/// Maps a [`BASE_CHAINS`] entry to the netfilter hook it is named after.
fn hook(chain: &str) -> NfHook {
    match chain {
        "input" => NfHook::Input,
        "forward" => NfHook::Forward,
        other => unreachable!("BASE_CHAINS entry {other:?} has no hook mapping"),
    }
}

fn table() -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: TABLE.into(),
        handle: None,
    }
}

/// A regular (non-base) chain in the gateway table.
fn chain(name: &str) -> Chain<'static> {
    Chain {
        family: NfFamily::INet,
        table: TABLE.into(),
        name: name.to_string().into(),
        ..Chain::default()
    }
}

fn add_chain(chain: Chain<'static>) -> NfCmd<'static> {
    NfCmd::Add(NfListObject::Chain(chain))
}

fn add_rule(chain: &str, expr: Vec<Statement<'static>>) -> NfCmd<'static> {
    NfCmd::Add(NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: TABLE.into(),
        chain: chain.to_string().into(),
        expr: expr.into(),
        handle: None,
        index: None,
        comment: None,
    }))
}

fn matches(
    op: Operator,
    left: Expression<'static>,
    right: Expression<'static>,
) -> Statement<'static> {
    Statement::Match(Match { left, right, op })
}

fn match_eq(left: Expression<'static>, right: Expression<'static>) -> Statement<'static> {
    matches(Operator::EQ, left, right)
}

fn counter() -> Statement<'static> {
    Statement::Counter(stmt::Counter::Anonymous(Some(AnonymousCounter::default())))
}

fn jump(chain: &str) -> Statement<'static> {
    Statement::Jump(target(chain))
}

fn target(chain: &str) -> JumpTarget<'static> {
    JumpTarget {
        target: chain.to_string().into(),
    }
}

fn string(s: &str) -> Expression<'static> {
    Expression::String(s.to_string().into())
}

fn meta(key: MetaKey) -> Expression<'static> {
    Expression::Named(NamedExpression::Meta(Meta { key }))
}

fn ct(key: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::CT(CT {
        key: key.into(),
        family: None,
        dir: None,
    }))
}

fn payload(protocol: &str, field: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: protocol.to_string().into(),
            field: field.into(),
        },
    )))
}

/// `ip <field>` or `ip6 <field>`, matching `ip`'s family.
fn addr_field(ip: IpAddr, field: &'static str) -> Expression<'static> {
    payload(if ip.is_ipv4() { "ip" } else { "ip6" }, field)
}

fn host(ip: IpAddr) -> Expression<'static> {
    string(&ip.to_string())
}

/// A single-address network as a plain address, anything else as a prefix.
fn network(net: IpNetwork) -> Expression<'static> {
    let full = if net.is_ipv4() { 32 } else { 128 };
    if net.prefix() == full {
        host(net.ip())
    } else {
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(host(net.ip())),
            len: net.prefix().into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::policy::Policy;

    fn example() -> (Policy, Ruleset) {
        let policy = Policy::parse(include_str!("../../examples/policy.yaml")).unwrap();
        let ruleset =
            Ruleset::from_policy(&policy, "wg0", &["192.168.50.1:8443".parse().unwrap()]).unwrap();
        (policy, ruleset)
    }

    fn to_value(doc: &Nftables) -> Value {
        serde_json::to_value(doc).unwrap()
    }

    #[test]
    fn apply_matches_golden() {
        let golden: Value = serde_json::from_str(include_str!("../../tests/data/example.json"))
            .expect("example.json is valid JSON");
        assert_eq!(to_value(&apply(&example().1)), golden);
    }

    #[test]
    fn teardown_adds_then_deletes_the_table() {
        let table = json!({"family": "inet", "name": "drawbridge"});
        assert_eq!(
            to_value(&teardown()),
            json!({"nftables": [{"add": {"table": table}}, {"delete": {"table": table}}]})
        );
    }

    /// Each command of `doc` as `(command, object kind, chain or set name)`.
    fn outline(doc: &Nftables) -> Vec<(String, String, String)> {
        let value = to_value(doc);
        let cmds = value["nftables"].as_array().unwrap();
        cmds.iter()
            .map(|cmd| {
                let (verb, obj) = cmd.as_object().unwrap().iter().next().unwrap();
                let (kind, body) = obj.as_object().unwrap().iter().next().unwrap();
                let name = body.get("chain").or(body.get("name")).unwrap();
                (
                    verb.clone(),
                    kind.clone(),
                    name.as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn cmd(verb: &str, kind: &str, name: &str) -> (String, String, String) {
        (verb.into(), kind.into(), name.into())
    }

    #[test]
    fn session_update_adds_chains_first_and_deletes_them_last() {
        let (policy, _) = example();
        let s1 =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        let doc = update_sessions(std::slice::from_ref(&s1), &[2], std::slice::from_ref(&s1));
        assert_eq!(
            outline(&doc),
            [
                cmd("add", "chain", "session_1"),
                cmd("add", "rule", "session_1"),
                cmd("add", "rule", "session_1"),
                cmd("flush", "chain", "sessions"),
                cmd("flush", "chain", "session_flows"),
                cmd("add", "rule", "sessions"),
                cmd("add", "rule", "session_flows"),
                cmd("delete", "chain", "session_2"),
            ]
        );
    }

    #[test]
    fn without_drop_log_keeps_its_chains_but_no_sets_or_log_rules() {
        let (_, ruleset) = example();
        let full = outline(&apply(&ruleset));
        let reduced = outline(&apply_without_drop_log(&ruleset));
        let is_drop_log = |(_, kind, name): &(String, String, String)| {
            kind == "set" || (kind == "rule" && name.starts_with("drop_log"))
        };
        assert!(reduced.contains(&cmd("add", "chain", "drop_log")));
        assert!(!reduced.iter().any(is_drop_log));
        let kept: Vec<_> = full.into_iter().filter(|c| !is_drop_log(c)).collect();
        assert_eq!(kept, reduced);
    }

    #[test]
    fn permissive_accepts_by_default_and_logs_would_drop() {
        let (_, mut ruleset) = example();
        ruleset.mode = Mode::Permissive;
        let text = to_value(&apply(&ruleset)).to_string();
        assert!(!text.contains(r#""drop""#));
        assert!(text.contains(r#""prefix":"drawbridge would-drop: ""#));
        assert!(!text.contains("drawbridge drop: "));
    }
}
