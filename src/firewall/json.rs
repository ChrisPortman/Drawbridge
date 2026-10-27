//! Pure conversion of a [`Ruleset`] and its [`SessionRules`] into `nft -j` documents, built from
//! the `nftables` crate's serde types: the apply, session update and teardown batches.
//!
//! Each document is one `nft -j -f` transaction. A kernel loaded from [`apply`] lists the same
//! ruleset as `tests/data/example.kernel.nft`.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use nftables::expr::{
    CT, Expression, Fib, FibFlag, FibResult, Meta, MetaKey, NamedExpression, Payload, PayloadField,
    Prefix, Range,
};
use nftables::schema::{
    Chain, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetFlag, SetType,
    SetTypeValue, Table,
};
use nftables::stmt::{self, AnonymousCounter, JumpTarget, Match, NAT, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use super::ruleset::{
    BASE_CHAIN_PRIORITY, BASE_CHAINS, DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN, FILTER_CHAIN, Family,
    KeyField, LOG_BURST, LOG_RATE, LOG_SET_SIZE, LOG_SETS, LOG_WINDOW, LogSet, Mode, NAT_CHAIN,
    PORT_PROTOS, PROXY_REDIRECT_CHAIN, RedirectSpec, RuleProto, RuleSpec, Ruleset,
    SESSION_FLOWS_CHAIN, SESSIONS_CHAIN, SessionRules, TABLE, session_chain,
};
use crate::policy::PortSpec;

/// The `dstnat` priority of the nat chain, as a number: nft 0.9.3's JSON takes no names.
const NAT_CHAIN_PRIORITY: i32 = -100;

/// IANA protocol numbers, as `meta l4proto` compares them.
const IPPROTO_ICMP: u32 = 1;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_ICMPV6: u32 = 58;

/// The batch atomically replacing the gateway table with one implementing `ruleset`. Adding then
/// deleting the table first clears any copy left behind by a previous run.
pub(crate) fn apply(ruleset: &Ruleset) -> Nftables<'static> {
    let mut cmds = apply_cmds(ruleset);
    cmds.extend(nat(ruleset));
    cmds.extend(drop_log(ruleset.mode));
    document(cmds)
}

/// [`apply`] without the drop log's sets and the rules in its chains (the chains, and the base
/// chains' jumps to them, stay). If the kernel rejects [`apply`] but `nft -c` accepts this, the
/// drop log is to blame.
pub(crate) fn apply_without_drop_log(ruleset: &Ruleset) -> Nftables<'static> {
    let mut cmds = apply_cmds(ruleset);
    cmds.extend(nat(ruleset));
    document(cmds)
}

/// [`apply`] without the nat `prerouting` and `proxy_redirect` chains (the proxy accept in
/// `client_filter`, which needs only conntrack, stays). If the kernel rejects [`apply`] but
/// `nft -c` accepts this, the nat modules are missing.
pub(crate) fn apply_without_nat(ruleset: &Ruleset) -> Nftables<'static> {
    let mut cmds = apply_cmds(ruleset);
    cmds.extend(drop_log(ruleset.mode));
    document(cmds)
}

/// The batch installing `added` sessions, rewriting `sessions`, `session_flows` and
/// `proxy_redirect` for the `live` ones (which include `added`) on top of `base`'s client
/// redirects, and deleting the chains of the `removed` session ids. New chains come first, so the
/// dispatch rules can jump to them, and removed ones last, once nothing refers to them. The table
/// must already exist (see [`apply`]); `base.sessions` is ignored.
pub(crate) fn update_sessions(
    base: &Ruleset,
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
    // Without a proxy port, apply installed no nat chains.
    if base.proxy_port.is_some() {
        cmds.push(NfCmd::Flush(FlushObject::Chain(chain(
            PROXY_REDIRECT_CHAIN,
        ))));
    }
    live_session_cmds(&mut cmds, live);
    redirect_cmds(&mut cmds, base, live);
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
    if let Some(port) = ruleset.proxy_port {
        cmds.push(add_rule(FILTER_CHAIN, proxy_accept_rule(port)));
    }
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

/// The nat `prerouting` base chain (at dstnat priority, -100) sending the external interface's
/// traffic to `proxy_redirect`, and that chain with the client and session redirects. Nothing
/// without a proxy port, so kernels without nat support still run policies without host rules.
fn nat(ruleset: &Ruleset) -> Vec<NfCmd<'static>> {
    if ruleset.proxy_port.is_none() {
        return Vec::new();
    }
    let mut cmds = vec![
        add_chain(chain(PROXY_REDIRECT_CHAIN)),
        add_chain(Chain {
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Prerouting),
            prio: Some(NAT_CHAIN_PRIORITY),
            policy: Some(NfChainPolicy::Accept),
            ..chain(NAT_CHAIN)
        }),
        add_rule(
            NAT_CHAIN,
            vec![
                match_eq(meta(MetaKey::Iifname), string(&ruleset.external_iface)),
                jump(PROXY_REDIRECT_CHAIN),
            ],
        ),
    ];
    redirect_cmds(&mut cmds, ruleset, &ruleset.sessions);
    cmds
}

/// Fills the (empty) `proxy_redirect` chain: `base`'s client redirects, then the `live`
/// sessions'. Nothing without a proxy port.
fn redirect_cmds(cmds: &mut Vec<NfCmd<'static>>, base: &Ruleset, live: &[SessionRules]) {
    let Some(port) = base.proxy_port else { return };
    let session_redirects = live.iter().flat_map(|s| &s.redirects);
    for redirect in base.redirects.iter().chain(session_redirects) {
        cmds.push(add_rule(
            PROXY_REDIRECT_CHAIN,
            redirect_rule(redirect, port),
        ));
    }
}

/// `ip[6] saddr S ip[6] daddr D tcp dport X [ct mark set M] counter redirect to :P`.
fn redirect_rule(spec: &RedirectSpec, proxy_port: u16) -> Vec<Statement<'static>> {
    let mut rule = vec![
        match_eq(addr_field(spec.src.ip(), "saddr"), network(spec.src)),
        match_eq(addr_field(spec.src.ip(), "daddr"), network(spec.dst)),
        match_eq(payload("tcp", "dport"), ports(spec.ports)),
    ];
    if let Some(mark) = spec.mark {
        rule.push(set_mark(mark));
    }
    rule.push(counter());
    rule.push(Statement::Redirect(Some(NAT {
        addr: None,
        family: None,
        port: Some(Expression::Number(proxy_port.into())),
        flags: None,
    })));
    rule
}

/// `meta l4proto tcp th dport P ct status dnat fib daddr type local counter accept`: only
/// connections redirected to the proxy reach it. `fib daddr type local` keeps it from accepting
/// someone else's DNAT to port P (a container's published port, say) in the forward hook.
fn proxy_accept_rule(proxy_port: u16) -> Vec<Statement<'static>> {
    vec![
        match_eq(meta(MetaKey::L4proto), Expression::Number(IPPROTO_TCP)),
        match_eq(
            payload("th", "dport"),
            Expression::Number(proxy_port.into()),
        ),
        matches(Operator::IN, ct("status"), string("dnat")),
        match_eq(
            Expression::Named(NamedExpression::Fib(Fib {
                result: FibResult::Type,
                flags: HashSet::from([FibFlag::Daddr]),
            })),
            string("local"),
        ),
        counter(),
        Statement::Accept(None),
    ]
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
        (RuleProto::Tcp | RuleProto::Udp, Some(p)) => {
            rule.push(match_eq(
                payload(&spec.proto.to_string(), "dport"),
                ports(p),
            ));
        }
        (RuleProto::Icmp, _) if !spec.src.is_ipv4() => {
            rule.push(match_eq(
                meta(MetaKey::L4proto),
                Expression::Number(IPPROTO_ICMPV6),
            ));
        }
        (RuleProto::Tcp | RuleProto::Udp | RuleProto::Icmp, _) => {
            let proto = Expression::Number(l4proto(spec.proto));
            rule.push(match_eq(meta(MetaKey::L4proto), proto));
        }
        (RuleProto::Any, _) => {}
    }
    if let Some(mark) = spec.mark {
        rule.push(set_mark(mark));
    }
    rule.push(counter());
    rule.push(Statement::Accept(None));
    rule
}

/// `ct mark set <mark>`.
fn set_mark(mark: u32) -> Statement<'static> {
    Statement::Mangle(stmt::Mangle {
        key: ct("mark"),
        value: Expression::Number(mark),
    })
}

/// A single port, or a range.
fn ports(p: PortSpec) -> Expression<'static> {
    if p.lo == p.hi {
        Expression::Number(p.lo.into())
    } else {
        Expression::Range(Box::new(Range {
            range: [
                Expression::Number(p.lo.into()),
                Expression::Number(p.hi.into()),
            ],
        }))
    }
}

/// The IPv4 protocol number of `proto` (IPv6 ICMP rules use [`IPPROTO_ICMPV6`]).
fn l4proto(proto: RuleProto) -> u32 {
    match proto {
        RuleProto::Tcp => IPPROTO_TCP,
        RuleProto::Udp => IPPROTO_UDP,
        RuleProto::Icmp => IPPROTO_ICMP,
        RuleProto::Any => unreachable!("`any` matches every protocol"),
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
        let ruleset = Ruleset::from_policy(
            &policy,
            "wg0",
            &["192.168.50.1:8443".parse().unwrap()],
            Some(3128),
        )
        .unwrap();
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

    /// The first (in nft JSON, the only) key and value of a JSON object.
    fn only_entry(value: &serde_json::Value) -> (&String, &serde_json::Value) {
        value.as_object().unwrap().iter().next().unwrap()
    }

    /// Each command of `doc` as `(command, object kind, chain or set name)`.
    fn outline(doc: &Nftables) -> Vec<(String, String, String)> {
        let value = to_value(doc);
        let cmds = value["nftables"].as_array().unwrap();
        cmds.iter()
            .map(|cmd| {
                let (verb, obj) = only_entry(cmd);
                let (kind, body) = only_entry(obj);
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
        let (policy, ruleset) = example();
        let s1 =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        let doc = update_sessions(
            &ruleset,
            std::slice::from_ref(&s1),
            &[2],
            std::slice::from_ref(&s1),
        );
        assert_eq!(
            outline(&doc),
            [
                cmd("add", "chain", "session_1"),
                cmd("add", "rule", "session_1"),
                cmd("add", "rule", "session_1"),
                cmd("flush", "chain", "sessions"),
                cmd("flush", "chain", "session_flows"),
                cmd("flush", "chain", "proxy_redirect"),
                cmd("add", "rule", "sessions"),
                cmd("add", "rule", "session_flows"),
                cmd("add", "rule", "proxy_redirect"),
                cmd("add", "rule", "proxy_redirect"),
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

    /// The `expr` of each rule `doc` adds to `chain`.
    fn rules_in(doc: &Nftables, chain: &str) -> Vec<Value> {
        let value = to_value(doc);
        value["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("add")?.get("rule"))
            .filter(|r| r["chain"] == chain)
            .map(|r| r["expr"].clone())
            .collect()
    }

    fn rule_value(rule: Vec<Statement<'static>>) -> Value {
        serde_json::to_value(rule).unwrap()
    }

    fn redirect(src: &str, dst: &str, lo: u16, hi: u16, mark: Option<u32>) -> RedirectSpec {
        RedirectSpec {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            ports: PortSpec { lo, hi },
            mark,
        }
    }

    const COUNTER: &str = r#"{"counter": {"packets": 0, "bytes": 0}}"#;

    // The redirect, `ct status` and nat chain forms follow nftables 0.9.3's src/parser_json.c:
    // json_parse_nat_stmt reads `redirect` as an object with optional `family`, `addr`, `port`
    // and `flags`; json_parse_match_expr maps op "in" to OP_IMPLICIT, the flag test of
    // `ct status dnat`; json_parse_cmd_add_chain needs an integer `prio` (dstnat is -100).
    #[test]
    fn redirect_rule_v4_without_mark() {
        let spec = redirect("192.168.50.0/24", "10.0.2.0/24", 443, 443, None);
        let counter: Value = serde_json::from_str(COUNTER).unwrap();
        assert_eq!(
            rule_value(redirect_rule(&spec, 3128)),
            json!([
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                    "right": {"prefix": {"addr": "192.168.50.0", "len": 24}}}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                    "right": {"prefix": {"addr": "10.0.2.0", "len": 24}}}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 443}},
                counter,
                {"redirect": {"port": 3128}},
            ])
        );
    }

    #[test]
    fn redirect_rule_v6_with_mark_and_port_range() {
        let spec = redirect("fd09::1/128", "fd04::/64", 9000, 9001, Some(7));
        let counter: Value = serde_json::from_str(COUNTER).unwrap();
        assert_eq!(
            rule_value(redirect_rule(&spec, 3128)),
            json!([
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                    "right": "fd09::1"}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
                    "right": {"prefix": {"addr": "fd04::", "len": 64}}}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"range": [9000, 9001]}}},
                {"mangle": {"key": {"ct": {"key": "mark"}}, "value": 7}},
                counter,
                {"redirect": {"port": 3128}},
            ])
        );
    }

    #[test]
    fn proxy_accept_requires_a_dnat_connection_to_the_proxy_port() {
        let counter: Value = serde_json::from_str(COUNTER).unwrap();
        assert_eq!(
            rule_value(proxy_accept_rule(3128)),
            json!([
                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": 6}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}},
                    "right": 3128}},
                {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}},
                {"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}},
                    "right": "local"}},
                counter,
                {"accept": null},
            ])
        );
    }

    #[test]
    fn apply_adds_the_nat_chain_and_proxy_redirect() {
        let (policy, mut ruleset) = example();
        let s1 =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        ruleset.sessions = vec![s1];
        let doc = apply(&ruleset);
        let value = to_value(&doc);
        let nat = value["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|c| {
                c.get("add")?
                    .get("chain")
                    .filter(|c| c["name"] == "prerouting")
            })
            .expect("a prerouting chain");
        assert_eq!(nat["type"], "nat");
        assert_eq!(nat["hook"], "prerouting");
        assert_eq!(nat["prio"], -100);
        assert_eq!(nat["policy"], "accept");
        assert_eq!(
            rules_in(&doc, "prerouting"),
            [json!([
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                {"jump": {"target": "proxy_redirect"}},
            ])]
        );
        let session = &ruleset.sessions[0];
        let expected: Vec<Value> = ruleset
            .redirects
            .iter()
            .chain(&session.redirects)
            .map(|r| rule_value(redirect_rule(r, 3128)))
            .collect();
        assert_eq!(expected.len(), 2);
        assert_eq!(rules_in(&doc, "proxy_redirect"), expected);
        // The proxy accept comes right after `ct state established,related accept`.
        assert_eq!(
            rules_in(&doc, "client_filter")[2],
            rule_value(proxy_accept_rule(3128))
        );
    }

    #[test]
    fn session_update_refills_proxy_redirect() {
        let (policy, ruleset) = example();
        let s1 =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        let doc = update_sessions(&ruleset, &[], &[], std::slice::from_ref(&s1));
        assert!(outline(&doc).contains(&cmd("flush", "chain", "proxy_redirect")));
        let expected: Vec<Value> = ruleset
            .redirects
            .iter()
            .chain(&s1.redirects)
            .map(|r| rule_value(redirect_rule(r, 3128)))
            .collect();
        assert_eq!(rules_in(&doc, "proxy_redirect"), expected);
    }

    #[test]
    fn without_nat_leaves_out_the_nat_chains() {
        let (_, ruleset) = example();
        let full = outline(&apply(&ruleset));
        let reduced = outline(&apply_without_nat(&ruleset));
        let is_nat = |(_, _, name): &(String, String, String)| {
            name == "prerouting" || name == "proxy_redirect"
        };
        assert!(full.iter().any(is_nat));
        let kept: Vec<_> = full.into_iter().filter(|c| !is_nat(c)).collect();
        assert_eq!(kept, reduced);
    }

    #[test]
    fn no_proxy_port_emits_no_nat_chains() {
        let ruleset = Ruleset::from_policy(&Policy::default(), "wg0", &[], None).unwrap();
        let mentions_nat = |doc: &Nftables| {
            let text = serde_json::to_string(doc).unwrap();
            text.contains("prerouting") || text.contains("proxy_redirect")
        };
        assert!(!mentions_nat(&apply(&ruleset)));
        assert!(!mentions_nat(&apply_without_drop_log(&ruleset)));
        assert!(!mentions_nat(&update_sessions(&ruleset, &[], &[], &[])));
        assert!(!to_value(&apply(&ruleset)).to_string().contains("ct status"));
    }
}
