//! Translates a [`Ruleset`] into nf_tables netlink batches via `rustables`, sent with
//! `netlink::send_batch`.

mod netlink;
mod nfraw;
pub mod ruleset;

pub use netlink::NetlinkError;

use std::net::SocketAddr;
use std::ops::Range;

use ipnetwork::IpNetwork;
use rustables::error::BuilderError;
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Counter, HighLevelPayload,
    Immediate, Meta, MetaType, Register, TCPHeaderField, TransportHeaderField, UDPHeaderField,
    VerdictKind,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};

use crate::policy::{PortSpec, Proto};
use ruleset::{
    BASE_CHAIN_PRIORITY, BASE_CHAINS, DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN, FILTER_CHAIN, Mode,
    RuleSpec, Ruleset, SESSION_FLOWS_CHAIN, SESSIONS_CHAIN, SessionRules, TABLE, session_chain,
};

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("failed to build nftables rule")]
    Build(#[from] BuilderError),
    #[error("nftables netlink request failed")]
    Netlink(#[from] NetlinkError),
    #[error(
        "the kernel rejected the drop log; check that the nft_log, nf_log_syslog and nft_limit \
         modules are available (built in, or loadable)"
    )]
    DropLog(#[source] NetlinkError),
}

fn table() -> Table {
    Table::new(ProtocolFamily::Inet).with_name(TABLE)
}

/// Atomically replaces the gateway table with one implementing `ruleset`.
pub fn apply(ruleset: &Ruleset) -> Result<(), FirewallError> {
    let (batch, drop_log) = apply_batch_bytes(ruleset)?;
    netlink::send_batch(&batch).map_err(|e| match e {
        NetlinkError::Kernel { seq, .. } if drop_log.contains(&seq) => FirewallError::DropLog(e),
        e => e.into(),
    })
}

/// The rustables-built batch for [`apply`], plus the drop log's hand-encoded sets and the whole
/// contents of its chains, which go last: they need the log chains, and nothing in the batch
/// refers to them. Also returns the drop log's sequence numbers.
fn apply_batch_bytes(ruleset: &Ruleset) -> Result<(Vec<u8>, Range<u32>), BuilderError> {
    let batch = build_apply_batch(ruleset)?.finalize();
    Ok(nfraw::splice(batch, &nfraw::drop_log(ruleset.mode)))
}

/// Atomically installs `added` sessions, removes the chains of the `removed` session ids, and
/// rewrites the dispatch chain to send each of the `live` sessions to its chain. `live` must
/// include every session in `added`. The table must already exist (see [`apply`]).
pub fn update_sessions(
    added: &[SessionRules],
    removed: &[u32],
    live: &[SessionRules],
) -> Result<(), FirewallError> {
    netlink::send_batch(&build_sessions_batch(added, removed, live)?.finalize())?;
    Ok(())
}

/// Deletes the gateway table. Returns `false` if it did not exist.
pub fn teardown() -> Result<bool, FirewallError> {
    let mut batch = Batch::new();
    batch.add(&table(), MsgType::Del);
    match netlink::send_batch(&batch.finalize()) {
        Ok(()) => Ok(true),
        Err(NetlinkError::Kernel { errno, .. }) if errno == libc::ENOENT => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Builds the batch for [`apply`]. Adding then deleting the table first clears any copy left
/// behind by a previous run, all within the same transaction.
fn build_apply_batch(ruleset: &Ruleset) -> Result<Batch, BuilderError> {
    let mut batch = Batch::new();
    let table = table();
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    let table = table.add_to_batch(&mut batch);

    let filter = Chain::new(&table)
        .with_name(FILTER_CHAIN)
        .add_to_batch(&mut batch);
    // Jump targets must exist before the rules that reference them.
    chain(&table, SESSION_FLOWS_CHAIN).add_to_batch(&mut batch);
    chain(&table, SESSIONS_CHAIN).add_to_batch(&mut batch);
    // Filled by nfraw (see apply_batch_bytes).
    chain(&table, DROP_LOG_CHAIN).add_to_batch(&mut batch);
    chain(&table, DROP_LOG_PORTS_CHAIN).add_to_batch(&mut batch);
    for session in &ruleset.sessions {
        add_session_chain(&mut batch, &table, session)?;
    }

    for name in BASE_CHAINS {
        let chain = Chain::new(&table)
            .with_name(name)
            .with_hook(Hook::new(hook_class(name), BASE_CHAIN_PRIORITY))
            .with_policy(ChainPolicy::Accept)
            .with_type(ChainType::Filter)
            .add_to_batch(&mut batch);
        let external = || Rule::new(&chain)?.iiface(&ruleset.external_iface);
        jump(external()?, FILTER_CHAIN).add_to_batch(&mut batch);
        // Whatever comes back from client_filter is logged, then meets the default action.
        jump(external()?, DROP_LOG_CHAIN).add_to_batch(&mut batch);
        let default = external()?.with_expr(Counter::default());
        match ruleset.mode {
            Mode::Enforcing => default.drop(),
            Mode::Permissive => default.accept(),
        }
        .add_to_batch(&mut batch);
    }

    // Marked connections belong to a session; once it has gone, they fall through to the default
    // action (see SESSION_FLOWS_CHAIN).
    Rule::new(&filter)?
        .with_expr(Conntrack::new(ConntrackKey::Mark))
        .with_expr(Cmp::new(CmpOp::Neq, 0u32.to_ne_bytes()))
        .with_expr(Immediate::new_verdict(VerdictKind::Goto {
            chain: SESSION_FLOWS_CHAIN.to_string(),
        }))
        .add_to_batch(&mut batch);
    established_or_related(Rule::new(&filter)?)?
        .accept()
        .add_to_batch(&mut batch);
    for &addr in &ruleset.portal {
        portal_rule(Rule::new(&filter)?, addr)?.add_to_batch(&mut batch);
    }
    for spec in &ruleset.rules {
        allow_rule(Rule::new(&filter)?, spec)?.add_to_batch(&mut batch);
    }
    jump(Rule::new(&filter)?, SESSIONS_CHAIN).add_to_batch(&mut batch);

    add_live_sessions(&mut batch, &table, &ruleset.sessions)?;
    Ok(batch)
}

/// Builds the batch for [`update_sessions`]: new chains first, so the rewritten dispatch rules can
/// jump to them, and removed chains last, once nothing references them.
fn build_sessions_batch(
    added: &[SessionRules],
    removed: &[u32],
    live: &[SessionRules],
) -> Result<Batch, BuilderError> {
    let mut batch = Batch::new();
    let table = table();
    for session in added {
        add_session_chain(&mut batch, &table, session)?;
    }
    // A rule delete with no handle flushes the whole chain.
    for name in [SESSIONS_CHAIN, SESSION_FLOWS_CHAIN] {
        batch.add(&Rule::new(&chain(&table, name))?, MsgType::Del);
    }
    add_live_sessions(&mut batch, &table, live)?;
    for &id in removed {
        batch.add(&chain(&table, &session_chain(id)), MsgType::Del);
    }
    Ok(batch)
}

/// Fills the (empty) `sessions` and `session_flows` chains for the `live` sessions.
fn add_live_sessions(
    batch: &mut Batch,
    table: &Table,
    live: &[SessionRules],
) -> Result<(), BuilderError> {
    let sessions = chain(table, SESSIONS_CHAIN);
    let flows = chain(table, SESSION_FLOWS_CHAIN);
    for session in live {
        dispatch_rule(Rule::new(&sessions)?, session)?.add_to_batch(batch);
        Rule::new(&flows)?
            .snetwork(IpNetwork::from(session.ip))?
            .with_expr(Conntrack::new(ConntrackKey::Mark))
            .with_expr(Cmp::new(CmpOp::Eq, session.id.to_ne_bytes()))
            .accept()
            .add_to_batch(batch);
    }
    Ok(())
}

/// A regular (non-base) chain in `table`.
fn chain(table: &Table, name: &str) -> Chain {
    Chain::new(table).with_name(name)
}

fn add_session_chain(
    batch: &mut Batch,
    table: &Table,
    session: &SessionRules,
) -> Result<(), BuilderError> {
    let chain = chain(table, &session.chain()).add_to_batch(batch);
    for spec in &session.rules {
        allow_rule(Rule::new(&chain)?, spec)?.add_to_batch(batch);
    }
    Ok(())
}

fn jump(rule: Rule, chain: &str) -> Rule {
    rule.with_expr(Immediate::new_verdict(VerdictKind::Jump {
        chain: chain.to_string(),
    }))
}

/// `ip saddr <session ip> jump session_<id>`.
fn dispatch_rule(rule: Rule, session: &SessionRules) -> Result<Rule, BuilderError> {
    Ok(jump(
        rule.snetwork(IpNetwork::from(session.ip))?,
        &session.chain(),
    ))
}

/// `ip daddr <addr> tcp dport <port> counter accept`.
fn portal_rule(rule: Rule, addr: SocketAddr) -> Result<Rule, BuilderError> {
    Ok(rule
        .dnetwork(IpNetwork::from(addr.ip()))?
        .dport(addr.port(), Protocol::TCP)
        .with_expr(Counter::default())
        .accept())
}

/// Maps a [`BASE_CHAINS`] entry to the netfilter hook it is named after.
fn hook_class(chain: &str) -> HookClass {
    match chain {
        "input" => HookClass::In,
        "forward" => HookClass::Forward,
        other => unreachable!("BASE_CHAINS entry {other:?} has no hook mapping"),
    }
}

/// `ct state established,related` — rustables' `Rule::established` omits `related`.
fn established_or_related(rule: Rule) -> Result<Rule, BuilderError> {
    let states = (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED).bits();
    Ok(rule
        .with_expr(Conntrack::new(ConntrackKey::State))
        .with_expr(Bitwise::new(states.to_ne_bytes(), 0u32.to_ne_bytes())?)
        .with_expr(Cmp::new(CmpOp::Neq, 0u32.to_ne_bytes())))
}

fn allow_rule(rule: Rule, spec: &RuleSpec) -> Result<Rule, BuilderError> {
    let mut rule = rule.snetwork(spec.src)?.dnetwork(spec.dst)?;
    rule = match spec.proto {
        Proto::Tcp => match_ports(rule, Protocol::TCP, spec.ports),
        Proto::Udp => match_ports(rule, Protocol::UDP, spec.ports),
        Proto::Icmp => {
            let l4 = if spec.src.is_ipv4() {
                libc::IPPROTO_ICMP
            } else {
                libc::IPPROTO_ICMPV6
            };
            rule.with_expr(Meta::new(MetaType::L4Proto))
                .with_expr(Cmp::new(CmpOp::Eq, [l4 as u8]))
        }
        Proto::Any => rule,
    };
    if let Some(mark) = spec.mark {
        rule = rule
            .with_expr(Immediate::new_data(
                mark.to_ne_bytes().to_vec(),
                Register::Reg1,
            ))
            .with_expr(Conntrack::default().with_mark_value(Register::Reg1));
    }
    Ok(rule.with_expr(Counter::default()).accept())
}

fn match_ports(rule: Rule, protocol: Protocol, ports: Option<PortSpec>) -> Rule {
    match ports {
        None => rule.protocol(protocol),
        Some(p) if p.lo == p.hi => rule.dport(p.lo, protocol),
        Some(p) => {
            let dport = match protocol {
                Protocol::TCP => TransportHeaderField::Tcp(TCPHeaderField::Dport),
                Protocol::UDP => TransportHeaderField::Udp(UDPHeaderField::Dport),
            };
            let (lo, hi) = port_range_bounds(p);
            rule.protocol(protocol)
                .with_expr(HighLevelPayload::Transport(dport).build())
                .with_expr(Cmp::new(CmpOp::Gte, lo))
                .with_expr(Cmp::new(CmpOp::Lte, hi))
        }
    }
}

/// Ports are compared in network byte order, which `cmp` orders correctly as it compares bytewise.
fn port_range_bounds(p: PortSpec) -> ([u8; 2], [u8; 2]) {
    (p.lo.to_be_bytes(), p.hi.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn port_range_is_big_endian() {
        assert_eq!(
            port_range_bounds(PortSpec { lo: 8000, hi: 8100 }),
            ([0x1f, 0x40], [0x1f, 0xa4])
        );
    }

    #[test]
    fn every_base_chain_has_a_hook() {
        for name in BASE_CHAINS {
            hook_class(name);
        }
    }

    #[test]
    fn builds_batch_for_example() {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        let mut ruleset =
            Ruleset::from_policy(&policy, "wg0", &["192.168.50.1:8443".parse().unwrap()]).unwrap();
        let session =
            SessionRules::for_user(&policy, 1, "alice", "192.168.60.7".parse().unwrap()).unwrap();
        ruleset.sessions.push(session.clone());
        let (batch, drop_log) = apply_batch_bytes(&ruleset).unwrap();
        assert!(!batch.is_empty() && !drop_log.is_empty());
        let live = [session.clone()];
        assert!(
            !build_sessions_batch(&live, &[2], &live)
                .unwrap()
                .finalize()
                .is_empty()
        );
    }
}
