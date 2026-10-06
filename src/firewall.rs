//! Translates a [`Ruleset`] into nf_tables netlink batches via `rustables`.

use rustables::error::{BuilderError, QueryError};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Counter, HighLevelPayload,
    Immediate, Meta, MetaType, TCPHeaderField, TransportHeaderField, UDPHeaderField, VerdictKind,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};

use crate::policy::{PortSpec, Proto};
use crate::ruleset::{FILTER_CHAIN, RuleSpec, Ruleset, TABLE};

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("failed to build nftables rule: {0}")]
    Build(#[from] BuilderError),
    #[error("nftables netlink request failed: {0}")]
    Netlink(#[from] QueryError),
}

fn table() -> Table {
    Table::new(ProtocolFamily::Inet).with_name(TABLE)
}

/// Atomically replaces the gateway table with one implementing `ruleset`.
pub fn apply(ruleset: &Ruleset) -> Result<(), FirewallError> {
    build_apply_batch(ruleset)?.send()?;
    Ok(())
}

/// Deletes the gateway table. Returns `false` if it did not exist.
pub fn teardown() -> Result<bool, FirewallError> {
    let mut batch = Batch::new();
    batch.add(&table(), MsgType::Del);
    match batch.send() {
        Ok(()) => Ok(true),
        // rustables reports errno as a positive value, unlike the kernel's negative nlmsgerr.
        Err(QueryError::NetlinkError(e)) if e.error.abs() == libc::ENOENT => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Builds the batch for [`apply`]. Adding then deleting the table first clears any copy left
/// behind by a previous run, all within the same transaction.
pub fn build_apply_batch(ruleset: &Ruleset) -> Result<Batch, BuilderError> {
    let mut batch = Batch::new();
    let table = table();
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    let table = table.add_to_batch(&mut batch);

    let filter = Chain::new(&table)
        .with_name(FILTER_CHAIN)
        .add_to_batch(&mut batch);

    for (name, class) in [("input", HookClass::In), ("forward", HookClass::Forward)] {
        let chain = Chain::new(&table)
            .with_name(name)
            .with_hook(Hook::new(class, 0))
            .with_policy(ChainPolicy::Accept)
            .with_type(ChainType::Filter)
            .add_to_batch(&mut batch);
        Rule::new(&chain)?
            .iiface(&ruleset.external_iface)?
            .with_expr(Immediate::new_verdict(VerdictKind::Jump {
                chain: FILTER_CHAIN.to_string(),
            }))
            .add_to_batch(&mut batch);
    }

    established_or_related(Rule::new(&filter)?)?
        .accept()
        .add_to_batch(&mut batch);
    for spec in &ruleset.rules {
        allow_rule(Rule::new(&filter)?, spec)?.add_to_batch(&mut batch);
    }
    Rule::new(&filter)?
        .with_expr(Counter::default())
        .drop()
        .add_to_batch(&mut batch);

    Ok(batch)
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
    fn builds_batch_for_example() {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        let ruleset = Ruleset::from_policy(&policy, "wg0").unwrap();
        assert!(!build_apply_batch(&ruleset).unwrap().finalize().is_empty());
    }
}
