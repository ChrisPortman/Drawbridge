//! Hand-encoded nf_tables messages for the drop log, which rustables 0.9 can't express: sets with
//! a size and timeout, and rules that build a concatenated key in consecutive 32-bit registers,
//! look it up and add it from the packet path (`dynset`). The encoding matches what `nft` 1.1
//! sends for what [`Ruleset`](super::ruleset::Ruleset) renders in the log chains. The messages are
//! appended to a finalized rustables batch with [`splice`].

use std::mem::size_of;
use std::ops::Range;

use rustables::sys::{
    NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NFT_CMP_EQ, NFT_DYNSET_OP_ADD, NFT_GOTO,
    NFT_LIMIT_PKTS, NFT_LOOKUP_F_INV, NFT_META_L4PROTO, NFT_META_NFPROTO, NFT_MSG_NEWRULE,
    NFT_MSG_NEWSET, NFT_PAYLOAD_NETWORK_HEADER, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
    NFT_REG_VERDICT, NFT_REG32_00, NFT_SET_EVAL, NFT_SET_TIMEOUT, NFTA_CMP_DATA, NFTA_CMP_OP,
    NFTA_CMP_SREG, NFTA_DATA_VALUE, NFTA_DATA_VERDICT, NFTA_DYNSET_OP, NFTA_DYNSET_SET_ID,
    NFTA_DYNSET_SET_NAME, NFTA_DYNSET_SREG_KEY, NFTA_EXPR_DATA, NFTA_EXPR_NAME,
    NFTA_IMMEDIATE_DATA, NFTA_IMMEDIATE_DREG, NFTA_LIMIT_BURST, NFTA_LIMIT_FLAGS, NFTA_LIMIT_RATE,
    NFTA_LIMIT_TYPE, NFTA_LIMIT_UNIT, NFTA_LIST_ELEM, NFTA_LOG_PREFIX, NFTA_LOOKUP_FLAGS,
    NFTA_LOOKUP_SET, NFTA_LOOKUP_SET_ID, NFTA_LOOKUP_SREG, NFTA_META_DREG, NFTA_META_KEY,
    NFTA_PAYLOAD_BASE, NFTA_PAYLOAD_DREG, NFTA_PAYLOAD_LEN, NFTA_PAYLOAD_OFFSET, NFTA_RULE_CHAIN,
    NFTA_RULE_EXPRESSIONS, NFTA_RULE_TABLE, NFTA_SET_DESC, NFTA_SET_DESC_SIZE, NFTA_SET_FLAGS,
    NFTA_SET_ID, NFTA_SET_KEY_LEN, NFTA_SET_KEY_TYPE, NFTA_SET_NAME, NFTA_SET_TABLE,
    NFTA_SET_TIMEOUT, NFTA_VERDICT_CHAIN, NFTA_VERDICT_CODE, NLA_F_NESTED, NLM_F_ACK, NLM_F_APPEND,
    NLM_F_CREATE, nfgenmsg, nlmsghdr,
};

use super::ruleset::{
    DROP_LOG_CHAIN, DROP_LOG_PORTS_CHAIN, Family, KeyField, LOG_BURST, LOG_RATE, LOG_SET_SIZE,
    LOG_SETS, LOG_WINDOW, LogSet, Mode, PORT_PROTOS, TABLE,
};
use crate::policy::Proto;

const HEADER_LEN: usize = size_of::<nlmsghdr>() + size_of::<nfgenmsg>();
/// nft's datatype ids, which a concatenated set key type packs 6 bits apiece.
const TYPE_IPV4_ADDR: u32 = 7;
const TYPE_IPV6_ADDR: u32 = 8;
const TYPE_INET_PROTO: u32 = 12;
const TYPE_INET_SERVICE: u32 = 13;
const TYPE_BITS: u32 = 6;

/// One nf_tables request, encoded but for its sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Message {
    kind: u32,
    flags: u32,
    attrs: Vec<u8>,
}

impl Message {
    fn encode(&self, seq: u32) -> Vec<u8> {
        let len = u32::try_from(HEADER_LEN + self.attrs.len()).expect("message fits in u32");
        let kind = u16::try_from((NFNL_SUBSYS_NFTABLES << 8) | self.kind).expect("u16 type");
        let flags =
            u16::try_from(libc::NLM_F_REQUEST as u32 | NLM_F_ACK | self.flags).expect("u16 flags");
        let mut buf = Vec::with_capacity(len as usize);
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel
        // nfgenmsg: family, version (NFNETLINK_V0), resource id.
        buf.extend_from_slice(&[libc::NFPROTO_INET as u8, 0, 0, 0]);
        buf.extend_from_slice(&self.attrs);
        buf
    }
}

/// Inserts `msgs` before the BATCH_END that rustables' `Batch::finalize` puts last, numbering them
/// on from it so the kernel's acks stay in sequence. Also returns the sequence numbers `msgs` got,
/// to tell which part of the batch the kernel rejected.
///
/// # Panics
///
/// If `batch` doesn't end with a BATCH_END message.
pub(crate) fn splice(mut batch: Vec<u8>, msgs: &[Message]) -> (Vec<u8>, Range<u32>) {
    let end = batch.split_off(batch.len().saturating_sub(HEADER_LEN));
    let kind = u16::from_ne_bytes([end[4], end[5]]);
    assert_eq!(
        (end.len(), u32::from(kind)),
        (HEADER_LEN, NFNL_MSG_BATCH_END),
        "batch must end with BATCH_END"
    );
    let first = u32::from_ne_bytes(end[8..12].try_into().unwrap());
    let mut seq = first;
    for msg in msgs {
        batch.extend(msg.encode(seq));
        seq += 1;
    }
    batch.extend_from_slice(&end[..8]);
    batch.extend_from_slice(&seq.to_ne_bytes());
    batch.extend_from_slice(&end[12..]);
    (batch, first..seq)
}

/// The drop log: its sets, then every rule of the (existing, empty) log chains in chain order.
/// The `goto` rules come before the log rules in [`DROP_LOG_CHAIN`], so that TCP and UDP are
/// keyed by port, and each set's miss rule follows its log rule.
pub(crate) fn drop_log(mode: Mode) -> Vec<Message> {
    let sets = LOG_SETS
        .iter()
        .enumerate()
        .map(|(i, &s)| new_set(s, set_id(i)));
    let gotos = PORT_PROTOS.map(goto_ports_rule);
    let logs = LOG_SETS
        .iter()
        .enumerate()
        .flat_map(|(i, &s)| [log_rule(s, set_id(i), mode), miss_rule(s, set_id(i))]);
    sets.chain(gotos).chain(logs).collect()
}

/// The batch-local id of `LOG_SETS[index]`, by which its rule refers to it. Ids only need to be
/// unique within the batch, and rustables assigns none.
fn set_id(index: usize) -> u32 {
    u32::try_from(index + 1).expect("few sets")
}

fn new_set(set: LogSet, id: u32) -> Message {
    let fields = key_fields(set);
    let key_type = fields
        .iter()
        .fold(0, |acc, f| (acc << TYPE_BITS) | f.datatype);
    let key_len: u32 = fields.iter().map(|f| f.words() * 4).sum();
    let mut a = Attrs::default();
    a.string(NFTA_SET_TABLE, TABLE);
    a.string(NFTA_SET_NAME, set.name());
    a.u32(NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
    a.u32(NFTA_SET_KEY_TYPE, key_type);
    a.u32(NFTA_SET_KEY_LEN, key_len);
    a.u32(NFTA_SET_ID, id);
    a.nested(NFTA_SET_DESC, |d| d.u32(NFTA_SET_DESC_SIZE, LOG_SET_SIZE));
    let timeout_ms = u64::try_from(LOG_WINDOW.as_millis()).expect("window fits in u64 ms");
    a.u64(NFTA_SET_TIMEOUT, timeout_ms);
    Message {
        kind: NFT_MSG_NEWSET,
        flags: NLM_F_CREATE,
        attrs: a.0,
    }
}

/// `meta l4proto <proto> goto drop_log_ports`.
fn goto_ports_rule(proto: Proto) -> Message {
    let l4 = match proto {
        Proto::Tcp => libc::IPPROTO_TCP,
        Proto::Udp => libc::IPPROTO_UDP,
        Proto::Icmp | Proto::Any => unreachable!("{proto} has no ports"),
    };
    let mut exprs = Attrs::default();
    exprs.expr("meta", |e| {
        e.u32(NFTA_META_KEY, NFT_META_L4PROTO);
        e.u32(NFTA_META_DREG, NFT_REG_1);
    });
    cmp_eq(&mut exprs, &[l4 as u8]);
    exprs.expr("immediate", |e| {
        e.u32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        e.nested(NFTA_IMMEDIATE_DATA, |d| {
            d.nested(NFTA_DATA_VERDICT, |v| {
                v.u32(NFTA_VERDICT_CODE, NFT_GOTO.cast_unsigned());
                v.string(NFTA_VERDICT_CHAIN, DROP_LOG_PORTS_CHAIN);
            });
        });
    });
    new_rule(DROP_LOG_CHAIN, exprs)
}

/// `<key> != @set limit rate .. add @set { <key> } counter log prefix "<prefix>"`.
fn log_rule(set: LogSet, id: u32, mode: Mode) -> Message {
    let mut exprs = new_key(set, id);
    exprs.expr("limit", |e| {
        e.u64(NFTA_LIMIT_RATE, LOG_RATE.into());
        e.u64(NFTA_LIMIT_UNIT, 1); // seconds
        e.u32(NFTA_LIMIT_BURST, LOG_BURST);
        e.u32(NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
        e.u32(NFTA_LIMIT_FLAGS, 0u32);
    });
    // The dynset reads the key again, and nft loads it afresh for it.
    load_key(&mut exprs, set);
    exprs.expr("dynset", |e| {
        e.u32(NFTA_DYNSET_SREG_KEY, NFT_REG_1);
        e.u32(NFTA_DYNSET_OP, NFT_DYNSET_OP_ADD);
        e.string(NFTA_DYNSET_SET_NAME, set.name());
        e.u32(NFTA_DYNSET_SET_ID, id);
    });
    exprs.expr("counter", |_| {});
    exprs.expr("log", |e| e.string(NFTA_LOG_PREFIX, mode.log_prefix()));
    new_rule(set.chain(), exprs)
}

/// `<key> != @set counter`.
fn miss_rule(set: LogSet, id: u32) -> Message {
    let mut exprs = new_key(set, id);
    exprs.expr("counter", |_| {});
    new_rule(set.chain(), exprs)
}

/// The start of a rule matching packets of `set`'s family whose key isn't in the set yet.
fn new_key(set: LogSet, id: u32) -> Attrs {
    let nfproto = match set.family {
        Family::V4 => libc::NFPROTO_IPV4,
        Family::V6 => libc::NFPROTO_IPV6,
    };
    let mut exprs = Attrs::default();
    exprs.expr("meta", |e| {
        e.u32(NFTA_META_KEY, NFT_META_NFPROTO);
        e.u32(NFTA_META_DREG, NFT_REG_1);
    });
    cmp_eq(&mut exprs, &[nfproto as u8]);
    load_key(&mut exprs, set);
    exprs.expr("lookup", |e| {
        e.u32(NFTA_LOOKUP_SREG, NFT_REG_1);
        e.string(NFTA_LOOKUP_SET, set.name());
        e.u32(NFTA_LOOKUP_SET_ID, id);
        e.u32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
    });
    exprs
}

/// `cmp eq reg 1 <value>`.
fn cmp_eq(exprs: &mut Attrs, value: &[u8]) {
    exprs.expr("cmp", |e| {
        e.u32(NFTA_CMP_SREG, NFT_REG_1);
        e.u32(NFTA_CMP_OP, NFT_CMP_EQ);
        e.nested(NFTA_CMP_DATA, |d| d.bytes(NFTA_DATA_VALUE, value));
    });
}

/// A rule appended to `chain`.
fn new_rule(chain: &str, exprs: Attrs) -> Message {
    let mut a = Attrs::default();
    a.string(NFTA_RULE_TABLE, TABLE);
    a.string(NFTA_RULE_CHAIN, chain);
    a.nested(NFTA_RULE_EXPRESSIONS, |e| e.0.extend(exprs.0));
    Message {
        kind: NFT_MSG_NEWRULE,
        flags: NLM_F_CREATE | NLM_F_APPEND,
        attrs: a.0,
    }
}

/// Where one key field is loaded from.
enum Source {
    Payload { base: u32, offset: u32 },
    Meta(u32),
}

struct Load {
    source: Source,
    len: u32,
    datatype: u32,
}

impl Load {
    /// Each field takes whole 32-bit registers.
    fn words(&self) -> u32 {
        self.len.div_ceil(4)
    }
}

/// How to load each field of `set`'s key.
fn key_fields(set: LogSet) -> Vec<Load> {
    let (saddr, len, datatype) = match set.family {
        Family::V4 => (12, 4, TYPE_IPV4_ADDR),
        Family::V6 => (8, 16, TYPE_IPV6_ADDR),
    };
    let network = |offset| Load {
        source: Source::Payload {
            base: NFT_PAYLOAD_NETWORK_HEADER,
            offset,
        },
        len,
        datatype,
    };
    set.key()
        .iter()
        .map(|field| match field {
            KeyField::SrcAddr => network(saddr),
            KeyField::DstAddr => network(saddr + len),
            KeyField::L4Proto => Load {
                source: Source::Meta(NFT_META_L4PROTO),
                len: 1,
                datatype: TYPE_INET_PROTO,
            },
            KeyField::DstPort => Load {
                source: Source::Payload {
                    base: NFT_PAYLOAD_TRANSPORT_HEADER,
                    offset: 2,
                },
                len: 2,
                datatype: TYPE_INET_SERVICE,
            },
        })
        .collect()
}

/// Loads `set`'s key into consecutive registers, starting at the first.
fn load_key(exprs: &mut Attrs, set: LogSet) {
    let mut word = 0;
    for field in key_fields(set) {
        let dreg = register(word);
        match field.source {
            Source::Payload { base, offset } => exprs.expr("payload", |e| {
                e.u32(NFTA_PAYLOAD_DREG, dreg);
                e.u32(NFTA_PAYLOAD_BASE, base);
                e.u32(NFTA_PAYLOAD_OFFSET, offset);
                e.u32(NFTA_PAYLOAD_LEN, field.len);
            }),
            Source::Meta(key) => exprs.expr("meta", |e| {
                e.u32(NFTA_META_KEY, key);
                e.u32(NFTA_META_DREG, dreg);
            }),
        }
        word += field.words();
    }
}

/// The register starting at 32-bit word `word` of the register file. Like nft, this names it as a
/// 128-bit register when aligned to one; both numberings address the same storage.
fn register(word: u32) -> u32 {
    if word.is_multiple_of(4) {
        NFT_REG_1 + word / 4
    } else {
        NFT_REG32_00 + word
    }
}

/// Netlink attributes (TLVs), with nf_tables' big-endian integers.
#[derive(Default)]
struct Attrs(Vec<u8>);

impl Attrs {
    fn bytes(&mut self, kind: impl Into<u32>, value: &[u8]) {
        let len = u16::try_from(4 + value.len()).expect("attribute fits in u16");
        let kind = u16::try_from(kind.into()).expect("u16 attribute type");
        self.0.extend_from_slice(&len.to_ne_bytes());
        self.0.extend_from_slice(&kind.to_ne_bytes());
        self.0.extend_from_slice(value);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
    }

    fn u32(&mut self, kind: impl Into<u32>, value: impl Into<u32>) {
        self.bytes(kind, &value.into().to_be_bytes());
    }

    fn u64(&mut self, kind: impl Into<u32>, value: u64) {
        self.bytes(kind, &value.to_be_bytes());
    }

    fn string(&mut self, kind: impl Into<u32>, value: &str) {
        self.bytes(kind, &[value.as_bytes(), &[0]].concat());
    }

    fn nested(&mut self, kind: impl Into<u32>, build: impl FnOnce(&mut Attrs)) {
        let mut inner = Attrs::default();
        build(&mut inner);
        self.bytes(kind.into() | NLA_F_NESTED, &inner.0);
    }

    /// One element of an expression list: the expression's name and its attributes.
    fn expr(&mut self, name: &str, build: impl FnOnce(&mut Attrs)) {
        self.nested(NFTA_LIST_ELEM, |e| {
            e.string(NFTA_EXPR_NAME, name);
            e.nested(NFTA_EXPR_DATA, build);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `(kind, hex attributes)` per message, as in `tests/data/drop_log.netlink.hex`.
    fn described(msgs: &[Message]) -> Vec<String> {
        msgs.iter()
            .map(|m| {
                let kind = if m.kind == NFT_MSG_NEWSET {
                    "set"
                } else {
                    "rule"
                };
                format!("{kind} {}", hex(&m.attrs))
            })
            .collect()
    }

    #[test]
    fn matches_nft_encoding() {
        let fixture: Vec<&str> = include_str!("../../tests/data/drop_log.netlink.hex")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect();
        let ours = described(&drop_log(Mode::Enforcing));
        assert_eq!(ours.len(), fixture.len());
        for (i, (ours, nft)) in ours.iter().zip(fixture).enumerate() {
            assert_eq!(ours, nft, "message {i}");
        }
    }

    #[test]
    fn permissive_changes_only_the_log_prefix() {
        let enforcing = described(&drop_log(Mode::Enforcing));
        let permissive = described(&drop_log(Mode::Permissive));
        let prefix = |mode: Mode| hex(mode.log_prefix().as_bytes());
        let changed: Vec<_> = enforcing
            .iter()
            .zip(&permissive)
            .filter(|(e, p)| e != p)
            .map(|(e, p)| {
                let expected = e.replace(&prefix(Mode::Enforcing), &prefix(Mode::Permissive));
                assert_ne!(&expected, e, "only log rules change");
                // The longer prefix also changes the attribute lengths, so compare structurally.
                assert!(p.contains(&prefix(Mode::Permissive)), "{p}");
            })
            .collect();
        assert_eq!(changed.len(), LOG_SETS.len(), "one log rule per set");
    }

    #[test]
    fn registers_follow_nft_numbering() {
        assert_eq!(
            [0, 1, 2, 3, 4, 8, 9].map(register),
            [1, 9, 10, 11, 2, 3, 17]
        );
    }

    #[test]
    fn splice_numbers_messages_before_batch_end() {
        let mut batch = rustables::Batch::new();
        let table = rustables::Table::new(rustables::ProtocolFamily::Inet).with_name("t");
        batch.add(&table, rustables::MsgType::Add);
        let rustables_part = batch.finalize();
        let msgs = drop_log(Mode::Enforcing);
        let (spliced, seqs) = splice(rustables_part.clone(), &msgs[..2]);
        assert_eq!(seqs, 2..4);

        let prefix = rustables_part.len() - HEADER_LEN;
        assert_eq!(spliced[..prefix], rustables_part[..prefix]);
        // BEGIN is seq 0 and the table seq 1, so the spliced messages are 2 and 3, and END 4.
        let seqs: Vec<u32> = headers(&spliced[prefix..]).map(|(_, seq)| seq).collect();
        assert_eq!(seqs, [2, 3, 4]);
        let (last_kind, _) = headers(&spliced[prefix..]).last().unwrap();
        assert_eq!(u32::from(last_kind), NFNL_MSG_BATCH_END);
    }

    #[test]
    #[should_panic(expected = "batch must end with BATCH_END")]
    fn splice_rejects_unterminated_batch() {
        splice(drop_log(Mode::Enforcing)[0].encode(1), &[]);
    }

    /// `(type, seq)` of each netlink message in `buf`.
    fn headers(mut buf: &[u8]) -> impl Iterator<Item = (u16, u32)> {
        std::iter::from_fn(move || {
            let len = u32::from_ne_bytes(buf.get(..4)?.try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
            let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
            buf = &buf[len.next_multiple_of(4)..];
            Some((kind, seq))
        })
    }
}
