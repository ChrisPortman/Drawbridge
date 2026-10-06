//! Sends nf_tables batches over netlink with socket buffers sized to the batch.
//!
//! rustables' `Batch::send` uses default-sized socket buffers, which breaks for large rulesets:
//! the send fails with EMSGSIZE, or worse, the kernel commits the batch but the per-message acks
//! overflow the receive buffer, so the caller sees ENOBUFS for a ruleset that is in fact live.
//! Batches are still built with rustables; this module only transports the finalized bytes.

use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, send,
    setsockopt, sockopt,
};
use nix::sys::time::TimeVal;

/// `sizeof(struct nlmsghdr)`.
const NLMSG_HDRLEN: usize = 16;
/// `NLMSG_ERROR`: carries an errno, where 0 is an ack.
const NLMSG_ERROR: u16 = 2;
/// `NFNL_MSG_BATCH_END`: closes a batch; the kernel does not ack it.
const NFNL_MSG_BATCH_END: u16 = 0x11;
/// How long to wait for the kernel's acks before giving up, in seconds.
const RECV_TIMEOUT_SECS: i64 = 5;
/// Receive-buffer allowance per acked message, on top of the echoed message bytes. Each ack is
/// queued as its own skb, whose accounted size far exceeds its payload.
const ACK_OVERHEAD: usize = 1024;
/// Spare send-buffer room beyond the batch itself, for the kernel's per-skb accounting.
const SNDBUF_HEADROOM: usize = 64 * 1024;
/// Size of each `recv` into the reply buffer.
const RECV_CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum NetlinkError {
    #[error("netlink socket operation failed")]
    Socket(#[from] Errno),
    #[error("sent only {sent} of {len} batch bytes")]
    ShortSend { sent: usize, len: usize },
    #[error(
        "no ack from the kernel within {RECV_TIMEOUT_SECS}s; the batch may have been committed"
    )]
    Timeout,
    #[error("kernel acks were lost (ENOBUFS); the batch may have been committed")]
    AcksLost,
    #[error("kernel rejected message {seq}: {}", Errno::from_raw(*.errno))]
    Kernel { errno: i32, seq: u32 },
    #[error("malformed netlink message")]
    Malformed,
    #[error("batch has no BATCH_END message")]
    Unterminated,
}

/// Outcome of parsing one chunk of replies.
#[derive(Debug, PartialEq, Eq)]
enum Progress {
    /// The ack for the last message arrived: the batch is committed.
    Done,
    /// More replies are needed.
    Pending,
}

/// Sends a finalized batch and waits until the kernel has acked its last message.
pub fn send_batch(batch: &[u8]) -> Result<(), NetlinkError> {
    let last_seq = last_acked_seq(batch)?;
    let sock = open_socket(batch.len(), last_seq)?;

    // A netlink datagram can't be resumed after a partial send: the remainder would arrive as a
    // separate, corrupt batch.
    let sent = send(sock.as_raw_fd(), batch, MsgFlags::empty())?;
    if sent != batch.len() {
        return Err(NetlinkError::ShortSend {
            sent,
            len: batch.len(),
        });
    }

    let mut buf = vec![0u8; RECV_CHUNK];
    loop {
        let len = recv(sock.as_raw_fd(), &mut buf, MsgFlags::empty()).map_err(|e| match e {
            Errno::EAGAIN => NetlinkError::Timeout,
            Errno::ENOBUFS => NetlinkError::AcksLost,
            e => NetlinkError::Socket(e),
        })?;
        if parse_replies(&buf[..len], last_seq)? == Progress::Done {
            return Ok(());
        }
    }
}

fn open_socket(batch_len: usize, last_seq: u32) -> Result<OwnedFd, NetlinkError> {
    let sock = nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkNetFilter,
    )?;
    bind(sock.as_raw_fd(), &NetlinkAddr::new(0, 0))?;

    // The whole batch must go in one send, and every message is acked with a copy of itself.
    let sndbuf = batch_len + SNDBUF_HEADROOM;
    let rcvbuf = 2 * batch_len + (last_seq as usize + 16) * ACK_OVERHEAD;
    // The *FORCE variants bypass rmem_max/wmem_max and need CAP_NET_ADMIN, which we hold; fall
    // back to the capped variants so small batches still work without it.
    if setsockopt(&sock, sockopt::SndBufForce, &sndbuf).is_err() {
        setsockopt(&sock, sockopt::SndBuf, &sndbuf)?;
    }
    if setsockopt(&sock, sockopt::RcvBufForce, &rcvbuf).is_err() {
        setsockopt(&sock, sockopt::RcvBuf, &rcvbuf)?;
    }
    setsockopt(
        &sock,
        sockopt::ReceiveTimeout,
        &TimeVal::new(RECV_TIMEOUT_SECS, 0),
    )?;
    Ok(sock)
}

/// One netlink message header, decoded from native-endian bytes.
struct Header {
    len: usize,
    kind: u16,
    seq: u32,
}

fn read_header(buf: &[u8]) -> Result<Header, NetlinkError> {
    let field = |range: std::ops::Range<usize>| buf.get(range).ok_or(NetlinkError::Malformed);
    let len = u32::from_ne_bytes(field(0..4)?.try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes(field(4..6)?.try_into().unwrap());
    let seq = u32::from_ne_bytes(field(8..12)?.try_into().unwrap());
    if len < NLMSG_HDRLEN || len > buf.len() {
        return Err(NetlinkError::Malformed);
    }
    Ok(Header { len, kind, seq })
}

/// Iterates over the netlink messages in `buf`, yielding each header and its full bytes.
fn messages(buf: &[u8]) -> impl Iterator<Item = Result<(Header, &[u8]), NetlinkError>> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match read_header(rest) {
            Ok(hdr) => {
                let msg = &rest[..hdr.len];
                // Messages are 4-byte aligned; the final one may omit its padding.
                rest = &rest[hdr.len.next_multiple_of(4).min(rest.len())..];
                Some(Ok((hdr, msg)))
            }
            Err(e) => {
                // Nothing after a malformed header can be located; stop iterating.
                rest = &[];
                Some(Err(e))
            }
        }
    })
}

/// The sequence number of the last message the kernel will ack: the one before BATCH_END.
fn last_acked_seq(batch: &[u8]) -> Result<u32, NetlinkError> {
    for msg in messages(batch) {
        let (hdr, _) = msg?;
        if hdr.kind == NFNL_MSG_BATCH_END {
            return hdr.seq.checked_sub(1).ok_or(NetlinkError::Malformed);
        }
    }
    Err(NetlinkError::Unterminated)
}

/// Processes replies, failing on the first kernel error and finishing at the ack for `last_seq`.
fn parse_replies(buf: &[u8], last_seq: u32) -> Result<Progress, NetlinkError> {
    for msg in messages(buf) {
        let (hdr, bytes) = msg?;
        if hdr.kind != NLMSG_ERROR {
            continue;
        }
        let errno = bytes
            .get(NLMSG_HDRLEN..NLMSG_HDRLEN + 4)
            .ok_or(NetlinkError::Malformed)?;
        // The kernel reports a negative errno; 0 acknowledges success.
        let errno = i32::from_ne_bytes(errno.try_into().unwrap()).wrapping_neg();
        if errno != 0 {
            return Err(NetlinkError::Kernel {
                errno,
                seq: hdr.seq,
            });
        }
        if hdr.seq == last_seq {
            return Ok(Progress::Done);
        }
    }
    Ok(Progress::Pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `NLMSG_ERROR` reply carrying `errno` (0 = ack) for message `seq`.
    fn error_msg(seq: u32, errno: i32) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&36u32.to_ne_bytes()); // header + errno + echoed header
        msg.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&(-errno).to_ne_bytes());
        msg.extend_from_slice(&[0u8; NLMSG_HDRLEN]);
        msg
    }

    #[test]
    fn ack_for_last_seq_completes() {
        assert_eq!(parse_replies(&error_msg(3, 0), 3).unwrap(), Progress::Done);
    }

    #[test]
    fn ack_for_earlier_seq_is_pending() {
        assert_eq!(
            parse_replies(&error_msg(2, 0), 3).unwrap(),
            Progress::Pending
        );
    }

    #[test]
    fn several_messages_in_one_buffer() {
        let buf = [error_msg(1, 0), error_msg(2, 0), error_msg(3, 0)].concat();
        assert_eq!(parse_replies(&buf, 3).unwrap(), Progress::Done);
    }

    #[test]
    fn kernel_error_is_reported_with_its_seq() {
        let buf = [error_msg(1, 0), error_msg(2, libc::ENOENT)].concat();
        match parse_replies(&buf, 3) {
            Err(NetlinkError::Kernel { errno, seq }) => {
                assert_eq!((errno, seq), (libc::ENOENT, 2));
            }
            other => panic!("expected kernel error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_buffer_is_malformed() {
        let msg = error_msg(1, 0);
        assert!(matches!(
            parse_replies(&msg[..20], 1),
            Err(NetlinkError::Malformed)
        ));
    }

    #[test]
    fn messages_stop_after_malformed_header() {
        let items: Vec<_> = messages(&[0u8; 8]).collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn socket_error_detail_is_not_repeated() {
        let e = NetlinkError::from(Errno::EPERM);
        let source = std::error::Error::source(&e).unwrap().to_string();
        assert!(!e.to_string().contains(&source), "{e}");
    }

    #[test]
    fn last_acked_seq_comes_from_batch_end() {
        let mut batch = rustables::Batch::new();
        let table = rustables::Table::new(rustables::ProtocolFamily::Inet).with_name("t");
        batch.add(&table, rustables::MsgType::Add);
        batch.add(&table, rustables::MsgType::Del);
        assert_eq!(last_acked_seq(&batch.finalize()).unwrap(), 2);
    }

    #[test]
    fn batch_without_end_is_rejected() {
        assert!(matches!(
            last_acked_seq(&error_msg(1, 0)),
            Err(NetlinkError::Unterminated)
        ));
    }
}
