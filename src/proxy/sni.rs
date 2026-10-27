//! Pure TLS ClientHello parser: extracts the SNI host name, or says why it can't.

//!
//! rustls' `Acceptor` can't report ECH and consumes its input, so this walks the bytes itself
//! (ADR 0004). It does no I/O: the caller passes everything read so far and reads more on
//! [`ClientHello::NeedMore`].

/// The most input the parser looks at. A ClientHello not complete within it is malformed.
pub(crate) const MAX_INPUT: usize = 16 * 1024;

pub(super) const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const NAME_TYPE_HOST_NAME: u8 = 0;

/// What the bytes read so far say about the connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHello {
    /// The ClientHello isn't complete yet; read more and call again.
    NeedMore,
    /// The ClientHello names this host.
    Sni(String),
    /// A complete ClientHello without a host name.
    NoSni,
    /// The ClientHello uses Encrypted Client Hello, so its SNI isn't the real destination.
    Ech,
    /// The input isn't a TLS handshake.
    NotTls,
    /// A TLS handshake that isn't a well-formed ClientHello within [`MAX_INPUT`].
    Malformed,
}

/// Parses the start of a client's TLS stream.
pub(crate) fn parse(buf: &[u8]) -> ClientHello {
    match handshake_message(&buf[..buf.len().min(MAX_INPUT)]) {
        Ok(body) => client_hello(&body).unwrap_or(ClientHello::Malformed),
        Err(ClientHello::NeedMore) if buf.len() >= MAX_INPUT => ClientHello::Malformed,
        Err(other) => other,
    }
}

/// Reassembles the first handshake message from its TLS records and returns its body.
fn handshake_message(buf: &[u8]) -> Result<Vec<u8>, ClientHello> {
    let mut handshake = Vec::new();
    let mut rest = buf;
    loop {
        let first = handshake.is_empty();
        match rest {
            [] => return Err(ClientHello::NeedMore),
            [ty, ..] if *ty != CONTENT_HANDSHAKE => {
                return Err(if first {
                    ClientHello::NotTls
                } else {
                    ClientHello::Malformed
                });
            }
            [_, major, ..] if *major != 0x03 => {
                return Err(if first {
                    ClientHello::NotTls
                } else {
                    ClientHello::Malformed
                });
            }
            [_, _, _, hi, lo, payload @ ..] => {
                let len = usize::from(u16::from_be_bytes([*hi, *lo]));
                if len == 0 {
                    return Err(ClientHello::Malformed);
                }
                let take = len.min(payload.len());
                handshake.extend_from_slice(&payload[..take]);
                rest = &payload[take..];
                if let Some(body) = complete_message(&handshake)? {
                    return Ok(body.to_vec());
                }
                if take < len {
                    return Err(ClientHello::NeedMore);
                }
            }
            _ => return Err(ClientHello::NeedMore),
        }
    }
}

/// Returns the ClientHello body once `handshake` holds all of it.
fn complete_message(handshake: &[u8]) -> Result<Option<&[u8]>, ClientHello> {
    let [ty, a, b, c, body @ ..] = handshake else {
        return Ok(None);
    };
    if *ty != HANDSHAKE_CLIENT_HELLO {
        return Err(ClientHello::Malformed);
    }
    let len = u32::from_be_bytes([0, *a, *b, *c]) as usize;
    if len > MAX_INPUT {
        return Err(ClientHello::Malformed);
    }
    Ok(body.get(..len))
}

/// Reads the extensions of a complete ClientHello body. `None` means it is malformed.
fn client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut r = Reader(body);
    r.take(2 + 32)?; // legacy_version, random
    r.vec8()?; // legacy_session_id
    r.vec16()?; // cipher_suites
    r.vec8()?; // legacy_compression_methods
    if r.0.is_empty() {
        return Some(ClientHello::NoSni);
    }
    let mut extensions = Reader(r.vec16()?);
    let mut sni = None;
    while !extensions.0.is_empty() {
        let ty = extensions.u16()?;
        let data = extensions.vec16()?;
        match ty {
            EXT_ENCRYPTED_CLIENT_HELLO => return Some(ClientHello::Ech),
            EXT_SERVER_NAME => sni = Some(host_name(data)?),
            _ => {}
        }
    }
    Some(sni.flatten().map_or(ClientHello::NoSni, ClientHello::Sni))
}

/// Reads a `server_name` extension: the host name entry, if there is one.
fn host_name(data: &[u8]) -> Option<Option<String>> {
    let mut list = Reader(Reader(data).vec16()?);
    while !list.0.is_empty() {
        let ty = list.u8()?;
        let name = list.vec16()?;
        if ty == NAME_TYPE_HOST_NAME {
            let name = std::str::from_utf8(name).ok()?;
            return Some(Some(name.to_owned()));
        }
    }
    Some(None)
}

/// A bounds-checked cursor; every read returns `None` past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n.into())
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n.into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;

    pub(crate) fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.enable_sni = sni.is_some();
        let name = sni.unwrap_or("example.com").to_owned().try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    /// Re-frames a single-record ClientHello as records of at most `chunk` payload bytes.
    fn split_records(hello: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in hello[5..].chunks(chunk) {
            out.extend_from_slice(&hello[..3]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Offsets of each extension's type field in a single-record ClientHello.
    fn extension_offsets(hello: &[u8]) -> Vec<usize> {
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(hello[at]);
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 1 + usize::from(hello[at]);
        at += 2;
        let mut offsets = Vec::new();
        while at < hello.len() {
            offsets.push(at);
            at += 4 + usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
        }
        offsets
    }

    #[test]
    fn no_sni_when_the_client_sends_none() {
        assert_eq!(parse(&client_hello(None)), ClientHello::NoSni);
    }

    #[test]
    fn ech_extension_is_reported() {
        let mut hello = client_hello(Some("git.example.com"));
        let last = *extension_offsets(&hello).last().unwrap();
        hello[last..last + 2].copy_from_slice(&0xfe0du16.to_be_bytes());
        assert_eq!(parse(&hello), ClientHello::Ech);
    }

    #[test]
    fn ech_wins_over_a_server_name_after_it() {
        let mut hello = client_hello(Some("git.example.com"));
        let first = extension_offsets(&hello)
            .into_iter()
            .find(|&at| hello[at..at + 2] != [0, 0])
            .unwrap();
        hello[first..first + 2].copy_from_slice(&0xfe0du16.to_be_bytes());
        assert_eq!(parse(&hello), ClientHello::Ech);
    }

    #[test]
    fn every_truncation_needs_more() {
        let hello = client_hello(Some("git.example.com"));
        for len in 0..hello.len() {
            assert_eq!(parse(&hello[..len]), ClientHello::NeedMore, "at {len}");
        }
    }

    #[test]
    fn hello_split_across_records() {
        let hello = split_records(&client_hello(Some("git.example.com")), 7);
        assert_eq!(parse(&hello), ClientHello::Sni("git.example.com".into()));
        let cut = hello.len() - 3;
        assert_eq!(parse(&hello[..cut]), ClientHello::NeedMore);
    }

    #[test]
    fn oversized_input_is_malformed() {
        let hello = client_hello(Some("git.example.com"));
        // A handshake claiming more than the cap is rejected before it arrives.
        let mut big = hello.clone();
        big[6..9].copy_from_slice(&[0x01, 0x00, 0x00]);
        assert_eq!(parse(&big), ClientHello::Malformed);
        // Records that never complete the message are cut off at the cap.
        let mut endless = hello[..9].to_vec();
        endless[6..9].copy_from_slice(&[0x00, 0x3f, 0xff]);
        endless.resize(MAX_INPUT, 0);
        let endless = split_records(&endless, 100);
        assert_eq!(parse(&endless[..MAX_INPUT - 1]), ClientHello::NeedMore);
        assert_eq!(parse(&endless), ClientHello::Malformed);
    }

    #[test]
    fn non_tls_input() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), ClientHello::NotTls);
        assert_eq!(parse(b"\x16\x01"), ClientHello::NotTls);
    }

    #[test]
    fn non_handshake_record_after_the_first_is_malformed() {
        let hello = split_records(&client_hello(Some("a.example")), 50);
        let mut bad = hello[..55].to_vec();
        bad.extend_from_slice(b"\x17\x03\x03\x00\x01x");
        assert_eq!(parse(&bad), ClientHello::Malformed);
    }

    #[test]
    fn garbage_lengths_do_not_panic() {
        let hello = client_hello(Some("git.example.com"));
        for at in 0..hello.len() {
            for value in [0x00, 0x01, 0x7f, 0xff] {
                let mut bad = hello.clone();
                bad[at] = value;
                let _ = parse(&bad);
            }
        }
        let mut state = 0x2545_f491_u32;
        for _ in 0..2000 {
            let mut bytes = vec![0x16, 0x03, 0x01];
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                bytes.push(state as u8);
            }
            let _ = parse(&bytes);
        }
    }

    #[test]
    fn reports_the_sni_host_name() {
        assert_eq!(
            parse(&client_hello(Some("git.example.com"))),
            ClientHello::Sni("git.example.com".into())
        );
    }
}
