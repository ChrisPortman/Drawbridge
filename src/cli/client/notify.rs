//! `sd_notify`: tells systemd about the service's progress (`Type=notify` units).

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

use tracing::warn;

/// Sends `state` (e.g. `READY=1\nSTATUS=…`) to `$NOTIFY_SOCKET`. Does nothing outside systemd,
/// so the service can run in a terminal.
pub(super) fn notify(state: &str) {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Err(e) = send(&socket, state) {
        warn!(error = %e, "could not notify systemd");
    }
}

fn send(socket: &OsStr, state: &str) -> io::Result<()> {
    let addr = match socket.as_bytes().strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)?,
        None => SocketAddr::from_pathname(socket)?,
    };
    UnixDatagram::unbound()?.send_to_addr(state.as_bytes(), &addr)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_path_and_abstract_sockets() {
        let path = std::env::temp_dir().join(format!("drawbridge-notify-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let receiver = UnixDatagram::bind(&path).unwrap();
        send(path.as_os_str(), "READY=1\nSTATUS=ok\n").unwrap();
        let mut buf = [0; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=ok\n");
        std::fs::remove_file(&path).unwrap();

        let name = format!("drawbridge-notify-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&addr).unwrap();
        send(OsStr::new(&format!("@{name}")), "STOPPING=1\n").unwrap();
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1\n");
    }
}
