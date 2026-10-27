//! Runs the `nft` binary: `nft -j -f -` (apply), `nft -c -j -f -` (check) and `nft --version`,
//! each under a fixed deadline, with stderr captured verbatim. Parsing the version and
//! classifying a failure are pure functions.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Every `nft` child is killed after this long (#27).
pub(crate) const NFT_TIMEOUT: Duration = Duration::from_secs(30);

/// The oldest nftables whose JSON parser accepts everything Drawbridge emits (#23).
pub(crate) const MIN_VERSION: NftVersion = NftVersion {
    major: 0,
    minor: 9,
    patch: 3,
};

/// The first three components of an nftables release (a 4th, as in `1.0.6.1`, is ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NftVersion {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) patch: u32,
}

impl fmt::Display for NftVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parses `nft --version` output, e.g. `nftables v1.1.3 (Commodore Bullwinkle #4)`.
pub(crate) fn parse_version(output: &str) -> Option<NftVersion> {
    let rest = output.trim_start().strip_prefix("nftables v")?;
    let token = rest.split_whitespace().next()?;
    let mut parts = token.split('.');
    let mut next = || -> Option<u32> {
        let p = parts.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    Some(NftVersion {
        major: next()?,
        minor: next()?,
        patch: next()?,
    })
}

/// Why running `nft` failed. `stderr` is nft's own output, trimmed but otherwise verbatim.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error(
        "nft not found at {}: install nftables (>= {MIN_VERSION}) or point --nft-path at it",
        path.display()
    )]
    NotFound { path: PathBuf },
    #[error("failed to run nft")]
    Spawn(#[source] io::Error),
    #[error(
        "nft was denied permission: Drawbridge needs CAP_NET_ADMIN and it must survive exec \
         (run as root, or with systemd AmbientCapabilities=CAP_NET_ADMIN): {stderr}"
    )]
    PermissionDenied { stderr: String },
    #[error(
        "nft rejected command {index} of the batch as invalid JSON; this is a Drawbridge bug: {stderr}"
    )]
    InvalidJson { index: usize, stderr: String },
    #[error("nft rejected the batch: {stderr}")]
    Rejected { stderr: String },
    #[error(
        "nft did not finish within {after:?} and was killed; the batch may have been committed"
    )]
    Timeout { after: Duration },
}

/// Classifies the stderr of an `nft` run that exited non-zero. The permission check runs first.
pub(crate) fn classify(stderr: &str) -> NftError {
    let stderr = stderr.trim().to_owned();
    if stderr.contains("Operation not permitted") {
        return NftError::PermissionDenied { stderr };
    }
    const MARKER: &str = "Parsing command array at index ";
    if let Some(at) = stderr.find(MARKER) {
        let digits: String = stderr[at + MARKER.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(index) = digits.parse() {
            return NftError::InvalidJson { index, stderr };
        }
    }
    NftError::Rejected { stderr }
}

/// Spawns `nft` from an absolute path (never looked up in `PATH`).
#[derive(Debug, Clone)]
pub(crate) struct Nft {
    path: PathBuf,
    timeout: Duration,
}

impl Nft {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: NFT_TIMEOUT,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Applies a JSON batch with `nft -j -f -`.
    pub(crate) async fn apply(&self, json: &str) -> Result<(), NftError> {
        self.run(&["-j", "-f", "-"], Some(json)).await.map(drop)
    }

    /// Dry-runs a JSON batch with `nft -c -j -f -`; nothing is committed.
    pub(crate) async fn check(&self, json: &str) -> Result<(), NftError> {
        self.run(&["-c", "-j", "-f", "-"], Some(json))
            .await
            .map(drop)
    }

    /// Returns the raw stdout of `nft --version`, trimmed.
    pub(crate) async fn version(&self) -> Result<String, NftError> {
        self.run(&["--version"], None).await
    }

    async fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
        let mut child = Command::new(&self.path)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => NftError::NotFound {
                    path: self.path.clone(),
                },
                _ => NftError::Spawn(e),
            })?;

        let mut child_stdin = child.stdin.take();
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let input = stdin.unwrap_or_default().as_bytes();

        let work = async {
            let write = async {
                if let Some(mut pipe) = child_stdin.take() {
                    pipe.write_all(input).await?;
                    pipe.shutdown().await?;
                }
                Ok::<_, io::Error>(())
            };
            let mut out = Vec::new();
            let mut err = Vec::new();
            let (w, o, e) = tokio::join!(
                write,
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err)
            );
            // A child that exits without reading stdin breaks the pipe; its status says why.
            if let Err(e) = w
                && e.kind() != io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
            o?;
            e?;
            let status = child.wait().await?;
            Ok((status, out, err))
        };

        let (status, out, err) = match tokio::time::timeout(self.timeout, work).await {
            Ok(result) => result.map_err(NftError::Spawn)?,
            Err(_) => {
                // `work` is dropped here; kill and reap the child before reporting.
                let _ = child.kill().await;
                return Err(NftError::Timeout {
                    after: self.timeout,
                });
            }
        };
        if status.success() {
            Ok(String::from_utf8_lossy(&out).trim().to_owned())
        } else {
            Err(classify(&String::from_utf8_lossy(&err)))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn v(major: u32, minor: u32, patch: u32) -> NftVersion {
        NftVersion {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn parses_real_version_strings() {
        assert_eq!(
            parse_version("nftables v1.1.3 (Commodore Bullwinkle #4)\n"),
            Some(v(1, 1, 3))
        );
        assert_eq!(parse_version("nftables v0.9.3 (Topsy)"), Some(v(0, 9, 3)));
        assert_eq!(
            parse_version("nftables v1.0.6.1 (Lester Gooch #5)"),
            Some(v(1, 0, 6))
        );
        assert_eq!(
            parse_version("nftables v1.0.2 (Lester Gooch)"),
            Some(v(1, 0, 2))
        );
    }

    #[test]
    fn rejects_unparseable_version_output() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("iptables v1.8.9 (nf_tables)"), None);
        assert_eq!(parse_version("nftables v1.x.3"), None);
        assert_eq!(parse_version("nftables v1.1"), None);
    }

    #[test]
    fn floor_is_0_9_3() {
        assert!(v(0, 9, 0) < MIN_VERSION);
        assert!(v(0, 9, 3) >= MIN_VERSION);
        assert!(v(1, 0, 2) >= MIN_VERSION);
    }

    #[test]
    fn classifies_permission_denied() {
        let e = classify("netlink: Error: cache initialization failed: Operation not permitted\n");
        assert!(matches!(e, NftError::PermissionDenied { ref stderr }
            if stderr == "netlink: Error: cache initialization failed: Operation not permitted"));
    }

    #[test]
    fn permission_check_runs_first() {
        let e = classify(
            "netlink: Error: cache initialization failed: Operation not permitted\n\
             internal:0:0-0: Error: Parsing command array at index 1 failed.",
        );
        assert!(matches!(e, NftError::PermissionDenied { .. }));
    }

    #[test]
    fn classifies_invalid_json_with_index() {
        let e = classify(
            "/j/3schema.json:1:4-4: Error: Object item not found: name\n\
             internal:0:0-0: Error: Parsing command array at index 1 failed.\n",
        );
        assert!(matches!(e, NftError::InvalidJson { index: 1, ref stderr }
            if stderr.ends_with("index 1 failed.")));
        let e = classify("internal:0:0-0: Error: Parsing command array at index 42 failed.");
        assert!(matches!(e, NftError::InvalidJson { index: 42, .. }));
    }

    #[test]
    fn other_errors_are_rejected_verbatim() {
        let raw = "internal:0:0-0: Error: Could not process rule: No such file or directory\n\
                   internal:0:0-0: Error: Could not process rule: No such file or directory\n";
        let e = classify(raw);
        assert!(matches!(e, NftError::Rejected { ref stderr } if stderr == raw.trim()));
        assert!(matches!(
            classify("file:1:1-1: Error: syntax error, unexpected '{'"),
            NftError::Rejected { .. }
        ));
    }

    /// A fake `nft` in a fresh temp directory.
    pub(crate) fn fake_nft(name: &str, script: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("drawbridge-nft-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nft");
        std::fs::write(
            &path,
            format!("#!/bin/sh\n[ -n \"$FAKE_NFT_PROBE\" ] && exit 0\n{script}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Another test thread's fork may briefly inherit our write fd, making exec fail with
        // ETXTBSY. Wait until the file can be executed.
        for _ in 0..100 {
            match std::process::Command::new(&path)
                .env("FAKE_NFT_PROBE", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => break,
            }
        }
        path
    }

    #[tokio::test]
    async fn missing_binary_is_not_found() {
        let path = PathBuf::from("/nonexistent/drawbridge/nft");
        let e = Nft::new(&path).version().await.unwrap_err();
        assert!(matches!(e, NftError::NotFound { path: ref p } if *p == path));
    }

    #[tokio::test]
    async fn non_executable_is_spawn_error() {
        let path = fake_nft("noexec", "exit 0");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = Nft::new(&path).version().await.unwrap_err();
        assert!(matches!(e, NftError::Spawn(_)), "{e:?}");
    }

    #[tokio::test]
    async fn version_returns_stdout_and_passes_args() {
        let path = fake_nft(
            "version",
            r#"echo "nftables v1.1.3 (Commodore Bullwinkle #4) $*""#,
        );
        let out = Nft::new(&path).version().await.unwrap();
        assert_eq!(out, "nftables v1.1.3 (Commodore Bullwinkle #4) --version");
    }

    /// A fake `nft` that succeeds only for `args` and `{"nftables":[]}` on stdin.
    fn expecting(name: &str, args: &str) -> PathBuf {
        fake_nft(
            name,
            &format!(
                r#"[ "$*" = "{args}" ] || {{ echo "args: $*" >&2; exit 2; }}
[ "$(cat)" = '{{"nftables":[]}}' ] || {{ echo "bad stdin" >&2; exit 2; }}"#
            ),
        )
    }

    #[tokio::test]
    async fn apply_sends_json_on_stdin() {
        let nft = Nft::new(expecting("apply", "-j -f -"));
        nft.apply(r#"{"nftables":[]}"#).await.unwrap();
    }

    #[tokio::test]
    async fn check_uses_check_mode() {
        let nft = Nft::new(expecting("check", "-c -j -f -"));
        nft.check(r#"{"nftables":[]}"#).await.unwrap();
        let e = nft.apply(r#"{"nftables":[]}"#).await.unwrap_err();
        assert!(matches!(e, NftError::Rejected { ref stderr } if stderr == "args: -j -f -"));
    }

    #[tokio::test]
    async fn failure_is_classified_from_stderr() {
        let path = fake_nft(
            "fail",
            "cat >/dev/null; echo 'netlink: Error: cache initialization failed: Operation not permitted' >&2; exit 1",
        );
        let e = Nft::new(&path).apply("{}").await.unwrap_err();
        assert!(matches!(e, NftError::PermissionDenied { .. }), "{e:?}");
    }

    #[tokio::test]
    async fn child_that_ignores_stdin_still_reports() {
        let path = fake_nft("nostdin", "echo 'Error: nope' >&2; exit 1");
        let big = "x".repeat(1 << 20);
        let e = Nft::new(&path).apply(&big).await.unwrap_err();
        assert!(
            matches!(e, NftError::Rejected { ref stderr } if stderr == "Error: nope"),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn hung_nft_times_out() {
        let path = fake_nft("hang", "exec sleep 30");
        let nft = Nft {
            timeout: Duration::from_millis(200),
            ..Nft::new(&path)
        };
        let started = std::time::Instant::now();
        let e = nft.version().await.unwrap_err();
        assert!(matches!(e, NftError::Timeout { after } if after == Duration::from_millis(200)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
