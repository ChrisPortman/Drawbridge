//! Applies a [`Ruleset`] to the kernel by sending `nft -j` batches (built by `json`) through the
//! `nft` binary (run by `nft`).

mod json;
mod nft;
pub mod ruleset;

pub use nft::NftError;

use std::path::PathBuf;

use nftables::schema::{NfObject, Nftables};
use tracing::{debug, error};

use nft::{MIN_VERSION, Nft, parse_version};
use ruleset::{Ruleset, SessionRules};

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error(transparent)]
    Nft(#[from] NftError),
    #[error(
        "the kernel rejected the drop log; check that the nft_log, nf_log_syslog and nft_limit \
         modules are available (built in, or loadable): {stderr}"
    )]
    DropLog { stderr: String },
    #[error(
        "the kernel rejected the transparent proxy's rules; check that the nft_redir, nft_nat, \
         nft_fib_inet and nf_conntrack modules are available (built in, or loadable): {stderr}"
    )]
    Proxy { stderr: String },
    #[error("nft at {} is v{found}; Drawbridge needs nftables >= {MIN_VERSION}", path.display())]
    UnsupportedVersion { path: PathBuf, found: String },
    #[error(
        "can't parse the version of nft at {} from {raw:?}; if this nft is >= {MIN_VERSION}, \
         set --nft-skip-version-check",
        path.display()
    )]
    UnparseableVersion { path: PathBuf, raw: String },
}

/// The gateway's handle on nftables, through the `nft` binary at an absolute path.
#[derive(Debug, Clone)]
pub struct Firewall {
    nft: Nft,
}

impl Firewall {
    pub fn new(nft_path: impl Into<PathBuf>) -> Self {
        Self {
            nft: Nft::new(nft_path),
        }
    }

    /// Runs `nft --version` and returns its raw output. Unless `skip_floor`, also checks that it
    /// is at least [`MIN_VERSION`]. A missing or hung nft is an error either way.
    pub(crate) async fn check_version(&self, skip_floor: bool) -> Result<String, FirewallError> {
        let raw = self.nft.version().await?;
        if skip_floor {
            return Ok(raw);
        }
        let path = self.nft.path().to_owned();
        match parse_version(&raw) {
            Some(v) if v >= MIN_VERSION => Ok(raw),
            Some(v) => Err(FirewallError::UnsupportedVersion {
                path,
                found: v.to_string(),
            }),
            None => Err(FirewallError::UnparseableVersion { path, raw }),
        }
    }

    /// Dry-runs the teardown batch with `nft -c`, so a missing capability shows up before any
    /// change. Commits nothing.
    pub(crate) async fn probe(&self) -> Result<(), FirewallError> {
        self.dry_run(&json::teardown()).await
    }

    /// Atomically replaces the gateway table with one implementing `ruleset`. If the kernel
    /// rejects it but accepts the same batch without the drop log, reports
    /// [`FirewallError::DropLog`]; failing that, if it accepts the batch without the proxy's rules,
    /// [`FirewallError::Proxy`]. Each dry run leaves out one part only, so a kernel missing both
    /// sets of modules gets the plain rejection.
    pub async fn apply(&self, ruleset: &Ruleset) -> Result<(), FirewallError> {
        let err = match self.send(&json::apply(ruleset)).await {
            Ok(()) => return Ok(()),
            Err(FirewallError::Nft(NftError::Rejected { stderr })) => stderr,
            Err(e) => return Err(e),
        };
        // Kernel errors carry no command index; dry-run without the drop log to attribute it.
        match self.dry_run(&json::apply_without_drop_log(ruleset)).await {
            Ok(()) => return Err(FirewallError::DropLog { stderr: err }),
            Err(retry) => debug!(error = %retry, "the batch without the drop log was rejected too"),
        }
        match self.dry_run(&json::apply_without_nat(ruleset)).await {
            Ok(()) => Err(FirewallError::Proxy { stderr: err }),
            Err(retry) => {
                debug!(error = %retry, "the batch without the nat chains was rejected too");
                Err(NftError::Rejected { stderr: err }.into())
            }
        }
    }

    /// Atomically installs `added` sessions, removes the chains of the `removed` session ids, and
    /// rewrites the dispatch chains and `proxy_redirect` for the `live` sessions, which must
    /// include `added`, on top of `base`'s client redirects. The table must already exist (see
    /// [`Firewall::apply`]).
    pub async fn update_sessions(
        &self,
        base: &Ruleset,
        added: &[SessionRules],
        removed: &[u32],
        live: &[SessionRules],
    ) -> Result<(), FirewallError> {
        self.send(&json::update_sessions(base, added, removed, live))
            .await
    }

    /// Deletes the gateway table. Succeeds whether or not it exists.
    pub async fn teardown(&self) -> Result<(), FirewallError> {
        self.send(&json::teardown()).await
    }

    async fn send(&self, doc: &Nftables<'_>) -> Result<(), FirewallError> {
        let result = self.nft.apply(&to_json(doc)).await;
        Ok(result.inspect_err(|e| log_invalid(doc, e))?)
    }

    async fn dry_run(&self, doc: &Nftables<'_>) -> Result<(), FirewallError> {
        let result = self.nft.check(&to_json(doc)).await;
        Ok(result.inspect_err(|e| log_invalid(doc, e))?)
    }
}

fn to_json(doc: &Nftables) -> String {
    serde_json::to_string(doc).expect("nftables documents always serialize")
}

/// Logs the command nft refused to parse: a Drawbridge bug.
fn log_invalid(doc: &Nftables, e: &NftError) {
    if let NftError::InvalidJson { index, .. } = e {
        let cmd =
            invalid_command(doc, *index).map(|c| serde_json::to_string(c).unwrap_or_default());
        error!(
            index,
            command = cmd.as_deref().unwrap_or("?"),
            "nft rejected a command as invalid JSON"
        );
    }
}

/// The command at nft's "command array" `index`. nft counts every array element (a `metainfo`
/// object too), so this is a plain index into `objects`.
fn invalid_command<'a, 'b>(doc: &'a Nftables<'b>, index: usize) -> Option<&'a NfObject<'b>> {
    doc.objects.get(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use nft::tests::fake_nft;

    fn ruleset() -> Ruleset {
        let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
        Ruleset::from_policy(
            &policy,
            "wg0",
            &["192.168.50.1:8443".parse().unwrap()],
            Some(3128),
        )
        .unwrap()
    }

    /// A fake nft whose `-j -f -` (apply) and `-c -j -f -` (check) runs exit with the given
    /// script fragments.
    fn nft(name: &str, apply: &str, check: &str) -> Firewall {
        Firewall::new(fake_nft(
            name,
            &format!(
                r#"cat >/dev/null
case "$*" in
  "-j -f -") {apply} ;;
  "-c -j -f -") {check} ;;
  *) echo "args: $*" >&2; exit 2 ;;
esac"#
            ),
        ))
    }

    const REJECT: &str =
        "echo 'Error: Could not process rule: No such file or directory' >&2; exit 1";

    #[tokio::test]
    async fn drop_log_is_blamed_when_the_batch_passes_without_it() {
        let fw = nft("fw-droplog", REJECT, "exit 0");
        let e = fw.apply(&ruleset()).await.unwrap_err();
        assert!(
            matches!(e, FirewallError::DropLog { ref stderr } if stderr.contains("No such file")),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn rejection_stands_when_the_retry_also_fails() {
        let fw = nft("fw-rejected", REJECT, REJECT);
        let e = fw.apply(&ruleset()).await.unwrap_err();
        assert!(
            matches!(e, FirewallError::Nft(NftError::Rejected { .. })),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn proxy_is_blamed_when_only_the_batch_without_nat_passes() {
        let fw = Firewall::new(fake_nft(
            "fw-proxy",
            &format!(
                r#"doc=$(cat)
case "$*" in
  "-c -j -f -") case "$doc" in *'"prerouting"'*) {REJECT} ;; *) exit 0 ;; esac ;;
  *) {REJECT} ;;
esac"#
            ),
        ));
        let e = fw.apply(&ruleset()).await.unwrap_err();
        assert!(
            matches!(e, FirewallError::Proxy { ref stderr } if stderr.contains("No such file")),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn permission_denied_is_not_retried() {
        let fw = nft(
            "fw-eperm",
            "echo 'Error: Operation not permitted' >&2; exit 1",
            "exit 0",
        );
        let e = fw.apply(&ruleset()).await.unwrap_err();
        assert!(
            matches!(e, FirewallError::Nft(NftError::PermissionDenied { .. })),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn session_updates_skip_the_drop_log_check() {
        let fw = nft("fw-sessions", REJECT, "exit 0");
        let e = fw
            .update_sessions(&ruleset(), &[], &[1], &[])
            .await
            .unwrap_err();
        assert!(
            matches!(e, FirewallError::Nft(NftError::Rejected { .. })),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn probe_dry_runs_and_teardown_applies() {
        let fw = nft("fw-probe", REJECT, "exit 0");
        fw.probe().await.unwrap();
        assert!(fw.teardown().await.is_err());
    }

    /// Captured from nft v1.1.3 given three commands whose third (a chain without a name) is
    /// invalid. A leading `metainfo` object gives the same index.
    const INVALID_AT_2: &str = "Error: Object item not found: name\n\
        {\"nftables\":[...]}\n   ^\n\
        internal:0:0-0: Error: Parsing command array at index 2 failed.\n";

    #[test]
    fn invalid_json_index_names_the_bad_command() {
        let doc = json::apply(&ruleset());
        let NftError::InvalidJson { index, .. } = nft::classify(INVALID_AT_2) else {
            panic!("not InvalidJson");
        };
        assert_eq!(index, 2);
        assert!(std::ptr::eq(
            invalid_command(&doc, index).unwrap(),
            &doc.objects[2]
        ));
    }

    fn version(name: &str, out: &str) -> Firewall {
        Firewall::new(fake_nft(name, &format!("echo '{out}'")))
    }

    #[tokio::test]
    async fn skipped_version_check_still_needs_nft() {
        let raw = version("fw-v-skip", "nft 2 (new format)")
            .check_version(true)
            .await
            .unwrap();
        assert_eq!(raw, "nft 2 (new format)");

        let e = Firewall::new("/nonexistent/nft")
            .check_version(true)
            .await
            .unwrap_err();
        assert!(matches!(e, FirewallError::Nft(_)), "{e:?}");
    }

    #[tokio::test]
    async fn version_check() {
        let raw = version("fw-v-ok", "nftables v1.0.6 (Lester Gooch #5)")
            .check_version(false)
            .await
            .unwrap();
        assert_eq!(raw, "nftables v1.0.6 (Lester Gooch #5)");

        let e = version("fw-v-old", "nftables v0.9.1 (Headless Horseman)")
            .check_version(false)
            .await
            .unwrap_err();
        assert!(
            e.to_string()
                .ends_with("is v0.9.1; Drawbridge needs nftables >= 0.9.3"),
            "{e}"
        );

        let e = version("fw-v-odd", "nft 2 (new format)")
            .check_version(false)
            .await
            .unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("\"nft 2 (new format)\"") && msg.contains("--nft-skip-version-check"),
            "{msg}"
        );
    }
}
