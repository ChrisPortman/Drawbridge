//! Subcommand implementations.

use std::fs::{File, OpenOptions, TryLockError};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

use super::{LockArgs, PolicyArgs, PortalArgs, RunArgs};
use crate::firewall;
use crate::firewall::ruleset::{Mode, Ruleset, TABLE};
use crate::policy::Policy;
use crate::portal::{OidcConfig, PortalConfig, Prepared, Servers};
use crate::session::{self, Kernel, SessionTable};

/// How long open portal connections get to finish at shutdown.
const PORTAL_DRAIN: Duration = Duration::from_secs(2);

fn load(args: &PolicyArgs) -> anyhow::Result<(Policy, Ruleset)> {
    let policy = Policy::load(&args.policy)?;
    let mut ruleset = Ruleset::from_policy(&policy, &args.external_iface, &args.portal_listen)?;
    if args.permissive {
        ruleset.mode = Mode::Permissive;
    }
    Ok((policy, ruleset))
}

/// Unwraps a required portal option, naming its flag and environment variable.
fn required<T>(value: Option<T>, flag: &str) -> anyhow::Result<T> {
    let env = format!("DRAWBRIDGE_{}", flag.to_uppercase().replace('-', "_"));
    value.with_context(|| format!("--{flag} ({env}) is required when the portal is enabled"))
}

/// Builds the portal's configuration from its flags, which are required once it is enabled.
fn portal_config(args: &PortalArgs, listen: &[SocketAddr]) -> anyhow::Result<PortalConfig> {
    let url = required(args.portal_url.clone(), "portal-url")?;
    if url.scheme() != "https" {
        bail!("--portal-url must be an https URL, got {url}");
    }
    let redirect_url = url.join("callback").context("building the redirect URL")?;
    let tls_cert = required(args.tls_cert.clone(), "tls-cert")?;
    let tls_key = required(args.tls_key.clone(), "tls-key")?;
    Ok(PortalConfig {
        oidc: OidcConfig {
            issuer: required(args.oidc_issuer.clone(), "oidc-issuer")?,
            client_id: required(args.oidc_client_id.clone(), "oidc-client-id")?,
            client_secret: required(args.oidc_client_secret.clone(), "oidc-client-secret")?,
            redirect_url: redirect_url.into(),
            username_claim: args.oidc_username_claim.clone(),
            scopes: args.oidc_scopes.clone(),
            allow_insecure_http: args.oidc_allow_insecure_http,
        },
        tls_cert,
        tls_key,
        listen: listen.to_vec(),
    })
}

/// Takes the instance lock, so one instance can't remove the table another is enforcing with.
/// The lock is released when the returned file is dropped.
fn lock(args: &LockArgs) -> anyhow::Result<File> {
    let path: &Path = &args.lock_file;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening lock file {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another drawbridge instance holds {}", path.display())
        }
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

pub fn check(args: &PolicyArgs) -> anyhow::Result<()> {
    print!("{}", load(args)?.1);
    Ok(())
}

pub async fn run(args: &RunArgs) -> anyhow::Result<()> {
    let (policy, ruleset) = load(&args.policy)?;
    let listen = &args.policy.portal_listen;
    if !policy.users.is_empty() && listen.is_empty() {
        bail!("the policy has users, but the login portal is disabled; set --portal-listen");
    }
    let _lock = lock(&args.lock)?;

    // A misnamed interface would install rules that match nothing, leaving clients unfiltered.
    let iface = &ruleset.external_iface;
    let iface_index = nix::net::if_::if_nametoindex(iface.as_str())
        .with_context(|| format!("external interface {iface:?} not found"))?;

    // Set up before touching nftables, so a misconfiguration can't leave the table provisioned.
    let prepared = if listen.is_empty() {
        None
    } else {
        Some(Prepared::new(portal_config(&args.portal, listen)?).await?)
    };

    // Install handlers before touching nftables so a signal during apply still reaches teardown.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

    // The apply batch is atomic: if it fails, the previous state (including any table left by an
    // earlier run) is still in place, so tearing down here could only remove enforcement.
    // Nothing after it may return early: every exit must go through the teardown below.
    firewall::apply(&ruleset).context("provisioning access")?;
    info!(
        table = TABLE,
        iface = %iface,
        iface_index,
        rules = ruleset.rules.len(),
        mode = ?ruleset.mode,
        "access provisioned"
    );
    if ruleset.mode == Mode::Permissive {
        warn!("permissive mode: traffic outside the policy is logged and allowed, not dropped");
    }

    let mut servers = Servers::default();
    let mut sessions_task = None;
    if let Some(portal) = prepared {
        let (sessions, task) = session::spawn(SessionTable::new(
            Arc::new(policy),
            Kernel {
                base: ruleset.clone(),
            },
            args.portal.session_max_ttl,
        ));
        sessions_task = Some(task);
        servers = portal.serve(sessions);
    }

    // A dead portal or session manager can't be recovered from; shut down (fail-open) and report.
    let sessions_exited = async {
        match sessions_task.as_mut() {
            Some(task) => task.await,
            None => std::future::pending().await,
        }
    };
    let failure = tokio::select! {
        _ = sigint.recv() => { info!("received SIGINT"); None }
        _ = sigterm.recv() => { info!("received SIGTERM"); None }
        Some(e) = servers.stopped() => Some(e.into()),
        exited = sessions_exited => {
            // The handle has completed; awaiting it again below would panic and skip teardown.
            sessions_task = None;
            Some(match exited {
                Ok(()) => anyhow::anyhow!("session manager stopped"),
                Err(e) => anyhow::Error::new(e).context("session manager panicked"),
            })
        }
    };
    if let Some(e) = &failure {
        error!("{e:#}");
    }

    servers.shutdown(PORTAL_DRAIN).await;
    // The session manager must be gone before teardown, or a rebuild could recreate the table.
    if let Some(task) = sessions_task {
        task.abort();
        let _ = task.await;
    }

    firewall::teardown().context("deprovisioning access")?;
    info!(table = TABLE, "access deprovisioned");
    failure.map_or(Ok(()), Err)
}

pub fn teardown(args: &LockArgs) -> anyhow::Result<()> {
    let _lock = lock(args)?;
    if firewall::teardown().context("removing table")? {
        info!(table = TABLE, "table removed");
    } else {
        info!(table = TABLE, "table not present");
    }
    Ok(())
}
