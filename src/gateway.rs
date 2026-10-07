//! Subcommand implementations.

use std::fs::{File, OpenOptions, TryLockError};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use axum_server::tls_rustls::RustlsConfig;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::cli::{LockArgs, PolicyArgs, PortalArgs, RunArgs};
use crate::firewall;
use crate::oidc::{Oidc, OidcConfig};
use crate::policy::Policy;
use crate::portal::{self, Portal};
use crate::ruleset::{Mode, Ruleset, TABLE};
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

/// Everything the portal needs, set up before the firewall is touched so a misconfiguration
/// can't leave the table half-provisioned.
struct PreparedPortal {
    oidc: Oidc,
    tls: RustlsConfig,
    listeners: Vec<TcpListener>,
}

/// Unwraps a required portal option, naming its flag and environment variable.
fn required<T>(value: Option<T>, flag: &str) -> anyhow::Result<T> {
    let env = format!("DRAWBRIDGE_{}", flag.to_uppercase().replace('-', "_"));
    value.with_context(|| format!("--{flag} ({env}) is required when the portal is enabled"))
}

async fn prepare_portal(
    args: &PortalArgs,
    listen: &[SocketAddr],
) -> anyhow::Result<PreparedPortal> {
    let url = required(args.portal_url.clone(), "portal-url")?;
    if url.scheme() != "https" {
        bail!("--portal-url must be an https URL, got {url}");
    }
    let redirect_url = url.join("callback").context("building the redirect URL")?;
    let cert = required(args.tls_cert.as_ref(), "tls-cert")?;
    let key = required(args.tls_key.as_ref(), "tls-key")?;
    let config = OidcConfig {
        issuer: required(args.oidc_issuer.clone(), "oidc-issuer")?,
        client_id: required(args.oidc_client_id.clone(), "oidc-client-id")?,
        client_secret: required(args.oidc_client_secret.clone(), "oidc-client-secret")?,
        redirect_url: redirect_url.into(),
        username_claim: args.oidc_username_claim.clone(),
        scopes: args.oidc_scopes.clone(),
        allow_insecure_http: args.oidc_allow_insecure_http,
    };

    let tls = RustlsConfig::from_pem_file(cert, key)
        .await
        .with_context(|| {
            format!(
                "loading TLS certificate {} and key {}",
                cert.display(),
                key.display()
            )
        })?;
    let issuer = config.issuer.clone();
    let oidc = Oidc::discover(config)
        .await
        .with_context(|| format!("contacting OIDC issuer {issuer}"))?;
    let listeners = listen
        .iter()
        .map(|&addr| {
            let l = TcpListener::bind(addr)
                .with_context(|| format!("binding portal listener {addr}"))?;
            l.set_nonblocking(true)?;
            Ok(l)
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(PreparedPortal {
        oidc,
        tls,
        listeners,
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

    let prepared = if listen.is_empty() {
        None
    } else {
        // rustls needs a process-wide crypto provider; `Err` only means one is installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Some(prepare_portal(&args.portal, listen).await?)
    };

    // Install handlers before touching nftables so a signal during apply still reaches teardown.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

    // The apply batch is atomic: if it fails, the previous state (including any table left by an
    // earlier run) is still in place, so tearing down here could only remove enforcement.
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

    let mut servers = JoinSet::new();
    let server_handle = axum_server::Handle::new();
    let mut sessions_task = None;
    if let Some(p) = prepared {
        let (sessions, task) = session::spawn(SessionTable::new(
            Arc::new(policy),
            Kernel {
                base: ruleset.clone(),
            },
            args.portal.session_max_ttl,
        ));
        sessions_task = Some(task);
        let app = portal::router(Portal::new(p.oidc, sessions))
            .into_make_service_with_connect_info::<SocketAddr>();
        for listener in p.listeners {
            let addr = listener.local_addr()?;
            let server = axum_server::from_tcp_rustls(listener, p.tls.clone())?
                .handle(server_handle.clone());
            let app = app.clone();
            servers.spawn(async move { (addr, server.serve(app).await) });
            info!(%addr, "portal listening");
        }
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
        Some(joined) = servers.join_next() => Some(match joined {
            Ok((addr, Ok(()))) => anyhow::anyhow!("portal listener {addr} stopped"),
            Ok((addr, Err(e))) => anyhow::Error::new(e).context(format!("portal listener {addr} failed")),
            Err(e) => anyhow::Error::new(e).context("portal task panicked"),
        }),
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

    server_handle.graceful_shutdown(Some(PORTAL_DRAIN));
    while servers.join_next().await.is_some() {}
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
