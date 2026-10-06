//! Subcommand implementations.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

use crate::cli::{LockArgs, PolicyArgs, RunArgs};
use crate::firewall;
use crate::policy::Policy;
use crate::ruleset::{Ruleset, TABLE};

fn load(args: &PolicyArgs) -> anyhow::Result<Ruleset> {
    let policy = Policy::load(&args.policy)?;
    Ok(Ruleset::from_policy(&policy, &args.external_iface)?)
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
    print!("{}", load(args)?);
    Ok(())
}

pub async fn run(args: &RunArgs) -> anyhow::Result<()> {
    let ruleset = load(&args.policy)?;
    let _lock = lock(&args.lock)?;

    // A misnamed interface would install rules that match nothing, leaving clients unfiltered.
    let iface = &ruleset.external_iface;
    let iface_index = nix::net::if_::if_nametoindex(iface.as_str())
        .with_context(|| format!("external interface {iface:?} not found"))?;

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
        "access provisioned"
    );

    tokio::select! {
        _ = sigint.recv() => info!("received SIGINT"),
        _ = sigterm.recv() => info!("received SIGTERM"),
    }

    firewall::teardown().context("deprovisioning access")?;
    info!(table = TABLE, "access deprovisioned");
    Ok(())
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
