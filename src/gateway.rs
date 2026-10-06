//! Subcommand implementations.

use anyhow::Context;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};

use crate::cli::PolicyArgs;
use crate::firewall;
use crate::policy::Policy;
use crate::ruleset::{Ruleset, TABLE};

fn load(args: &PolicyArgs) -> anyhow::Result<Ruleset> {
    let policy = Policy::load(&args.policy)?;
    Ok(Ruleset::from_policy(&policy, &args.external_iface)?)
}

pub fn check(args: &PolicyArgs) -> anyhow::Result<()> {
    print!("{}", load(args)?);
    Ok(())
}

pub async fn run(args: &PolicyArgs) -> anyhow::Result<()> {
    let ruleset = load(args)?;

    // Install handlers before touching nftables so a signal during apply still reaches teardown.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

    if let Err(e) = firewall::apply(&ruleset) {
        if let Err(t) = firewall::teardown() {
            warn!("teardown after failed apply also failed: {t}");
        }
        return Err(e).context("provisioning access");
    }
    info!(
        table = TABLE,
        iface = %ruleset.external_iface,
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

pub fn teardown() -> anyhow::Result<()> {
    if firewall::teardown()? {
        info!(table = TABLE, "table removed");
    } else {
        info!(table = TABLE, "table not present");
    }
    Ok(())
}
