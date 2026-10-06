//! Command-line interface. Every option can also be set via a `DRAWBRIDGE_*` environment variable.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "Drawbridge: identity-aware L3/L4 access gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Provision the policy, wait for SIGINT/SIGTERM, then deprovision it.
    Run(RunArgs),
    /// Validate the policy and print the ruleset that `run` would install.
    Check(PolicyArgs),
    /// Remove the gateway's nftables table, e.g. after a crash.
    Teardown(LockArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,
    #[command(flatten)]
    pub lock: LockArgs,
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Path to the YAML allow-list policy.
    #[arg(long, env = "DRAWBRIDGE_POLICY")]
    pub policy: PathBuf,
    /// Interface that clients connect through (e.g. wg0).
    #[arg(long, env = "DRAWBRIDGE_EXTERNAL_IFACE")]
    pub external_iface: String,
}

#[derive(Debug, Args)]
pub struct LockArgs {
    /// Lock file ensuring only one instance manages the nftables table at a time.
    #[arg(
        long,
        env = "DRAWBRIDGE_LOCK_FILE",
        default_value = "/run/drawbridge.lock"
    )]
    pub lock_file: PathBuf,
}
