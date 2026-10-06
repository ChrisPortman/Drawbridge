use std::process::ExitCode;

use clap::Parser;
use drawbridge::cli::{Cli, Command};
use drawbridge::gateway;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Run(args) => gateway::run(args).await,
        Command::Check(args) => gateway::check(args),
        Command::Teardown(args) => gateway::teardown(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
