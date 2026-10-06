use std::process::ExitCode;

use access_portal::cli::{Cli, Command};
use access_portal::gateway;
use clap::Parser;
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
        Command::Teardown => gateway::teardown(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
