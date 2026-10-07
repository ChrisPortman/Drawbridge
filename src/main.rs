use std::process::ExitCode;

use clap::Parser;
use drawbridge::cli::{self, Cli, Command};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Run(args) => cli::run(args).await,
        Command::Check(args) => cli::check(args),
        Command::Teardown(args) => cli::teardown(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
