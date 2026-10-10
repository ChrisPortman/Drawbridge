use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use drawbridge::cli::{self, Cli, ClientCommand, Command, ServerCommand};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        // Logs go to stderr, apart from the client commands' output, and have no colour codes in
        // the journal or other captured logs.
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Server { command } => match command {
            ServerCommand::Run(args) => cli::run(args).await,
            ServerCommand::Check(args) => cli::check(args),
            ServerCommand::Teardown(args) => cli::teardown(args),
        },
        Command::Client { command } => match command {
            ClientCommand::Init(args) => cli::init(args),
            ClientCommand::Login(args) => cli::login(args),
            ClientCommand::Logout(args) => cli::logout(args),
            ClientCommand::Service(args) => cli::service(args).await,
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
