//! Command-line interface. Every option can also be set via a `DRAWBRIDGE_*` environment variable.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

mod client;
mod gateway;

pub use crate::portal::Secret;
pub use client::{init, login, logout, service};
pub use gateway::{check, run, teardown};

#[derive(Debug, Parser)]
#[command(version, about = "Drawbridge: identity-aware L3/L4 access gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the gateway.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Log in to a gateway from this machine and keep the session alive.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Provision the policy, wait for SIGINT/SIGTERM, then deprovision it.
    Run(Box<RunArgs>),
    /// Validate the policy and print the ruleset that `run` would install.
    Check(PolicyArgs),
    /// Remove the gateway's nftables table, e.g. after a crash.
    Teardown(LockArgs),
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Write the client settings and the drawbridge-client user service.
    Init(InitArgs),
    /// Start drawbridge-client.service, which logs you in through your browser, and wait until
    /// access is live. Same as `systemctl --user start drawbridge-client`. If you interrupt it,
    /// the login carries on in the background; `logout` cancels it.
    Login(UnitArgs),
    /// Stop drawbridge-client.service, which ends the session at the gateway. Same as
    /// `systemctl --user stop drawbridge-client`.
    Logout(UnitArgs),
    /// The process drawbridge-client.service runs: logs in, keeps the session alive, and ends
    /// it when stopped.
    #[command(hide = true)]
    Service(ClientArgs),
}

/// `client init` settings, saved to `$XDG_CONFIG_HOME/drawbridge/client.yaml`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// The gateway portal's base URL, e.g. `https://gateway.example:443`.
    #[arg(long, env = "DRAWBRIDGE_PORTAL_URL")]
    pub portal_url: url::Url,
    /// PEM CA certificates to trust for the portal, besides the system's, comma-separated.
    #[arg(long, env = "DRAWBRIDGE_CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    /// Don't open a browser to log in; follow the URL that `login` prints instead.
    #[arg(long, env = "DRAWBRIDGE_NO_BROWSER")]
    pub no_browser: bool,
    /// Don't check the portal's TLS certificate. **Only for test setups**: anyone between you and
    /// the gateway could then pose as the portal and take your session.
    #[arg(
        long,
        env = "DRAWBRIDGE_INSECURE_SKIP_TLS_VERIFY",
        conflicts_with = "ca_cert"
    )]
    pub insecure_skip_tls_verify: bool,
    #[command(flatten)]
    pub unit: UnitArgs,
}

/// How to reach the user's service manager.
#[derive(Debug, Args)]
pub struct UnitArgs {
    /// The systemctl binary; tests substitute a stand-in.
    #[arg(
        long,
        env = "DRAWBRIDGE_SYSTEMCTL",
        default_value = "systemctl",
        hide = true
    )]
    pub systemctl: PathBuf,
}

/// The client service's settings. Flags and environment variables override the settings file.
#[derive(Debug, Args)]
pub struct ClientArgs {
    /// Settings file; defaults to `$XDG_CONFIG_HOME/drawbridge/client.yaml`.
    #[arg(long, env = "DRAWBRIDGE_CLIENT_CONFIG")]
    pub config: Option<PathBuf>,
    /// The gateway portal's base URL.
    #[arg(long, env = "DRAWBRIDGE_PORTAL_URL")]
    pub portal_url: Option<url::Url>,
    /// PEM CA certificates to trust for the portal, besides the system's, comma-separated.
    #[arg(long, env = "DRAWBRIDGE_CA_CERT", value_delimiter = ',')]
    pub ca_cert: Vec<PathBuf>,
    /// Don't check the portal's TLS certificate. **Only for test setups**: anyone between you and
    /// the gateway could then pose as the portal and take your session.
    #[arg(long, env = "DRAWBRIDGE_INSECURE_SKIP_TLS_VERIFY")]
    pub insecure_skip_tls_verify: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,
    #[command(flatten)]
    pub lock: LockArgs,
    #[command(flatten)]
    pub portal: PortalArgs,
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Path to the YAML allow-list policy.
    #[arg(long, env = "DRAWBRIDGE_POLICY")]
    pub policy: PathBuf,
    /// Interface that clients connect through (e.g. wg0).
    #[arg(long, env = "DRAWBRIDGE_EXTERNAL_IFACE")]
    pub external_iface: String,
    /// Gateway addresses for the login portal's HTTPS listener, comma-separated (e.g.
    /// 10.8.0.1:443). Setting this enables the portal; every client may connect to it.
    #[arg(long, env = "DRAWBRIDGE_PORTAL_LISTEN", value_delimiter = ',')]
    pub portal_listen: Vec<SocketAddr>,
    /// Accept traffic the policy doesn't allow instead of dropping it, logging it as
    /// "drawbridge would-drop". For rolling out onto a gateway already carrying traffic: tune the
    /// policy until nothing you need is logged, then restart without this flag.
    #[arg(long, env = "DRAWBRIDGE_PERMISSIVE")]
    pub permissive: bool,
}

/// Login portal and OIDC settings. Required when `--portal-listen` is set.
#[derive(Debug, Args)]
pub struct PortalArgs {
    /// The portal's base URL as clients reach it, e.g. `https://gateway.example:443`. The OIDC
    /// redirect URI is this URL's `/callback`.
    #[arg(long, env = "DRAWBRIDGE_PORTAL_URL")]
    pub portal_url: Option<url::Url>,
    /// PEM certificate chain for the portal.
    #[arg(long, env = "DRAWBRIDGE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key for the portal.
    #[arg(long, env = "DRAWBRIDGE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
    /// OIDC issuer URL; its discovery document is fetched at startup.
    #[arg(long, env = "DRAWBRIDGE_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,
    #[arg(long, env = "DRAWBRIDGE_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,
    /// Prefer the environment variable, so the secret doesn't show in the process list.
    #[arg(long, env = "DRAWBRIDGE_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: Option<Secret>,
    /// ID-token claim matched against `users[].username`. `email` counts only when verified.
    /// Use a claim only administrators can change: some providers let users edit
    /// `preferred_username`, which would let them pick whose access they get.
    #[arg(
        long,
        env = "DRAWBRIDGE_OIDC_USERNAME_CLAIM",
        default_value = "preferred_username"
    )]
    pub oidc_username_claim: String,
    /// Scopes to request besides `openid`, comma-separated. `offline_access` asks for the refresh
    /// tokens that keep sessions alive; without them, browsers re-authenticate with the
    /// provider and the client service can't extend its session.
    #[arg(
        long,
        env = "DRAWBRIDGE_OIDC_SCOPES",
        value_delimiter = ',',
        default_value = "profile,offline_access"
    )]
    pub oidc_scopes: Vec<String>,
    /// Permit an `http://` issuer, token endpoint or JWKS URL. Only for test setups: the client
    /// secret and tokens then cross the network in cleartext.
    #[arg(long, env = "DRAWBRIDGE_OIDC_ALLOW_INSECURE_HTTP")]
    pub oidc_allow_insecure_http: bool,
    /// Longest a login (or re-authentication) keeps access, however long the ID token lasts,
    /// e.g. `900`, `15m` or `2h`. `0` follows the token's expiry alone.
    #[arg(
        long,
        env = "DRAWBRIDGE_SESSION_MAX_TTL",
        default_value = "15m",
        value_parser = parse_duration
    )]
    pub session_max_ttl: Duration,
}

/// Seconds, optionally suffixed with `s`, `m` or `h`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (digits, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
        _ => (s, 's'),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?}: use e.g. 900, 15m or 2h"))?;
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        _ => return Err(format!("invalid duration unit in {s:?}: use s, m or h")),
    };
    n.checked_mul(mult)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration {s:?} is too large"))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &str) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("drawbridge").chain(args.split_whitespace()))
    }

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_server_and_client_commands() {
        let cli = parse("server check --policy p.yaml --external-iface wg0").unwrap();
        assert!(matches!(
            cli.command,
            Command::Server {
                command: ServerCommand::Check(_)
            }
        ));
        let cli = parse("server teardown --lock-file /tmp/l").unwrap();
        assert!(matches!(
            cli.command,
            Command::Server {
                command: ServerCommand::Teardown(_)
            }
        ));
        let cli = parse(
            "client init --portal-url https://gw.example:8443 --ca-cert a.pem,b.pem --no-browser",
        )
        .unwrap();
        let Command::Client {
            command: ClientCommand::Init(init),
        } = cli.command
        else {
            panic!("not init");
        };
        assert_eq!(init.portal_url.as_str(), "https://gw.example:8443/");
        assert_eq!(
            init.ca_cert,
            [PathBuf::from("a.pem"), PathBuf::from("b.pem")]
        );
        assert!(init.no_browser && !init.insecure_skip_tls_verify);
        assert!(
            parse("client init --portal-url https://gw.example --insecure-skip-tls-verify").is_ok()
        );
        // Trusting a CA and trusting anything don't mix.
        let both = "client init --portal-url https://gw.example --ca-cert a.pem \
                    --insecure-skip-tls-verify";
        assert!(parse(both).is_err());
        assert!(parse("client login").is_ok());
        assert!(parse("client logout").is_ok());
        assert!(parse("client service --portal-url https://gw.example").is_ok());
        // The old top-level commands are gone.
        assert!(parse("run").is_err());
    }

    #[test]
    fn service_is_hidden_from_help() {
        let help = Cli::command()
            .find_subcommand_mut("client")
            .unwrap()
            .render_help()
            .to_string();
        let listed = |name: &str| help.lines().any(|l| l.trim_start().starts_with(name));
        assert!(listed("login") && !listed("service"), "{help}");
    }

    #[test]
    fn parses_durations() {
        for (s, secs) in [
            ("900", 900),
            ("30s", 30),
            ("15m", 900),
            ("2h", 7200),
            ("0", 0),
        ] {
            assert_eq!(parse_duration(s), Ok(Duration::from_secs(secs)), "{s}");
        }
        for s in ["", "m", "15x", "-1", "1.5h", "99999999999999999999h"] {
            assert!(parse_duration(s).is_err(), "{s}");
        }
    }
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
