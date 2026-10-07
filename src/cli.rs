//! Command-line interface. Every option can also be set via a `DRAWBRIDGE_*` environment variable.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

mod gateway;

pub use crate::portal::Secret;
pub use gateway::{check, run, teardown};

#[derive(Debug, Parser)]
#[command(version, about = "Drawbridge: identity-aware L3/L4 access gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Provision the policy, wait for SIGINT/SIGTERM, then deprovision it.
    Run(Box<RunArgs>),
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
    /// The portal's base URL as clients reach it, e.g. https://gateway.example:443. The OIDC
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
    /// Scopes to request besides `openid`, comma-separated.
    #[arg(
        long,
        env = "DRAWBRIDGE_OIDC_SCOPES",
        value_delimiter = ',',
        default_value = "profile"
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
    use super::*;

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
