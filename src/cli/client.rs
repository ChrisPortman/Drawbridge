//! `drawbridge client`: logs this machine in to a gateway through a user systemd service.
//!
//! `login` and `logout` only start and stop drawbridge-client.service, so `systemctl --user
//! start|stop drawbridge-client` does the same. The service process does the work: it opens the
//! portal's login in the browser, receives a one-time code on a loopback listener, swaps it for
//! the session token, refreshes the session until stopped, then ends it at the gateway. The token
//! exists only in that process's memory.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use openidconnect::PkceCodeChallenge;
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{ClientArgs, InitArgs, UnitArgs};
use crate::portal::{CliTokenJson, LoginError, SessionJson};
use api::{PortalClient, Refresh};
use loopback::Callback;
use notify::notify;
use openidconnect::CsrfToken;
use unit::{JOURNAL_HINT, LOGIN_TIMEOUT, LOGIN_WAIT_LIMIT, Step, UNIT_NAME};

mod api;
mod loopback;
mod notify;
mod unit;

/// How often `login` polls the unit.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// How long ending the session at the gateway may take at shutdown.
const END_TIMEOUT: Duration = Duration::from_secs(5);
/// Without one of these there is no desktop to open a browser on.
const DISPLAY_SERVERS: [&str; 2] = ["DISPLAY", "WAYLAND_DISPLAY"];
/// The longest a session's expiry is believed to be away, against nonsense from the portal.
const MAX_REMAINING: Duration = Duration::from_secs(86_400);
/// What `login` passes to the user manager, so the service can open a browser there.
const DISPLAY_VARS: [&str; 3] = [DISPLAY_SERVERS[0], DISPLAY_SERVERS[1], "XAUTHORITY"];

/// `client.yaml`, written by `init`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    portal_url: String,
    #[serde(default)]
    ca_cert: Vec<PathBuf>,
    #[serde(default = "yes")]
    open_browser: bool,
}

fn yes() -> bool {
    true
}

/// What the service runs with.
#[derive(Debug)]
struct Settings {
    portal_url: url::Url,
    ca_cert: Vec<PathBuf>,
    open_browser: bool,
}

/// The settings file (if present), overridden by flags and the environment.
fn load_settings(args: &ClientArgs) -> anyhow::Result<Settings> {
    let path = match &args.config {
        Some(p) => p.clone(),
        None => unit::default_config_path()?,
    };
    let file: Option<SettingsFile> = match std::fs::read_to_string(&path) {
        Ok(text) => Some(
            serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let portal_url = match (&args.portal_url, &file) {
        (Some(url), _) => url.clone(),
        (None, Some(f)) => f
            .portal_url
            .parse()
            .with_context(|| format!("portal_url in {}", path.display()))?,
        (None, None) => bail!(
            "no portal URL: run `drawbridge client init`, or set --portal-url \
             (DRAWBRIDGE_PORTAL_URL)"
        ),
    };
    let ca_cert = if args.ca_cert.is_empty() {
        file.as_ref().map(|f| f.ca_cert.clone()).unwrap_or_default()
    } else {
        args.ca_cert.clone()
    };
    Ok(Settings {
        portal_url,
        ca_cert,
        open_browser: file.is_none_or(|f| f.open_browser),
    })
}

/// Writes `contents` to `path`, creating its directory.
fn write_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Runs `systemctl --user <args>` and returns its output; fails on a non-zero exit.
fn systemctl(unit: &UnitArgs, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(&unit.systemctl)
        .arg("--user")
        .args(args)
        .output()
        .with_context(|| format!("running {}", unit.systemctl.display()))?;
    if !out.status.success() {
        bail!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn unit_state(unit: &UnitArgs) -> anyhow::Result<unit::UnitState> {
    let out = systemctl(
        unit,
        &[
            "show",
            "--property=ActiveState,Result,StatusText",
            UNIT_NAME,
        ],
    )?;
    Ok(unit::parse_show(&out))
}

pub fn init(args: &InitArgs) -> anyhow::Result<()> {
    // Checks the URL and the CA files now, so mistakes show here rather than in the journal.
    PortalClient::new(args.portal_url.clone(), &args.ca_cert)?;
    let ca_cert = args
        .ca_cert
        .iter()
        .map(|p| std::path::absolute(p).with_context(|| format!("resolving {}", p.display())))
        .collect::<anyhow::Result<_>>()?;
    let settings = SettingsFile {
        portal_url: args.portal_url.to_string(),
        ca_cert,
        open_browser: !args.no_browser,
    };
    let config = unit::default_config_path()?;
    write_file(&config, &serde_norway::to_string(&settings)?)?;
    let exe = std::env::current_exe().context("finding the drawbridge binary")?;
    let unit_file = unit::unit_path()?;
    write_file(&unit_file, &unit::render_unit(&exe)?)?;
    systemctl(&args.unit, &["daemon-reload"])?;
    println!("Wrote {} and {}.", config.display(), unit_file.display());
    println!("Run `drawbridge client login` to log in.");
    Ok(())
}

pub fn login(args: &UnitArgs) -> anyhow::Result<()> {
    let unit_file = unit::unit_path()?;
    if !unit_file.exists() {
        bail!(
            "{} is missing; run `drawbridge client init` first",
            unit_file.display()
        );
    }
    let state = unit_state(args)?;
    if state.active == "active" {
        println!("Already logged in: {}", state.status);
        return Ok(());
    }
    let display: Vec<&str> = DISPLAY_VARS
        .into_iter()
        .filter(|v| std::env::var_os(v).is_some())
        .collect();
    if !display.is_empty() {
        let mut cmd = vec!["import-environment"];
        cmd.extend(&display);
        systemctl(args, &cmd)?;
    }
    // A failure left by an earlier run would otherwise read as this one's.
    if let Err(e) = systemctl(args, &["reset-failed", UNIT_NAME]) {
        warn!("{e:#}");
    }
    systemctl(args, &["start", "--no-block", UNIT_NAME])?;

    let started = Instant::now();
    let mut shown = String::new();
    loop {
        std::thread::sleep(POLL_INTERVAL);
        let state = unit_state(args)?;
        if !state.status.is_empty() && state.status != shown {
            println!("{}", state.status);
            shown = state.status.clone();
        }
        match unit::login_step(&state, started.elapsed()) {
            Step::Done => return Ok(()),
            Step::Failed(why) => bail!("login failed ({why}); see {JOURNAL_HINT}"),
            Step::Wait if started.elapsed() > LOGIN_WAIT_LIMIT => {
                bail!("gave up waiting for the login; see {JOURNAL_HINT}")
            }
            Step::Wait => {}
        }
    }
}

pub fn logout(args: &UnitArgs) -> anyhow::Result<()> {
    systemctl(args, &["stop", UNIT_NAME])?;
    let state = unit_state(args)?;
    if !state.status.is_empty() {
        println!("{}", state.status);
    }
    println!("Stopped {UNIT_NAME}. Details: {JOURNAL_HINT}");
    Ok(())
}

/// A logged-in session: the token, and when it expires on this machine's clock.
struct Session {
    token: String,
    username: String,
    expires: Instant,
}

impl Session {
    fn new(json: CliTokenJson) -> Self {
        let mut session = Session {
            token: json.token,
            username: String::new(),
            expires: Instant::now(),
        };
        session.update(&json.session);
        session
    }

    fn update(&mut self, json: &SessionJson) {
        let remaining = json.info.expires_at.saturating_sub(json.server_now);
        self.expires = Instant::now() + Duration::from_secs(remaining).min(MAX_REMAINING);
        self.username.clone_from(&json.info.username);
    }

    fn remaining(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }

    fn status(&self) -> String {
        format!(
            "Logged in as {}; access expires in {} unless refreshed",
            self.username,
            unit::human(self.remaining())
        )
    }
}

struct Signals {
    term: Signal,
    int: Signal,
}

impl Signals {
    fn new() -> anyhow::Result<Self> {
        Ok(Signals {
            term: signal(SignalKind::terminate()).context("installing SIGTERM handler")?,
            int: signal(SignalKind::interrupt()).context("installing SIGINT handler")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

pub async fn service(args: &ClientArgs) -> anyhow::Result<()> {
    let settings = load_settings(args)?;
    let portal = PortalClient::new(settings.portal_url, &settings.ca_cert)?;
    let mut signals = Signals::new()?;
    let Some(mut session) = log_in(&portal, settings.open_browser, &mut signals).await? else {
        info!("stopped before the login completed");
        return Ok(());
    };
    info!(username = session.username, "logged in");
    notify(&format!("READY=1\nSTATUS={}\n", session.status()));
    keep_alive(&portal, &mut session, &mut signals).await
}

/// Runs the browser login. `None` if a signal stopped it first.
async fn log_in(
    portal: &PortalClient,
    open_browser: bool,
    signals: &mut Signals,
) -> anyhow::Result<Option<Session>> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("binding the loopback listener")?;
    let port = listener.local_addr()?.port();
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();
    let url = portal.login_url(port, challenge.as_str(), state.secret());
    info!(%url, "log in at");
    notify(&format!("STATUS=Log in at {url}\n"));
    if open_browser {
        open(url.as_str());
    }

    let (mut callbacks, server) = loopback::serve(listener, state.secret().clone());
    let logged_in = tokio::select! {
        r = receive_login(portal, &mut callbacks, verifier.secret()) => r,
        () = tokio::time::sleep(LOGIN_TIMEOUT) => Err(anyhow::anyhow!(
            "login not completed within {}", unit::human(LOGIN_TIMEOUT)
        )),
        () = signals.recv() => {
            server.abort();
            return Ok(None);
        }
    };
    server.abort();
    match logged_in {
        Ok(json) => Ok(Some(Session::new(json))),
        Err(e) => {
            notify(&format!("STATUS=Login failed: {e:#}\n"));
            Err(e)
        }
    }
}

/// Waits for the browser to come back with a one-time code and redeems it. The listener passes on
/// only callbacks carrying this login's state.
async fn receive_login(
    portal: &PortalClient,
    callbacks: &mut mpsc::Receiver<Callback>,
    verifier: &str,
) -> anyhow::Result<CliTokenJson> {
    match callbacks.recv().await {
        Some(Callback::Code(code)) => portal.cli_token(&code, verifier).await,
        Some(Callback::Error(error)) => bail!(login_error_message(error)),
        None => bail!("the loopback listener stopped"),
    }
}

fn login_error_message(error: LoginError) -> &'static str {
    match error {
        LoginError::LoginFailed => "the identity provider did not complete the login",
    }
}

/// Refreshes the session until a signal stops the service, then ends it at the gateway.
async fn keep_alive(
    portal: &PortalClient,
    session: &mut Session,
    signals: &mut Signals,
) -> anyhow::Result<()> {
    let mut wait = unit::refresh_delay(session.remaining());
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = signals.recv() => return end(portal, session).await,
        }
        let refreshed = portal.refresh(&session.token).await;
        wait = match next_step(refreshed, session.remaining()) {
            Next::Extended(json) => {
                session.update(&json);
                info!(
                    username = session.username,
                    expires_in = %unit::human(session.remaining()),
                    "session extended"
                );
                notify(&format!("STATUS={}\n", session.status()));
                unit::refresh_delay(session.remaining())
            }
            Next::Retry { after, why } => {
                warn!(retry_in = %unit::human(after), error = why, "refresh failed; retrying");
                after
            }
            Next::Unrefreshable => return run_out(portal, session, signals).await,
            Next::Lost(why) => return lost(&why),
        };
    }
}

/// Keeps a session that can't be refreshed until it expires, so stopping the service still ends
/// it at the gateway; then fails.
async fn run_out(
    portal: &PortalClient,
    session: &Session,
    signals: &mut Signals,
) -> anyhow::Result<()> {
    let left = unit::human(session.remaining());
    warn!("the gateway cannot refresh this session; access ends in {left}");
    notify(&format!(
        "STATUS=The gateway cannot refresh this session; access ends in {left}\n"
    ));
    tokio::select! {
        () = tokio::time::sleep(session.remaining()) => {}
        () = signals.recv() => return end(portal, session).await,
    }
    lost("the gateway cannot refresh this session")
}

/// Reports a session that can't be kept alive; the unit then fails rather than restarting.
fn lost(why: &str) -> anyhow::Result<()> {
    notify(&format!("STATUS=Session lost: {why}\n"));
    bail!("session lost: {why}")
}

/// What to do after a refresh, with `remaining` left on the session.
#[derive(Debug)]
enum Next {
    Extended(SessionJson),
    Retry {
        after: Duration,
        why: String,
    },
    /// The session lives on until its expiry, but can't be refreshed.
    Unrefreshable,
    /// The session is gone; the unit then fails rather than restarting.
    Lost(String),
}

fn next_step(refreshed: Refresh, remaining: Duration) -> Next {
    match refreshed {
        Refresh::Extended(json) => Next::Extended(json),
        Refresh::Gone => Next::Lost("session ended by the gateway".into()),
        Refresh::Unavailable => Next::Unrefreshable,
        Refresh::Retry { why, .. } if remaining.is_zero() => Next::Lost(format!(
            "session expired while the portal was unreachable ({why})"
        )),
        // Not past the expiry: one last try just after it tells whether the session is gone.
        Refresh::Retry { after, why } => Next::Retry {
            after: after.min(remaining.max(Duration::from_secs(1))),
            why,
        },
    }
}

/// Ends the session at the gateway, as `client logout` (or shutdown) stops the service.
async fn end(portal: &PortalClient, session: &Session) -> anyhow::Result<()> {
    notify("STOPPING=1\n");
    match tokio::time::timeout(END_TIMEOUT, portal.end(&session.token)).await {
        Ok(Ok(())) => {
            info!(username = session.username, "session ended at the gateway");
            notify("STATUS=Logged out\n");
        }
        Ok(Err(e)) => warn_not_ended(session, &format!("{e:#}")),
        Err(_) => warn_not_ended(session, "timed out"),
    }
    Ok(())
}

fn warn_not_ended(session: &Session, why: &str) {
    let left = unit::human(session.remaining());
    warn!(
        error = why,
        "could not end the session at the gateway; access lasts {left} more"
    );
    notify(&format!(
        "STATUS=Could not end the session at the gateway ({why}); access lasts {left} more\n"
    ));
}

/// Opens `url` in the user's browser, if there is a desktop to show it on. Under systemd the
/// user manager starts it as a unit of its own, outside this service's sandbox, so stopping the
/// service doesn't close a browser it started.
fn open(url: &str) {
    if DISPLAY_SERVERS
        .iter()
        .all(|v| std::env::var_os(v).is_none())
    {
        info!("no display; open the login URL in a browser");
        return;
    }
    let mut cmd = if std::env::var_os("NOTIFY_SOCKET").is_some() {
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--quiet", "--collect", "--", "xdg-open"]);
        cmd
    } else {
        Command::new("xdg-open")
    };
    match cmd.arg(url).env_remove("NOTIFY_SOCKET").spawn() {
        // Reaped in the background; the browser may outlive the opener.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => warn!(error = %e, "could not open a browser; open the login URL by hand"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(config: &Path) -> ClientArgs {
        ClientArgs {
            config: Some(config.to_path_buf()),
            portal_url: None,
            ca_cert: Vec::new(),
        }
    }

    /// A settings file with `contents`, removed when dropped.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(name: &str, contents: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("drawbridge-{name}-{}.yaml", std::process::id()));
            std::fs::write(&path, contents).unwrap();
            TempFile(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn settings_come_from_the_file() {
        let file = TempFile::new(
            "settings",
            "portal_url: https://gw.example/\nca_cert: [/etc/ca.pem]\nopen_browser: false\n",
        );
        let settings = load_settings(&args(&file.0)).unwrap();
        assert_eq!(settings.portal_url.as_str(), "https://gw.example/");
        assert_eq!(settings.ca_cert, [PathBuf::from("/etc/ca.pem")]);
        assert!(!settings.open_browser);
    }

    #[test]
    fn flags_override_the_settings_file() {
        let file = TempFile::new("override", "portal_url: https://gw.example/\n");
        let mut over = args(&file.0);
        over.portal_url = Some("https://other.example/".parse().unwrap());
        over.ca_cert = vec!["/tmp/ca.pem".into()];
        let settings = load_settings(&over).unwrap();
        assert_eq!(settings.portal_url.as_str(), "https://other.example/");
        assert_eq!(settings.ca_cert, [PathBuf::from("/tmp/ca.pem")]);
        assert!(settings.open_browser, "the browser opens by default");
    }

    #[test]
    fn unknown_settings_are_refused() {
        let file = TempFile::new("unknown", "portal_url: https://gw.example/\nbrowser: no\n");
        assert!(load_settings(&args(&file.0)).is_err());
    }

    #[test]
    fn settings_need_a_portal_url() {
        let missing = std::env::temp_dir().join("drawbridge-no-such-settings.yaml");
        assert!(load_settings(&args(&missing)).is_err());
        let mut flags = args(&missing);
        flags.portal_url = Some("https://gw.example/".parse().unwrap());
        assert!(load_settings(&flags).unwrap().open_browser);
    }

    fn session_json(remaining: u64) -> SessionJson {
        serde_json::from_value(serde_json::json!({
            "username": "alice", "expires_at": 1000 + remaining, "access": [], "server_now": 1000,
        }))
        .unwrap()
    }

    #[test]
    fn session_status_counts_down() {
        let session = Session::new(CliTokenJson {
            token: "t".into(),
            session: session_json(30),
        });
        assert_eq!(session.username, "alice");
        assert!(session.remaining() > Duration::from_secs(28));
        assert!(
            session
                .status()
                .starts_with("Logged in as alice; access expires in ")
        );
    }

    #[test]
    fn refresh_outcomes_decide_the_next_step() {
        let secs = Duration::from_secs;
        let retry = |after| Refresh::Retry {
            after: secs(after),
            why: "503".into(),
        };
        assert!(matches!(
            next_step(Refresh::Extended(session_json(30)), secs(10)),
            Next::Extended(_)
        ));
        assert!(matches!(next_step(Refresh::Gone, secs(10)), Next::Lost(_)));
        assert!(matches!(
            next_step(Refresh::Unavailable, secs(10)),
            Next::Unrefreshable
        ));
        // Retries follow the portal's advice, but don't sleep through the expiry.
        assert!(
            matches!(next_step(retry(5), secs(10)), Next::Retry { after, .. } if after == secs(5))
        );
        assert!(
            matches!(next_step(retry(5), secs(2)), Next::Retry { after, .. } if after == secs(2))
        );
        assert!(matches!(
            next_step(retry(5), Duration::from_millis(10)),
            Next::Retry { after, .. } if after == secs(1)
        ));
        assert!(matches!(next_step(retry(5), Duration::ZERO), Next::Lost(_)));
    }

    #[test]
    fn login_errors_have_messages() {
        assert!(login_error_message(LoginError::LoginFailed).contains("identity provider"));
    }

    #[test]
    fn nonsense_expiries_are_clamped() {
        let mut json = session_json(0);
        json.info.expires_at = u64::MAX;
        let session = Session::new(CliTokenJson {
            token: "t".into(),
            session: json,
        });
        assert!(session.remaining() <= MAX_REMAINING);
    }
}
