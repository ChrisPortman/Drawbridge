//! The drawbridge-client user unit, and reading its state back from `systemctl show`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};

pub(super) const UNIT_NAME: &str = "drawbridge-client.service";
/// What `client login` and `client logout` point to for details.
pub(super) const JOURNAL_HINT: &str = "journalctl --user -u drawbridge-client.service";
/// The unit's start timeout: as long as the portal keeps a started login.
const START_TIMEOUT: Duration = crate::portal::LOGIN_TTL;
/// How long the service waits for a login, giving up just before systemd would kill it.
pub(super) const LOGIN_TIMEOUT: Duration = START_TIMEOUT.saturating_sub(Duration::from_secs(30));
/// How long `login` waits for the unit, a little longer than systemd itself.
pub(super) const LOGIN_WAIT_LIMIT: Duration = START_TIMEOUT.saturating_add(Duration::from_secs(60));
/// How long `login` keeps reading an inactive unit as "not started yet".
const START_GRACE: Duration = Duration::from_secs(5);
/// Refresh once this fraction of the remaining lifetime has passed, as the portal page does,
/// but not more often than [`MIN_REFRESH_DELAY`].
const REFRESH_FRACTION: f64 = 0.8;
const MIN_REFRESH_DELAY: Duration = Duration::from_secs(5);

/// The unit file for a service running `exe client service`. There is no `[Install]` section:
/// `client login` starts it, and a session doesn't outlive a reboot.
pub(super) fn render_unit(exe: &Path) -> anyhow::Result<String> {
    Ok(format!(
        "\
[Unit]
Description=Drawbridge client session
Documentation=https://github.com/ChrisPortman/Drawbridge

[Service]
Type=notify
NotifyAccess=main
ExecStart={} client service
TimeoutStartSec={}s
TimeoutStopSec=15s
Restart=no
# The session token lives in this process's memory: no core dumps, and a narrow sandbox. The
# browser runs as a unit of its own, outside it.
LimitCORE=0
NoNewPrivileges=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
",
        quote(exe)?,
        START_TIMEOUT.as_secs()
    ))
}

/// `path` as one quoted systemd command-line word: `%` and `$` would otherwise be expanded as
/// specifiers and variables.
fn quote(path: &Path) -> anyhow::Result<String> {
    let s = path
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    if s.contains(['\n', '\r']) {
        bail!("{s:?} contains a line break");
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// `$XDG_CONFIG_HOME`, or `~/.config`.
pub(super) fn config_home() -> anyhow::Result<PathBuf> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
        .context("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(dir)
}

pub(super) fn unit_path() -> anyhow::Result<PathBuf> {
    Ok(config_home()?.join("systemd/user").join(UNIT_NAME))
}

pub(super) fn default_config_path() -> anyhow::Result<PathBuf> {
    Ok(config_home()?.join("drawbridge/client.yaml"))
}

/// When to refresh a session with `remaining` left.
pub(super) fn refresh_delay(remaining: Duration) -> Duration {
    remaining.mul_f64(REFRESH_FRACTION).max(MIN_REFRESH_DELAY)
}

/// `90s` as `1m 30s`.
pub(super) fn human(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// The unit's state, from `systemctl show`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct UnitState {
    pub(super) active: String,
    pub(super) result: String,
    /// What the service last reported with `STATUS=`.
    pub(super) status: String,
}

/// Parses `Key=value` lines; a value may itself contain `=`.
pub(super) fn parse_show(out: &str) -> UnitState {
    let mut state = UnitState::default();
    for line in out.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let field = match key {
            "ActiveState" => &mut state.active,
            "Result" => &mut state.result,
            "StatusText" => &mut state.status,
            _ => continue,
        };
        *field = value.to_string();
    }
    state
}

/// What `login` should do, `elapsed` after starting the unit.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    Wait,
    Done,
    Failed(String),
}

pub(super) fn login_step(state: &UnitState, elapsed: Duration) -> Step {
    match state.active.as_str() {
        "active" => Step::Done,
        "failed" => Step::Failed(format!("the service failed: {}", state.result)),
        // Right after `start --no-block` the job may not have run yet.
        "inactive" if elapsed >= START_GRACE => Step::Failed("the service stopped".into()),
        _ => Step::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_unit() {
        let unit = render_unit(Path::new("/usr/local/bin/drawbridge")).unwrap();
        assert_eq!(
            unit,
            "\
[Unit]
Description=Drawbridge client session
Documentation=https://github.com/ChrisPortman/Drawbridge

[Service]
Type=notify
NotifyAccess=main
ExecStart=\"/usr/local/bin/drawbridge\" client service
TimeoutStartSec=600s
TimeoutStopSec=15s
Restart=no
# The session token lives in this process's memory: no core dumps, and a narrow sandbox. The
# browser runs as a unit of its own, outside it.
LimitCORE=0
NoNewPrivileges=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
"
        );
    }

    #[test]
    fn quotes_paths_for_systemd() {
        let q = |s: &str| quote(Path::new(s)).unwrap();
        assert_eq!(
            q("/opt/my tools/drawbridge"),
            r#""/opt/my tools/drawbridge""#
        );
        assert_eq!(q("/opt/100%/$HOME"), r#""/opt/100%%/$$HOME""#);
        assert_eq!(q(r#"/opt/a"b\c"#), r#""/opt/a\"b\\c""#);
        assert!(quote(Path::new("/opt/a\nb")).is_err());
    }

    #[test]
    fn refresh_delay_is_a_fraction_with_a_floor() {
        assert_eq!(
            refresh_delay(Duration::from_secs(30)),
            Duration::from_secs(24)
        );
        assert_eq!(refresh_delay(Duration::from_secs(2)), MIN_REFRESH_DELAY);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(human(Duration::from_secs(42)), "42s");
        assert_eq!(human(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn parses_systemctl_show() {
        let state = parse_show(
            "ActiveState=activating\nSubState=start\nResult=success\n\
             StatusText=Log in at https://gw/login?cli_port=1&cli_challenge=x\n",
        );
        assert_eq!(state.active, "activating");
        assert_eq!(state.result, "success");
        assert_eq!(
            state.status,
            "Log in at https://gw/login?cli_port=1&cli_challenge=x"
        );
    }

    #[test]
    fn login_waits_until_active_or_failed() {
        let state = |active: &str| UnitState {
            active: active.into(),
            result: "exit-code".into(),
            status: String::new(),
        };
        let early = Duration::from_secs(1);
        let late = Duration::from_secs(60);
        assert_eq!(login_step(&state("activating"), late), Step::Wait);
        assert_eq!(login_step(&state("active"), early), Step::Done);
        assert_eq!(login_step(&state("inactive"), early), Step::Wait);
        assert!(matches!(
            login_step(&state("inactive"), late),
            Step::Failed(_)
        ));
        assert_eq!(
            login_step(&state("failed"), early),
            Step::Failed("the service failed: exit-code".into())
        );
    }
}
