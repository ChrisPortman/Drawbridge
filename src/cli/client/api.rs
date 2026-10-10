//! The client service's side of the portal's JSON API.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use reqwest::{Certificate, StatusCode, header};
use url::Url;

use crate::portal::SessionJson;
use crate::portal::{
    ApiError, CliTokenJson, CliTokenRequest, ErrorCode, REQUEST_HEADER, SESSION_COOKIE,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait before retrying when the portal names no time.
const RETRY_DEFAULT: Duration = Duration::from_secs(5);

pub(super) struct PortalClient {
    http: reqwest::Client,
    base: Url,
}

/// What a refresh came to.
#[derive(Debug)]
pub(super) enum Refresh {
    Extended(SessionJson),
    /// No session for this token: ended, expired, or the gateway restarted.
    Gone,
    /// The gateway can't refresh this session; it lasts until its expiry.
    Unavailable,
    /// Worth trying again `after`.
    Retry {
        after: Duration,
        why: String,
    },
}

impl PortalClient {
    /// A client for the portal at `base` that trusts the system's CAs and `ca_certs`.
    pub(super) fn new(base: Url, ca_certs: &[PathBuf]) -> anyhow::Result<Self> {
        if base.scheme() != "https" {
            bail!("the portal URL must be https, got {base}");
        }
        let mut builder = reqwest::ClientBuilder::new()
            .tls_built_in_webpki_certs(false)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT);
        for cert in load_certs(ca_certs)? {
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build().context("building the HTTPS client")?;
        Ok(PortalClient { http, base })
    }

    fn url(&self, path: &str) -> Url {
        self.base.join(path).expect("constant relative path")
    }

    /// Where to send the browser to log in for the service listening on `port`.
    pub(super) fn login_url(&self, port: u16, challenge: &str, state: &str) -> Url {
        let mut url = self.url("login");
        url.query_pairs_mut()
            .append_pair("cli_port", &port.to_string())
            .append_pair("cli_challenge", challenge)
            .append_pair("cli_state", state);
        url
    }

    pub(super) async fn cli_token(
        &self,
        code: &str,
        verifier: &str,
    ) -> anyhow::Result<CliTokenJson> {
        let response = self
            .http
            .post(self.url("api/cli/token"))
            .header(REQUEST_HEADER, "1")
            .json(&CliTokenRequest {
                code: code.into(),
                verifier: verifier.into(),
            })
            .send()
            .await
            .context("contacting the portal")?;
        if response.status().is_success() {
            return response.json().await.context("reading the portal's answer");
        }
        let status = response.status();
        match response.json::<ApiError>().await.map(|e| e.error) {
            Ok(ErrorCode::NoAccess) => {
                bail!("you are signed in, but no access is configured for this account")
            }
            Ok(ErrorCode::ProvisioningFailed) => {
                bail!("the gateway could not provision your access")
            }
            Ok(code) => bail!("the portal refused the login: {status} {code:?}"),
            Err(_) => bail!("the portal refused the login: {status}"),
        }
    }

    pub(super) async fn refresh(&self, token: &str) -> Refresh {
        let sent = self
            .http
            .post(self.url("api/session/refresh"))
            .header(REQUEST_HEADER, "1")
            .header(header::COOKIE, cookie(token))
            .send()
            .await;
        let response = match sent {
            Ok(r) => r,
            Err(e) => {
                return Refresh::Retry {
                    after: RETRY_DEFAULT,
                    why: format!("{e:#}"),
                };
            }
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs);
        match classify(status) {
            Class::Extended => match response.json().await {
                Ok(session) => Refresh::Extended(session),
                Err(e) => Refresh::Retry {
                    after: RETRY_DEFAULT,
                    why: format!("reading the answer: {e:#}"),
                },
            },
            Class::Gone => Refresh::Gone,
            Class::Unavailable => Refresh::Unavailable,
            Class::Retry => Refresh::Retry {
                after: retry_after.unwrap_or(RETRY_DEFAULT),
                why: error_text(response).await,
            },
        }
    }

    /// Ends the session at the gateway. A session that is already gone counts as ended.
    pub(super) async fn end(&self, token: &str) -> anyhow::Result<()> {
        let response = self
            .http
            .delete(self.url("api/session"))
            .header(REQUEST_HEADER, "1")
            .header(header::COOKIE, cookie(token))
            .send()
            .await
            .context("contacting the portal")?;
        match response.status() {
            s if s.is_success() || s == StatusCode::UNAUTHORIZED => Ok(()),
            _ => bail!("the portal answered {}", error_text(response).await),
        }
    }
}

fn load_certs(paths: &[PathBuf]) -> anyhow::Result<Vec<Certificate>> {
    let mut certs = Vec::new();
    for path in paths {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let found = Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing {}", path.display()))?;
        if found.is_empty() {
            bail!("{} holds no PEM certificate", path.display());
        }
        certs.extend(found);
    }
    Ok(certs)
}

fn cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}")
}

/// The portal's error code and HTTP status, for messages.
async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<ApiError>().await {
        Ok(e) => format!("{status} {:?}", e.error),
        Err(_) => status.to_string(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Class {
    Extended,
    Gone,
    Unavailable,
    Retry,
}

/// A refresh's status: 401 no session, 409 can't be refreshed; anything else unexpected is
/// retried.
fn classify(status: StatusCode) -> Class {
    match status {
        s if s.is_success() => Class::Extended,
        StatusCode::UNAUTHORIZED => Class::Gone,
        StatusCode::CONFLICT => Class::Unavailable,
        _ => Class::Retry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_refresh_answers() {
        assert_eq!(classify(StatusCode::OK), Class::Extended);
        assert_eq!(classify(StatusCode::UNAUTHORIZED), Class::Gone);
        assert_eq!(classify(StatusCode::CONFLICT), Class::Unavailable);
        for s in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(classify(s), Class::Retry);
        }
    }

    #[test]
    fn builds_portal_urls() {
        let client = PortalClient::new("https://gw.example:8443".parse().unwrap(), &[]).unwrap();
        assert_eq!(
            client.login_url(40123, "abc", "st").as_str(),
            "https://gw.example:8443/login?cli_port=40123&cli_challenge=abc&cli_state=st"
        );
        assert_eq!(
            client.url("api/session").as_str(),
            "https://gw.example:8443/api/session"
        );
        assert!(PortalClient::new("http://gw.example".parse().unwrap(), &[]).is_err());
    }

    #[test]
    fn rejects_files_without_certificates() {
        let path = std::env::temp_dir().join(format!("drawbridge-ca-{}", std::process::id()));
        std::fs::write(&path, "not a certificate\n").unwrap();
        let base: Url = "https://gw.example".parse().unwrap();
        let result = PortalClient::new(base.clone(), std::slice::from_ref(&path));
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
        let missing = [PathBuf::from("/nonexistent/ca.pem")];
        assert!(PortalClient::new(base, &missing).is_err());
    }

    #[tokio::test]
    async fn ending_an_unreachable_session_fails_within_the_timeout() {
        // A port nothing listens on: the connection is refused straight away.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let base = format!("https://127.0.0.1:{port}").parse().unwrap();
        let client = PortalClient::new(base, &[]).unwrap();
        let started = std::time::Instant::now();
        assert!(client.end("token").await.is_err());
        assert!(started.elapsed() < TIMEOUT);
    }
}
