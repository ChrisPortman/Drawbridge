//! OpenID Connect relying party: authorization-code flow with PKCE, as a confidential client.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenClaims, IdTokenFields, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    RequestTokenError, Scope, StandardErrorResponse, StandardTokenResponse, TokenResponse, reqwest,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// A secret whose `Debug` output is redacted, so logging a config can't leak it.
#[derive(Clone)]
pub struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
impl Secret {
    pub(crate) fn new(s: String) -> Self {
        Secret(s)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Secret(s.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OidcError {
    #[error("invalid OIDC configuration: {0}")]
    Config(String),
    #[error("failed to build HTTP client")]
    Http(#[from] reqwest::Error),
    #[error("OIDC discovery failed for {issuer}")]
    Discovery {
        issuer: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("token exchange failed")]
    Exchange(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("token response has no ID token")]
    NoIdToken,
    #[error("ID token rejected")]
    Claims(#[from] openidconnect::ClaimsVerificationError),
    #[error("ID token has no usable {0:?} claim")]
    MissingUsername(String),
    #[error("ID token has already expired")]
    Expired,
}

/// Claims outside the OIDC standard set, so any string claim can serve as the username.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ExtraClaims(HashMap<String, serde_json::Value>);

impl AdditionalClaims for ExtraClaims {}

type IdFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type TokenResp = StandardTokenResponse<IdFields, CoreTokenType>;
type Claims = IdTokenClaims<ExtraClaims, CoreGenderClaim>;

/// `CoreClient` with [`ExtraClaims`], in the endpoint state discovery leaves it in.
type Client = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    TokenResp,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Relying-party settings, from the `DRAWBRIDGE_OIDC_*` options.
#[derive(Debug, Clone)]
pub(crate) struct OidcConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Secret,
    pub(crate) redirect_url: String,
    /// The ID-token claim holding the username matched against `users[].username`.
    pub(crate) username_claim: String,
    /// Requested in addition to `openid`.
    pub(crate) scopes: Vec<String>,
    /// Permit `http://` provider URLs, which expose the client secret and tokens on the wire.
    pub(crate) allow_insecure_http: bool,
}

/// State kept between redirecting to the provider and its callback.
#[derive(Debug)]
pub(crate) struct PendingLogin {
    pub(crate) nonce: Nonce,
    pub(crate) pkce_verifier: PkceCodeVerifier,
}

/// An authorization request: send the browser to `url`; `state` comes back on the callback.
#[derive(Debug)]
pub(crate) struct AuthRequest {
    pub(crate) url: String,
    pub(crate) state: String,
    pub(crate) pending: PendingLogin,
}

/// A verified login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) username: String,
    /// The ID token's `exp`: access is deprovisioned then unless the browser re-authenticates.
    pub(crate) expires_at: SystemTime,
}

/// A completed login or refresh: who, and the refresh token the provider issued, if any.
#[derive(Debug)]
pub(crate) struct LoggedIn {
    pub(crate) identity: Identity,
    pub(crate) refresh_token: Option<Secret>,
}

/// Why a refresh didn't produce a new ID token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RefreshFailure {
    /// The provider refused the refresh token, or what it returned can't be used: refreshing
    /// this session won't work again.
    #[error("refresh rejected")]
    Rejected(#[source] OidcError),
    /// The provider couldn't be reached or answered unintelligibly; a later attempt may work.
    #[error("provider unreachable")]
    Unreachable(#[source] OidcError),
}

/// The parts of the OIDC flow the portal depends on, so its handlers can be tested without a
/// provider.
pub(crate) trait Authenticator: Send + Sync + 'static {
    /// Builds an authorization request; `silent` asks the provider not to interact (`prompt=none`).
    fn authorize(&self, silent: bool) -> AuthRequest;
    /// Redeems `code` and verifies the resulting ID token against `pending`.
    fn complete(
        &self,
        code: String,
        pending: PendingLogin,
    ) -> impl Future<Output = Result<LoggedIn, OidcError>> + Send;
    /// Redeems `refresh_token` for a new ID token and verifies it.
    fn refresh(
        &self,
        refresh_token: Secret,
    ) -> impl Future<Output = Result<LoggedIn, RefreshFailure>> + Send;
}

pub(crate) struct Oidc {
    client: Client,
    http: reqwest::Client,
    username_claim: String,
    scopes: Vec<String>,
}

impl Oidc {
    /// Fetches the provider's metadata and signing keys.
    pub(crate) async fn discover(config: OidcConfig) -> Result<Self, OidcError> {
        let issuer =
            IssuerUrl::new(config.issuer.clone()).map_err(|e| OidcError::Config(e.to_string()))?;
        let https = |what: &str, url: &url::Url| {
            if url.scheme() == "https" || config.allow_insecure_http {
                Ok(())
            } else {
                Err(OidcError::Config(format!(
                    "{what} {url} is not https; set --oidc-allow-insecure-http to permit it"
                )))
            }
        };
        https("issuer", issuer.url())?;
        let redirect = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| OidcError::Config(e.to_string()))?;
        // Following redirects from the token endpoint would forward the client secret. The
        // timeouts stop a stalled provider from hanging startup or piling up callbacks.
        // The gateway trusts the bundled roots only; native roots are compiled in for the client.
        let http = reqwest::ClientBuilder::new()
            .tls_built_in_native_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .build()?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| OidcError::Discovery {
                issuer: config.issuer.clone(),
                source: Box::new(e),
            })?;
        // The secret goes to the token endpoint; the keys that make tokens trustworthy come from
        // the JWKS URL. Either may be on a different host from the issuer.
        if let Some(token) = metadata.token_endpoint() {
            https("token endpoint", token.url())?;
        }
        https("JWKS URL", metadata.jwks_uri().url())?;
        let client = Client::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret.0)),
        )
        .set_redirect_uri(redirect);
        Ok(Oidc {
            client,
            http,
            username_claim: config.username_claim,
            scopes: config.scopes,
        })
    }
}

impl Authenticator for Oidc {
    fn authorize(&self, silent: bool) -> AuthRequest {
        let (challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        if silent {
            req = req.add_prompt(CoreAuthPrompt::None);
        }
        let (url, state, nonce) = req.url();
        AuthRequest {
            url: url.into(),
            state: state.into_secret(),
            pending: PendingLogin {
                nonce,
                pkce_verifier,
            },
        }
    }

    async fn complete(&self, code: String, pending: PendingLogin) -> Result<LoggedIn, OidcError> {
        let response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcError::Config(e.to_string()))?
            .set_pkce_verifier(pending.pkce_verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| OidcError::Exchange(Box::new(e)))?;
        // Checks the signature, issuer, audience, expiry and nonce.
        self.logged_in(&response, &pending.nonce)
    }

    async fn refresh(&self, refresh_token: Secret) -> Result<LoggedIn, RefreshFailure> {
        let token = RefreshToken::new(refresh_token.0);
        let response = self
            .client
            .exchange_refresh_token(&token)
            .map_err(|e| RefreshFailure::Rejected(OidcError::Config(e.to_string())))?
            .request_async(&self.http)
            .await
            .map_err(classify)?;
        // A refreshed ID token may repeat the login's nonce or carry none (OIDC Core 12.2);
        // the signature, issuer, audience and expiry are still checked.
        let any_nonce = |_: Option<&Nonce>| Ok(());
        self.logged_in(&response, any_nonce)
            .map_err(RefreshFailure::Rejected)
    }
}

impl Oidc {
    /// Verifies the response's ID token and reads the username and refresh token from it.
    fn logged_in(
        &self,
        response: &TokenResp,
        nonce: impl openidconnect::NonceVerifier,
    ) -> Result<LoggedIn, OidcError> {
        let id_token = response.id_token().ok_or(OidcError::NoIdToken)?;
        let claims = id_token.claims(&self.client.id_token_verifier(), nonce)?;
        let username = username(claims, &self.username_claim)?;
        let expires_at = SystemTime::from(claims.expiration());
        if expires_at <= SystemTime::now() {
            return Err(OidcError::Expired);
        }
        debug!(%username, "ID token verified");
        Ok(LoggedIn {
            identity: Identity {
                username,
                expires_at,
            },
            refresh_token: response.refresh_token().map(|t| Secret(t.secret().clone())),
        })
    }
}

/// A provider's error response is a refusal; failing to reach it, or to parse its answer (e.g.
/// a 5xx error page), may be temporary.
fn classify<RE, T>(e: RequestTokenError<RE, T>) -> RefreshFailure
where
    RE: std::error::Error + Send + Sync + 'static,
    T: openidconnect::ErrorResponse + Send + Sync + 'static,
{
    let rejected = matches!(e, RequestTokenError::ServerResponse(_));
    let e = OidcError::Exchange(Box::new(e));
    if rejected {
        RefreshFailure::Rejected(e)
    } else {
        RefreshFailure::Unreachable(e)
    }
}

/// Reads the username from `claim`. `email` is only trusted when the provider marks it verified.
fn username(claims: &Claims, claim: &str) -> Result<String, OidcError> {
    let value = match claim {
        "sub" => Some(claims.subject().to_string()),
        "preferred_username" => claims.preferred_username().map(|u| u.to_string()),
        "email" => claims
            .email()
            .filter(|_| claims.email_verified() == Some(true))
            .map(|e| e.to_string()),
        other => claims
            .additional_claims()
            .0
            .get(other)
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| OidcError::MissingUsername(claim.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: serde_json::Value) -> Claims {
        let mut base = serde_json::json!({
            "iss": "https://idp.example",
            "aud": ["drawbridge"],
            "exp": 2_000_000_000,
            "iat": 1_000_000_000,
            "sub": "u-1",
        });
        base.as_object_mut()
            .unwrap()
            .extend(json.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn refresh_errors_split_refusals_from_outages() {
        type E = RequestTokenError<std::io::Error, StandardErrorResponse<CoreErrorResponseType>>;
        let refused: E = RequestTokenError::ServerResponse(StandardErrorResponse::new(
            CoreErrorResponseType::InvalidGrant,
            None,
            None,
        ));
        assert!(matches!(classify(refused), RefreshFailure::Rejected(_)));
        let down: E = RequestTokenError::Request(std::io::Error::other("connection refused"));
        assert!(matches!(classify(down), RefreshFailure::Unreachable(_)));
        let garbled: E = RequestTokenError::Other("502 Bad Gateway".into());
        assert!(matches!(classify(garbled), RefreshFailure::Unreachable(_)));
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", Secret("hunter2".into())),
            "Secret([redacted])"
        );
    }

    #[test]
    fn reads_standard_and_custom_claims() {
        let c = claims(serde_json::json!({
            "preferred_username": "alice",
            "email": "a@example.com",
            "email_verified": true,
            "uid": "alice2",
        }));
        assert_eq!(username(&c, "preferred_username").unwrap(), "alice");
        assert_eq!(username(&c, "sub").unwrap(), "u-1");
        assert_eq!(username(&c, "email").unwrap(), "a@example.com");
        assert_eq!(username(&c, "uid").unwrap(), "alice2");
    }

    #[test]
    fn rejects_missing_or_unverified_username() {
        let c = claims(serde_json::json!({
            "email": "a@example.com",
            "email_verified": false,
            "uid": 7,
            "blank": "",
        }));
        for claim in ["preferred_username", "email", "uid", "blank", "absent"] {
            assert!(
                matches!(username(&c, claim), Err(OidcError::MissingUsername(_))),
                "{claim}"
            );
        }
    }
}
