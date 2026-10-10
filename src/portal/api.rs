//! The portal's JSON API types, shared with the client service so the two can't drift apart.

use serde::{Deserialize, Serialize};

use crate::session::SessionInfo;

/// Holds the session token. `__Host-` makes browsers insist on Secure, Path=/ and no Domain. The
/// client service sends its token under the same name.
pub(crate) const SESSION_COOKIE: &str = "__Host-drawbridge_session";
/// Required, with value `1`, on requests that change a session. A page on another origin can't
/// send a custom header without a CORS preflight, which the portal never grants.
pub(crate) const REQUEST_HEADER: &str = "x-drawbridge";

/// A live session, as `GET /api/session` and a refresh report it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SessionJson {
    #[serde(flatten)]
    pub(crate) info: SessionInfo,
    /// Lets clients schedule a refresh without trusting their own clock.
    pub(crate) server_now: u64,
}

/// `POST /api/cli/token`: the one-time code from the loopback redirect and the PKCE verifier
/// whose S256 challenge started the login.
#[derive(Serialize, Deserialize)]
pub(crate) struct CliTokenRequest {
    pub(crate) code: String,
    pub(crate) verifier: String,
}

/// The session token handed to the client service, with the session it opens.
#[derive(Serialize, Deserialize)]
pub(crate) struct CliTokenJson {
    pub(crate) token: String,
    #[serde(flatten)]
    pub(crate) session: SessionJson,
}

/// The body of every API error response.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ApiError {
    pub(crate) error: ErrorCode,
}

/// Why an API request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorCode {
    /// No live session for this token and address.
    NoSession,
    /// A state-changing request without [`REQUEST_HEADER`].
    MissingRequestHeader,
    /// The session has no usable refresh token; it lasts until its expiry.
    RefreshUnavailable,
    RefreshInProgress,
    ProviderUnavailable,
    /// The one-time code is unknown, used, expired, or the verifier doesn't match it.
    InvalidCode,
    AddressMismatch,
    /// The login was for a user with no access configured.
    NoAccess,
    /// The gateway couldn't provision the session.
    ProvisioningFailed,
    BadRequest,
    InternalError,
}

/// Why a command-line login failed, sent to the client service's loopback as `?error=`. Whether
/// the user has access is only known when the code is redeemed ([`ErrorCode::NoAccess`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoginError {
    /// The provider refused the login, or it couldn't be verified.
    LoginFailed,
}

impl LoginError {
    /// The query value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LoginError::LoginFailed => "login_failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_errors_render_as_they_parse() {
        let e = LoginError::LoginFailed;
        assert_eq!(serde_json::to_value(e).unwrap(), e.as_str());
    }

    #[test]
    fn error_codes_are_snake_case() {
        let json = serde_json::to_string(&ApiError {
            error: ErrorCode::MissingRequestHeader,
        })
        .unwrap();
        assert_eq!(json, r#"{"error":"missing_request_header"}"#);
    }
}
