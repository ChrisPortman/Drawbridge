# Human Client Authentication

Access policies can be defined such that they apply to a human user identified by username.

The objectives of this milestone are:

* The policy configuration can include access allow lists specified against a username.
* A basic web interface that when the user opens it, initiates an oauth/oidc flow to authenticate
  the user.
* The web interface should immediately redirect the client to though the oauth process. Once
  authenticated and access is provisioned, it shall provide a simple visual confirmation that their
  access is provisioned.
* When the user has authenticated, the username as per the OIDC token claims will be used to resolve
  the allow lists relevant to the user.
* The firewall will be updated to allow the user's client IP to the allow listed destinations.
* The session remains active as long as the browser window remains open, keeping the oidc session
  tokens alive.
* Once the browser is closed and the token expires, access shall be deprovisioned.


This functionality is in addition to the current IP assigned policies.

Out of scope:

* Group based access control.

Technology:

* For the static web page, rely on basic inline javascript unless the complexity grows beyond which
  is scalable. Vue.js may be used in future.
* The web page and assets are to be embedded into the rust binary.
* Consider implementing per client nft chains.

## Implementation notes

### Configuration

The portal is enabled by `--portal-listen`. Every option also has an environment variable:

| Variable | Meaning |
|---|---|
| `DRAWBRIDGE_PORTAL_LISTEN` | Comma-separated gateway addresses for the HTTPS listener, e.g. `10.8.0.1:443`. Each must be a specific address; every client may connect to it. |
| `DRAWBRIDGE_PORTAL_URL` | The portal's `https://` base URL as clients see it. The redirect URI is `<url>/callback`. |
| `DRAWBRIDGE_TLS_CERT`, `DRAWBRIDGE_TLS_KEY` | PEM certificate chain and private key for the portal. |
| `DRAWBRIDGE_OIDC_ISSUER` | Issuer URL. Discovery runs at startup, and `run` fails if it is unreachable. |
| `DRAWBRIDGE_OIDC_CLIENT_ID`, `DRAWBRIDGE_OIDC_CLIENT_SECRET` | Confidential client credentials. Pass the secret through the environment. |
| `DRAWBRIDGE_OIDC_USERNAME_CLAIM` | ID-token claim matched against `users[].username` (default `preferred_username`). `email` is accepted only when `email_verified` is true; other names are read as custom string claims. |
| `DRAWBRIDGE_OIDC_SCOPES` | Scopes besides `openid` (default `profile`). |
| `DRAWBRIDGE_OIDC_ALLOW_INSECURE_HTTP` | Permit an `http://` issuer, token endpoint or JWKS URL (default: refused). For test setups only: the client secret and tokens then cross the network in cleartext. |
| `DRAWBRIDGE_SESSION_MAX_TTL` | Longest one login or re-authentication keeps access, whatever the token's lifetime, e.g. `900`, `15m`, `2h` (default `15m`; `0` follows the token alone). |

**The username claim is the authorization key.** Whoever can set it chooses whose allow list they
get. Some providers let users edit `preferred_username` themselves. Use it only where
administrators control it (Authentik does by default); otherwise, use verified `email`, `sub` or an
admin-managed custom claim.

Register the client with the provider as a confidential web client that uses the authorization
code flow, with redirect URI `<portal url>/callback`. Clients' browsers must reach the provider
before they're authenticated, so allow it with a `clients` rule covering the client range.

### Session lifetime

Access lasts until the ID token's `exp`, capped at `DRAWBRIDGE_SESSION_MAX_TTL` from the login. While the page is open, it re-authenticates with a
top-level redirect to the provider with `prompt=none`, at 80% of the remaining lifetime. Each
successful callback pushes the expiry out. Once the page is closed, the next expiry deprovisions
the session, and connections it opened stop passing too. They are tagged with the session's id as
their conntrack mark. With a provider that keeps an SSO session (e.g. Authentik), this needs no user
interaction. Providers without one (e.g. Dex) show their login form again. Browsers throttle
timers in background tabs, so keep ID-token lifetimes at a few minutes or more.
