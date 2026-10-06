# Access Gateway Specification

## Objectives

The *Access Gateway* functions as a network access control point at OSI Layer 3/4 by allow listing
network access across the gateway based on user identity.  The administrator, via a configuration
file, will define access policies and assign then to a user, or group of users.  When a user
authenticates via an Oauth provider such as Authentik, the *Access Gateway* will install firewall
rules that will allow the access according to policy.

Additionally, the administrator may define policy and assign it to a client IP address (CIDR). This
access will always be enabled. It is intended to support use cases like machine to machine
access rather than access assigned to a human user.

## Expected User Experience

A user will complete an authentication process using the configured oauth provider.  The clients IP
address will be observed and used to provision firewall rules on the gateway that allow network
access according to the access policy assigned to the user and groups that the user is a member of.

The access session will expire once once the oauth OIDC token expires.  The user may keep the
session alive by extending the session using appropriate oauth processes.

## Expected administrator Experience

The administrator will provide access policy to the process via a `yaml` configuration file.  The
access policy will associate allow listed network access in the form of destination CIDR lists and
ports, to user names or group names.

For simplicity, access policies are additive and are allow list only - no support for deny listing.
The access policies implicitly deny any connectivity not explicitly allowed.

Other configuration such as OIDC settings should be configurable via environment variables.

## Key Assumptions

* The deployment host will have an internal and external interface.  Clients will be connected by
  the external interface and will connect to network locations via the internal interface as well as
  the local host in some situations.
* A client's IP address will be static for the duration of the session.

## Technologies

### Server

* Language: Rust
* Web Framework: Axum
* CLI Framework: Clap
* Async Runtime: Tokio

### Network Access control

* NFTables

