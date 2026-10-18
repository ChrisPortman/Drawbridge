# Drawbridge

An identity-aware access gateway: a policy lists what each client or logged-in user may reach, and
everything else arriving from them is dropped.

## Language

**Client**:
A source CIDR in the policy whose allow list is always in force, with no login.
_Avoid_: Host, peer

**User**:
A person in the policy whose allow list is in force only for the source IP of a live session.
_Avoid_: Account, identity

**Session**:
A user's logged-in presence at one source IP, lasting until their ID token expires.
_Avoid_: Login, lease

**Allow rule**:
One entry in a client's or user's `allow` list: a set of destinations, a protocol and optional ports.
_Avoid_: ACL entry, permission

**Host rule**:
An allow rule with protocol `http` or `https`, which also names the hostnames (and, for http, paths)
that may be requested at its destinations.
_Avoid_: URL rule, web rule

**Host**:
The name a client asks for in a host rule's traffic: the TLS SNI for https, the `Host` header for http.
_Avoid_: Domain, server name
