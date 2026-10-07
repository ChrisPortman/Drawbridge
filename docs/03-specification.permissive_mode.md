# Permissive Mode

Using a command line flag or environment variable, the operator may enable "permissive mode".

When enabled, the default deny rule is replaced with a default allow with a counter.

Additionally, a firewall logging rule should be inserted into the drawbridge base nftable, just
before the default action, that logs traffic that is being dropped (permissive mode not enabled) or
*would* be dropped (permissive mode enabled).

The purpose of "permissive mode" is to allow an operator to deploy Drawbridge onto an existing
gateway host already routing traffic in a safe way.  The operator can monitor for traffic logged as
would be dropped and fine tune the access policy as required, before disabling permissive mode.
