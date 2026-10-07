# Refactor Top Level Modules

Consider the top level module layout.  Refactor the modules into 3 top level modules, moving
existing modules under the appropriate new top level module and refining the `pub(crate)` api.

Top level modules should be:

* `cli` containing:
   * existing `cli` and `gateway`,
* `firewall` containing:
   * existing `firewall`, `netlink` and `nfraw`
* `portal` containing all web interface modules
* `session` containing everything relevant to managing user sessions.

Ideally `pub(crate)` APIs would be exposed via the top level modules via re-export where
appropriate.
