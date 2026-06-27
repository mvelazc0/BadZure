# Attack Paths

BadZure builds attack paths into the tenant on top of the baseline organization. An attack path is a chain that begins where an attacker first gains access and ends at the access they obtain. BadZure supports two kinds of attack path: atomic and chained.

## Atomic and chained

An **atomic** path describes a single privilege escalation technique. You select one technique from the catalog of seven and configure it with three sections, and BadZure picks the victim and target from the baseline and builds the full chain. Atomic paths are a great way to start exploring attack paths and their variations: swap the initial access, the assignment type, or the objective to study how each variant changes the chain. An atomic path covers one technique, so it cannot chain two privilege escalation techniques together. See [Atomic](atomic.md).

A **chained** path defines the tenant state as an explicit graph built from primitives. These building blocks (role assignments, group membership and ownership, application ownership, credentials, and planted secrets) let you wire arbitrary relationships between entities and chain multiple privilege escalation techniques into a single attack path. See [Chained](chained.md).
