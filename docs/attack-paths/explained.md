# Attack Paths Explained

A **cloud attack path** is a chain of entitlements that links identities, permissions, and resources in a way that enables abuse. Once the right identity is compromised, an adversary traverses the chain by using legitimate cloud features to reach a goal such as data exfiltration, lateral movement, or full tenant compromise.

These paths do not rely on software vulnerabilities. They emerge from everyday administration: creating identities, granting permissions, provisioning resources, and configuring automation. Each configuration is reasonable on its own; connected, they form an escalation route.

The graphs below are real BadZure labs. Each illustrates one way a path forms. For the colors and line styles, see [How to Read These Graphs](reading-graphs.md).

## Explicit configurations

The most direct attack paths come from visible, intentional relationships.

**Application ownership.** When a user is set as the owner of an application registration, that user can add credentials to the application and authenticate as its service principal. If the application holds a privileged Entra role, the user inherits that privilege.

<iframe class="bz-graph" src="/reports/app-ownership.report.html?embed=posture-owns_privileged_app" title="Application ownership posture" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/app-ownership.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

**A secret in a vault.** A user with Key Vault access can read a secret stored inside. If that secret is an application's client secret, reading it lets the user authenticate as the application. If the application holds a permission like `Mail.Read`, the user can now read every mailbox in the tenant.

<iframe class="bz-graph" src="/reports/key-vault-to-app.report.html?embed=posture-vault_secret_to_mailbox" title="Key Vault to application posture" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/key-vault-to-app.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

These relationships are explicit: an administrator created them deliberately. They still form an escalation path when the downstream privilege of an application is broader than what was intended for the user who can reach it.

## Implicit configurations

More subtle paths emerge from relationships that each follow best practice but combine into something unintended.

**Group indirection.** A user who is a member of a group inherits whatever the group holds, even though nothing was assigned to the user directly. If the group holds Application Administrator and a controlled application holds a powerful permission, the member can escalate. The privilege reaches the user through a level of indirection that a per-user review misses.

<iframe class="bz-graph" src="/reports/group-indirection.report.html?embed=posture-group_member_to_app_admin" title="Group indirection posture" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/group-indirection.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

**Access through a managed identity.** An operator holds Contributor on a virtual machine, a compute-management role that says nothing about data. But the VM runs as a managed identity, and controlling the VM means acting as that identity. If that identity can read a sensitive Cosmos DB database, so can the operator, reaching records nothing ever granted their account. The access is implicit in the resource's attached identity, invisible to a review of the operator's own permissions.

<iframe class="bz-graph" src="/reports/managed-identity.report.html?embed=posture-vm_identity_to_cosmos" title="Managed identity to Cosmos DB posture" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/managed-identity.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

No single configuration here is obviously wrong. Together, they form a complete route to Global Administrator.

## From posture to attack

Posture shows the relationships. The **attack** graph shows the adversary walking them, in order, one action per step. This is the same application-ownership lab as above, now as the action sequence: compromise the user, take over the owned app, achieve the objective.

<iframe class="bz-graph" src="/reports/app-ownership.report.html?embed=attack-owns_privileged_app" title="Application ownership attack" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/app-ownership.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

Every technique in the [catalog](techniques/index.md) is a variation on this: a posture that exists, and an attack that walks it. Continue with [Anatomy of a Path](anatomy.md) to see the parts every path is built from.
