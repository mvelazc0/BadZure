# Anatomy of a Path

Every BadZure attack path has three parts: where the attacker starts, how they move, and what they reach. The graph below is a chained path that reaches Global Administrator from a single leaked pipeline secret.

<iframe class="bz-graph" src="/reports/chained-showcase.report.html?embed=attack-pipeline_to_ga" title="A chained attack path, step by step" loading="lazy"></iframe>

<small class="bz-graph-caption"><a href="/reports/chained-showcase.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## How the attacker traverses it

Following the graph from the foothold to the goal, the attacker:

1. **Initial access.** Starts with a leaked client secret for the `deploy-agent` service principal, the foothold BadZure provides.
2. **Application Ownership Abuse.** `deploy-agent` owns `release-bot`, so the attacker adds a credential to that application and authenticates as it.
3. **Group membership.** `release-bot` belongs to the `platform-eng` group, so the attacker inherits everything the group can do.
4. **Managed Identity Abuse.** `platform-eng` holds Virtual Machine Contributor on `vm-build01`, so the attacker takes control of the VM and acts as its managed identity.
5. **Key Vault Secret Theft.** That managed identity reads the pipeline Key Vault and loots the client secret of `directory-sync`.
6. **Objective reached.** The attacker authenticates as `directory-sync`, which holds Global Administrator, and now controls the tenant.

Four escalation mechanisms connect one leaked secret to full tenant control.

## Initial access

The path starts at a **foothold**, an identity or host the attacker already controls. BadZure provides the foothold, so you begin after the compromise. A foothold is either a compromised **credential** (a user or service principal the attacker holds) or a **resource foothold** (code execution on an internet-exposed VM or a vulnerable web app). See [Initial Access](initial-access.md).

## The pivots

The middle of the path is a sequence of **pivots**. Each one uses a relationship in the tenant to bring a new principal or resource under the attacker's control, as the walkthrough above shows: application ownership, group membership, a managed identity, a stolen secret. Each pivot is one of BadZure's building-block primitives. An atomic path uses the sequence defined by one technique template; a chained path declares any supported sequence explicitly. See [Atomic vs Chained Paths](atomic-vs-chained.md).

## The objective

The path ends at the **objective**, the access the attacker holds once the walk completes. An objective is one of:

- an **Entra role** (for example, Global Administrator),
- an **API permission** (for example, an app that can read all mail),
- an **Azure role** on a resource.

The objective is what `check` verifies: it confirms a controlled principal actually reaches it. A path whose objective is unreachable is reported as blocked, with the hop where it dead-ends. See the [`check` reference](../reference/commands.md#check).

## Posture behind the path

The action sequence above walks a state that exists in the tenant. That state, the ownership, membership, roles, and stored secret the path uses, is the **posture**, shown as its own graph in every lab report. Read the two together: posture is the misconfiguration; attack is the traversal.
