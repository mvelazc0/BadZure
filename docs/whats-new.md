# What's New

If you used an earlier version of BadZure, this is what changed. The most visible change is the attack-path config shape: older configs no longer validate.

## Attack-path config shape

A privilege-escalation technique is now a **mapping** under `privilege_escalation:` with a `technique:` field, alongside `initial_access:` and `objective:` blocks. The old flat shape is retired.

=== "Now"

    ```yaml
    attack_paths:
      my_path:
        initial_access:
          vector: compromised_credential
          principal_type: user
        privilege_escalation:
          technique: ApplicationOwnershipAbuse
          assignment_type: direct
        objective:
          entra_role: 62e90394-69f5-4237-9190-012177145e10
    ```

=== "Retired"

    ```yaml
    attack_paths:
      my_path:
        privilege_escalation: ApplicationOwnershipAbuse
        method: AzureADRole
        entra_role: 62e90394-69f5-4237-9190-012177145e10
    ```

The legacy `mode: random | targeted` config format is removed. See [Atomic Reference](reference/atomic.md).

## Offline gates

Two commands verify a lab without deploying:

- **`check`** walks the attack graph and reports whether each objective is reachable, and if not, the hop where it dead-ends.
- **`plan`** runs `terraform plan` as a dry run to catch deploy-breaking errors before `build`.

See [`check`](reference/commands.md#check) and [`plan`](reference/commands.md#plan)
in the CLI reference.

## Interactive lab report

**`report`** renders a lab as a self-contained interactive HTML report: the posture and attack graphs, plus the identity, resource, and assignment inventories. It runs offline. Every graph in this documentation is one of these reports. See [How to Read These Graphs](attack-paths/reading-graphs.md#the-full-lab-report).

## Chained attack paths

Alongside the seven atomic technique templates, you can author a **chained** path: an explicit graph built from primitives that can reproduce one catalog behavior or combine several in a custom sequence. See [Chained Paths and Primitives](attack-paths/chaining.md) and [Chained Reference](reference/chained.md).

## New initial-access vectors

Beyond compromised credentials, a path can start from an internet-exposed VM (`exposed_rdp`, `exposed_ssh`) or a vulnerable web application (`vulnerable_web_app`), landing the attacker on a compute host. See [Initial Access](attack-paths/initial-access.md).

## Authoring with Claude Code

BadZure ships an agentic authoring workflow: a crew of Claude Code agents that generate an org baseline, design an attack path, and gate it against the reachability check. Related commands: `generate` (LLM-authored configs), `compile-baseline` (expand an org design), `baseline-spec`, and `uniquify`. See [Authoring with Claude Code](building/authoring-with-claude.md).

## MITRE ATT&CK mapping

Attack paths carry ATT&CK technique IDs, derived from the traversal. They appear on the attack graph edges and in the report.
