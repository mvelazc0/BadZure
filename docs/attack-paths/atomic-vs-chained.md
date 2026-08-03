# Atomic vs Chained Paths

Every BadZure attack path has the same basic anatomy: an attacker starts from
**initial access**, traverses one or more **pivots**, and reaches an **objective**.
BadZure provides two ways to describe the pivots between that starting point and
objective: an **atomic path** or a **chained path**.

The difference is how the path is authored. An atomic path asks BadZure to expand
one named technique template. A chained path describes the graph explicitly from
lower-level building blocks. Both forms are checked, reported, and deployed through
the same workflow.

## At a glance

| | Atomic path | Chained path |
|---|---|---|
| What you provide | A named technique and a few options | The identities, resources, credentials, and relationships that form the graph |
| Main configuration key | `privilege_escalation:` | `assignments:` |
| How the path is assembled | BadZure selects suitable entities and expands the technique into a complete path | BadZure uses the graph you declare |
| Composition | One of BadZure's seven built-in technique templates | Any supported combination of primitives |
| Best suited to | Focused labs for learning, exercising, or varying one supported technique | Precise scenarios, named entities, and custom multi-stage paths |
| Authoring effort | Lower | Higher, with more control |

## Atomic paths

An atomic path describes the attack at a high level. You select one of BadZure's
seven built-in privilege-escalation techniques, such as `KeyVaultSecretTheft` or
`ApplicationOwnershipAbuse`, and configure its relevant options. BadZure then finds
suitable identities and resources in the baseline and generates the relationships
needed to make the path possible.

The defining field is `privilege_escalation.technique`:

```yaml
attack_paths:
  key_vault_to_admin:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: KeyVaultSecretTheft
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10
```

Atomic paths are useful when a built-in technique already represents the behavior
you want to explore and the exact identities chosen for the path are not important.
The available templates and their variants are listed in the
[technique catalog](techniques/index.md).

## Chained paths

A chained path describes the attack graph directly. Instead of selecting a named
technique, you declare the identities and resources involved and connect them with
primitives such as application ownership, group membership, Entra roles, Azure RBAC,
credentials, and stored data.

The defining field is `assignments:`. It replaces `privilege_escalation:`; the two
forms cannot be used together on the same path.

This minimal chained path starts with a compromised user who owns an application.
The attacker can add a credential to that application, authenticate as its service
principal, and inherit its Global Administrator role:

```yaml
attack_paths:
  owned_app_to_admin:
    objective:
      capability: entra_role
      role: "Global Administrator"
    initial_access:
      method: compromised_identity
      principal_ref: alice
    identities:
      users: [{ ref: alice }]
      applications: [{ ref: admin-app }]
    assignments:
      - id: a1
        type: app_ownership
        principal_ref: alice
        app_ref: admin-app
      - id: a2
        type: entra_role
        principal_ref: admin-app
        role: "Global Administrator"
```

Here, nothing is selected from the baseline: `alice`, `admin-app`, their ownership
relationship, and the application's role are all declared explicitly.

This explicit form gives you control over each participant and relationship. It can
model a path that crosses between the identity and infrastructure planes several
times, uses stable named entities for a training narrative, or combines behaviors
that no single built-in template represents. See [Chained Paths and Primitives](chaining.md)
for an interactive example.

!!! important "Atomic and chained do not describe path length"

    An atomic path can contain several attacker actions. For example, a managed
    identity path can include taking control of a host, acting as its managed
    identity, reading a stored credential, and authenticating as another principal.
    It is atomic because all those actions were generated from one named template.

    A chained path does not have to be long or combine several named techniques. It
    can explicitly reproduce a single Key Vault theft or define a much longer path.
    It is chained because the graph is authored from primitives rather than selected
    from the technique catalog.

## Which one should you use?

Use an **atomic path** when one of the seven templates describes the behavior you
want and you want BadZure to assemble the required entities and relationships.

Use a **chained path** when the exact graph matters: you need specific identities or
resources, several escalation mechanisms, a deterministic training scenario, or a
path the built-in templates cannot express.

Whichever form you choose, the next steps are the same: run `check` to verify that
the objective is reachable, use `report` to inspect the posture and attack graphs,
and then use `build` to deploy the lab. Continue with
[Author an Atomic Path](../building/authoring-atomic.md) or
[Author a Chained Path](../building/authoring-chained.md) for the complete workflow.
