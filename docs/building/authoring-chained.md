# Author a Chained Path

A chained path declares the attack graph explicitly. You name the identities and
resources involved, connect them with assignments, and provide any credentials or
stored data that the attacker must acquire along the way.

This guide builds a compact Key Vault path: a compromised user can read a client
secret from a vault, authenticate as the application that owns the secret, and reach
Global Administrator.

## Start with the attack sequence

Before writing YAML, express the intended traversal in one line:

```text
alice → Key Vault access → stored client secret → directory-sync → Global Administrator
```

Each participant becomes an identity or resource, and each arrow becomes an
assignment or stored credential in the configuration.

## Start with a complete lab

Save the following as `my-chained-lab.yml`:

```yaml
tenant:
  # null values use the BADZURE_* variables from your environment.
  tenant_id: null
  domain: null
  subscription_id: null

attack_paths:
  vault_secret_to_admin:
    # The access BadZure must prove the attacker reaches.
    objective:
      name: "Global Administrator via Key Vault"
      capability: entra_role
      role: "Global Administrator"
      impact: critical

    # The attacker begins with this user's credentials.
    initial_access:
      method: compromised_identity
      principal_ref: alice

    # Chained paths declare their participants explicitly.
    identities:
      users:
        - { ref: alice }
      applications:
        - { ref: directory-sync }
    resources:
      resource_groups:
        - { ref: rg-badzure-chain, location: East US }
      key_vaults:
        - { ref: badzure-chain-kv, resource_group: rg-badzure-chain }

    # These relationships form the graph.
    assignments:
      - id: vault_access
        type: azure_rbac
        principal_ref: alice
        role: "Key Vault Contributor"
        scope_ref: badzure-chain-kv

      - id: terminal_role
        type: entra_role
        principal_ref: directory-sync
        role: "Global Administrator"

    # Create a real client secret for the terminal application.
    credentials:
      - ref: directory_sync_secret
        app_ref: directory-sync
        type: password

    # Store that secret where the compromised user can read it.
    data_injects:
      - id: planted_secret
        material: app_secret
        credential_ref: directory_sync_secret
        location: key_vault_secret
        location_ref: badzure-chain-kv
        name: client-secret-directory-sync
```

Unlike an atomic path, this configuration does not use
`privilege_escalation.technique`. The relationships under `assignments:` and the
credential stored through `data_injects:` describe the route directly.

## 1. Declare the participants

Every reference used by the path must resolve to an identity or resource. This lab
declares the participants inline:

- `alice` is the compromised user.
- `directory-sync` is the application whose credential will be stolen.
- `badzure-chain-kv` stores that credential.
- `rg-badzure-chain` contains the vault.

The `ref` value is the stable name used everywhere else in the path. Chained paths
can also borrow participants from the baseline; see
[Borrowing baseline entities](../reference/chained.md#borrowing-baseline-entities).

## 2. Set the foothold and objective

`initial_access.principal_ref` selects the identity the attacker controls first:

```yaml
initial_access:
  method: compromised_identity
  principal_ref: alice
```

The objective gives the reachability gate a machine-checkable destination. For an
Entra role, set `capability: entra_role` and its friendly name or GUID:

```yaml
objective:
  capability: entra_role
  role: "Global Administrator"
```

Chained objectives can also target an API permission or an Azure role. See the
[Chained Reference](../reference/chained.md#objective) for each shape.

## 3. Wire the assignments

Assignments describe relationships in the tenant. The first assignment gives
`alice` access to the vault:

```yaml
- id: vault_access
  type: azure_rbac
  principal_ref: alice
  role: "Key Vault Contributor"
  scope_ref: badzure-chain-kv
```

The second assignment gives `directory-sync` the role that satisfies the objective:

```yaml
- id: terminal_role
  type: entra_role
  principal_ref: directory-sync
  role: "Global Administrator"
```

These assignments alone do not connect the user to the application. The stored
credential supplies that pivot.

## 4. Create and plant the credential

`credentials` creates authentication material on an application. `data_injects`
places that material in a resource:

```yaml
credentials:
  - ref: directory_sync_secret
    app_ref: directory-sync
    type: password

data_injects:
  - id: planted_secret
    material: app_secret
    credential_ref: directory_sync_secret
    location: key_vault_secret
    location_ref: badzure-chain-kv
    name: client-secret-directory-sync
```

The shared `credential_ref` connects the planted value to the application secret.
Because `alice` can read the vault, the reachability walk can loot the secret and
bring `directory-sync` under the attacker's control.

## 5. Check and inspect the path

Verify the traversal offline:

```bash
python BadZure.py check --config my-chained-lab.yml
```

Use `--verbose` to see every derived step. If a reference or relationship is
missing, `check` reports where the walk stops. Once it is reachable, render the
posture and attack graphs:

```bash
python BadZure.py report --config my-chained-lab.yml
```

Confirm that the red attack spine follows the sequence you intended before
deploying anything.

## 6. Choose a unique resource name

Key Vault names are globally unique. Before deployment, replace `badzure-chain-kv`
with your own unique name in all three places: the resource declaration, the
`vault_access.scope_ref`, and the `planted_secret.location_ref`. Run `check` again
after the change.

## 7. Build and destroy the lab

Deploy the checked configuration:

```bash
python BadZure.py build --config my-chained-lab.yml
```

BadZure prints `alice`'s credentials after the build. Use them as the starting point
for the path. When finished, remove the lab:

```bash
python BadZure.py destroy
```

See [Installation](../installation.md#authenticate-to-azure) for authentication
requirements and the [`build` reference](../reference/commands.md#build) for options.

## Extend the chain

To add another pivot, declare its participant, add the relationship that makes it
reachable, and run `check` again. Building incrementally makes a broken hop easy to
identify.

The [Chained Paths and Primitives](../attack-paths/chaining.md) page shows a longer
identity-to-resource-to-identity example. The
[Chained Reference](../reference/chained.md) documents every assignment, credential,
and data-injection field.
