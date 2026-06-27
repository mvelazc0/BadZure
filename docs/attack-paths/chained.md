# Chained Paths

A chained path describes an attack path as an explicit graph that you author directly in YAML. Instead of naming a single technique, you declare the entities and the relationships between them as generic building blocks. A chained path can span several steps and combine more than one privilege escalation technique in a single path.

A chained path is defined with `assignments:` instead of `privilege_escalation:`. The two are mutually exclusive within a path.

## Structure

A chained path declares:

- **`objective`** the goal the path reaches: a capability and the target it acts on.
- **`initial_access`** where the attacker starts: a compromised identity, or a foothold on an exposed resource.
- **`identities` and `resources`** the entities the path uses, declared inline. A path can also borrow an entity from the baseline with `{ ref: name, from: baseline }`.
- **`assignments`** the relationships that form the chain. Each assignment is one of the building blocks: `entra_role`, `azure_rbac`, `api_permission`, `group_membership`, `group_ownership`, `app_ownership`, `au_membership`.
- **`credentials`** the credentials the path creates on an application.
- **`data_injects`** material placed into a resource for an attacker to read.

## Example

```yaml
attack_paths:
  explicit_kv_to_ga:
    objective:
      name: "Global Administrator via Key Vault"
      impact: critical
      capability: entra_role          # what the attacker ultimately gains
      role: "Global Administrator"
    initial_access: { method: compromised_identity, principal_ref: priya }
    identities:
      users:        [{ ref: priya }]
      applications: [{ ref: billing-sync-app }]
    resources:
      key_vaults:   [{ ref: badzure-ref-kv-01 }]
    assignments:
      - { id: a1, type: azure_rbac, principal_ref: priya,
          role: "Key Vault Contributor", scope_ref: badzure-ref-kv-01 }
      - { id: a2, type: entra_role, principal_ref: billing-sync-app,
          role: "Global Administrator" }
    credentials:
      - { ref: app_secret, app_ref: billing-sync-app, type: password }
    data_injects:
      - { id: d1, material: app_secret, credential_ref: app_secret,
          location: key_vault_secret, location_ref: badzure-ref-kv-01,
          name: client-secret-billing-sync-app }
```

This path reads as: `priya` holds Key Vault Contributor on the vault, reads the planted secret, and authenticates as `billing-sync-app`, which holds Global Administrator.

## Reference

The [Configuration Guide](../configuration.md#authoring-an-explicit-graph-chained) documents every assignment type, the initial access shapes, and the data inject options. Worked examples live in the `examples/chained/` directory.
