# Chained Reference

A chained path is an explicit graph built from primitives rather than a named technique template. It can reproduce one catalog behavior or combine several behaviors in any supported sequence. A path uses either `privilege_escalation:` (atomic) or `assignments:` (chained): never both.

A chained path declares an `objective`, an `initial_access` point, the `identities` and `resources` it uses, the `assignments` that form the chain, and any `credentials` and `data_injects` it plants.

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
      key_vaults:   [{ ref: badzure-ref-kv-01 }]   # ref doubles as the real, globally-unique name
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

The chain reads: `priya` holds Key Vault Contributor → reads the planted secret → authenticates as `billing-sync-app`, which holds Global Administrator.

## objective

The machine-checkable goal the reachability gate verifies. Set `capability` and the target:

- `capability: entra_role` with `role:`: a controlled principal must hold the role.
- `capability: api_permission`: a controlled application must hold a mail/graph permission (for example `read_mail`).
- `capability: azure_role`: a controlled principal must hold an Azure role at a scope.

`name`, `impact`, and `description` are metadata shown in the report.

## initial_access

Where the attacker starts. One of:

- Compromised identity: `{ method: compromised_identity, principal_ref: <user or app ref> }`. The walk seeds at that identity.
- Exposed-host foothold: `{ vector: exposed_rdp, target_ref: <vm ref> }`. The attacker lands on the VM with code execution; the walk seeds at the host. Optional `expose_to_internet` (default `false`) and `credential` (default `known`).
- Vulnerable-web-app foothold: `{ vector: vulnerable_web_app, target_ref: <app_service ref> }`. Seeds at the App Service. Optional `variant` (default `rce`) and `expose_to_internet`.

```yaml
    initial_access:
      vector: exposed_rdp
      target_ref: vm_foothold
      expose_to_internet: false
      credential: weak
    resources:
      virtual_machines: [{ ref: vm_foothold, os_type: Windows }]
    assignments:
      - { id: a1, type: azure_rbac, principal_ref: vm_foothold,
          principal_type: managed_identity, mi_source_type: vm,
          role: "Key Vault Secrets User", scope_ref: badzure-ref-kv-01 }
```

## assignments

The relationships that form the chain. Each is one of seven `type`s:

| Type | Wires |
|---|---|
| `entra_role` | A directory role held by a principal |
| `azure_rbac` | An Azure role on a resource (a control role also grants the resource's managed identity) |
| `api_permission` | A Graph or Exchange app role on a service principal |
| `group_membership` | A principal into a group |
| `group_ownership` | A principal as a group owner |
| `app_ownership` | A principal as an application owner |
| `au_membership` | A user or group into an administrative unit |

A managed-identity assignment sets `principal_type: managed_identity` and `mi_source_type` (the compute kind), since a resource ref cannot be inferred as a principal.

## credentials

Client secrets or certificates minted on an application, referenced by `data_injects`:

```yaml
credentials:
  - { ref: app_secret, app_ref: billing-sync-app, type: password }   # or type: certificate
```

## data_injects

Material planted in a resource for an attacker to loot. `location_type` selects the resource family and `material` selects what is planted:

- **location_type**: `key_vault_secret`, `key_vault_certificate` (Key Vault), `storage_blob` (Storage container), `cosmos_document` (Cosmos DB container).
- **material**: `app_secret` (a declared credential via `credential_ref`), `app_client_id` (an app's client ID via `source_ref`), `app_certificate` (a certificate file via `file_path`), or `literal` (content via `literal_value`).

Key Vault and Storage injects are written by Terraform; `cosmos_document` injects are planted by the post-apply data-plane phase using the Cosmos account key.

## Borrowing baseline entities

A chained path can weave in baseline entities:

- `{ ref: victim, from: baseline }`: a random unused entity of that kind.
- `{ ref: victim, from: baseline, match: hannah.lee }`: a specific entity, matched case-insensitively by baseline ref, UPN, display name, or resource name.

Worked examples are in `examples/chained/`, including `chained_hybrid.yml` (borrowing), `chained_exposed_rdp.yml`, `chained_vulnerable_webapp.yml`, `chained_cosmos_inject.yml`, and `long_chain.yml` (a thirty-step chain exercising every primitive).
