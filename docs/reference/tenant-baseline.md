# Tenant & Baseline Reference

Every config has a `tenant` block and a `baseline` block. This page documents both, and how resources are placed into resource groups. For attack paths, see the [Atomic](atomic.md) and [Chained](chained.md) references.

## Tenant

The `tenant` section identifies your Azure environment.

| Setting | Description |
|---|---|
| `tenant_id` | Entra ID tenant GUID |
| `domain` | Tenant domain (e.g. `contoso.onmicrosoft.com`) |
| `subscription_id` | Azure subscription GUID for provisioning resources |

These can also be set as environment variables in a `.env` file (`BADZURE_TENANT_ID`, `BADZURE_DOMAIN`, `BADZURE_SUBSCRIPTION_ID`). Leave a YAML value `null` to use the variable. See `.env.example`.

## Baseline

The `baseline` section populates the lab with benign background entities so the tenant looks like a real organization. In a tenant containing only attack-path resources, every object an operator enumerates is part of the solution; the baseline buries the paths in benign noise so they must be uncovered through reconnaissance. The baseline has three sub-sections.

### identities: Entra entities

| Setting | Description |
|---|---|
| `users` | User accounts to create |
| `applications` | Application registrations / service principals |
| `groups` | Security groups |
| `administrative_units` | Administrative units |

### resources: Azure resources

| Setting | Description | Used by |
|---|---|---|
| `resource_groups` | How many groups to spread resources across (one is created if omitted) | None |
| `key_vaults` | Key Vaults | KeyVaultSecretTheft, ManagedIdentityAbuse |
| `storage_accounts` | Storage Accounts | StorageCertificateTheft, ManagedIdentityAbuse |
| `virtual_machines` | Windows or Linux VMs | ManagedIdentityAbuse |
| `logic_apps` | Logic Apps | ManagedIdentityAbuse |
| `automation_accounts` | Automation Accounts | ManagedIdentityAbuse |
| `function_apps` | Function Apps | ManagedIdentityAbuse |
| `app_services` | App Services (Linux web apps) | ManagedIdentityAbuse |
| `cosmos_dbs` | Cosmos DB accounts | CosmosDBSecretTheft, ManagedIdentityAbuse |

Baseline VMs are private: only an exposed-host foothold VM gets a public IP. App Service creation is throttled per subscription, so rapid build/destroy cycles can hit transient throttling.

### assignments: permission sprawl (optional)

Realistic everyday grants that recreate how access is distributed across a real organization, so seeded attack paths blend into believable access patterns.

```yaml
baseline:
  identities: { users: 15, groups: 4, applications: 6, administrative_units: 2 }
  resources:  { key_vaults: 2, storage_accounts: 1 }
  assignments:
    group_memberships: 12   # users/groups added to groups
    entra_roles: 4          # low-priv directory roles on users/apps
    api_permissions: 3      # benign Graph permissions on apps
    au_memberships: 2       # users/groups in administrative units
    azure_rbac: 6           # Reader/Contributor/... over the baseline resources
    group_ownerships: 3     # users owning groups
    app_ownerships: 3       # users owning app registrations
    app_credentials: 4      # client secrets on service principals
    data_injects: 2         # benign secrets/blobs in the baseline vaults/storage
```

Omit the block to create entities with no random grants.

### Explicit baselines

Counts produce a different generated organization on each build. For stable names
and exact relationships, provide lists instead and connect their `ref` values with
the same primitives used by chained paths:

```yaml
baseline:
  identities:
    users: [{ ref: alice.chen }]
    groups: [{ ref: Engineering }]
  assignments:
    - { type: group_membership, principal_ref: alice.chen,
        group_ref: Engineering }
```

### Generating an explicit baseline

For larger deterministic organizations, describe departments and headcounts instead
of enumerating every identity:

```yaml
company: { name: Northwind Tech, industry: SaaS }
departments:
  - { name: Engineering, headcount: 12 }
  - { name: Finance, headcount: 4 }
resources:
  resource_groups:
    - { ref: rg-prod, location: West US 2 }
  key_vaults:
    - { ref: kv-nwprod01, resource_group: rg-prod }
```

`compile-baseline` expands the design into a full explicit baseline, offline and
deterministically:

```bash
python BadZure.py compile-baseline --design org-design.yml -o generated.yml
```

An org design can declare additional groups, service principals, administrative
units, RBAC, Entra roles, ownerships, fake secrets, and blobs. Print the complete,
always-current contract with:

```bash
python BadZure.py baseline-spec
```

## Resource groups

Every Azure resource lives in a resource group. BadZure creates the groups and places resources into them; you choose how explicit that placement is.

In `baseline` resources are counts, so `resource_groups` is a count too: BadZure creates that many groups with generated names and spreads resources randomly across them. If you declare resources but no groups, it creates one.

In a chained path resources are named, so you can name the groups. Declare them under `resources.resource_groups` and pin a resource to one with its `resource_group` field. A resource that names a group lands there and takes its location; a resource that omits the field is spread randomly. Naming an undeclared group stops the build with an error.

```yaml
# baseline (counts): two groups, resources spread randomly
baseline:
  resources: { resource_groups: 2, key_vaults: 2, storage_accounts: 1 }

# chained (named): pin some, leave others random
attack_paths:
  kv_to_ga:
    resources:
      resource_groups:
        - { ref: rg-prod, location: "West US" }
        - { ref: rg-corp, location: "East US" }
      key_vaults:
        - { ref: badzure-ref-kv-01, resource_group: rg-prod }   # pinned
        - { ref: badzure-ref-kv-02 }                            # random
```
