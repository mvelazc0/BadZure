# Lab Anatomy

A BadZure lab is one YAML file with three parts: the `tenant` it targets, a `baseline` organization, and the `attack_paths` layered on top. This page annotates a complete lab end to end. For every field, see the [reference](../reference/tenant-baseline.md).

```yaml
# 1. TENANT: where the lab deploys. null values fall back to BADZURE_* env vars.
tenant:
  tenant_id: null
  domain: null
  subscription_id: null

# 2. BASELINE: the realistic background organization the attack lands in.
baseline:
  # Entra entities, by count. BadZure names and fabricates them.
  identities:
    users: 12
    groups: 5
    applications: 10
  # Azure resources, by count.
  resources:
    resource_groups: 4
    key_vaults: 3
    storage_accounts: 2
    virtual_machines: 2
  # Everyday permission sprawl: benign grants scattered across the org so the
  # attack path has context to hide in. Omit this block for entities only.
  assignments:
    group_memberships: 6
    entra_roles: 4
    api_permissions: 4
    azure_rbac: 4

# 3. ATTACK PATHS: the deliberate misconfigurations.
attack_paths:
  kv_theft:
    # How the attacker first lands.
    initial_access:
      vector: compromised_credential
      principal_type: user
    # The technique (atomic) OR an explicit graph (chained, via assignments:).
    privilege_escalation:
      technique: KeyVaultSecretTheft
      assignment_type: direct
    # The access held at the end: what `check` verifies.
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

## The three parts

**Tenant.** The identifiers BadZure deploys against. Leaving them `null` uses the `BADZURE_*` environment variables from your `.env`, so one config runs against different tenants.

**Baseline.** The background organization. `identities` and `resources` are counts; BadZure fabricates realistic entities. `assignments` scatters benign grants so an attack path lands in a believable tenant rather than an empty one. You can also declare a fully explicit baseline with named entities: see the [Tenant & Baseline Reference](../reference/tenant-baseline.md#explicit-baselines).

**Attack paths.** A map of named paths. Each is either **atomic** (a `privilege_escalation:` technique) or **chained** (an explicit graph under `assignments:`). Every path has an `initial_access` and an `objective`.

## Two ways to author

- **Atomic**: name a technique and a few options; BadZure picks the victim and target from the baseline and builds the chain. See [Author an Atomic Path](authoring-atomic.md).
- **Chained**: wire an explicit graph of primitives in any sequence. See [Author a Chained Path](authoring-chained.md) and [Chained Reference](../reference/chained.md).

## The workflow

Author the file, then:

```bash
python BadZure.py check  --config your-lab.yml   # prove it's reachable (offline)
python BadZure.py report --config your-lab.yml   # see it as graphs (offline)
python BadZure.py build  --config your-lab.yml   # deploy it
python BadZure.py destroy                        # tear it down
```

The annotated reference config `badzure.yml` and the `examples/` directory hold many complete labs.
