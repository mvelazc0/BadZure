---
name: badzure-attack-authoring
description: Authoring contract for a BadZure chained attack path as YAML (objective, initial_access, identities/resources, assignments, credentials, data_injects) that the deterministic reachability gate (`badzure check`) confirms is traversable. Use when designing or refining a multi-hop privilege-escalation path through a BadZure org baseline. Not for the org baseline itself.
user-invocable: false
---

# BadZure attack authoring

A practical, condensed reference for authoring a **chained** BadZure attack path as YAML.
Canonical sources: `docs/attack-paths/chained.md`, `docs/configuration.md`, and the worked
example `examples/chained/chained_apex.yml`. When in doubt, read those.

This is for **authorized lab tenants** only. The whole point is a path that the reachability
gate (`badzure check`) confirms is actually traversable, then deploys for training/detection.

---

## The shape of a chained path
A path lives under `attack_paths.<name>` and uses `assignments:` (NOT `privilege_escalation:` —
the two are mutually exclusive). It declares:

```yaml
attack_paths:
  helpdesk_to_ga:
    objective:                       # the goal the path must REACH
      name: "Global Administrator via Key Vault"
      capability: entra_role         # what the attacker ultimately gains
      role: "Global Administrator"   # the target of that capability
      impact: critical
    metadata:                        # optional, for narrative/output
      complexity: high
      mitre: [T1078, T1098, T1555]
    initial_access:                  # where the attacker starts
      method: compromised_identity
      principal_ref: hannah.lee
    identities:                      # entities the path uses (declare inline)
      users:        [{ ref: hannah.lee }]
      applications: [{ ref: svc-deviceenroll }, { ref: svc-clinicaldatasync }]
      groups:       [{ ref: grp-helpdesk }]
      administrative_units: [{ ref: au-tier0 }]
    resources:
      resource_groups: [{ ref: rg-clinical, location: "East US" }]
      key_vaults:      [{ ref: kv-clinical-ops, resource_group: rg-clinical }]
    assignments:                     # the chain (each is one building block)
      - { id: a1, type: group_membership, principal_ref: hannah.lee, group_ref: grp-helpdesk }
      - { id: a2, type: app_ownership,    principal_ref: grp-helpdesk, app_ref: svc-deviceenroll }
      - { id: a3, type: azure_rbac, principal_ref: svc-deviceenroll,
          role: "Key Vault Secrets User", scope_ref: kv-clinical-ops }
      - { id: a4, type: entra_role, principal_ref: svc-clinicaldatasync, role: "Application Administrator" }
    credentials:                     # creds the path mints on an app
      - { ref: cr_cds, app_ref: svc-clinicaldatasync, type: password }
    data_injects:                    # material planted for the attacker to read
      - { id: d1, material: app_secret, credential_ref: cr_cds,
          location: key_vault_secret, location_ref: kv-clinical-ops,
          name: clinicaldatasync-client-secret }
```

Borrow a baseline entity instead of declaring a new one: `{ ref: alice.chen, from: baseline }`
picks a *random* unused baseline entity of that kind. To thread a **specific named**
baseline employee/resource instead, add `match:` —
`{ ref: victim, from: baseline, match: hannah.lee }` binds the org's real `hannah.lee`
(matches the baseline ref, UPN, display name, or resource name, case-insensitively). Prefer
`match:` when the narrative names a real person; one baseline entity can back only one ref.

## The 7 assignment building blocks (the only `type:` values)
| type | required fields | meaning |
|------|-----------------|---------|
| `entra_role` | `principal_ref`, `role` | principal holds an Entra directory role (name or GUID) |
| `azure_rbac` | `principal_ref`, `role`, `scope_ref` | Azure RBAC role on a resource. For a managed identity add `principal_type: managed_identity`, `mi_source: vm\|logic_app\|automation_account\|function_app`, and set `principal_ref` to the resource ref |
| `api_permission` | `principal_ref`, `api_type` (`graph`\|`exchange`), `app_role` | app/Graph permission granted to an SP |
| `group_membership` | `principal_ref`, `group_ref` | principal is a member of the group |
| `group_ownership` | `principal_ref`, `group_ref` | principal OWNS the group (can wield its grants) |
| `app_ownership` | `principal_ref`, `app_ref` | principal OWNS the app registration (can add creds, act as the SP) |
| `au_membership` | `principal_ref`, `au_ref` | principal is in an administrative unit |

`credentials`: `{ ref, app_ref, type: password|certificate }`.
`data_injects`: `{ id, material: app_secret|app_certificate, credential_ref (app_secret) | source_ref (app_certificate), location: key_vault_secret|key_vault_certificate|storage_blob|cosmos_document, location_ref, name }`.

## How a hop actually chains (the mental model the gate enforces)
- **Own an app → become it.** `app_ownership` lets the attacker mint a credential on the app and
  authenticate as that service principal.
- **Own/are a member of a group → wield its grants.** Roles/RBAC held by a group flow to its
  owners/members.
- **Control a resource → control its managed identity.** `azure_rbac` control roles (e.g.
  "Virtual Machine Contributor", "Website Contributor", "Logic App Contributor",
  "Automation Contributor") over a resource let the attacker run code as that resource's MI.
- **Read a store → loot the planted secret.** A `data_inject` puts the *next* app's secret into a
  Key Vault / storage blob / Cosmos doc; an MI (or principal) with a read role on that store loots
  it and authenticates as the next app. This is the identity→resource→identity pivot.
- **Cert legs come in PAIRS.** To have the attacker loot a *certificate* and auth as app X, author
  BOTH: a `data_inject { material: app_certificate, source_ref: X, location, location_ref, name }`
  planting the lootable `.pfx`, AND a `credentials: { app_ref: X, type: certificate }` registering
  the public key on X's app registration. The credential is what makes cert auth work — without it
  the planted `.pfx` authenticates as nothing and the gate reports the hop UNREACHABLE. (Files are
  auto-minted and shared, so the loot matches the registered key; you only declare the intent.)
- **Terminal hop = the objective.** The final controlled principal must hold the objective
  capability (e.g. `entra_role: Global Administrator`, or `Privileged Role Administrator`,
  or read access to the target resource for a theft objective).

## Rules that keep a chain traversable (read before authoring)
1. **One secret per store.** Give each managed identity a read role scoped to a SINGLE resource,
   and plant each looted secret in its OWN store. If two planted secrets share one vault, the walk
   loots BOTH the moment any reader controls that vault — short-circuiting the chain.
2. **Every hop must be derivable.** The gate walks from `initial_access` forward; a hop only
   counts if the principal you reached actually confers the next capability. Don't skip the
   app_ownership/RBAC step that grants the access — name it explicitly.
3. **The objective must be reached by a CONTROLLED principal.** The terminal role/access has to
   sit on an app/identity the attacker provably controls via the chain.

## Escalation-worthy Entra roles (common terminal/high-priv)
<!-- GENERATED from src/vocabulary.py — run `./venv/bin/python -m src.skill_vocab` to refresh. -->
<!-- BADZURE:GEN escalation_entra_roles -->
`Global Administrator`, `Privileged Role Administrator`, `Application Administrator`, `Cloud
Application Administrator`, `Privileged Authentication Administrator`, `User Administrator`
<!-- /BADZURE:GEN escalation_entra_roles -->
(Application/Cloud-App Admin → add creds to a higher-priv app → escalate.)

## Self-check loop (ALWAYS do this)
After writing/editing the `attack_paths:` block:
```
./venv/bin/python BadZure.py check --config <file> --json
```
Always run BadZure through the project virtualenv interpreter (`./venv/bin/python`, from the repo
root) — bare `python` / `python3` is the system interpreter, lacks BadZure's dependencies, and fails.

- `ok: true` and your path `status: "reached"` → done.
- `status: "blocked"/"invalid"` → read `reason`, it names where the walk dead-ends. Insert the
  missing hop (usually an ownership or RBAC grant) or re-route, and check again. Repeat until green.

Never hand off a path the gate has not confirmed `reached`.
