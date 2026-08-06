# ManagedIdentityAbuse

**Category:** Resource based

A compromised identity controls a compute resource that has a system-assigned managed identity. Controlling the resource means acting as its managed identity. That identity has access to another resource (a Key Vault, Storage Account, or Cosmos DB) from which the attacker loots an application credential.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-mi_abuse" title="ManagedIdentityAbuse posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-mi_abuse" title="ManagedIdentityAbuse attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Control roles such as Virtual Machine Contributor and Website Contributor let the holder run code on a compute resource. Code running on the resource can request its managed-identity token from the local metadata endpoint. From that point the attacker acts as the managed identity, using whatever access it was granted. This is the pivot from the identity plane into the infrastructure plane.

## Configure it

```yaml
attack_paths:
  mi_abuse:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: ManagedIdentityAbuse
      source_type: vm                     # the compute resource with the managed identity
      privilege_source: stored_credential
      target_resource_type: key_vault     # where the looted credential is stored
      credential_type: secret
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

Ensure the baseline contains the source compute and target resource (for example `virtual_machines: 1` and `key_vaults: 1`), or declare them on the path.

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

The derived steps show the managed-identity pivot (`Steal Application Access Token`, ATT&CK **T1528**) followed by the loot from the target resource.

## Variants

**Source resource** (`source_type`): the compute resource whose managed identity is abused:

| Value | Resource |
|---|---|
| `vm` | Virtual Machine |
| `logic_app` | Logic App |
| `automation_account` | Automation Account |
| `function_app` | Function App (Linux/Python) |
| `app_service` | App Service (Linux/Python) |

**Flavor** (`privilege_source`):

- `stored_credential`: the managed identity reads an application credential from the `target_resource_type` resource; the objective is the looted application's role or permission.
- `managed_identity`: the managed identity is itself over-privileged; there is no target resource and the objective is an Azure role on the managed identity.

**Target resource** (`target_resource_type`): `key_vault`, `storage_account`, or `cosmos_db`.

**Credential type** (`credential_type`): `secret` (default) or `certificate` (Key Vault and Storage).

**Foothold**: pairs naturally with the `exposed_rdp`, `exposed_ssh`, and `vulnerable_web_app` vectors, which land directly on a compute host. See [Initial Access](../initial-access.md).

Full options are in the [Atomic Reference](../../reference/atomic.md#managedidentityabuse).
