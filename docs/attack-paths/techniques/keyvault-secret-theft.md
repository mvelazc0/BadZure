# KeyVaultSecretTheft

**Category:** Resource based

A compromised identity has direct access to an Azure Key Vault that stores an application's client secret. The attacker reads the secret and authenticates as the application's service principal.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-kv_theft" title="KeyVaultSecretTheft posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-kv_theft" title="KeyVaultSecretTheft attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Roles such as Key Vault Contributor and Key Vault Secrets User let the holder read secrets. When a secret is an application's client secret, reading it is enough to authenticate as that application and hold whatever it holds. The access is direct, with no managed-identity step.

## Configure it

```yaml
attack_paths:
  kv_theft:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: KeyVaultSecretTheft
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

Ensure the baseline includes `key_vaults: 1` (or more).

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal can read the vault and take over the application whose secret is stored there.

## Variants

- **Assignment**: `assignment_type` controls whether the vault role is held directly or through a group.
- **Foothold**: `principal_type: user` or `service_principal`.

To reach a Key Vault through a stolen managed-identity token instead of direct access, use [ManagedIdentityAbuse](managed-identity-abuse.md) with `target_resource_type: key_vault`. Full options are in the [Atomic Reference](../../reference/atomic.md#keyvaultsecrettheft).
