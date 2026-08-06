# StorageCertificateTheft

**Category:** Resource based

A compromised identity has direct read access to an Azure Storage Account that holds an application's certificate. The attacker downloads the certificate and its private key and uses certificate-based authentication to impersonate the application.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-storage_theft" title="StorageCertificateTheft posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-storage_theft" title="StorageCertificateTheft attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

Storage Blob Data Reader and similar roles let the holder download blobs. When a blob is an application's certificate and private key, the attacker can authenticate as the application using certificate-based authentication. As with Key Vault theft, the access is direct.

## Configure it

```yaml
attack_paths:
  storage_theft:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: StorageCertificateTheft
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

Ensure the baseline includes `storage_accounts: 1` (or more).

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal can read the storage account and take over the application whose certificate is stored there.

## Variants

- **Assignment**: `assignment_type` controls whether the storage role is held directly or through a group.
- **Foothold**: `principal_type: user` or `service_principal`.

To reach a Storage Account through a stolen managed-identity token instead, use [ManagedIdentityAbuse](managed-identity-abuse.md) with `target_resource_type: storage_account`. Full options are in the [Atomic Reference](../../reference/atomic.md#storagecertificatetheft).
