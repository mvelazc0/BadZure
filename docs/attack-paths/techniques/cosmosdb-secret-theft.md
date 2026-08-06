# CosmosDBSecretTheft

**Category:** Resource based

A compromised identity has direct data-plane access to an Azure Cosmos DB account that holds an application's client secret in a document. The attacker reads the document and authenticates as the application's service principal.

<div class="bz-graph-pair" markdown="0">
  <figure>
    <figcaption>Posture: the state that exists</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=posture-cosmos_theft" title="CosmosDBSecretTheft posture" loading="lazy"></iframe>
  </figure>
  <figure>
    <figcaption>Attack: what the adversary does</figcaption>
    <iframe class="bz-graph" src="/reports/atomic-gallery.report.html?embed=attack-cosmos_theft" title="CosmosDBSecretTheft attack" loading="lazy"></iframe>
  </figure>
</div>

<small class="bz-graph-caption"><a href="/reports/atomic-gallery.report.html" target="_blank" rel="noopener">Open the full lab report ↗</a></small>

## What makes it possible

The Cosmos DB Built-in Data Contributor role grants data-plane access and lets the holder read documents. Applications sometimes store secrets or connection strings as documents. When a document is an application's client secret, reading it is enough to authenticate as that application.

## Configure it

```yaml
attack_paths:
  cosmos_theft:
    initial_access:
      vector: compromised_credential
      principal_type: user
    privilege_escalation:
      technique: CosmosDBSecretTheft
      assignment_type: direct
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10   # Global Administrator
```

Ensure the baseline includes `cosmos_dbs: 1` (or more). BadZure plants the secret document in a post-apply data-plane step.

## Verify it

```bash
python BadZure.py check --config your-config.yml
```

A `reachable` verdict confirms a controlled principal can read the Cosmos DB account and take over the application whose secret is stored there.

## Variants

- **Assignment**: `assignment_type` controls whether the Cosmos DB role is held directly or through a group.
- **Foothold**: `principal_type: user` or `service_principal`.

To reach Cosmos DB through a stolen managed-identity token instead, use [ManagedIdentityAbuse](managed-identity-abuse.md) with `target_resource_type: cosmos_db`. Full options are in the [Atomic Reference](../../reference/atomic.md#cosmosdbsecrettheft).
