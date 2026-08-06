# Built-in Atomic Techniques

BadZure provides seven named templates for authoring atomic attack paths. You select
one under `privilege_escalation.technique`, configure its options, and BadZure
expands it into the identities, resources, credentials, and relationships required
to create the path.

The catalog groups these templates by what makes the escalation possible: an
identity-plane privilege or access through an Azure resource. These categories do
not distinguish atomic paths from chained paths. See
[Atomic vs Chained Paths](../atomic-vs-chained.md) for that distinction.

Each technique page pairs the tenant posture with the attacker's traversal, then
shows the technique's configuration and supported variants.

!!! note "Using these behaviors in chained paths"

    A chained path does not select one of these technique names. It declares the
    underlying relationships as primitives instead. Those primitives can reproduce
    one catalog behavior or combine several behaviors into a custom path.

## Identity based

The escalation happens in the identity plane: application ownership or a directory role.

| Technique | What it exploits |
|---|---|
| [ApplicationOwnershipAbuse](application-ownership-abuse.md) | Owning an application to add credentials and authenticate as it |
| [ApplicationAdministratorAbuse](application-administrator-abuse.md) | The Application Administrator role, which can manage any application |
| [CloudAppAdministratorAbuse](cloud-app-administrator-abuse.md) | The Cloud Application Administrator role: narrower than Application Administrator |

## Resource based

The escalation crosses into the infrastructure plane: a managed identity or a secret stored in a resource.

| Technique | What it exploits |
|---|---|
| [ManagedIdentityAbuse](managed-identity-abuse.md) | Stealing a managed-identity token from a compute resource to reach a Key Vault, Storage Account, or Cosmos DB |
| [KeyVaultSecretTheft](keyvault-secret-theft.md) | Reading an application secret directly from Key Vault |
| [StorageCertificateTheft](storage-certificate-theft.md) | Reading an application certificate from Storage |
| [CosmosDBSecretTheft](cosmosdb-secret-theft.md) | Reading an application secret from Cosmos DB |

## At a glance

| Technique | Category | Foothold | Source resource | Target resource | Typical objective |
|---|---|---|---|---|---|
| ApplicationOwnershipAbuse | Identity | User or SP | None | None | Entra role |
| ApplicationAdministratorAbuse | Identity | User or SP | None | None | Entra role |
| CloudAppAdministratorAbuse | Identity | User or SP | None | None | Entra role |
| ManagedIdentityAbuse | Resource | Any | VM, Logic App, Automation, Function, App Service | Key Vault, Storage, Cosmos DB | Entra role, API permission, or Azure role |
| KeyVaultSecretTheft | Resource | User or SP | None | Key Vault | Entra role or API permission |
| StorageCertificateTheft | Resource | User or SP | None | Storage Account | Entra role or API permission |
| CosmosDBSecretTheft | Resource | User or SP | None | Cosmos DB | Entra role or API permission |

Full options for every technique are in the [Atomic Reference](../../reference/atomic.md).
