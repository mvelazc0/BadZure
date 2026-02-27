# Attack Paths

BadZure creates complete attack chains that start with a compromised identity and end at a high-privilege target. Each path represents a privilege escalation technique seen in real Azure and Entra ID environments.

## Overview

Every attack path follows the same structure:

1. **Initial Access** — A user account or service principal is compromised (BadZure provides the credentials)
2. **Misconfiguration** — The compromised identity has some form of excessive access: application ownership, an administrative role, contributor access to an Azure resource, or direct access to a secrets store
3. **Privilege Escalation** — The attacker leverages the misconfiguration to obtain credentials for a highly privileged application
4. **Impact** — The attacker authenticates as the privileged application, gaining elevated access to the tenant

``` mermaid
graph TD
    IA["Initial Access<br/><small>Compromised User or Service Principal</small>"]

    IA --> OWN["Owns Application"]
    IA --> ADMIN["Has App Admin Role"]
    IA --> CONTRIB["Has Contributor on<br/>Azure Resource"]
    IA --> KV["Has Key Vault Access"]
    IA --> SA["Has Storage Access"]
    IA --> CDB["Has Cosmos DB Access"]

    OWN --> CRED1["Add Credentials<br/>to Owned App"]
    ADMIN --> CRED2["Add Credentials<br/>to Any App"]
    CONTRIB --> MI["Steal Managed<br/>Identity Token"]
    MI --> RETRIEVE1["Retrieve Secrets<br/>from Key Vault"]
    MI --> RETRIEVE2["Retrieve Certs<br/>from Storage"]
    MI --> RETRIEVE5["Retrieve Secrets<br/>from Cosmos DB"]
    KV --> RETRIEVE3["Retrieve Secrets<br/>from Key Vault"]
    SA --> RETRIEVE4["Retrieve Certs<br/>from Storage"]
    CDB --> RETRIEVE6["Retrieve Secrets<br/>from Cosmos DB"]

    CRED1 --> PRIV["Authenticate as<br/>Privileged Application"]
    CRED2 --> PRIV
    RETRIEVE1 --> PRIV
    RETRIEVE2 --> PRIV
    RETRIEVE3 --> PRIV
    RETRIEVE4 --> PRIV
    RETRIEVE5 --> PRIV
    RETRIEVE6 --> PRIV


```

## Identity-Based Privilege Escalation

These paths exploit misconfigurations in Entra ID identity management, application settings, and managed identity configurations.

<div class="grid cards" markdown>

-   **[ApplicationOwnershipAbuse](app-ownership-abuse.md)**

    ---

    Exploit application ownership to add credentials to a privileged application. Simulates compromised developer or automation accounts that own overprivileged apps.

-   **[ApplicationAdministratorAbuse](app-administrator-abuse.md)**

    ---

    Exploit the Application Administrator Entra ID role to manage **any** application in the tenant. Broader scope than ownership abuse — one compromised admin can target all apps.

-   **[CloudAppAdministratorAbuse](cloud-app-administrator-abuse.md)**

    ---

    Exploit the Cloud Application Administrator Entra ID role. Similar to ApplicationAdministratorAbuse but with a narrower scope — cannot manage apps with certain sensitive permissions.

-   **[ManagedIdentityTheft](managed-identity-theft.md)**

    ---

    Steal managed identity tokens from Azure resources (VMs, Logic Apps, Automation Accounts, Function Apps) and use them to retrieve credentials from Key Vaults, Storage Accounts, or Cosmos DB.

</div>

## Resource-Based Privilege Escalation

These paths exploit direct access to Azure resources that store application credentials.

<div class="grid cards" markdown>

-   **[KeyVaultSecretTheft](keyvault-secret-theft.md)**

    ---

    Retrieve application client secrets directly from Azure Key Vault. Simulates scenarios where Key Vault access controls are misconfigured.

-   **[StorageCertificateTheft](storage-certificate-theft.md)**

    ---

    Retrieve application certificates and private keys from Azure Blob Storage. Simulates scenarios where authentication certificates are stored without proper access controls.

-   **[CosmosDBSecretTheft](cosmosdb-secret-theft.md)**

    ---

    Retrieve application client secrets from Azure Cosmos DB documents. Simulates scenarios where sensitive credentials are stored in database documents instead of proper secret management.

</div>

## Common Options

All attack paths share these configuration options:

| Option | Values | Description |
|---|---|---|
| `initial_access` | `user` (default), `service_principal` | Type of initial access identity |
| `assignment_type` | `direct` (default), `group_member`, `group_owner` | Whether permissions are assigned directly, through group membership, or through group ownership |
| `method` | `AzureADRole`, `APIPermission` | How the target application gets its privileges |

See the [Configuration Guide](../configuration.md) for full details on all parameters.
