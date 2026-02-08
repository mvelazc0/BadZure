# Attack Paths

BadZure creates complete attack chains that start with a compromised identity and end at a high-privilege target. Each path represents a realistic privilege escalation technique seen in real Azure and Entra ID environments.

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

    OWN --> CRED1["Add Credentials<br/>to Owned App"]
    ADMIN --> CRED2["Add Credentials<br/>to Any App"]
    CONTRIB --> MI["Steal Managed<br/>Identity Token"]
    MI --> RETRIEVE1["Retrieve Secrets<br/>from Key Vault"]
    MI --> RETRIEVE2["Retrieve Certs<br/>from Storage"]
    KV --> RETRIEVE3["Retrieve Secrets<br/>from Key Vault"]
    SA --> RETRIEVE4["Retrieve Certs<br/>from Storage"]

    CRED1 --> PRIV["Authenticate as<br/>Privileged Application"]
    CRED2 --> PRIV
    RETRIEVE1 --> PRIV
    RETRIEVE2 --> PRIV
    RETRIEVE3 --> PRIV
    RETRIEVE4 --> PRIV

    style IA fill:#ef5350,color:#fff
    style PRIV fill:#2e7d32,color:#fff
    style OWN fill:#37474f,color:#fff
    style ADMIN fill:#37474f,color:#fff
    style CONTRIB fill:#37474f,color:#fff
    style KV fill:#37474f,color:#fff
    style SA fill:#37474f,color:#fff
    style MI fill:#e65100,color:#fff
    style CRED1 fill:#455a64,color:#fff
    style CRED2 fill:#455a64,color:#fff
    style RETRIEVE1 fill:#455a64,color:#fff
    style RETRIEVE2 fill:#455a64,color:#fff
    style RETRIEVE3 fill:#455a64,color:#fff
    style RETRIEVE4 fill:#455a64,color:#fff
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

-   **[ManagedIdentityTheft](managed-identity-theft.md)**

    ---

    Steal managed identity tokens from Azure resources (VMs, Logic Apps, Automation Accounts, Function Apps) and use them to retrieve credentials from Key Vaults or Storage Accounts.

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

</div>

## Common Options

All attack paths share these configuration options:

| Option | Values | Description |
|---|---|---|
| `identity_type` | `user` (default), `service_principal` | Type of compromised identity |
| `initial_access` | `password`, `token` | How credentials are provided |
| `assignment_type` | `direct` (default), `group` | Whether permissions are assigned directly or through a security group |
| `method` | `AzureADRole`, `APIPermission` | How the target application gets its privileges |
| `entry_point` | `compromised_identity` (default) | How the attacker gains initial access |

See the [Configuration Guide](../configuration.md) for full details on all parameters.
