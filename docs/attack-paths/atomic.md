# Atomic Paths

An atomic path describes a single privilege escalation technique. You select one technique from the catalog below and configure it with three sections, and BadZure picks the victim and target from the baseline and builds the full chain.

## Structure

An atomic path has three sections:

- **`initial_access`** describes how the attacker first gains a foothold: a compromised credential of a user or service principal, or a foothold on an exposed resource.
- **`privilege_escalation`** names the technique and sets the options that control how it is built.
- **`objective`** describes the access the attacker holds at the end of the path: an Entra role, an API permission, or an Azure role.

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

Each technique page documents the options that apply to that technique. The [Configuration Guide](../configuration.md) covers every option in full. The flow of a typical atomic path is:

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

## Identity Based Privilege Escalation

These paths exploit misconfigurations in Entra ID identity management, application settings, and managed identity configurations.

<div class="grid cards" markdown>

-   **[ApplicationOwnershipAbuse](app-ownership-abuse.md)**

    ---

    Exploit application ownership to add credentials to a privileged application. Simulates compromised developer or automation accounts that own overprivileged apps.

-   **[ApplicationAdministratorAbuse](app-administrator-abuse.md)**

    ---

    Exploit the Application Administrator Entra ID role to manage **any** application in the tenant. Broader scope than ownership abuse: one compromised admin can target all apps.

-   **[CloudAppAdministratorAbuse](cloud-app-administrator-abuse.md)**

    ---

    Exploit the Cloud Application Administrator Entra ID role. Similar to ApplicationAdministratorAbuse but with a narrower scope: it cannot manage apps with certain sensitive permissions.

-   **[ManagedIdentityAbuse](managed-identity-abuse.md)**

    ---

    Steal managed identity tokens from Azure resources (VMs, Logic Apps, Automation Accounts, Function Apps) and use them to retrieve credentials from Key Vaults, Storage Accounts, or Cosmos DB.

</div>

## Resource Based Privilege Escalation

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
