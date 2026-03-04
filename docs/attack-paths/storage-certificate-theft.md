# StorageCertificateTheft

**Category:** Resource-Based Privilege Escalation

An attacker compromises an identity with **read access to Azure Blob Storage** and downloads application certificates and private keys stored in a storage container. The attacker uses certificate-based authentication to impersonate a privileged application.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Blob Data<br/>Reader on"| SA(("Azure Storage<br/>Account"))
    SA -->|"stores certificate for"| APP(("Privileged<br/>Application"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Download cert from"| SA(("Azure Storage<br/>Account"))
    A -->|"2. Authenticate as"| SP(("Service<br/>Principal"))
    SP -->|"3. Escalate to"| ACCESS(("Privileged<br/>Access"))
```

## What Happens

1. The attacker gains access to a **user account** or **service principal**
2. The compromised identity has **Storage Blob Data Reader** role on an Azure Storage Account
3. The storage account contains **X.509 certificates** (`.pem`) and **private keys** (`.key`) for application registrations
4. The attacker **downloads** the certificate and private key files from blob storage
5. The attacker uses **certificate-based authentication** to impersonate the application's service principal
6. The application has high-privileged **Entra ID roles** or **API permissions**

## How It Differs From KeyVaultSecretTheft

| | StorageCertificateTheft | KeyVaultSecretTheft |
|---|---|---|
| **Target resource** | Azure Storage Account | Azure Key Vault |
| **Credential type** | Certificates + private keys | Client secrets |
| **Auth method** | Certificate-based (X.509) | Secret-based (client credentials) |
| **Detection** | Certificate auth is harder to detect in logs | Secret-based auth produces clearer audit signals |

## How It Differs From ManagedIdentityAbuse

This attack path provides **direct access** to the Storage Account. Use this when simulating scenarios where a user or service principal has been directly granted blob storage access, rather than reaching it through a managed identity.

## Certificate Management

BadZure automatically handles certificate lifecycle:

- Generates **self-signed X.509 certificates** with 1-year validity
- Creates unique certificate and key file names to prevent conflicts
- Stores certificates in **private blob containers**
- Registers certificates with target applications via Terraform

## Variations

### By Identity Type

=== "User (default)"

    A user account with Storage Blob Data Reader role. Simulates a compromised user with overly broad storage access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>User")) -->|"Blob Data<br/>Reader"| SA(("Azure Storage<br/>Account"))
        SA -->|"download cert"| APP(("Privileged<br/>Application"))
    ```

=== "Service Principal"

    A service principal with Storage Blob Data Reader role. Simulates a compromised pipeline with excessive storage permissions.

    ``` mermaid
    graph LR
        SP(("Compromised<br/>Service Principal")) -->|"Blob Data<br/>Reader"| SA(("Azure Storage<br/>Account"))
        SA -->|"download cert"| APP(("Privileged<br/>Application"))
    ```

### By Assignment Type

=== "Direct (default)"

    Storage Blob Data Reader is assigned directly to the identity.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"Blob Data<br/>Reader"| SA(("Azure Storage<br/>Account"))
        SA -->|"download cert"| APP(("Privileged<br/>Application"))
    ```

=== "Group Member"

    The identity is a **member** of a security group with Storage Blob Data Reader access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"member of"| G(("Security<br/>Group"))
        G -->|"Storage Blob<br/>Data Reader"| SA(("Azure Storage<br/>Account"))
        SA -->|"download cert"| APP(("Privileged<br/>Application"))
    ```

=== "Group Owner"

    The identity **owns** a security group with Storage Blob Data Reader access. As group owner, the attacker can add themselves as a member to inherit the group's privileges.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"owner of"| G(("Security<br/>Group"))
        G -->|"Storage Blob<br/>Data Reader"| SA(("Azure Storage<br/>Account"))
        SA -->|"download cert"| APP(("Privileged<br/>Application"))
    ```

## Configuration Examples

User with direct storage access, application has Global Administrator role:

```yaml
attack_paths:
  storage_theft_basic:
    enabled: true
    privilege_escalation: StorageCertificateTheft
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Service principal with Graph API permissions:

```yaml
attack_paths:
  storage_theft_sp:
    enabled: true
    privilege_escalation: StorageCertificateTheft
    initial_access: service_principal
    method: APIPermission
    api_type: graph
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 19dbc75e-c2e2-444c-a770-ec69d8559fc7  # Directory.ReadWrite.All
```

Group-based assignment:

```yaml
attack_paths:
  storage_theft_group:
    enabled: true
    privilege_escalation: StorageCertificateTheft
    assignment_type: group_member
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

!!! tip
    Make sure your tenant configuration includes at least one Storage Account (`storage_accounts: 1`) when using this attack path.

## References

- [From listKeys to Glory: Privilege Escalation and RCE by Abusing Azure Storage Account Keys - Orca Security](https://orca.security/resources/blog/azure-shared-key-authorization-exploitation/)
- [Privilege Escalation via Storage Accounts - Rogier Dijkman](https://rogierdijkman.medium.com/privilege-escalation-via-storage-accounts-bca24373cc2e)
- [Not the Access You Asked For: How Azure Storage Account Permissions Can Be Abused - Yehuda Tamir](https://medium.com/@tamirye94/not-the-access-you-asked-for-how-azure-storage-account-read-write-permissions-can-be-abused-75311103430f)
- [Inside the Attack Chain: Threat Activity Targeting Azure Blob Storage - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)
