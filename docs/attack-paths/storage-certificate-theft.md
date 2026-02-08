# StorageCertificateTheft

**Category:** Resource-Based Privilege Escalation

An attacker compromises an identity with **read access to Azure Blob Storage** and downloads application certificates and private keys stored in a storage container. The attacker uses certificate-based authentication to impersonate a privileged application.

## Attack Flow

``` mermaid
graph LR
    A["Compromised<br/>Identity"] -->|"Storage Blob<br/>Data Reader"| B["Azure Storage<br/>Account"]
    B -->|"download"| C["Certificate +<br/>Private Key"]
    C -->|"cert-based auth"| D["Privileged<br/>Application"]
    D -->|"escalate to"| E["Privileged<br/>Access"]

    style A fill:#ef5350,color:#fff
    style B fill:#37474f,color:#fff
    style C fill:#e65100,color:#fff
    style D fill:#455a64,color:#fff
    style E fill:#2e7d32,color:#fff
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

## How It Differs From ManagedIdentityTheft

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

=== "Service Principal"

    A service principal with Storage Blob Data Reader role. Simulates a compromised pipeline with excessive storage permissions.

### By Assignment Type

=== "Direct (default)"

    Storage Blob Data Reader is assigned directly to the identity.

=== "Group"

    The identity is a member of a security group with Storage Blob Data Reader access.

    ``` mermaid
    graph LR
        U["Compromised<br/>Identity"] -->|"member of"| G["Security<br/>Group"]
        G -->|"Storage Blob<br/>Data Reader"| SA["Azure Storage<br/>Account"]
        SA -->|"download cert"| APP["Privileged<br/>App"]

        style U fill:#ef5350,color:#fff
        style G fill:#e65100,color:#fff
        style SA fill:#37474f,color:#fff
        style APP fill:#2e7d32,color:#fff
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
    identity_type: service_principal
    initial_access: token
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
    assignment_type: group
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

!!! tip
    Make sure your tenant configuration includes at least one Storage Account (`storage_accounts: 1`) when using this attack path.
