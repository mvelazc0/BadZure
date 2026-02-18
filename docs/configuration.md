# Configuration Guide

BadZure is configured through a YAML file that defines your tenant settings, the entities to create, and the attack paths to configure. By default, BadZure looks for `badzure.yml` in the project root.

## How It Works

You define the number of entities to create and the attack paths to configure. BadZure creates the specified entities with realistic names and **randomly assigns** them to attack paths. You define counts and attack path types, and BadZure handles the rest.

```yaml
tenant:
  tenant_id: YOUR-TENANT-GUID
  domain: yourdomain.onmicrosoft.com
  subscription_id: YOUR-SUBSCRIPTION-GUID
  users: 30
  applications: 10
  groups: 10

attack_paths:
  path_1:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: random
```

## Tenant Settings

The `tenant` section defines your Azure environment and resource counts.

### Required Settings

| Setting | Description |
|---|---|
| `tenant_id` | Your Entra ID tenant GUID |
| `domain` | Your tenant domain (e.g., `contoso.onmicrosoft.com`) |
| `subscription_id` | Azure subscription GUID for provisioning resources |

!!! tip
    These values can also be set via environment variables in a `.env` file. See `.env.example` for the template.

### Entra ID Entities

| Setting | Description |
|---|---|
| `users` | Number of user accounts to create |
| `applications` | Number of application registrations to create |
| `groups` | Number of security groups to create |
| `administrative_units` | Number of administrative units to create |

### Azure Resources

| Setting | Description | Required By |
|---|---|---|
| `resource_groups` | Number of resource groups | All Azure resources |
| `key_vaults` | Number of Key Vaults | KeyVaultSecretTheft, ManagedIdentityTheft (key_vault target) |
| `storage_accounts` | Number of Storage Accounts | StorageCertificateTheft, ManagedIdentityTheft (storage_account target) |
| `virtual_machines` | Number of Linux VMs (with networking) | ManagedIdentityTheft (vm source) |
| `logic_apps` | Number of Logic Apps (with system-assigned managed identities) | ManagedIdentityTheft (logic_app source) |
| `automation_accounts` | Number of Automation Accounts (with system-assigned managed identities) | ManagedIdentityTheft (automation_account source) |
| `function_apps` | Number of Function Apps (with system-assigned managed identities) | ManagedIdentityTheft (function_app source) |

!!! warning
    Make sure resource counts match your attack path requirements. For example, if you enable a ManagedIdentityTheft path with `source_type: vm`, you need at least `virtual_machines: 1`.

## Attack Path Options

Each attack path is a named entry under `attack_paths`. The name is arbitrary — use something descriptive.

### Common Options

These options are available for **all** attack path types:

| Option | Values | Default | Description |
|---|---|---|---|
| `enabled` | `true`, `false` | — | Whether this attack path is active |
| `privilege_escalation` | See below | — | The escalation technique |
| `method` | `AzureADRole`, `APIPermission` | — | How the target app gets its privileges |
| `identity_type` | `user`, `service_principal` | `user` | Type of compromised identity |
| `assignment_type` | `direct`, `group` | `direct` | Direct assignment or via group membership |

### Option Details

**`privilege_escalation`** — The privilege escalation technique to simulate:

- **`ApplicationOwnershipAbuse`** — Exploits application ownership to add credentials to privileged applications
- **`ApplicationAdministratorAbuse`** — Exploits the Application Administrator role to manage any application and add credentials
- **`CloudAppAdministratorAbuse`** — Exploits the Cloud Application Administrator role (narrower scope than Application Administrator)
- **`ManagedIdentityTheft`** — Exploits access to Azure resources with managed identities to steal tokens and pivot to other resources
- **`KeyVaultSecretTheft`** — Retrieves application secrets stored in Azure Key Vault through direct access
- **`StorageCertificateTheft`** — Retrieves application certificates and private keys from Azure Storage through direct access

For detailed descriptions of each technique, see the [Attack Paths](attack-paths/index.md) section.

**`identity_type`** — The type of identity used for initial access:

- **`user`** — A regular user account (default). Simulates compromised employee, developer, or administrator accounts
- **`service_principal`** — An application's service principal. Simulates compromised CI/CD pipelines, automation accounts, or third-party integrations

All attack paths support both identity types:

| Attack Path | User | Service Principal |
|---|---|---|
| ApplicationOwnershipAbuse | User as application owner | SP as application owner |
| ApplicationAdministratorAbuse | User with App Admin role | SP with App Admin role |
| CloudAppAdministratorAbuse | User with Cloud App Admin role | SP with Cloud App Admin role |
| ManagedIdentityTheft | User with Contributor access | SP with Contributor access |
| KeyVaultSecretTheft | User with Key Vault access | SP with Key Vault access |
| StorageCertificateTheft | User with Storage access | SP with Storage access |

!!! note
    The `helpdesk` scenario for ApplicationOwnershipAbuse is only available when `identity_type: user`.

**`assignment_type`** — How permissions are granted to the initial access identity:

- **`direct`** — Permissions assigned directly to the identity (default). The user or service principal has explicit permissions.
- **`group`** — Permissions assigned to a security group. The identity is added as a member of the group and inherits permissions through group membership. This creates more realistic attack scenarios that mirror enterprise configurations where permissions are managed through groups.

### Privilege Assignment

How the target application receives its high privileges.

**`method`** — The method used to assign privileges to the target application:

- **`AzureADRole`** — Assigns Entra ID directory roles to the application, enabling tenant-wide administrative privileges
- **`APIPermission`** — Assigns API application permissions to the application (supports Microsoft Graph and Exchange Online)

=== "Entra ID Role"

    Assign one or more directory roles using `method: AzureADRole`:

    ```yaml
    method: AzureADRole

    # Single role
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator

    # Multiple roles
    entra_role:
      - e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
      - 7be44c8a-adaf-4e2a-84d6-ab2649e08a13  # Privileged Authentication Administrator

    # Random high-privileged role
    entra_role: random
    ```

=== "API Permission"

    Assign API application permissions using `method: APIPermission`:

    ```yaml
    method: APIPermission

    # Microsoft Graph (default)
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory

    # Exchange Online
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40  # full_access_as_app

    # Multiple permissions
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory

    # Random high-privileged permission
    app_role: random
    ```

**`api_type`** — When using `method: APIPermission`, specifies which API to assign permissions for:

- **`graph`** — Microsoft Graph API (default). Provides access to Entra ID, Microsoft 365, and other Microsoft cloud services. Supports a wide range of high-privileged permissions.
- **`exchange`** — Exchange Online API. Provides direct access to Exchange Online mailboxes and configuration. Useful for testing email-based attack scenarios, including permissions like `full_access_as_app`.

## Per-Technique Options

### ApplicationOwnershipAbuse

**Required fields:**

- `privilege_escalation: ApplicationOwnershipAbuse`
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`
- `scenario`: `direct` (default) or `helpdesk`
    - **`direct`** — The attacker directly compromises the application owner
    - **`helpdesk`** — The attacker compromises a Helpdesk Administrator and resets the application owner's password first. Only available with `identity_type: user`.

### ApplicationAdministratorAbuse

**Required fields:**

- `privilege_escalation: ApplicationAdministratorAbuse`
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the target application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`
- `scope`: `directory` (default) or `application`

**`scope`** — Controls whether the Application Administrator role is assigned tenant-wide or scoped to a specific application:

- **`directory`** — The role applies to **all** applications in the tenant (default, existing behavior)
- **`application`** — The role is scoped to only the **target application**. This uses Azure Entra ID's `directory_scope_id` to restrict the role assignment. More realistic for least-privilege environments where admins are scoped to specific apps.

!!! note
    This technique does not support the `scenario` parameter.

### CloudAppAdministratorAbuse

**Required fields:**

- `privilege_escalation: CloudAppAdministratorAbuse`
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the target application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`
- `scope`: `directory` (default) or `application`

This technique is identical to `ApplicationAdministratorAbuse` in configuration, but uses the **Cloud Application Administrator** role (`158c047a-c907-4556-b7ef-446551a6b5f7`) instead. The Cloud Application Administrator role has a narrower scope — it cannot manage applications with certain sensitive permissions. See [CloudAppAdministratorAbuse](attack-paths/cloud-app-administrator-abuse.md) for details.

!!! note
    This technique does not support the `scenario` parameter.

### ManagedIdentityTheft

**Required fields:**

- `privilege_escalation: ManagedIdentityTheft`
- `source_type`: The Azure resource with the managed identity
- `target_resource_type`: The resource storing the application credentials
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`
- `credential_type`: `secret` (default) or `certificate`

**`source_type`** — The Azure resource with the managed identity:

| Value | Resource | Required Role |
|---|---|---|
| `vm` | Virtual Machine with system-assigned managed identity | VM Contributor |
| `logic_app` | Logic App with system-assigned managed identity | Logic App Contributor |
| `automation_account` | Automation Account with system-assigned managed identity | Automation Contributor |
| `function_app` | Function App with system-assigned managed identity (Linux/Python) | Website Contributor |

**`target_resource_type`** — The resource storing the application credentials:

| Value | Resource | Managed Identity Access |
|---|---|---|
| `key_vault` | Azure Key Vault | Key Vault Contributor — retrieves secrets or certificates |
| `storage_account` | Azure Storage Account | Storage Blob Data Reader — retrieves certificates |

**`credential_type`** — The type of credential stored in the target resource:

- **`secret`** — Application uses client ID and secret for authentication (default). Easier to implement but secrets can be logged or cached.
- **`certificate`** — Application uses X.509 certificate-based authentication. More secure and harder to detect in logs, but requires certificate management. Applies to both `key_vault` and `storage_account` targets.

### KeyVaultSecretTheft

**Required fields:**

- `privilege_escalation: KeyVaultSecretTheft`
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`

!!! note
    For scenarios involving managed identity token theft to access Key Vault, use `ManagedIdentityTheft` with `target_resource_type: key_vault` instead.

### StorageCertificateTheft

**Required fields:**

- `privilege_escalation: StorageCertificateTheft`
- `method`: `AzureADRole` or `APIPermission`
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**

- `identity_type`: `user` (default) or `service_principal`

!!! note
    For scenarios involving managed identity token theft to access Storage Account, use `ManagedIdentityTheft` with `target_resource_type: storage_account` instead.

## Group-Based Assignment

All privilege escalation techniques support group-based assignment using `assignment_type: group`. When enabled, permissions are assigned to a security group and the initial access identity is added as a member of that group, inheriting permissions through group membership.

This creates more realistic attack scenarios that mirror enterprise configurations where:

- Permissions are managed through groups rather than individual assignments
- Attack paths require discovering group memberships to understand privilege chains
- Detection requires correlating group membership with resource access

Groups created for attack paths use realistic names from the `entity_data/group-names.txt` file (e.g., "IT Security", "Cloud Infrastructure", "DevOps") with a random suffix for uniqueness.

### Group Assignment Examples

=== "ApplicationOwnershipAbuse"

    Service principal is a member of a group that owns the application:

    ```yaml
    attack_path_owner_group:
      enabled: true

      privilege_escalation: ApplicationOwnershipAbuse
      identity_type: service_principal
      assignment_type: group
      method: AzureADRole
      entra_role: e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
    ```

=== "ApplicationAdministratorAbuse"

    User inherits Application Administrator role through group membership:

    ```yaml
    attack_path_admin_group:
      enabled: true

      privilege_escalation: ApplicationAdministratorAbuse
      identity_type: user
      assignment_type: group
      method: APIPermission
      api_type: graph
      app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
    ```

=== "CloudAppAdministratorAbuse"

    User inherits Cloud Application Administrator role through group membership:

    ```yaml
    attack_path_cloud_admin_group:
      enabled: true

      privilege_escalation: CloudAppAdministratorAbuse
      identity_type: user
      assignment_type: group
      method: APIPermission
      api_type: graph
      app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
    ```

=== "ManagedIdentityTheft"

    User inherits VM Contributor through group membership:

    ```yaml
    attack_path_mi_group:
      enabled: true

      privilege_escalation: ManagedIdentityTheft
      source_type: vm
      target_resource_type: key_vault

      identity_type: user
      assignment_type: group
      method: APIPermission
      api_type: graph
      app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
    ```

=== "KeyVaultSecretTheft"

    User inherits Key Vault Contributor through group membership:

    ```yaml
    attack_path_kv_group:
      enabled: true

      privilege_escalation: KeyVaultSecretTheft
      identity_type: user
      assignment_type: group
      method: APIPermission
      api_type: graph
      app_role: random
    ```

=== "StorageCertificateTheft"

    User inherits Storage Blob Data Reader through group membership:

    ```yaml
    attack_path_storage_group:
      enabled: true

      privilege_escalation: StorageCertificateTheft
      identity_type: user
      assignment_type: group
      method: APIPermission
      api_type: graph
      app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
    ```

## Full Example

A complete configuration demonstrating multiple attack path types:

```yaml
tenant:
  tenant_id: your-tenant-guid
  domain: contoso.onmicrosoft.com
  subscription_id: your-subscription-guid

  users: 20
  applications: 10
  groups: 5
  administrative_units: 3

  resource_groups: 2
  key_vaults: 2
  storage_accounts: 1
  virtual_machines: 1
  logic_apps: 1
  automation_accounts: 1
  function_apps: 1

attack_paths:

  # Identity: User owns app with Global Admin
  ownership_abuse:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10

  # Identity: SP with App Admin targets Exchange
  admin_abuse:
    enabled: true
    privilege_escalation: ApplicationAdministratorAbuse
    identity_type: service_principal
    method: APIPermission
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40

  # Identity: User with Cloud App Admin targets Global Admin
  cloud_admin_abuse:
    enabled: true
    privilege_escalation: CloudAppAdministratorAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10

  # Resource: VM → Key Vault → privileged app
  vm_to_keyvault:
    enabled: true
    privilege_escalation: ManagedIdentityTheft
    source_type: vm
    target_resource_type: key_vault
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f

  # Resource: Direct Key Vault access via group
  keyvault_group:
    enabled: true
    privilege_escalation: KeyVaultSecretTheft
    assignment_type: group
    method: AzureADRole
    entra_role: random

  # Resource: Direct storage access with certs
  storage_certs:
    enabled: true
    privilege_escalation: StorageCertificateTheft
    method: APIPermission
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8
```
