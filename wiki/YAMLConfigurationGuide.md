# YAML Configuration Guide

## Overview

BadZure uses a YAML configuration file to define the setup of Entra ID tenants and Azure subscriptions, including the number of users, groups, applications, administrative units, Azure resources, and attack paths. This guide will help you understand the structure and options available in the YAML configuration file.

## Configuration Modes

BadZure supports two configuration modes:

### Random Mode (Default)

In random mode, BadZure automatically generates the specified number of entities and randomly assigns them to attack paths. This mode is ideal for quick testing and creating diverse environments.

**Configuration**:
```yaml
# No mode specified = random mode (default)
tenant:
  users: 30
  applications: 10
  groups: 10
  
attack_paths:
  attack_path_1:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: random
```

### Targeted Mode

In targeted mode, you specify exact entities for each attack path. This mode provides precise control over the environment configuration.

**Configuration**:
```yaml
mode: targeted  # Explicitly set targeted mode

attack_paths:
  attack_path_1:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10
    entities:
      users:
        - name: john.doe
      applications:
        - name: TargetApp
      resource_groups:
        - name: rg-target
```

**Entity Specification**:
- Use `name: specific-name` to create an entity with that exact name
- Use `name: random` to let BadZure generate a random name
- Entities are shared across attack paths if they have the same name

## Example Configuration

```yaml
tenant:
  tenant_id: your-tenant-guid
  domain: contoso.onmicrosoft.com
  subscription_id: your-subscription-guid
  
  # Azure AD Entities
  users: 100
  applications: 30
  groups: 20
  administrative_units: 30
  
  # Azure Resources
  resource_groups: 10
  key_vaults: 10
  storage_accounts: 10
  virtual_machines: 10

attack_paths:
  attack_path_1:
    enabled: true
    initial_access: password
    scenario: direct
    privilege_escalation: ApplicationOwnershipAbuse
    identity_type: user
    method: AzureADRole
    entra_role: random

  attack_path_2:
    enabled: true
    initial_access: token
    privilege_escalation: ApplicationAdministratorAbuse
    identity_type: service_principal
    method: APIPermission
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40

  attack_path_3:
    enabled: true
    initial_access: password
    privilege_escalation: KeyVaultSecretTheft
    identity_type: user
    method: APIPermission
    api_type: graph
    app_role: random

  attack_path_4:
    enabled: true
    initial_access: password
    privilege_escalation: ManagedIdentityTheft
    source_type: vm
    target_resource_type: storage_account
    entry_point: compromised_identity
    identity_type: user
    method: AzureADRole
    entra_role:
      - e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
      - 7be44c8a-adaf-4e2a-84d6-ab2649e08a13  # Privileged Authentication Administrator

  attack_path_5:
    enabled: true
    initial_access: token
    privilege_escalation: ManagedIdentityTheft
    source_type: logic_app
    target_resource_type: key_vault
    entry_point: compromised_identity
    identity_type: service_principal
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

## Tenant Configuration

The `tenant` section defines the Azure AD tenant details and the number of entities to create.

### Basic Tenant Settings
- `tenant_id`: The unique identifier for your Azure AD tenant.
- `domain`: The domain associated with your Azure AD tenant (e.g., contoso.onmicrosoft.com).
- `subscription_id`: The Azure subscription ID for provisioning Azure resources.

### Azure AD Entities
- `users`: The number of user accounts to create.
- `applications`: The number of application registrations to create.
- `groups`: The number of security groups to create.
- `administrative_units`: The number of administrative units to create.

### Azure Resources
- `resource_groups`: The number of Azure resource groups to create.
- `key_vaults`: The number of Azure Key Vaults to provision.
- `storage_accounts`: The number of Azure Storage Accounts to create.
- `virtual_machines`: The number of virtual machines to deploy (Linux VMs with networking).
- `logic_apps`: The number of Logic Apps to create (with system-assigned managed identities).
- `automation_accounts`: The number of Automation Accounts to create (with system-assigned managed identities).
- `function_apps`: The number of Function Apps to create (with system-assigned managed identities).

## Attack Paths Configuration

The `attack_paths` section defines different attack paths to simulate within the tenant. Each attack path can have its own configuration and represents a complete attack scenario from initial access to privilege escalation.

### Common Attack Path Options

- **enabled**: A boolean indicating whether the attack path is enabled.
  - **true**: The attack path is enabled and will be configured.
  - **false**: The attack path is disabled and will not be configured.

- **initial_access**: The method of initial access, either `password` or `token`.
  - **password**: Assigns a password to the user for initial access, simulating scenarios where an attacker has obtained valid credentials.
  - **token**: Generates JWT access tokens for initial access, simulating scenarios where an attacker uses stolen tokens.

- **entry_point**: How the attacker gains initial access (optional, defaults to `compromised_identity`).
  - **compromised_identity**: The attacker has compromised a user or service principal through credential theft, phishing, or token theft.
  - **Note**: Additional entry points may be added in future versions.

- **scenario**: The scenario type (optional, only for ApplicationOwnershipAbuse with identity_type: user).
  - **direct**: The user directly owns the application.
  - **helpdesk**: The user has Helpdesk Administrator role and can reset the application owner's password.
  - **Note**: The helpdesk scenario is only available when identity_type is 'user'.

- **privilege_escalation**: The privilege escalation technique. Available options:
  - **ApplicationOwnershipAbuse**: Exploits application ownership to add credentials to privileged applications.
  - **ApplicationAdministratorAbuse**: Exploits the Application Administrator role to manage any application and add credentials.
  - **ManagedIdentityTheft**: Exploits access to Azure resources with managed identities to steal tokens and pivot to other resources.
  - **KeyVaultSecretTheft**: Retrieves application secrets stored in Azure Key Vault through direct access.
  - **StorageCertificateTheft**: Retrieves application certificates and private keys from Azure Storage through direct access.

- **assignment_type**: How permissions are assigned to the initial access identity (optional, defaults to `direct`).
  - **direct**: Permissions assigned directly to the identity. The user or service principal has explicit permissions.
  - **group**: Permissions assigned to a security group. The identity is added as a member of the group and inherits permissions through group membership. This creates more realistic attack scenarios that mirror enterprise configurations.

- **method**: The method used to assign privileges to applications:
  - **AzureADRole**: Assigns Entra ID roles to applications.
  - **APIPermission**: Assigns API permissions to applications (supports Microsoft Graph and Exchange Online).

### Identity Types

For all attack paths, you can specify the type of identity that will be used for initial access:

- **identity_type**: The type of identity used for initial access:
  - **user**: A regular user account (default).
  - **service_principal**: An application's service principal.

**Supported Attack Paths**:
- **ApplicationOwnershipAbuse**: User or service principal as application owner
- **ApplicationAdministratorAbuse**: User or service principal with Application Administrator role
- **KeyVaultSecretTheft**: User or service principal with Key Vault access
- **StorageCertificateTheft**: User or service principal with Storage access
- **ManagedIdentityTheft**: User or service principal with Contributor access to source resource

**Note**: The `helpdesk` scenario for ApplicationOwnershipAbuse is only available when `identity_type: user`.

### Managed Identity Configuration

For **ManagedIdentityTheft** attack paths, specify the source and target resources, as well as the initial access identity:

- **source_type**: The type of Azure resource with the managed identity:
  - **vm**: A VM with system-assigned managed identity (requires VM Contributor role).
  - **logic_app**: A Logic App with system-assigned managed identity (requires Logic App Contributor role).
  - **automation_account**: An Automation Account with system-assigned managed identity (requires Automation Contributor role).
  - **function_app**: A Function App with system-assigned managed identity (requires Website Contributor role).
    - **Note**: Function Apps use Linux OS with Python runtime.

- **target_resource_type**: The type of resource the managed identity can access:
  - **key_vault**: Managed identity has access to Key Vault secrets or certificates.
  - **storage_account**: Managed identity has access to Storage Account certificates.

- **credential_type**: The type of credential stored in the target resource (optional, defaults to `secret`):
  - **secret**: Application uses client ID and secret for authentication (default).
  - **certificate**: Application uses certificate-based authentication (more secure, harder to detect).
  - **Note**: Applies to both key_vault and storage_account target types.

- **entry_point**: How the attacker gains initial access (optional, defaults to `compromised_identity`):
  - **compromised_identity**: The attacker has compromised a user or service principal with Contributor access to the source resource.

- **identity_type**: The type of identity with Contributor access to the source resource:
  - **user**: A user account with Contributor role on the source resource (default).
  - **service_principal**: A service principal with Contributor role on the source resource.

### API Permission Configuration

When using `method: APIPermission`, you can specify the API type:

- **api_type**: The API to assign permissions for:
  - **graph**: Microsoft Graph API (default)
  - **exchange**: Exchange Online API

### Role and Permission Configuration

#### Single Role/Permission Assignment
```yaml
entra_role: e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
app_role: 06b708a9-e830-4db3-a914-8e69da51d44f   # AppRoleAssignment.ReadWrite.All
```

#### Multiple Role/Permission Assignment
```yaml
entra_role: 
  - e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
  - 7be44c8a-adaf-4e2a-84d6-ab2649e08a13  # Privileged Authentication Administrator

app_role:
  - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
  - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

#### Random Assignment
```yaml
entra_role: random  # Assigns a random high-privileged Entra role
app_role: random    # Assigns a random high-privileged API permission
```

## Privilege Escalation Techniques

### ApplicationOwnershipAbuse
Simulates an attacker who owns an application and can add credentials to it. The application has high-privileged roles or API permissions.

**Required fields:**
- `privilege_escalation: ApplicationOwnershipAbuse`
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**
- `identity_type`: user (default) or service_principal
- `scenario`: direct (default) or helpdesk (only available with identity_type: user)

**Example with service principal owner:**
```yaml
attack_path_sp_owner:
  enabled: true
  initial_access: token
  privilege_escalation: ApplicationOwnershipAbuse
  identity_type: service_principal
  method: AzureADRole
  entra_role: e8611ab8-c189-46e8-94e1-60213ab1f814
```

### ApplicationAdministratorAbuse
Simulates an attacker with the Application Administrator role who can manage any application in the tenant and add credentials to privileged applications.

**Required fields:**
- `privilege_escalation: ApplicationAdministratorAbuse`
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the target application

**Optional fields:**
- `identity_type`: user (default) or service_principal

**Example with service principal:**
```yaml
attack_path_sp_admin:
  enabled: true
  initial_access: token
  privilege_escalation: ApplicationAdministratorAbuse
  identity_type: service_principal
  method: APIPermission
  api_type: graph
  app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8
```

### ManagedIdentityTheft
Simulates an attacker who exploits access to Azure resources with managed identities to steal identity tokens and pivot to other cloud resources.

**Required fields:**
- `privilege_escalation: ManagedIdentityTheft`
- `source_type`: vm, logic_app, automation_account, or function_app
- `target_resource_type`: key_vault or storage_account
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application

**Optional fields:**
- `entry_point`: compromised_identity (default) - how the attacker gains initial access
- `identity_type`: user (default) or service_principal - the type of identity with Contributor access
- `credential_type`: secret (default) or certificate - the type of credential stored in target resource

**Supported Source Types:**
- `vm`: Virtual Machine with VM Contributor role
- `logic_app`: Logic App with Logic App Contributor role
- `automation_account`: Automation Account with Automation Contributor role
- `function_app`: Function App with Website Contributor role (Linux/Python runtime)

**Example with certificate-based credentials:**
```yaml
attack_path_mi_cert:
  enabled: true
  initial_access: password
  privilege_escalation: ManagedIdentityTheft
  source_type: function_app
  target_resource_type: key_vault
  entry_point: compromised_identity
  identity_type: user
  credential_type: certificate  # Use certificate instead of secret
  method: APIPermission
  api_type: graph
  app_role: 06b708a9-e830-4db3-a914-8e69da51d44f
```

**Example with service principal initial access:**
```yaml
attack_path_mi_sp:
  enabled: true
  initial_access: token
  privilege_escalation: ManagedIdentityTheft
  source_type: logic_app
  target_resource_type: key_vault
  entry_point: compromised_identity
  identity_type: service_principal
  credential_type: secret  # Default
  method: APIPermission
  api_type: graph
  app_role: 06b708a9-e830-4db3-a914-8e69da51d44f
```

### KeyVaultSecretTheft
Simulates an attacker with direct access to Azure Key Vault who retrieves application secrets to authenticate as the application.

**Required fields:**
- `privilege_escalation: KeyVaultSecretTheft`
- `identity_type`: user or service_principal
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application

**Note**: For managed identity scenarios, use `ManagedIdentityTheft` with `target_resource_type: key_vault`.

### StorageCertificateTheft
Simulates an attacker with direct access to Azure Storage who retrieves application certificates and private keys to authenticate as the application.

**Required fields:**
- `privilege_escalation: StorageCertificateTheft`
- `identity_type`: user or service_principal
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application

**Note**: For managed identity scenarios, use `ManagedIdentityTheft` with `target_resource_type: storage_account`.

## Group-Based Assignment Examples

All privilege escalation techniques support group-based assignment using the `assignment_type: group` parameter. When using group assignment, permissions are assigned to a security group and the initial access identity is added as a member of that group.

### ManagedIdentityTheft with Group Assignment
```yaml
attack_path_mi_group:
  enabled: true
  initial_access: password
  privilege_escalation: ManagedIdentityTheft
  source_type: vm
  target_resource_type: key_vault
  entry_point: compromised_identity
  identity_type: user
  assignment_type: group  # User inherits VM Contributor through group membership
  method: APIPermission
  api_type: graph
  app_role: 06b708a9-e830-4db3-a914-8e69da51d44f
```

### ApplicationOwnershipAbuse with Group Assignment
```yaml
attack_path_owner_group:
  enabled: true
  initial_access: token
  privilege_escalation: ApplicationOwnershipAbuse
  identity_type: service_principal
  assignment_type: group  # Service principal is member of group that owns the application
  method: AzureADRole
  entra_role: e8611ab8-c189-46e8-94e1-60213ab1f814
```

### ApplicationAdministratorAbuse with Group Assignment
```yaml
attack_path_admin_group:
  enabled: true
  initial_access: password
  privilege_escalation: ApplicationAdministratorAbuse
  identity_type: user
  assignment_type: group  # User inherits Application Administrator role through group membership
  method: APIPermission
  api_type: graph
  app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8
```

### KeyVaultSecretTheft with Group Assignment
```yaml
attack_path_kv_group:
  enabled: true
  initial_access: password
  privilege_escalation: KeyVaultSecretTheft
  identity_type: user
  assignment_type: group  # User inherits Key Vault Contributor through group membership
  method: APIPermission
  api_type: graph
  app_role: random
```

**Note**: Groups created for attack paths use realistic names from the `entity_data/group-names.txt` file (e.g., "IT Security", "Cloud Infrastructure", "DevOps") with a random suffix for uniqueness.