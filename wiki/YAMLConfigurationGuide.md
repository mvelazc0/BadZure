# YAML Configuration Guide

## Overview

BadZure uses a YAML configuration file to define the setup of Entra ID tenants and Azure subscriptions, including the number of users, groups, applications, administrative units, Azure resources, and attack paths. This guide will help you understand the structure and options available in the YAML configuration file.

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
    method: AzureADRole
    entra_role: random

  attack_path_2:
    enabled: true
    initial_access: token
    privilege_escalation: ApplicationAdministratorAbuse
    method: APIPermission
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40

  attack_path_3:
    enabled: true
    initial_access: password
    scenario: helpdesk
    privilege_escalation: KeyVaultAbuse
    principal_type: managed_identity
    method: APIPermission
    api_type: graph
    app_role: random

  attack_path_4:
    enabled: true
    initial_access: password
    privilege_escalation: StorageAccountAbuse
    principal_type: user
    method: AzureADRole
    entra_role: 
      - e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
      - 7be44c8a-adaf-4e2a-84d6-ab2649e08a13  # Privileged Authentication Administrator
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

## Attack Paths Configuration

The `attack_paths` section defines different attack paths to simulate within the tenant. Each attack path can have its own configuration and represents a complete attack scenario from initial access to privilege escalation.

### Common Attack Path Options

- **enabled**: A boolean indicating whether the attack path is enabled.
  - **true**: The attack path is enabled and will be configured.
  - **false**: The attack path is disabled and will not be configured.

- **initial_access**: The method of initial access, either `password` or `token`.
  - **password**: Assigns a password to the user for initial access, simulating scenarios where an attacker has obtained valid credentials.
  - **token**: Generates JWT access tokens for initial access, simulating scenarios where an attacker uses stolen tokens.

- **scenario**: The scenario type (optional, only for ApplicationOwnershipAbuse).
  - **direct**: The user directly owns the application.
  - **helpdesk**: The user has Helpdesk Administrator role and can reset the application owner's password.

- **privilege_escalation**: The privilege escalation technique. Available options:
  - **ApplicationOwnershipAbuse**: Exploits application ownership to add credentials to privileged applications.
  - **ApplicationAdministratorAbuse**: Exploits the Application Administrator role to manage any application and add credentials.
  - **KeyVaultAbuse**: Retrieves application secrets stored in Azure Key Vault.
  - **StorageAccountAbuse**: Retrieves application certificates and private keys from Azure Storage.

- **method**: The method used to assign privileges to applications:
  - **AzureADRole**: Assigns Entra ID roles to applications.
  - **APIPermission**: Assigns API permissions to applications (supports Microsoft Graph and Exchange Online).

### Principal Types

For **KeyVaultAbuse** and **StorageAccountAbuse** attack paths, specify the type of principal that will access the Azure resources:

- **principal_type**: The type of identity granted access:
  - **user**: A regular user account.
  - **service_principal**: An application's service principal.
  - **managed_identity**: A virtual machine's managed identity.

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
- `scenario`: direct (default) or helpdesk

### ApplicationAdministratorAbuse
Simulates an attacker with the Application Administrator role who can manage any application in the tenant and add credentials to privileged applications.

**Required fields:**
- `privilege_escalation: ApplicationAdministratorAbuse`
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the target application

### KeyVaultAbuse
Simulates an attacker with access to Azure Key Vault who retrieves application secrets to authenticate as the application.

**Required fields:**
- `privilege_escalation: KeyVaultAbuse`
- `principal_type`: user, service_principal, or managed_identity
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application

### StorageAccountAbuse
Simulates an attacker with access to Azure Storage who retrieves application certificates and private keys to authenticate as the application.

**Required fields:**
- `privilege_escalation: StorageAccountAbuse`
- `principal_type`: user, service_principal, or managed_identity
- `method`: AzureADRole or APIPermission
- `entra_role` or `app_role`: The privileges assigned to the application