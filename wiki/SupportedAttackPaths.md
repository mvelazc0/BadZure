# Supported Attack Paths

## Overview

BadZure supports multiple attack path scenarios that simulate real-world privilege escalation techniques in Azure and Azure AD environments. Each attack path represents a complete attack chain from initial access to privilege escalation, designed to test security controls and detection capabilities.

## Attack Path Categories

BadZure organizes attack paths into two main categories:

**Identity-Based Privilege Escalation**: Exploits misconfigurations in Azure AD identity, application management, and managed identity configurations
**Resource-Based Privilege Escalation**: Exploits direct misconfigurations in Azure resource access controls

## Supported Attack Paths

### 1. ApplicationOwnershipAbuse

**Category**: Identity-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker exploits application ownership privileges to escalate privileges within an Azure AD tenant. The attack leverages the common misconfiguration where users are granted ownership of application registrations that have excessive permissions.

**Attack Scenario**: 
- An attacker gains initial access to a user account through credential compromise or social engineering
- The compromised user account has been granted ownership of an application registration
- The application has been assigned high-privileged Azure AD roles or API permissions
- The attacker generates new client credentials for the owned application and uses them to access resources with elevated privileges

**Technical Implementation**:
- Creates a user account with password or token-based authentication
- Assigns the user as owner of a randomly selected application registration
- Grants the application either Azure AD directory roles or API application permissions (Microsoft Graph, Exchange Online, etc.)
- Supports both direct access scenarios and helpdesk administrator privilege escalation paths

**Configuration Options**:
```yaml
privilege_escalation: ApplicationOwnershipAbuse
method: AzureADRole | APIPermission
scenario: direct | helpdesk
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Real-World Relevance**: This attack path is based on common misconfigurations where developers or administrators are granted application ownership without proper governance, leading to potential privilege escalation vectors. It simulates scenarios where compromised developer accounts or service accounts with application ownership can be leveraged for privilege escalation.

---

### 2. ApplicationAdministratorAbuse

**Category**: Identity-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker exploits the Application Administrator Entra ID role to manage any application in the tenant and escalate privileges. Unlike ApplicationOwnershipAbuse which targets specific owned applications, this technique leverages broad administrative privileges over all applications.

**Attack Scenario**:
- An attacker gains initial access to a user account with the Application Administrator role
- The Application Administrator role grants the ability to manage any application registration in the tenant
- The attacker identifies or creates an application with high-privileged Azure AD roles or API permissions
- The attacker adds new client credentials to the privileged application
- The attacker uses these credentials to authenticate as the application and leverage its elevated privileges

**Technical Implementation**:
- Creates a user account with password or token-based authentication
- Assigns the Application Administrator Entra ID role to the user
- Grants a target application either Azure AD directory roles or API application permissions
- The user can manage any application in the tenant, not just owned applications
- Supports multiple API types including Microsoft Graph and Exchange Online

**Key Differences from ApplicationOwnershipAbuse**:
- **Scope**: Can manage ANY application in the tenant vs. only owned applications
- **Initial Privilege**: Requires Application Administrator role vs. application ownership
- **Attack Surface**: Broader attack surface with access to all applications
- **Real-World Scenario**: Compromised admin account vs. compromised developer account

**Configuration Options**:
```yaml
privilege_escalation: ApplicationAdministratorAbuse
method: AzureADRole | APIPermission
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Note**: This technique does not support the `scenario` parameter as it focuses on direct exploitation of the Application Administrator role.

**Real-World Relevance**: This attack path reflects scenarios where Application Administrator accounts are compromised, providing attackers with broad control over application registrations. It's particularly relevant for testing the security of privileged administrative roles and their potential for abuse in privilege escalation attacks.

---

### 3. ManagedIdentityTheft

**Category**: Identity-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker exploits access to Azure resources with managed identities to steal identity tokens and pivot to other cloud resources. This technique represents the identity theft component of cloud-native privilege escalation attacks.

**Attack Scenario**:
- An attacker gains initial access to a user account with contributor access to an Azure resource (e.g., Virtual Machine, Logic App, or Automation Account)
- The Azure resource has a system-assigned managed identity with permissions to access other cloud resources
- The attacker leverages their access to the source resource to extract the managed identity token
- The attacker uses the stolen managed identity token to access the target resource (Key Vault or Storage Account)
- The attacker retrieves application credentials from the target resource
- The application has high-privileged permissions that enable further privilege escalation

**Technical Implementation**:
- Creates an Azure resource with system-assigned managed identity
- Assigns the user appropriate Contributor role on the resource (VM Contributor, Logic App Contributor, or Automation Contributor)
- Grants the managed identity access to target resources (Key Vault or Storage Account)
- Stores application credentials in the target resource
- Configures the target application with high-privileged Azure AD roles or API permissions

**Source Types**:
- **vm**: Virtual Machine with system-assigned managed identity (requires VM Contributor role)
- **logic_app**: Logic App with system-assigned managed identity (requires Logic App Contributor role)
- **automation_account**: Automation Account with system-assigned managed identity (requires Automation Contributor role)

**Target Resource Types**:
- **key_vault**: Managed identity has Key Vault Contributor access to retrieve secrets
- **storage_account**: Managed identity has Storage Blob Data Reader access to retrieve certificates

**Configuration Options**:
```yaml
privilege_escalation: ManagedIdentityTheft
source_type: vm | logic_app | automation_account
target_resource_type: key_vault | storage_account
method: AzureADRole | APIPermission
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Attack Variations by Source Type**:

1. **Virtual Machine**: Attacker with VM Contributor can run commands on the VM to extract the managed identity token via the Azure Instance Metadata Service (IMDS).

2. **Logic App**: Attacker with Logic App Contributor can modify workflow definitions to extract managed identity tokens through HTTP actions or custom connectors.

3. **Automation Account**: Attacker with Automation Contributor can create or modify runbooks to extract managed identity tokens and execute arbitrary code in the automation context.

**Real-World Relevance**: This attack path reflects scenarios where managed identities are overprivileged or where users have excessive permissions on Azure resources. It's particularly relevant for testing the security of managed identity configurations and resource access controls in cloud-native environments.

---

### 4. KeyVaultSecretTheft

**Category**: Resource-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker with direct access to Azure Key Vault retrieves application secrets for privilege escalation. Unlike ManagedIdentityTheft, this technique focuses on direct Key Vault access without the identity theft component.

**Attack Scenario**:
- An attacker gains initial access to a user or service principal account
- The identity has been granted direct access to an Azure Key Vault
- Application client secrets are stored in the Key Vault
- The attacker retrieves the client secrets from Key Vault
- The attacker uses the secrets to authenticate as the application
- The application has high-privileged permissions that allow further privilege escalation

**Technical Implementation**:
- Creates Azure Key Vault with RBAC authorization enabled
- Assigns Key Vault Contributor role to the specified principal (user or service principal)
- Generates and stores application client secrets in the Key Vault
- Configures the target application with high-privileged Azure AD roles or API permissions

**Principal Types**:
- **User**: Regular user account with Key Vault access
- **Service Principal**: Application service principal with Key Vault permissions

**Note**: For scenarios involving managed identity token theft to access Key Vault, use the `ManagedIdentityTheft` technique with `target_resource_type: key_vault`.

**Configuration Options**:
```yaml
privilege_escalation: KeyVaultSecretTheft
principal_type: user | service_principal
method: AzureADRole | APIPermission
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Real-World Relevance**: This attack path reflects scenarios where Key Vault access controls are misconfigured, allowing direct unauthorized access to sensitive application credentials.

---

### 5. StorageCertificateTheft

**Category**: Resource-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker with direct access to Azure Storage Account retrieves certificates and private keys used for application authentication. Unlike ManagedIdentityTheft, this technique focuses on direct storage access without the identity theft component.

**Attack Scenario**:
- An attacker gains initial access to a user or service principal account
- The identity has been granted direct read access to Azure Blob Storage containers
- Application certificates and private keys are stored in the storage account
- The attacker downloads the certificate and private key files from storage
- The attacker uses certificate-based authentication to impersonate the application
- The application has high-privileged permissions that enable further privilege escalation

**Technical Implementation**:
- Creates Azure Storage Account with private blob containers
- Generates self-signed X.509 certificates and private keys for target applications
- Uploads certificate (.pem) and private key (.key) files to storage containers
- Registers certificates with target applications for authentication
- Assigns Storage Blob Data Reader role to the specified principal (user or service principal)
- Configures applications with high-privileged Azure AD roles or API permissions

**Certificate Management**:
- Automatically generates self-signed certificates with 1-year validity
- Creates unique certificate and key file names to prevent conflicts
- Stores certificates in dedicated storage containers with private access
- Registers certificates with applications using Terraform automation

**Principal Types**:
- **User**: Regular user account with storage access
- **Service Principal**: Application service principal with storage permissions

**Note**: For scenarios involving managed identity token theft to access Storage Account, use the `ManagedIdentityTheft` technique with `target_resource_type: storage_account`.

**Configuration Options**:
```yaml
privilege_escalation: StorageCertificateTheft
principal_type: user | service_principal
method: AzureADRole | APIPermission
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Real-World Relevance**: This attack path is based on real scenarios where organizations store authentication certificates in cloud storage without proper access controls. It's particularly relevant for testing certificate-based authentication security and storage access controls.

---

## Attack Path Components

### Initial Access Methods

**Password-based Access**:
- Simulates credential compromise scenarios
- Provides direct username/password authentication
- Suitable for testing password-based attack vectors

**Token-based Access**:
- Simulates token theft or session hijacking scenarios  
- Generates JWT access tokens for authentication
- Suitable for testing token-based attack vectors

### Scenarios

**Direct Scenario** (ApplicationOwnershipAbuse only):
- Attacker gains direct access to the target user account
- No intermediate privilege escalation required
- Simulates straightforward credential compromise

**Helpdesk Scenario** (ApplicationOwnershipAbuse only):
- Attacker first compromises a helpdesk administrator account
- Uses helpdesk privileges to reset target user passwords
- Simulates insider threat or helpdesk account compromise

### Privilege Escalation Methods

**AzureADRole Method**:
- Assigns Azure AD directory roles to applications
- Enables tenant-wide administrative privileges
- Suitable for testing role-based privilege escalation

**APIPermission Method**:
- Assigns API application permissions from multiple sources
- Supports Microsoft Graph, Exchange Online, and other APIs
- Enables testing of various API-based privilege escalation scenarios
- Specify API type using the `api_type` parameter

### API Types

**graph** (Microsoft Graph):
- Default API type
- Provides access to Azure AD, Microsoft 365, and other Microsoft cloud services
- Supports a wide range of high-privileged permissions

**exchange** (Exchange Online):
- Provides direct access to Exchange Online mailboxes and configuration
- Useful for testing email-based attack scenarios
- Includes permissions like full mailbox access and Exchange management

Organizations can use these attack paths to validate their security controls, detection capabilities, and incident response procedures in a controlled environment.
