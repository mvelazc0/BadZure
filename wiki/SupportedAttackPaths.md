# Supported Attack Paths

## Overview

BadZure supports multiple attack path scenarios that simulate real-world privilege escalation techniques in Azure and Azure AD environments. Each attack path represents a complete attack chain from initial access to privilege escalation, designed to test security controls and detection capabilities.

## Attack Path Categories

BadZure organizes attack paths into two main categories:

**Identity-Based Privilege Escalation**: Exploits misconfigurations in Azure AD identity and application management
**Cloud Resource-Based Privilege Escalation**: Exploits misconfigurations in Azure resource access controls

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

### 3. KeyVaultAbuse

**Category**: Cloud Resource-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker gains unauthorized access to Azure Key Vault to retrieve application secrets, which are then used for privilege escalation. The attack exploits overprivileged access to Key Vault resources and the common practice of storing application credentials in Key Vault.

**Attack Scenario**:
- An attacker gains initial access through compromised credentials or insider threat
- The attacker's identity (user, service principal, or managed identity) has been granted excessive permissions to an Azure Key Vault
- Application client secrets are stored in the Key Vault for legitimate operational purposes
- The attacker retrieves the client secrets from Key Vault and uses them to authenticate as the application
- The application has high-privileged permissions that allow further privilege escalation

**Technical Implementation**:
- Creates Azure Key Vault with RBAC authorization enabled
- Assigns Key Vault Contributor role to the specified principal type (user, service principal, or managed identity)
- Generates and stores application client secrets in the Key Vault
- Configures the target application with high-privileged Azure AD roles or API permissions
- Supports flexible principal types including VM managed identities for cloud-native attack scenarios

**Principal Types**:
- **User**: Regular user account gains Key Vault access through role assignment
- **Service Principal**: Application service principal is granted Key Vault permissions
- **Managed Identity**: Virtual machine managed identity is assigned Key Vault access

**Configuration Options**:
```yaml
privilege_escalation: KeyVaultAbuse
principal_type: user | service_principal | managed_identity
method: AzureADRole | APIPermission
initial_access: password | token
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Real-World Relevance**: This attack path reflects common scenarios where Key Vault access controls are misconfigured, allowing unauthorized access to sensitive application credentials. It's particularly relevant in cloud-native environments where managed identities are used extensively.

---

### 4. StorageAccountAbuse

**Category**: Cloud Resource-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker gains access to Azure Storage Account to retrieve certificates and private keys used for application authentication. The attack exploits misconfigured storage permissions and the practice of storing authentication materials in blob storage.

**Attack Scenario**:
- An attacker gains initial access to an identity with storage account permissions
- The attacker's identity has been granted read access to Azure Blob Storage containers
- Application certificates and private keys are stored in the storage account for operational purposes
- The attacker downloads the certificate and private key files from storage
- The attacker uses certificate-based authentication to impersonate the application
- The application has high-privileged permissions that enable further privilege escalation

**Technical Implementation**:
- Creates Azure Storage Account with private blob containers
- Generates self-signed X.509 certificates and private keys for target applications
- Uploads certificate (.pem) and private key (.key) files to storage containers
- Registers certificates with target applications for authentication
- Assigns Storage Blob Data Reader role to the specified principal type
- Configures applications with high-privileged Azure AD roles or API permissions

**Certificate Management**:
- Automatically generates self-signed certificates with 1-year validity
- Creates unique certificate and key file names to prevent conflicts
- Stores certificates in dedicated storage containers with private access
- Registers certificates with applications using Terraform automation

**Principal Types**:
- **User**: Regular user account gains storage access through role assignment
- **Service Principal**: Application service principal is granted storage permissions  
- **Managed Identity**: Virtual machine managed identity is assigned storage access

**Configuration Options**:
```yaml
privilege_escalation: StorageAccountAbuse
principal_type: user | service_principal | managed_identity
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
