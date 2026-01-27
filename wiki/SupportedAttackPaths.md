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

**Description**: This attack path simulates scenarios where an attacker exploits application ownership privileges to escalate privileges within an Azure AD tenant. The attack leverages the common misconfiguration where users or service principals are granted ownership of application registrations that have excessive permissions.

**Attack Scenario**:
- An attacker gains initial access to a user account or service principal through credential compromise or social engineering
- The compromised identity has been granted ownership of an application registration
- The application has been assigned high-privileged Azure AD roles or API permissions
- The attacker generates new client credentials for the owned application and uses them to access resources with elevated privileges

**Technical Implementation**:
- Creates a user account or service principal with password or token-based authentication
- Assigns the identity as owner of a randomly selected application registration
- Grants the application either Azure AD directory roles or API application permissions (Microsoft Graph, Exchange Online, etc.)
- Supports both direct access scenarios and helpdesk administrator privilege escalation paths (helpdesk only for users)

**Identity Types**:
- **user**: Regular user account as application owner (default)
- **service_principal**: Application service principal as application owner

**Configuration Options**:
```yaml
privilege_escalation: ApplicationOwnershipAbuse
identity_type: user | service_principal  # Type of identity that owns the application
method: AzureADRole | APIPermission
scenario: direct | helpdesk  # helpdesk only available with identity_type: user
initial_access: password | token
entry_point: compromised_identity  # Default, how attacker gains initial access
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Attack Variations by Identity Type**:

1. **User**: Simulates scenarios where a user account with application ownership is compromised. The attacker uses the user's credentials to add new credentials to the owned application.

2. **Service Principal**: Simulates scenarios where an application's service principal that owns another application is compromised. This is common in CI/CD pipelines or automation scenarios where service principals are granted application ownership for deployment purposes.

**Real-World Relevance**: This attack path is based on common misconfigurations where developers or administrators are granted application ownership without proper governance, leading to potential privilege escalation vectors. It simulates scenarios where compromised developer accounts or service accounts with application ownership can be leveraged for privilege escalation.

---

### 2. ApplicationAdministratorAbuse

**Category**: Identity-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker exploits the Application Administrator Entra ID role to manage any application in the tenant and escalate privileges. Unlike ApplicationOwnershipAbuse which targets specific owned applications, this technique leverages broad administrative privileges over all applications.

**Attack Scenario**:
- An attacker gains initial access to a user account or service principal with the Application Administrator role
- The Application Administrator role grants the ability to manage any application registration in the tenant
- The attacker identifies or creates an application with high-privileged Azure AD roles or API permissions
- The attacker adds new client credentials to the privileged application
- The attacker uses these credentials to authenticate as the application and leverage its elevated privileges

**Technical Implementation**:
- Creates a user account or service principal with password or token-based authentication
- Assigns the Application Administrator Entra ID role to the identity
- Grants a target application either Azure AD directory roles or API application permissions
- The identity can manage any application in the tenant, not just owned applications
- Supports multiple API types including Microsoft Graph and Exchange Online

**Identity Types**:
- **user**: Regular user account with Application Administrator role (default)
- **service_principal**: Application service principal with Application Administrator role

**Key Differences from ApplicationOwnershipAbuse**:
- **Scope**: Can manage ANY application in the tenant vs. only owned applications
- **Initial Privilege**: Requires Application Administrator role vs. application ownership
- **Attack Surface**: Broader attack surface with access to all applications
- **Real-World Scenario**: Compromised admin account vs. compromised developer account

**Configuration Options**:
```yaml
privilege_escalation: ApplicationAdministratorAbuse
identity_type: user | service_principal  # Type of identity with Application Administrator role
method: AzureADRole | APIPermission
initial_access: password | token
entry_point: compromised_identity  # Default, how attacker gains initial access
entra_role: <role_id> | random | [<role_id1>, <role_id2>]
app_role: <permission_id> | random | [<permission_id1>, <permission_id2>]
api_type: graph | exchange  # Only for APIPermission method
```

**Attack Variations by Identity Type**:

1. **User**: Simulates scenarios where a user account with the Application Administrator role is compromised. The attacker uses the user's credentials to manage any application in the tenant.

2. **Service Principal**: Simulates scenarios where an application's service principal with the Application Administrator role is compromised. This is common in automation scenarios where service principals are granted administrative roles for application lifecycle management.

**Note**: This technique does not support the `scenario` parameter as it focuses on direct exploitation of the Application Administrator role.

**Real-World Relevance**: This attack path reflects scenarios where Application Administrator accounts are compromised, providing attackers with broad control over application registrations. It's particularly relevant for testing the security of privileged administrative roles and their potential for abuse in privilege escalation attacks.

---

### 3. ManagedIdentityTheft

**Category**: Identity-Based Privilege Escalation

**Description**: This attack path simulates scenarios where an attacker exploits access to Azure resources with managed identities to steal identity tokens and pivot to other cloud resources. This technique represents the identity theft component of cloud-native privilege escalation attacks.

**Attack Scenario**:
- An attacker gains initial access to a user or service principal account with contributor access to an Azure resource (e.g., Virtual Machine, Logic App, Automation Account, or Function App)
- The Azure resource has a system-assigned managed identity with permissions to access other cloud resources
- The attacker leverages their access to the source resource to extract the managed identity token
- The attacker uses the stolen managed identity token to access the target resource (Key Vault or Storage Account)
- The attacker retrieves application credentials (secrets or certificates) from the target resource
- The application has high-privileged permissions that enable further privilege escalation

**Technical Implementation**:
- Creates an Azure resource with system-assigned managed identity
- Assigns the initial access principal (user or service principal) appropriate Contributor role on the resource:
  - VM Contributor for Virtual Machines
  - Logic App Contributor for Logic Apps
  - Automation Contributor for Automation Accounts
  - Website Contributor for Function Apps
- Grants the managed identity access to target resources (Key Vault or Storage Account)
- Stores application credentials (secrets or certificates) in the target resource
- Configures the target application with high-privileged Azure AD roles or API permissions

**Source Types**:
- **vm**: Virtual Machine with system-assigned managed identity (requires VM Contributor role)
- **logic_app**: Logic App with system-assigned managed identity (requires Logic App Contributor role)
- **automation_account**: Automation Account with system-assigned managed identity (requires Automation Contributor role)
- **function_app**: Function App with system-assigned managed identity (requires Website Contributor role)
  - **Note**: Function Apps use Linux OS with Python runtime

**Target Resource Types**:
- **key_vault**: Managed identity has Key Vault Contributor access to retrieve secrets or certificates
- **storage_account**: Managed identity has Storage Blob Data Reader access to retrieve certificates

**Credential Types**:
- **secret** (default): Application uses client ID and secret for authentication
- **certificate**: Application uses certificate-based authentication (more secure, harder to detect)

**Identity Types**:
- **user**: Regular user account with Contributor access to the source resource (default)
- **service_principal**: Application service principal with Contributor access to the source resource

**Entry Point Types**:
- **compromised_identity**: Attacker has compromised credentials for the initial access principal (default)

**Configuration Options**:
```yaml
privilege_escalation: ManagedIdentityTheft
source_type: vm | logic_app | automation_account | function_app
target_resource_type: key_vault | storage_account
entry_point: compromised_identity  # How attacker gains initial access
identity_type: user | service_principal  # Type of initial access principal
credential_type: secret | certificate  # Type of credential stored in target resource
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

4. **Function App**: Attacker with Website Contributor can modify function code or configuration to extract managed identity tokens through the IMDS endpoint. Function Apps are deployed with Linux OS and Python runtime.

**Attack Variations by Credential Type**:

1. **Secret** (default): Application credentials stored as client ID and secret. Easier to implement but secrets can be logged or cached.

2. **Certificate**: Application credentials stored as X.509 certificates with private keys. More secure and harder to detect in logs, but requires certificate management.

**Attack Variations by Identity Type**:

1. **User**: Simulates scenarios where a user account with resource contributor access is compromised. The attacker uses the user's credentials to access the Azure resource and extract the managed identity token.

2. **Service Principal**: Simulates scenarios where an application's service principal with resource contributor access is compromised. This is common in CI/CD pipelines or automation scenarios where service principals are granted contributor access to Azure resources.

**Real-World Relevance**: This attack path reflects scenarios where managed identities are overprivileged or where users/service principals have excessive permissions on Azure resources. It's particularly relevant for testing the security of managed identity configurations and resource access controls in cloud-native environments.

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

**Identity Types**:
- **user**: Regular user account with Key Vault access
- **service_principal**: Application service principal with Key Vault permissions

**Note**: For scenarios involving managed identity token theft to access Key Vault, use the `ManagedIdentityTheft` technique with `target_resource_type: key_vault`.

**Configuration Options**:
```yaml
privilege_escalation: KeyVaultSecretTheft
identity_type: user | service_principal
method: AzureADRole | APIPermission
initial_access: password | token
entry_point: compromised_identity  # Default, how attacker gains initial access
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

**Identity Types**:
- **user**: Regular user account with storage access
- **service_principal**: Application service principal with storage permissions

**Note**: For scenarios involving managed identity token theft to access Storage Account, use the `ManagedIdentityTheft` technique with `target_resource_type: storage_account`.

**Configuration Options**:
```yaml
privilege_escalation: StorageCertificateTheft
identity_type: user | service_principal
method: AzureADRole | APIPermission
initial_access: password | token
entry_point: compromised_identity  # Default, how attacker gains initial access
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

## Entry Point Types

BadZure uses the `entry_point` parameter to define how an attacker gains initial access to the environment. This parameter is available for all attack paths.

### compromised_identity (Default)

Simulates scenarios where an attacker has compromised a user account or service principal through:
- Credential stuffing or password spraying
- Phishing attacks
- Token theft (reverse proxy phishing, endpoint malware, device code phishing)
- Leaked credentials in code repositories or configuration files

When using `entry_point: compromised_identity`, you must also specify:
- `identity_type`: user or service_principal
- `initial_access`: password or token

**Example**:
```yaml
attack_path_1:
  enabled: true
  privilege_escalation: ApplicationOwnershipAbuse
  entry_point: compromised_identity  # Default
  identity_type: user
  initial_access: password
```

### Future Entry Points

Additional entry points may be added in future versions, such as:
- `vulnerability`: Exploiting a vulnerability in an Azure resource
- `insider_threat`: Simulating malicious insider scenarios
- `supply_chain`: Compromised third-party integrations

---

Organizations can use these attack paths to validate their security controls, detection capabilities, and incident response procedures in a controlled environment.
