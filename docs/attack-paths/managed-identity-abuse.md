# ManagedIdentityAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity with **contributor access** to an Azure resource that has a **managed identity**. The attacker extracts the managed identity token from the resource, then uses it to retrieve application credentials from a Key Vault, Storage Account, or Cosmos DB. The target application has high privileges, completing the escalation chain.

This is the most complex attack path BadZure supports, with multiple source resources, target resources, and credential types.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Contributor on"| RES(("Azure Resource<br/>VM / Logic App /<br/>Automation / Function App"))
    RES -->|"has"| MI(("System Managed<br/>Identity"))
    MI -->|"can access"| TGT(("Target Resource<br/>Key Vault / Storage /<br/>Cosmos DB"))
    TGT -->|"stores credentials for"| APP(("Privileged<br/>Application"))
    APP -->|"assigned"| PRIV(("Entra ID Role or<br/>API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Execute code on"| RES(("Azure<br/>Resource"))
    A -->|"2. Steal token from"| MI(("Managed<br/>Identity"))
    A -->|"3. Retrieve credentials from"| TGT(("Target<br/>Resource"))
    A -->|"4. Authenticate as"| APP(("Privileged<br/>Application"))
```

## What Happens

1. The attacker gains access to a **user account** or **service principal** with **contributor-level access** to an Azure resource
2. The Azure resource has a **system-assigned managed identity** with permissions to access another resource
3. The attacker interacts with the source resource to **extract the managed identity token** (via IMDS on VMs, workflow modification on Logic Apps, runbook execution on Automation Accounts, or code modification on Function Apps)
4. Using the stolen token, the attacker accesses a **Key Vault** (to retrieve secrets), **Storage Account** (to retrieve certificates), or **Cosmos DB** (to retrieve secrets stored as documents)
5. The attacker uses the retrieved credentials to **authenticate as a privileged application**

## Variations

### By Source Type

BadZure supports any combination of source and target resource types:

``` mermaid
graph TD
    subgraph Sources
        VM(("Virtual Machine<br/>VM Contributor"))
        LA(("Logic App<br/>Logic App Contributor"))
        AA(("Automation Account<br/>Automation Contributor"))
        FA(("Function App<br/>Website Contributor"))
    end

    subgraph Targets
        KV(("Key Vault<br/>Secrets or Certificates"))
        SA(("Storage Account<br/>Certificates"))
        CDB(("Cosmos DB<br/>Secrets"))
    end

    VM --> KV
    VM --> SA
    VM --> CDB
    LA --> KV
    LA --> SA
    LA --> CDB
    AA --> KV
    AA --> SA
    AA --> CDB
    FA --> KV
    FA --> SA
    FA --> CDB
```

=== "Virtual Machine"

    The attacker runs commands on the VM to query the **Instance Metadata Service (IMDS)** and extract the managed identity token.

    - **Config value:** `source_type: vm`
    - **Required role:** VM Contributor

=== "Logic App"

    The attacker modifies the Logic App workflow to add an **HTTP action** that extracts the managed identity token.

    - **Config value:** `source_type: logic_app`
    - **Required role:** Logic App Contributor

=== "Automation Account"

    The attacker creates or modifies a **runbook** to extract the managed identity token.

    - **Config value:** `source_type: automation_account`
    - **Required role:** Automation Contributor

=== "Function App"

    The attacker modifies the **function code** to extract the managed identity token (Linux/Python).

    - **Config value:** `source_type: function_app`
    - **Required role:** Website Contributor

### By Target Type

=== "Key Vault"

    The managed identity has **Key Vault Contributor** access. The attacker retrieves application client secrets or certificates stored in the vault.

    - **Config value:** `target_resource_type: key_vault`
    - **Managed identity access:** Key Vault Contributor

=== "Storage Account"

    The managed identity has **Storage Blob Data Reader** access. The attacker retrieves application certificates and private keys stored as blobs.

    - **Config value:** `target_resource_type: storage_account`
    - **Managed identity access:** Storage Blob Data Reader

=== "Cosmos DB"

    The managed identity has **Cosmos DB Built-in Data Contributor** access. The attacker retrieves application client secrets stored as documents.

    - **Config value:** `target_resource_type: cosmos_db`
    - **Managed identity access:** Cosmos DB Built-in Data Contributor

### By Credential Type

=== "Secret (default)"

    The target resource stores an application **client secret**. The attacker retrieves the client ID and secret, then authenticates using the standard OAuth2 client credentials flow.

    ``` mermaid
    graph LR
        A(("Attacker")) -->|"steal token"| MI(("Managed<br/>Identity"))
        MI -->|"access"| TGT(("Key Vault / Storage /<br/>Cosmos DB"))
        TGT -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Certificate"

    The target resource stores an **X.509 certificate** with a private key. The attacker downloads the certificate and key files, then uses certificate-based authentication. This is harder to detect in logs than secret-based auth.

    ``` mermaid
    graph LR
        A(("Attacker")) -->|"steal token"| MI(("Managed<br/>Identity"))
        MI -->|"access"| TGT(("Key Vault /<br/>Storage Account"))
        TGT -->|"retrieve certificate"| APP(("Privileged<br/>Application"))
    ```

### By Identity Type

=== "User (default)"

    A user account with contributor access to the source resource. Simulates a compromised developer or operator.

    ``` mermaid
    graph LR
        U(("Compromised<br/>User")) -->|"Contributor on"| RES(("Azure<br/>Resource"))
        RES -->|"has"| MI(("Managed<br/>Identity"))
        MI -->|"access"| TGT(("Target<br/>Resource"))
    ```

=== "Service Principal"

    A service principal with contributor access. Simulates a compromised CI/CD pipeline or automation account with excessive resource permissions.

    ``` mermaid
    graph LR
        SP(("Compromised<br/>Service Principal")) -->|"Contributor on"| RES(("Azure<br/>Resource"))
        RES -->|"has"| MI(("Managed<br/>Identity"))
        MI -->|"access"| TGT(("Target<br/>Resource"))
    ```

### By Assignment Type

=== "Direct (default)"

    Contributor access is assigned directly to the identity.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"Contributor on"| RES(("Azure<br/>Resource"))
        RES -->|"has"| MI(("Managed<br/>Identity"))
        MI -->|"access"| TGT(("Target<br/>Resource"))
    ```

=== "Group Member"

    The identity is a **member** of a security group with contributor access to the source resource.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"member of"| G(("Security<br/>Group"))
        G -->|"contributor"| RES(("Azure<br/>Resource"))
        RES -->|"managed identity<br/>token theft"| TGT(("Target<br/>Resource"))
    ```

=== "Group Owner"

    The identity **owns** a security group with contributor access to the source resource. As group owner, the attacker can add themselves as a member to inherit the group's privileges.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"owner of"| G(("Security<br/>Group"))
        G -->|"contributor"| RES(("Azure<br/>Resource"))
        RES -->|"managed identity<br/>token theft"| TGT(("Target<br/>Resource"))
    ```

## Configuration Examples

VM to Key Vault with Graph API permissions:

```yaml
attack_paths:
  mi_vm_keyvault:
    enabled: true
    privilege_escalation: ManagedIdentityAbuse
    source_type: vm
    target_resource_type: key_vault
    method: APIPermission
    api_type: graph
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 19dbc75e-c2e2-444c-a770-ec69d8559fc7  # Directory.ReadWrite.All
```

Logic App to Storage Account with service principal:

```yaml
attack_paths:
  mi_logicapp_storage:
    enabled: true
    privilege_escalation: ManagedIdentityAbuse
    source_type: logic_app
    target_resource_type: storage_account
    initial_access: service_principal
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Function App with certificate-based credentials:

```yaml
attack_paths:
  mi_functionapp_cert:
    enabled: true
    privilege_escalation: ManagedIdentityAbuse
    source_type: function_app
    target_resource_type: key_vault
    credential_type: certificate
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

Automation Account with group-based assignment:

```yaml
attack_paths:
  mi_automation_group:
    enabled: true
    privilege_escalation: ManagedIdentityAbuse
    source_type: automation_account
    target_resource_type: key_vault
    assignment_type: group_member
    method: APIPermission
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

VM to Cosmos DB with Graph API permissions:

```yaml
attack_paths:
  mi_vm_cosmos:
    enabled: true
    privilege_escalation: ManagedIdentityAbuse
    source_type: vm
    target_resource_type: cosmos_db
    method: APIPermission
    api_type: graph
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 19dbc75e-c2e2-444c-a770-ec69d8559fc7  # Directory.ReadWrite.All
```

## References

- [Azure Privilege Escalation Using Managed Identities - NetSPI](https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-privilege-escalation-using-managed-identities/)
- [Abusing Managed Identities - Hacking The Cloud](https://hackingthe.cloud/azure/abusing-managed-identities/)
- [Azure AD & IAM Part II - Leveraging Managed Identities for Privilege Escalation - Orca Security](https://orca.security/resources/blog/azure-ad-iam-part-ii-leveraging-managed-identities-for-privilege-escalation/)
- [An Attempt at Detecting Managed Identity Abuse - TrustOnCloud](https://trustoncloud.com/blog/an-attempt-at-detecting-managed-identity-abuse/)
- [Privilege Escalation - Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/PrivEsc/)
