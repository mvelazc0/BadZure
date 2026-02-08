# ManagedIdentityTheft

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity with **contributor access** to an Azure resource that has a **managed identity**. The attacker extracts the managed identity token from the resource, then uses it to retrieve application credentials from a Key Vault or Storage Account. The target application has high privileges, completing the escalation chain.

This is the most complex attack path BadZure supports, with multiple source resources, target resources, and credential types.

## Attack Flow

``` mermaid
graph LR
    A["Compromised<br/>Identity"] -->|"contributor<br/>access"| B["Azure Resource<br/><small>VM / Logic App /<br/>Automation Account /<br/>Function App</small>"]
    B -->|"has"| C["Managed<br/>Identity"]
    C -->|"steal token"| D["Identity<br/>Token"]
    D -->|"access"| E["Target Resource<br/><small>Key Vault /<br/>Storage Account</small>"]
    E -->|"retrieve"| F["App Credentials<br/><small>Secret or Certificate</small>"]
    F -->|"authenticate as"| G["Privileged<br/>Application"]

    style A fill:#ef5350,color:#fff
    style B fill:#37474f,color:#fff
    style C fill:#e65100,color:#fff
    style D fill:#e65100,color:#fff
    style E fill:#37474f,color:#fff
    style F fill:#455a64,color:#fff
    style G fill:#2e7d32,color:#fff
```

## What Happens

1. The attacker gains access to a **user account** or **service principal** with **contributor-level access** to an Azure resource
2. The Azure resource has a **system-assigned managed identity** with permissions to access another resource
3. The attacker interacts with the source resource to **extract the managed identity token** (via IMDS on VMs, workflow modification on Logic Apps, runbook execution on Automation Accounts, or code modification on Function Apps)
4. Using the stolen token, the attacker accesses a **Key Vault** (to retrieve secrets) or **Storage Account** (to retrieve certificates)
5. The attacker uses the retrieved credentials to **authenticate as a privileged application**

## Source and Target Combinations

BadZure supports any combination of source and target resource types:

``` mermaid
graph TD
    subgraph Sources
        VM["Virtual Machine<br/><small>VM Contributor</small>"]
        LA["Logic App<br/><small>Logic App Contributor</small>"]
        AA["Automation Account<br/><small>Automation Contributor</small>"]
        FA["Function App<br/><small>Website Contributor</small>"]
    end

    subgraph Targets
        KV["Key Vault<br/><small>Secrets or Certificates</small>"]
        SA["Storage Account<br/><small>Certificates</small>"]
    end

    VM --> KV
    VM --> SA
    LA --> KV
    LA --> SA
    AA --> KV
    AA --> SA
    FA --> KV
    FA --> SA

    style VM fill:#37474f,color:#fff
    style LA fill:#37474f,color:#fff
    style AA fill:#37474f,color:#fff
    style FA fill:#37474f,color:#fff
    style KV fill:#e65100,color:#fff
    style SA fill:#e65100,color:#fff
```

### Source Types

| Source | Required Role | How Token Is Stolen |
|---|---|---|
| `vm` | VM Contributor | Run commands via IMDS to extract token |
| `logic_app` | Logic App Contributor | Modify workflow to extract token via HTTP action |
| `automation_account` | Automation Contributor | Create/modify runbook to extract token |
| `function_app` | Website Contributor | Modify function code to extract token (Linux/Python) |

### Target Types

| Target | Managed Identity Access | What's Retrieved |
|---|---|---|
| `key_vault` | Key Vault Contributor | Application client secrets or certificates |
| `storage_account` | Storage Blob Data Reader | Application certificates and private keys |

## Variations

### By Credential Type

=== "Secret (default)"

    The target resource stores an application **client secret**. The attacker retrieves the client ID and secret, then authenticates using the standard OAuth2 client credentials flow.

=== "Certificate"

    The target resource stores an **X.509 certificate** with a private key. The attacker downloads the certificate and key files, then uses certificate-based authentication. This is harder to detect in logs than secret-based auth.

### By Identity Type

=== "User (default)"

    A user account with contributor access to the source resource. Simulates a compromised developer or operator.

=== "Service Principal"

    A service principal with contributor access. Simulates a compromised CI/CD pipeline or automation account with excessive resource permissions.

### By Assignment Type

=== "Direct (default)"

    Contributor access is assigned directly to the identity.

=== "Group"

    The identity is a member of a security group with contributor access to the source resource.

    ``` mermaid
    graph LR
        U["Compromised<br/>Identity"] -->|"member of"| G["Security<br/>Group"]
        G -->|"contributor"| RES["Azure<br/>Resource"]
        RES -->|"managed identity<br/>token theft"| TGT["Target<br/>Resource"]

        style U fill:#ef5350,color:#fff
        style G fill:#e65100,color:#fff
        style RES fill:#37474f,color:#fff
        style TGT fill:#37474f,color:#fff
    ```

## Configuration Examples

VM to Key Vault with Graph API permissions:

```yaml
attack_paths:
  mi_vm_keyvault:
    enabled: true
    privilege_escalation: ManagedIdentityTheft
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
    privilege_escalation: ManagedIdentityTheft
    source_type: logic_app
    target_resource_type: storage_account
    identity_type: service_principal
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Function App with certificate-based credentials:

```yaml
attack_paths:
  mi_functionapp_cert:
    enabled: true
    privilege_escalation: ManagedIdentityTheft
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
    privilege_escalation: ManagedIdentityTheft
    source_type: automation_account
    target_resource_type: key_vault
    assignment_type: group
    method: APIPermission
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

## Real-World Relevance

Managed identity abuse is a core technique in cloud-native attacks. Organizations frequently grant contributor access to Azure resources without considering the attack surface created by managed identities. A developer with VM Contributor access can extract managed identity tokens to access resources far beyond what their direct permissions allow. This attack path is particularly relevant for:

- Testing managed identity configurations
- Validating resource access controls
- Understanding lateral movement in Azure environments
- Detecting token theft and unauthorized resource access
