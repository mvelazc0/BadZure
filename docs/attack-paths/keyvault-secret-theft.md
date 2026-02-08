# KeyVaultSecretTheft

**Category:** Resource-Based Privilege Escalation

An attacker compromises an identity with **direct access to Azure Key Vault** and retrieves application client secrets stored inside. The attacker uses the secrets to authenticate as a privileged application.

## Attack Flow

``` mermaid
graph LR
    A["Compromised<br/>Identity"] -->|"Key Vault<br/>Contributor"| B["Azure<br/>Key Vault"]
    B -->|"retrieve"| C["Application<br/>Client Secret"]
    C -->|"authenticate as"| D["Privileged<br/>Application"]
    D -->|"escalate to"| E["Privileged<br/>Access"]

    style A fill:#ef5350,color:#fff
    style B fill:#37474f,color:#fff
    style C fill:#e65100,color:#fff
    style D fill:#455a64,color:#fff
    style E fill:#2e7d32,color:#fff
```

## What Happens

1. The attacker gains access to a **user account** or **service principal**
2. The compromised identity has **Key Vault Contributor** role on an Azure Key Vault
3. The Key Vault contains **client secrets** for one or more application registrations
4. The attacker **retrieves the secrets** from the Key Vault
5. The attacker authenticates as the application's **service principal** using the retrieved secrets
6. The application has high-privileged **Entra ID roles** or **API permissions**

## How It Differs From ManagedIdentityTheft

This attack path provides **direct access** to the Key Vault — there is no intermediate managed identity token theft step. Use this when simulating scenarios where a user or service principal has been directly granted Key Vault access, rather than inheriting it through a managed identity.

| | KeyVaultSecretTheft | ManagedIdentityTheft (with key_vault target) |
|---|---|---|
| **Access method** | Direct Key Vault role | Via managed identity token from another resource |
| **Steps** | 3 (access vault → get secret → authenticate) | 5+ (access resource → steal token → access vault → get secret → authenticate) |
| **Simulates** | Misconfigured Key Vault RBAC | Overprivileged managed identity chain |

## Variations

### By Identity Type

=== "User (default)"

    A user account with Key Vault Contributor role. Simulates a compromised operator or developer with direct vault access.

=== "Service Principal"

    A service principal with Key Vault Contributor role. Simulates a compromised automation pipeline with excessive Key Vault permissions.

### By Assignment Type

=== "Direct (default)"

    Key Vault Contributor role is assigned directly to the identity.

=== "Group"

    The identity is a member of a security group with Key Vault Contributor access.

    ``` mermaid
    graph LR
        U["Compromised<br/>Identity"] -->|"member of"| G["Security<br/>Group"]
        G -->|"Key Vault<br/>Contributor"| KV["Azure<br/>Key Vault"]
        KV -->|"retrieve secret"| APP["Privileged<br/>App"]

        style U fill:#ef5350,color:#fff
        style G fill:#e65100,color:#fff
        style KV fill:#37474f,color:#fff
        style APP fill:#2e7d32,color:#fff
    ```

## Configuration Examples

User with direct Key Vault access, application has Global Administrator role:

```yaml
attack_paths:
  kv_theft_basic:
    enabled: true
    privilege_escalation: KeyVaultSecretTheft
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Service principal with Graph API permissions:

```yaml
attack_paths:
  kv_theft_sp:
    enabled: true
    privilege_escalation: KeyVaultSecretTheft
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
  kv_theft_group:
    enabled: true
    privilege_escalation: KeyVaultSecretTheft
    assignment_type: group
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

!!! tip
    Make sure your tenant configuration includes at least one Key Vault (`key_vaults: 1`) when using this attack path.
