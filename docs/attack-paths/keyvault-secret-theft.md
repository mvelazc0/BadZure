# KeyVaultSecretTheft

**Category:** Resource-Based Privilege Escalation

An attacker compromises an identity with **direct access to Azure Key Vault** and retrieves application client secrets stored inside. The attacker uses the secrets to authenticate as a privileged application.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Key Vault<br/>Contributor on"| KV(("Azure<br/>Key Vault"))
    KV -->|"stores secret for"| APP(("Privileged<br/>Application"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Retrieve secret from"| KV(("Azure<br/>Key Vault"))
    A -->|"2. Authenticate as"| SP(("Service<br/>Principal"))
    SP -->|"3. Escalate to"| ACCESS(("Privileged<br/>Access"))
```

## What Happens

1. The attacker gains access to a **user account** or **service principal**
2. The compromised identity has **Key Vault Contributor** role on an Azure Key Vault
3. The Key Vault contains **client secrets** for one or more application registrations
4. The attacker **retrieves the secrets** from the Key Vault
5. The attacker authenticates as the application's **service principal** using the retrieved secrets
6. The application has high-privileged **Entra ID roles** or **API permissions**

## How It Differs From ManagedIdentityAbuse

This attack path provides **direct access** to the Key Vault — there is no intermediate managed identity token theft step. Use this when simulating scenarios where a user or service principal has been directly granted Key Vault access, rather than inheriting it through a managed identity.

| | KeyVaultSecretTheft | ManagedIdentityAbuse (with key_vault target) |
|---|---|---|
| **Access method** | Direct Key Vault role | Via managed identity token from another resource |
| **Steps** | 3 (access vault → get secret → authenticate) | 5+ (access resource → steal token → access vault → get secret → authenticate) |
| **Simulates** | Misconfigured Key Vault RBAC | Overprivileged managed identity chain |

## Variations

### By Identity Type

=== "User (default)"

    A user account with Key Vault Contributor role. Simulates a compromised operator or developer with direct vault access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>User")) -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
        KV -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Service Principal"

    A service principal with Key Vault Contributor role. Simulates a compromised automation pipeline with excessive Key Vault permissions.

    ``` mermaid
    graph LR
        SP(("Compromised<br/>Service Principal")) -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
        KV -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

### By Assignment Type

=== "Direct (default)"

    Key Vault Contributor role is assigned directly to the identity.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
        KV -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Group Member"

    The identity is a **member** of a security group with Key Vault Contributor access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"member of"| G(("Security<br/>Group"))
        G -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
        KV -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Group Owner"

    The identity **owns** a security group with Key Vault Contributor access. As group owner, the attacker can add themselves as a member to inherit the group's privileges.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"owner of"| G(("Security<br/>Group"))
        G -->|"Key Vault<br/>Contributor"| KV(("Azure<br/>Key Vault"))
        KV -->|"retrieve secret"| APP(("Privileged<br/>Application"))
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
    initial_access: service_principal
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
    assignment_type: group_member
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

!!! tip
    Make sure your tenant configuration includes at least one Key Vault (`key_vaults: 1`) when using this attack path.
