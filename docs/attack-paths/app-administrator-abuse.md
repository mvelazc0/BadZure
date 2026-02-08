# ApplicationAdministratorAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity with the **Application Administrator** Entra ID role, which grants the ability to manage **any** application registration in the tenant. The attacker identifies an application with high privileges, adds new credentials to it, and authenticates as that application.

## Attack Flow

``` mermaid
graph LR
    A["Compromised<br/>Identity"] -->|"has role"| B["Application<br/>Administrator"]
    B -->|"can manage"| C["Any Application<br/>in Tenant"]
    C -->|"target"| D["Privileged<br/>Application"]
    A -->|"adds new<br/>credential"| D
    D -->|"authenticate as"| E["Service<br/>Principal"]
    E -->|"escalate to"| F["Privileged<br/>Access"]

    style A fill:#ef5350,color:#fff
    style B fill:#e65100,color:#fff
    style C fill:#37474f,color:#fff
    style D fill:#37474f,color:#fff
    style E fill:#455a64,color:#fff
    style F fill:#2e7d32,color:#fff
```

## What Happens

1. The attacker gains access to a **user account** or **service principal** with the **Application Administrator** role
2. This role allows managing **every** application registration in the tenant — not just owned ones
3. The attacker identifies an application with a high-privileged **Entra ID role** or **API permission**
4. The attacker **adds new credentials** to that application
5. The attacker authenticates as the application's service principal with elevated privileges

## How It Differs From ApplicationOwnershipAbuse

| | ApplicationOwnershipAbuse | ApplicationAdministratorAbuse |
|---|---|---|
| **Scope** | Only owned applications | **All** applications in the tenant |
| **Prerequisite** | Application ownership | Application Administrator role |
| **Attack surface** | Narrow — one app | Broad — every app |
| **Real-world scenario** | Compromised developer | Compromised admin account |

## Variations

### By Identity Type

=== "User (default)"

    A user account with the Application Administrator role. Simulates a compromised IT admin.

=== "Service Principal"

    A service principal with the Application Administrator role. Simulates a compromised automation pipeline with excessive permissions.

### By Assignment Type

=== "Direct (default)"

    The Application Administrator role is assigned directly to the identity.

=== "Group"

    The identity is a member of a security group that holds the Application Administrator role.

    ``` mermaid
    graph LR
        U["Compromised<br/>Identity"] -->|"member of"| G["Security<br/>Group"]
        G -->|"has"| ROLE["Application<br/>Administrator Role"]
        ROLE -->|"manage"| APP["Privileged<br/>App"]

        style U fill:#ef5350,color:#fff
        style G fill:#e65100,color:#fff
        style ROLE fill:#37474f,color:#fff
        style APP fill:#37474f,color:#fff
    ```

## Configuration Examples

User with Application Administrator targeting an app with Exchange permissions:

```yaml
attack_paths:
  app_admin_exchange:
    enabled: true
    privilege_escalation: ApplicationAdministratorAbuse
    method: APIPermission
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40  # full_access_as_app
```

Service principal with Application Administrator targeting Global Admin role:

```yaml
attack_paths:
  app_admin_sp:
    enabled: true
    privilege_escalation: ApplicationAdministratorAbuse
    identity_type: service_principal
    initial_access: token
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Group-based assignment with Graph API permissions:

```yaml
attack_paths:
  app_admin_group:
    enabled: true
    privilege_escalation: ApplicationAdministratorAbuse
    assignment_type: group
    method: APIPermission
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

!!! note
    This attack path does not support the `scenario` parameter (no helpdesk variant). It focuses on direct exploitation of the Application Administrator role.
