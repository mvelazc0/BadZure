# ApplicationAdministratorAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity with the **Application Administrator** Entra ID role, which grants the ability to manage **any** application registration in the tenant. The attacker identifies an application with high privileges, adds new credentials to it, and authenticates as that application.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"assigned"| ROLE(("Application<br/>Administrator Role"))
    ROLE -->|"can manage"| APP(("Application<br/>Registration"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Add credential to"| APP(("Target<br/>Application"))
    A -->|"2. Authenticate as"| SP(("Service<br/>Principal"))
    SP -->|"3. Escalate to"| ACCESS(("Privileged<br/>Access"))
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
        U(("Compromised<br/>Identity")) -->|"member of"| G(("Security<br/>Group"))
        G -->|"has"| ROLE(("Application<br/>Administrator Role"))
        ROLE -->|"manage"| APP(("Privileged<br/>Application"))
    ```

### By Scope

=== "Directory (default)"

    The Application Administrator role applies **tenant-wide**, allowing the identity to manage all applications.

=== "Application"

    The role is **scoped to a specific application** using `directory_scope_id`. The identity can only manage the target application, not all apps in the tenant. This simulates least-privilege environments where admin roles are scoped per-application.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"assigned"| ROLE(("Application<br/>Administrator Role"))
        ROLE -->|"scoped to"| APP(("Target<br/>Application"))
        APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
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

Application-scoped role assignment (role only applies to the target application):

```yaml
attack_paths:
  app_admin_scoped:
    enabled: true
    privilege_escalation: ApplicationAdministratorAbuse
    scope: application
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

!!! note
    This attack path does not support the `scenario` parameter (no helpdesk variant). It focuses on direct exploitation of the Application Administrator role.

## See Also

- [CloudAppAdministratorAbuse](cloud-app-administrator-abuse.md) — Same attack pattern using the Cloud Application Administrator role, which has a narrower scope (cannot manage apps with certain sensitive permissions)
