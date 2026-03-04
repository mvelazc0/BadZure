# ApplicationOwnershipAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity that **owns** an application registration with high privileges. The attacker adds new credentials to the owned application, then authenticates as that application to gain elevated access.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"owner of"| APP(("Application<br/>Registration"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Add credential"| APP(("Owned<br/>Application"))
    A -->|"2. Authenticate as"| SP(("Service<br/>Principal"))
    SP -->|"3. Escalate to"| ACCESS(("Privileged<br/>Access"))
```

## What Happens

1. The attacker gains access to a **user account** or **service principal**
2. The compromised identity is an **owner** of an application registration
3. The owned application has been assigned a high-privileged **Entra ID role** (e.g., Global Administrator) or **API permission** (e.g., RoleManagement.ReadWrite.Directory)
4. As an owner, the attacker **adds new client credentials** (a secret or certificate) to the application
5. The attacker uses the new credentials to **authenticate as the application's service principal**
6. The attacker now has all the privileges assigned to that application

## How It Differs From ApplicationAdministratorAbuse

| | ApplicationOwnershipAbuse | ApplicationAdministratorAbuse |
|---|---|---|
| **Scope** | Only owned applications | **All** applications in the tenant |
| **Prerequisite** | Application ownership | Application Administrator role |
| **Attack surface** | Narrow — one app | Broad — every app |
| **Group assignment** | Not supported (direct only) | Supported (group_member, group_owner) |
| **Real-world scenario** | Compromised developer | Compromised admin account |

## Variations

### By Identity Type

=== "User (default)"

    A user account owns the application. Simulates a compromised developer or admin.

    ``` mermaid
    graph LR
        U(("Compromised<br/>User")) -->|"owns"| APP(("Privileged<br/>Application"))
        U -->|"add credential"| APP
        APP -->|"authenticate"| SP(("Service<br/>Principal"))
    ```

=== "Service Principal"

    A service principal owns another application. Simulates a compromised CI/CD pipeline or automation account.

    ``` mermaid
    graph LR
        SP1(("Compromised<br/>Service Principal")) -->|"owns"| APP(("Privileged<br/>Application"))
        SP1 -->|"add credential"| APP
        APP -->|"authenticate"| SP2(("Target Service<br/>Principal"))
    ```

### By Assignment Type

=== "Direct (default)"

    The identity directly owns the application.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"owner of"| APP(("Privileged<br/>Application"))
        APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
    ```

!!! warning
    This technique only supports `direct` assignment. Azure AD does not allow security groups to be application owners, so `group_member` and `group_owner` assignment types are **not supported** and will fall back to `direct`.

## Configuration Examples

Basic — user owns an application with Global Administrator role:

```yaml
attack_paths:
  app_ownership_basic:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Service principal with API permissions:

```yaml
attack_paths:
  app_ownership_sp:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    initial_access: service_principal
    method: APIPermission
    api_type: graph
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

## References

- [Azure Privilege Escalation via Service Principal Abuse - SpecterOps](https://specterops.io/blog/2021/10/12/azure-privilege-escalation-via-service-principal-abuse/)
- [Azure Privilege Escalation via Azure API Permissions Abuse - Andy Robbins / SpecterOps](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
- [Passwordless Persistence and Privilege Escalation in Azure - Andy Robbins / SpecterOps](https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f)
- [Privilege Escalation - Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/PrivEsc/)
