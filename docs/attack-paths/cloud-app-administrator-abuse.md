# CloudAppAdministratorAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity with the **Cloud Application Administrator** Entra ID role, which grants the ability to manage application registrations in the tenant. The attacker identifies an application with high privileges, adds new credentials to it, and authenticates as that application.

!!! note
    This technique is very similar to [ApplicationAdministratorAbuse](app-administrator-abuse.md). The only difference is the Entra ID role used. Refer to the ApplicationAdministratorAbuse page for full details on attack steps, variations, and configuration options.

## Key Difference

The **Cloud Application Administrator** role (`158c047a-c907-4556-b7ef-446551a6b5f7`) has a narrower scope than the **Application Administrator** role (`9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`). Specifically, Cloud Application Administrator **cannot** manage applications that have been assigned certain sensitive permissions (such as those held by first-party Microsoft applications).

| | ApplicationAdministratorAbuse | CloudAppAdministratorAbuse |
|---|---|---|
| **Entra ID Role** | Application Administrator | Cloud Application Administrator |
| **Role ID** | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| **Scope** | All applications | Most applications (excludes those with sensitive permissions) |
| **Real-world scenario** | Compromised admin with full app management | Compromised admin with limited app management |

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"assigned"| ROLE(("Cloud Application<br/>Administrator Role"))
    ROLE -->|"can manage"| APP(("Application<br/>Registration"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Configuration Examples

User with Cloud Application Administrator targeting an app with an Entra ID role:

```yaml
attack_paths:
  cloud_app_admin_role:
    enabled: true
    privilege_escalation: CloudAppAdministratorAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Application-scoped role assignment:

```yaml
attack_paths:
  cloud_app_admin_scoped:
    enabled: true
    privilege_escalation: CloudAppAdministratorAbuse
    scope: application
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Group-based assignment with API permissions:

```yaml
attack_paths:
  cloud_app_admin_group:
    enabled: true
    privilege_escalation: CloudAppAdministratorAbuse
    assignment_type: group_member
    method: APIPermission
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

## See Also

- [ApplicationAdministratorAbuse](app-administrator-abuse.md) — Same attack pattern using the broader Application Administrator role

## Further Reading

- [Azure AD Privilege Escalation - Taking Over Default Application Permissions as Application Admin - Dirk-jan Mollema](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/)
- [Azure Privilege Escalation via Azure API Permissions Abuse - Andy Robbins / SpecterOps](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
- [Microsoft Entra Built-in Roles - Cloud Application Administrator - Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator)
- [Privilege Escalation - Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/PrivEsc/)
