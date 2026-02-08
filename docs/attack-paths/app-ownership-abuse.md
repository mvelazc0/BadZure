# ApplicationOwnershipAbuse

**Category:** Identity-Based Privilege Escalation

An attacker compromises an identity that **owns** an application registration with high privileges. The attacker adds new credentials to the owned application, then authenticates as that application to gain elevated access.

## Attack Flow

``` mermaid
graph LR
    A["Compromised<br/>Identity"] -->|"owns"| B["Application<br/>Registration"]
    B -->|"has"| C["High-Privilege<br/>Role or Permission"]
    A -->|"adds new<br/>credential"| D["New Secret<br/>or Certificate"]
    D -->|"authenticate as"| E["Service<br/>Principal"]
    E -->|"escalate to"| F["Privileged<br/>Access"]

    style A fill:#ef5350,color:#fff
    style B fill:#37474f,color:#fff
    style C fill:#e65100,color:#fff
    style D fill:#455a64,color:#fff
    style E fill:#455a64,color:#fff
    style F fill:#2e7d32,color:#fff
```

## What Happens

1. The attacker gains access to a **user account** or **service principal** (BadZure provides the credentials)
2. The compromised identity is an **owner** of an application registration
3. The owned application has been assigned a high-privileged **Entra ID role** (e.g., Global Administrator) or **API permission** (e.g., RoleManagement.ReadWrite.Directory)
4. As an owner, the attacker **adds new client credentials** (a secret or certificate) to the application
5. The attacker uses the new credentials to **authenticate as the application's service principal**
6. The attacker now has all the privileges assigned to that application

## Real-World Relevance

This is one of the most common Entra ID misconfigurations. Developers and automation pipelines are frequently granted application ownership for deployment purposes, but the owned applications often have excessive permissions. A compromised developer account or CI/CD service principal can turn application ownership into tenant-wide administrative access.

## Variations

### By Identity Type

=== "User (default)"

    A user account owns the application. Simulates a compromised developer or admin.

    ``` mermaid
    graph LR
        U["Compromised<br/>User"] -->|"owns"| APP["Privileged<br/>App"]
        U -->|"add credential"| APP
        APP -->|"authenticate"| SP["Service<br/>Principal"]

        style U fill:#ef5350,color:#fff
        style APP fill:#37474f,color:#fff
        style SP fill:#2e7d32,color:#fff
    ```

=== "Service Principal"

    A service principal owns another application. Simulates a compromised CI/CD pipeline or automation account.

    ``` mermaid
    graph LR
        SP1["Compromised<br/>Service Principal"] -->|"owns"| APP["Privileged<br/>App"]
        SP1 -->|"add credential"| APP
        APP -->|"authenticate"| SP2["Target Service<br/>Principal"]

        style SP1 fill:#ef5350,color:#fff
        style APP fill:#37474f,color:#fff
        style SP2 fill:#2e7d32,color:#fff
    ```

### By Scenario

=== "Direct (default)"

    The attacker directly compromises the application owner.

=== "Helpdesk"

    The attacker first compromises a **Helpdesk Administrator**, resets the application owner's password, then exploits the ownership. Only available with `identity_type: user`.

    ``` mermaid
    graph LR
        H["Compromised<br/>Helpdesk Admin"] -->|"reset password"| U["Application<br/>Owner"]
        U -->|"owns"| APP["Privileged<br/>App"]
        U -->|"add credential"| APP
        APP -->|"authenticate"| SP["Service<br/>Principal"]

        style H fill:#ef5350,color:#fff
        style U fill:#e65100,color:#fff
        style APP fill:#37474f,color:#fff
        style SP fill:#2e7d32,color:#fff
    ```

### By Assignment Type

=== "Direct (default)"

    The identity directly owns the application.

=== "Group"

    The identity is a member of a **security group** that owns the application. Mirrors enterprise configurations where permissions are managed through group membership.

    ``` mermaid
    graph LR
        U["Compromised<br/>Identity"] -->|"member of"| G["Security<br/>Group"]
        G -->|"owns"| APP["Privileged<br/>App"]

        style U fill:#ef5350,color:#fff
        style G fill:#e65100,color:#fff
        style APP fill:#37474f,color:#fff
    ```

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
    identity_type: service_principal
    method: APIPermission
    api_type: graph
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
```

Helpdesk scenario:

```yaml
attack_paths:
  app_ownership_helpdesk:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    scenario: helpdesk
    method: AzureADRole
    entra_role: 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3  # Application Administrator
```

Group-based assignment:

```yaml
attack_paths:
  app_ownership_group:
    enabled: true
    privilege_escalation: ApplicationOwnershipAbuse
    assignment_type: group
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```
