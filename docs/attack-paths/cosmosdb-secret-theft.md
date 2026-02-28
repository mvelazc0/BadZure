# CosmosDBSecretTheft

**Category:** Resource-Based Privilege Escalation

An attacker compromises an identity with **direct access to Azure Cosmos DB** and retrieves application client secrets stored as JSON documents. The attacker uses the secrets to authenticate as a privileged application.

## Posture

``` mermaid
graph LR
    ID(("Compromised<br/>Identity")) -->|"Cosmos DB<br/>Data Contributor on"| CDB(("Azure<br/>Cosmos DB"))
    CDB -->|"stores secret for"| APP(("Privileged<br/>Application"))
    APP -->|"assigned"| PRIV(("Entra ID Role<br/>or API Permission"))
```

## Attack Steps

``` mermaid
graph LR
    A(("Attacker")) -->|"1. Retrieve secret from"| CDB(("Azure<br/>Cosmos DB"))
    A -->|"2. Authenticate as"| SP(("Service<br/>Principal"))
    SP -->|"3. Escalate to"| ACCESS(("Privileged<br/>Access"))
```

## What Happens

1. The attacker gains access to a **user account** or **service principal**
2. The compromised identity has **Cosmos DB Built-in Data Contributor** role on an Azure Cosmos DB account
3. The Cosmos DB account contains **client secrets** for one or more application registrations stored as JSON documents
4. The attacker **retrieves the secrets** from the Cosmos DB account
5. The attacker authenticates as the application's **service principal** using the retrieved secrets
6. The application has high-privileged **Entra ID roles** or **API permissions**

## How It Differs From ManagedIdentityAbuse

This attack path provides **direct access** to the Cosmos DB account — there is no intermediate managed identity token theft step. Use this when simulating scenarios where a user or service principal has been directly granted Cosmos DB data access, rather than inheriting it through a managed identity.

| | CosmosDBSecretTheft | ManagedIdentityAbuse (with cosmos_db target) |
|---|---|---|
| **Access method** | Direct Cosmos DB data role | Via managed identity token from another resource |
| **Steps** | 3 (access Cosmos DB → get secret → authenticate) | 5+ (access resource → steal token → access Cosmos DB → get secret → authenticate) |
| **Simulates** | Misconfigured Cosmos DB RBAC | Overprivileged managed identity chain |

## Variations

### By Identity Type

=== "User (default)"

    A user account with Cosmos DB Built-in Data Contributor role. Simulates a compromised operator or developer with direct database access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>User")) -->|"Cosmos DB<br/>Data Contributor"| CDB(("Azure<br/>Cosmos DB"))
        CDB -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Service Principal"

    A service principal with Cosmos DB Built-in Data Contributor role. Simulates a compromised automation pipeline with excessive Cosmos DB permissions.

    ``` mermaid
    graph LR
        SP(("Compromised<br/>Service Principal")) -->|"Cosmos DB<br/>Data Contributor"| CDB(("Azure<br/>Cosmos DB"))
        CDB -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

### By Assignment Type

=== "Direct (default)"

    Cosmos DB Built-in Data Contributor role is assigned directly to the identity.

    ``` mermaid
    graph LR
        ID(("Compromised<br/>Identity")) -->|"Cosmos DB<br/>Data Contributor"| CDB(("Azure<br/>Cosmos DB"))
        CDB -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Group Member"

    The identity is a **member** of a security group with Cosmos DB Data Contributor access.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"member of"| G(("Security<br/>Group"))
        G -->|"Cosmos DB<br/>Data Contributor"| CDB(("Azure<br/>Cosmos DB"))
        CDB -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

=== "Group Owner"

    The identity **owns** a security group with Cosmos DB Data Contributor access. As group owner, the attacker can add themselves as a member to inherit the group's privileges.

    ``` mermaid
    graph LR
        U(("Compromised<br/>Identity")) -->|"owner of"| G(("Security<br/>Group"))
        G -->|"Cosmos DB<br/>Data Contributor"| CDB(("Azure<br/>Cosmos DB"))
        CDB -->|"retrieve secret"| APP(("Privileged<br/>Application"))
    ```

## Configuration Examples

User with direct Cosmos DB access, application has Global Administrator role:

```yaml
attack_paths:
  cosmos_theft_basic:
    enabled: true
    privilege_escalation: CosmosDBSecretTheft
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Service principal with Graph API permissions:

```yaml
attack_paths:
  cosmos_theft_sp:
    enabled: true
    privilege_escalation: CosmosDBSecretTheft
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
  cosmos_theft_group:
    enabled: true
    privilege_escalation: CosmosDBSecretTheft
    assignment_type: group_member
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
```

!!! tip
    Make sure your tenant configuration includes at least one Cosmos DB account (`cosmos_dbs: 1`) when using this attack path.
