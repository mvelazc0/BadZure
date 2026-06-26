# Configuration Guide

BadZure is configured through a YAML file that defines your tenant, a **baseline** organization, and the **attack paths** to layer on top. By default, BadZure looks for `badzure.yml` in the project root; use `--config` to point at another file.

## How It Works

A BadZure YAML configuration file has two parts:

- **`baseline:`** defines the realistic background organization: benign users, groups, apps, resources, and everyday assignments. It is the environment the attack paths are applied to.
- **`attack_paths:`** defines the deliberate misconfigurations added on top of the baseline.

Each attack path is authored with one of two methods:

- **atomic:** specifies a single **`privilege_escalation:`** technique and a few options. BadZure builds the full chain and randomly selects the victim and target identities from the baseline.
- **chained:** defines the attack path explicitly using primitives. This method supports creating multi privilege escalation attack paths that span several steps.

A minimal config looks like this:

```yaml

tenant:
  tenant_id: YOUR-TENANT-GUID
  domain: yourdomain.onmicrosoft.com
  subscription_id: YOUR-SUBSCRIPTION-GUID

baseline:
  identities: { users: 5, applications: 3, groups: 2 }
  resources:  { key_vaults: 1 }

attack_paths:
  kv_theft:
    privilege_escalation: KeyVaultSecretTheft
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
```

Each path is active by default. To keep a path defined in the file but not deploy it, set `enabled: false`.

## Tenant Settings

The `tenant` section identifies your Azure environment.

| Setting | Description |
|---|---|
| `tenant_id` | Your Entra ID tenant GUID |
| `domain` | Your tenant domain (e.g., `contoso.onmicrosoft.com`) |
| `subscription_id` | Azure subscription GUID for provisioning resources |

!!! tip
    These can also be set via environment variables in a `.env` file (`BADZURE_TENANT_ID`, `BADZURE_DOMAIN`, `BADZURE_SUBSCRIPTION_ID`). Leave the YAML values `null` to use them. See `.env.example`.

## Baseline — the Background Organization

The `baseline:` section populates the lab with benign background entities such as users, groups, applications, Azure resources, and the routine assignments between them, so the tenant looks like a real organization. They exist to provide realism: in a tenant containing only attack path resources, every object an operator enumerates is part of the solution. The baseline buries those paths in benign noise, so they have to be uncovered through real reconnaissance instead of by listing every object in the tenant.

The baseline has three sub-sections.

### `baseline.identities` — Entra entities

| Setting | Description |
|---|---|
| `users` | Number of user accounts to create |
| `applications` | Number of application registrations / service principals |
| `groups` | Number of security groups |
| `administrative_units` | Number of administrative units |

### `baseline.resources` — Azure resources

| Setting | Description | Needed by |
|---|---|---|
| `key_vaults` | Key Vaults | KeyVaultSecretTheft, ManagedIdentityAbuse |
| `storage_accounts` | Storage Accounts | StorageCertificateTheft, ManagedIdentityAbuse |
| `virtual_machines` | Windows or Linux VMs | ManagedIdentityAbuse |
| `logic_apps` | Logic Apps | ManagedIdentityAbuse |
| `automation_accounts` | Automation Accounts | ManagedIdentityAbuse  |
| `function_apps` | Function Apps | ManagedIdentityAbuse  |
| `app_services` | App Services (Linux web apps) | ManagedIdentityAbuse  |
| `cosmos_dbs` | Cosmos DB accounts | CosmosDBSecretTheft, ManagedIdentityAbuse |

Baseline VMs are private — they get no public IP. Only an exposed-host foothold VM (an `exposed_rdp` / `exposed_ssh` initial-access vector) is allocated a public IP so the operator can log in.

App Service creation is throttled per subscription. Running multiple build and destroy iterations in a short period can result in throttling errors that prevent App Services from being created for a while.

Resource groups are created automatically. See [Resource Groups](#resource-groups) for how resources are placed into them.

### `baseline.assignments` — (optional)

Realistic everyday assignments that recreate how access is distributed across a real organization: users added to groups, groups granted access to resources, applications holding permissions accumulated over time. Modeling that structure is what makes the tenant look authentic, so the seeded attack paths blend into believable access patterns instead of standing out as the only relationships present.

```yaml
baseline:
  identities: { users: 15, groups: 4, applications: 6, administrative_units: 2 }
  resources:  { key_vaults: 2, storage_accounts: 1 }
  assignments:
    group_memberships: 12   # users/groups added to groups
    entra_roles: 4          # low-priv directory roles on users/apps
    api_permissions: 3      # benign Graph permissions on apps
    au_memberships: 2       # users/groups in administrative units
    azure_rbac: 6           # Reader/Contributor/... over the baseline resources
    group_ownerships: 3     # users owning groups
    app_ownerships: 3       # users owning app registrations
    app_credentials: 4      # client secrets on service principals
    data_injects: 2         # benign secrets/blobs in the baseline vaults/storage
```

## Attack Paths

The `attack_paths:` section defines the attack paths BadZure builds into the tenant. Each named entry is a single attack path.

A path is defined with one of two methods.


**Atomic** generates a path from a single privilege escalation technique. You select a technique from the supported list and set the options that control how it is built. An atomic path contains one escalation step.

**Chained** defines a path as an explicit tenat posture graph written directly in YAML under assignments:. You declare the entities and the relationships between them as primitives. This lets you combine multiple privilege escalation techniques into a single path and form an attack chain of several steps.

The rest of this section documents **atomic**; [Authoring an Explicit Graph](#authoring-an-explicit-graph-chained) covers **chained**.

### Common Options (atomic)

These options are available for **all** technique types:

| Option | Values | Default | Description |
|---|---|---|---|
| `enabled` | `true`, `false` | `true` | Set `false` to park the path (defined but not deployed). Applies to any path, atomic or chained |
| `privilege_escalation` | See below | — | The privilege-escalation technique |
| `method` | `AzureADRole`, `APIPermission` | — | How the target app gets its privileges |
| `initial_access` | `user`, `service_principal`, `exposed_rdp`, `exposed_ssh`, `vulnerable_web_app` | `user` | How the attacker first gains a foothold |
| `assignment_type` | `direct`, `group_member`, `group_owner` | `direct` | Direct, via group membership, or via group ownership |
| `expose_to_internet` | `true`, `false` | `false` (footholds) | Exposed-host and vulnerable-web-app footholds. `false` restricts access to the operator IP; `true` opens it to the public internet (`0.0.0.0/0` for VMs, no access restriction for App Service) |
| `credential` | `known`, `weak` | `known` | Exposed-host footholds only. `weak` sets a brute-forceable local admin password; `known` keeps the strong generated one |
| `variant` | `rce` | `rce` | Vulnerable-web-app foothold only. The vulnerability class deployed to the App Service |

### Option Details

**`privilege_escalation`** — The privilege escalation technique to simulate:

- **`ApplicationOwnershipAbuse`** — Exploits application ownership to add credentials to privileged applications
- **`ApplicationAdministratorAbuse`** — Exploits the Application Administrator role to manage any application and add credentials
- **`CloudAppAdministratorAbuse`** — Exploits the Cloud Application Administrator role (narrower scope than Application Administrator)
- **`ManagedIdentityAbuse`** — Exploits access to Azure resources with managed identities to steal tokens and pivot to other resources
- **`KeyVaultSecretTheft`** — Retrieves application secrets stored in Azure Key Vault through direct access
- **`StorageCertificateTheft`** — Retrieves application certificates and private keys from Azure Storage through direct access
- **`CosmosDBSecretTheft`** — Retrieves application secrets stored in Azure Cosmos DB through direct data plane access

For detailed descriptions of each technique, see the [Attack Paths](attack-paths/index.md) section.

**`initial_access`** — How the attacker first gains a foothold. Two kinds: a compromised identity, or an exposed host.

Compromised-identity vectors (supported by every technique):

- **`user`** — A regular user account (default). Simulates compromised employee, developer, or administrator accounts
- **`service_principal`** — An application's service principal. Simulates compromised CI/CD pipelines, automation accounts, or third-party integrations

Exposed-host foothold vectors (ManagedIdentityAbuse with `source_type: vm` only):

- **`exposed_rdp`** — An internet-reachable VM with RDP open, brute-forced to gain code execution on the host
- **`exposed_ssh`** — An internet-reachable VM with SSH open, brute-forced to gain code execution on the host

With an exposed-host foothold the attacker lands directly on the VM (no compromised identity), then pivots through the VM's managed identity to reach the target resource. The foothold VM is the managed-identity source, so `source_type` must be `vm`. The foothold host's OS follows the vector (`exposed_rdp` forces a Windows VM, `exposed_ssh` a Linux VM) so the open port matches the box. The build surfaces the VM public IP and admin credentials so the operator can log in and continue the chain. Tune the exposure with `expose_to_internet` and `credential`.

Vulnerable-web-app foothold vector (ManagedIdentityAbuse with `source_type: app_service` only):

- **`vulnerable_web_app`** — An internet-facing App Service running a deliberately vulnerable app. The attacker exploits a code-execution bug to run commands in the app's process context and read its managed-identity token.

With a vulnerable-web-app foothold the attacker lands directly on the App Service (no compromised identity), then pivots through the app's managed identity to reach the target resource. The vulnerable app is the managed-identity source, so `source_type` must be `app_service`. The `variant` knob selects the vulnerability class deployed to the app (`rce`, a command-injection diagnostics page). `expose_to_internet` controls the App Service access restrictions (the App Service analog of the VM foothold NSG): the default `false` restricts the app to the operator IP, while `true` leaves it open to the public internet. App Service has no host login, so `credential` does not apply. The build surfaces the app URL and the vulnerable endpoint so the operator knows where to start.

The compromised-identity vectors are supported by every technique:

| Technique | User | Service Principal |
|---|---|---|
| ApplicationOwnershipAbuse | User as application owner | SP as application owner |
| ApplicationAdministratorAbuse | User with App Admin role | SP with App Admin role |
| CloudAppAdministratorAbuse | User with Cloud App Admin role | SP with Cloud App Admin role |
| ManagedIdentityAbuse | User with Contributor access | SP with Contributor access |
| KeyVaultSecretTheft | User with Key Vault access | SP with Key Vault access |
| StorageCertificateTheft | User with Storage access | SP with Storage access |
| CosmosDBSecretTheft | User with Cosmos DB access | SP with Cosmos DB access |

**`expose_to_internet`** *(exposed-host and vulnerable-web-app footholds)* — Default `false`: access stays open to the operator IP only (the machine running BadZure), so the operator can still reach the foothold. For a VM this keeps RDP and SSH restricted to the operator IP; set `true` to add a `0.0.0.0/0` (Internet) allow rule, making the host reachable — and brute-forceable — from anywhere. For an App Service this sets an access restriction allowing only the operator IP; set `true` to leave the app open to the public internet.

**`credential`** *(exposed-host footholds)* — Default `known`: the VM keeps its strong generated admin password, surfaced to the operator so they can log in directly. Set `weak` to assign a brute-forceable local admin password for a realistic credential-guessing exercise.

**`assignment_type`** — How permissions are granted to the initial access identity:

- **`direct`** — Permissions assigned directly to the identity (default). The user or service principal has explicit permissions.
- **`group_member`** — Permissions assigned to a security group. The identity is added as a member of the group and inherits permissions through group membership. This mirrors enterprise configurations where permissions are managed through groups.
- **`group_owner`** — The identity is added as an owner of a security group that has permissions. This simulates scenarios where group ownership is leveraged to control privileged groups.

### Privilege Assignment

How the target application receives its high privileges.

**`method`** — The method used to assign privileges to the target application:

- **`AzureADRole`** — Assigns Entra ID directory roles to the application, enabling tenant-wide administrative privileges
- **`APIPermission`** — Assigns API application permissions to the application (supports Microsoft Graph and Exchange Online)

=== "Entra ID Role"

    Assign one or more directory roles using `method: AzureADRole`:

    ```yaml
    method: AzureADRole

    # Single role
    entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator

    # Multiple roles
    entra_role:
      - e8611ab8-c189-46e8-94e1-60213ab1f814  # Privileged Role Administrator
      - 7be44c8a-adaf-4e2a-84d6-ab2649e08a13  # Privileged Authentication Administrator

    # Random high-privileged role
    entra_role: random
    ```

=== "API Permission"

    Assign API application permissions using `method: APIPermission`:

    ```yaml
    method: APIPermission

    # Microsoft Graph (default)
    api_type: graph
    app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory

    # Exchange Online
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40  # full_access_as_app

    # Multiple permissions
    app_role:
      - 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
      - 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory

    # Random high-privileged permission
    app_role: random
    ```

**`api_type`** — When using `method: APIPermission`, specifies which API to assign permissions for:

- **`graph`** — Microsoft Graph API (default). Provides access to Entra ID, Microsoft 365, and other Microsoft cloud services. Supports a wide range of high-privileged permissions.
- **`exchange`** — Exchange Online API. Provides direct access to Exchange Online mailboxes and configuration. Useful for testing email-based attack scenarios, including permissions like `full_access_as_app`.

## Per-Technique Options

Each technique adds its own knobs. The required field is always `privilege_escalation: <Name>`.

### ApplicationOwnershipAbuse

**Required:** `privilege_escalation: ApplicationOwnershipAbuse`, `method` (`AzureADRole` or `APIPermission`), and the matching `entra_role`/`app_role`.

**Optional:** `initial_access` (`user` default, or `service_principal`).

!!! warning
    This technique only supports `direct` assignment. Azure AD does not allow security groups to own applications, so `group_member`/`group_owner` fall back to `direct`.

### ApplicationAdministratorAbuse

**Required:** `privilege_escalation: ApplicationAdministratorAbuse`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`, `scope`.

**`scope`** — Controls whether the Application Administrator role is assigned tenant-wide or scoped to a specific application:

- **`directory`** — The role applies to **all** applications in the tenant (default)
- **`application`** — The role is scoped to only the **target application** (uses Entra ID's `directory_scope_id`). More realistic for least-privilege environments.

### CloudAppAdministratorAbuse

**Required:** `privilege_escalation: CloudAppAdministratorAbuse`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`, `scope`.

Identical to `ApplicationAdministratorAbuse` in configuration, but uses the **Cloud Application Administrator** role (`158c047a-c907-4556-b7ef-446551a6b5f7`) — a narrower role that cannot manage applications with certain sensitive permissions. See [CloudAppAdministratorAbuse](attack-paths/cloud-app-administrator-abuse.md).

### ManagedIdentityAbuse

**Required:** `privilege_escalation: ManagedIdentityAbuse`, `source_type`, `target_resource_type`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`, `credential_type`.

**`source_type`** — The Azure resource with the managed identity:

| Value | Resource | Required Role |
|---|---|---|
| `vm` | Virtual Machine with system-assigned managed identity | VM Contributor |
| `logic_app` | Logic App with system-assigned managed identity | Logic App Contributor |
| `automation_account` | Automation Account with system-assigned managed identity | Automation Contributor |
| `function_app` | Function App with system-assigned managed identity (Linux/Python) | Website Contributor |
| `app_service` | App Service with system-assigned managed identity (Linux/Python) | Website Contributor |

**`target_resource_type`** — The resource storing the application credentials:

| Value | Resource | Managed Identity Access |
|---|---|---|
| `key_vault` | Azure Key Vault | Key Vault Contributor — retrieves secrets or certificates |
| `storage_account` | Azure Storage Account | Storage Blob Data Reader — retrieves certificates |
| `cosmos_db` | Azure Cosmos DB | Cosmos DB Built-in Data Contributor — retrieves secrets |

**`credential_type`** — The type of credential stored in the target resource:

- **`secret`** — Client ID + secret authentication (default).
- **`certificate`** — X.509 certificate-based authentication. Applies to `key_vault` and `storage_account` targets.

Ensure your baseline contains the source compute and target resource (e.g. `virtual_machines: 1` + `key_vaults: 1`), or declare them inline on the path.

### KeyVaultSecretTheft

**Required:** `privilege_escalation: KeyVaultSecretTheft`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`.

Ensure your baseline includes `key_vaults: 1` (or more).

!!! note
    For managed-identity token theft to access Key Vault, use `ManagedIdentityAbuse` with `target_resource_type: key_vault` instead.

### StorageCertificateTheft

**Required:** `privilege_escalation: StorageCertificateTheft`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`.

Ensure your baseline includes `storage_accounts: 1` (or more).

### CosmosDBSecretTheft

**Required:** `privilege_escalation: CosmosDBSecretTheft`, `method`, and the matching `entra_role`/`app_role`.

**Optional:** `initial_access`, `assignment_type`.

Ensure your baseline includes `cosmos_dbs: 1` (or more).

## Authoring an Explicit Graph (chained)

A chained path is built from primitives rather than from a named `privilege_escalation:` technique, which supports custom attack chains that span several steps. A chained path declares an objective, an initial access point, the entities it uses (declared inline), the assignments that form the chain, and any credentials it creates and data_injects it places. `privilege_escalation:` and `assignments:` are mutually exclusive within a path.

```yaml
attack_paths:
  explicit_kv_to_ga:
    objective:
      name: "Global Administrator via Key Vault"
      impact: critical
      capability: entra_role          # what the attacker ultimately gains
      role: "Global Administrator"
    initial_access: { method: compromised_identity, principal_ref: priya }
    identities:
      users:        [{ ref: priya }]
      applications: [{ ref: billing-sync-app }]
    resources:
      # ref doubles as the real Key Vault name -> globally unique, 3-24 chars
      key_vaults:   [{ ref: badzure-ref-kv-01 }]
    assignments:
      - { id: a1, type: azure_rbac, principal_ref: priya,
          role: "Key Vault Contributor", scope_ref: badzure-ref-kv-01 }
      - { id: a2, type: entra_role, principal_ref: billing-sync-app,
          role: "Global Administrator" }
    credentials:
      - { ref: app_secret, app_ref: billing-sync-app, type: password }
    data_injects:
      - { id: d1, material: app_secret, credential_ref: app_secret,
          location: key_vault_secret, location_ref: badzure-ref-kv-01,
          name: client-secret-billing-sync-app }
```

The chain reads: `priya` holds **Key Vault Contributor** on the vault → reads the planted secret → authenticates as `billing-sync-app`, which holds **Global Administrator**. 

### Initial access (chained)

`initial_access` declares where the attacker starts. It takes one of two shapes:

- A compromised identity: `{ method: compromised_identity, principal_ref: <user or app ref> }`. The walk seeds at that identity.
- An exposed-host foothold: `{ vector: exposed_rdp, target_ref: <vm ref> }`. The attacker lands on the VM with code execution; the walk seeds at the host, so any assignment that grants the VM's managed identity access continues the chain. Optional `expose_to_internet` (default `false`) and `credential` (default `known`) tune the exposure exactly as in atomic paths.
- A vulnerable-web-app foothold: `{ vector: vulnerable_web_app, target_ref: <app_service ref> }`. The attacker exploits an internet-facing App Service and lands with code execution in the app's process context; the walk seeds at the app, so any assignment that grants the app's managed identity access continues the chain. Optional `variant` (default `rce`) selects the vulnerability class, and `expose_to_internet` (default `false`) restricts the app to the operator IP or opens it to the internet.

```yaml
    initial_access:
      vector: exposed_rdp
      target_ref: vm_foothold
      expose_to_internet: false   # flip to true to open RDP/SSH to 0.0.0.0/0
      credential: weak            # a brute-forceable local admin password
    resources:
      virtual_machines: [{ ref: vm_foothold, os_type: Windows }]
    assignments:
      # the foothold VM's managed identity can read the vault's secrets
      - { id: a1, type: azure_rbac, principal_ref: vm_foothold,
          principal_type: managed_identity, mi_source_type: vm,
          role: "Key Vault Secrets User", scope_ref: badzure-ref-kv-01 }
```

See `examples/chained/chained_exposed_rdp.yml` for an exposed-host example and `examples/chained/chained_vulnerable_webapp.yml` for a vulnerable-web-app example.

The nine assignment `type`s are `entra_role`, `azure_rbac`, `api_permission`, `group_membership`, `group_ownership`, `app_ownership`, `au_membership` (plus `credentials` and `data_injects` as their own blocks). A chained path can also borrow entities from the baseline with `{ ref: victim, from: baseline }`. See `examples/chained/chained_hybrid.yml` for a worked hybrid example.

A `data_inject` places material into a resource an attacker can read. Its `location_type` selects the resource family: `key_vault_secret` and `key_vault_certificate` (a Key Vault), `storage_blob` (a Storage account container), and `cosmos_document` (a Cosmos DB container). The `material` is `app_secret` (bound to a declared credential via `credential_ref`), `app_client_id` (the client id of an application via `source_ref`), `app_certificate` (a certificate file via `file_path`), or `literal` (arbitrary content via `literal_value`). Key Vault and Storage injects are written by Terraform; `cosmos_document` injects are planted by the data-plane phase that runs after the Terraform apply, using the Cosmos account key to upsert one document per inject. See `examples/chained/chained_cosmos_inject.yml` for a worked Cosmos example.

## Resource Groups

Every Azure resource lives in a resource group. BadZure creates the resource groups and places the resources into them, and you choose how much of that placement is explicit.

In the `baseline:` section resources are declared as counts, so resource groups are a count too. BadZure creates that many groups with generated names and spreads the baseline resources randomly across them. If you declare resources but no groups, it creates one group to hold them.

In a chained path resources are named, so you can name the groups as well. Declare them under `resources.resource_groups` and place a resource in one with its `resource_group` field. A resource that names a group lands in that group and takes its location. A resource that omits the field is spread randomly across the declared groups. Naming a group that was never declared stops the build with an error, and a path that declares resources but no groups falls back to a single default group.

```yaml
# baseline (counts): two groups, resources spread randomly across them
baseline:
  resources: { resource_groups: 2, key_vaults: 2, storage_accounts: 1 }

# chained (named): pin some resources, leave others to random placement
attack_paths:
  kv_to_ga:
    resources:
      resource_groups:
        - { ref: rg-prod, location: "West US" }
        - { ref: rg-corp, location: "East US" }
      key_vaults:
        - { ref: badzure-ref-kv-01, resource_group: rg-prod }   # pinned
        - { ref: badzure-ref-kv-02 }                            # random placement
      storage_accounts:
        - { ref: stbadzure01 }                                  # random placement
```

## Group-Based Assignment

All identity- and resource-based techniques (except ApplicationOwnershipAbuse) support group-based assignment via `assignment_type: group_member` or `group_owner`. With `group_member`, the privilege is assigned to a security group and the initial-access identity is added as a **member**; with `group_owner`, the identity is added as an **owner** of the group instead.

This creates more realistic attack scenarios that mirror enterprise configurations where:

- Permissions are managed through groups rather than individual assignments
- Attack paths require discovering group memberships to understand privilege chains
- Detection requires correlating group membership with resource access

Groups created for attack paths use realistic names from `entity_data/group-names.txt` (e.g., "IT Security", "Cloud Infrastructure", "DevOps") with a random suffix for uniqueness.

### Group Assignment Examples

=== "ApplicationOwnershipAbuse"

    !!! warning
        `ApplicationOwnershipAbuse` only supports `direct` assignment — Azure AD does not allow security groups to own applications, so `group_member`/`group_owner` fall back to `direct`.

=== "ApplicationAdministratorAbuse"

    User inherits Application Administrator through group membership:

    ```yaml
    attack_paths:
      app_admin_group:
        privilege_escalation: ApplicationAdministratorAbuse
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
    ```

=== "CloudAppAdministratorAbuse"

    User inherits Cloud Application Administrator through group membership:

    ```yaml
    attack_paths:
      cloud_admin_group:
        privilege_escalation: CloudAppAdministratorAbuse
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8  # RoleManagement.ReadWrite.Directory
    ```

=== "ManagedIdentityAbuse"

    User inherits VM Contributor through group membership:

    ```yaml
    attack_paths:
      mi_group:
        privilege_escalation: ManagedIdentityAbuse
        source_type: vm
        target_resource_type: key_vault
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
    ```

=== "KeyVaultSecretTheft"

    User inherits Key Vault Contributor through group membership:

    ```yaml
    attack_paths:
      kv_group:
        privilege_escalation: KeyVaultSecretTheft
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: random
    ```

=== "StorageCertificateTheft"

    User inherits Storage Blob Data Reader through group membership:

    ```yaml
    attack_paths:
      storage_group:
        privilege_escalation: StorageCertificateTheft
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
    ```

=== "CosmosDBSecretTheft"

    User inherits Cosmos DB Data Contributor through group membership:

    ```yaml
    attack_paths:
      cosmos_group:
        privilege_escalation: CosmosDBSecretTheft
        initial_access: user
        assignment_type: group_member
        method: APIPermission
        api_type: graph
        app_role: 06b708a9-e830-4db3-a914-8e69da51d44f  # AppRoleAssignment.ReadWrite.All
    ```

## Full Example

A complete configuration: a small baseline (with a little org noise), an atomic technique path per scenario, and one chained explicit path.

```yaml

tenant:
  tenant_id: your-tenant-guid
  domain: contoso.onmicrosoft.com
  subscription_id: your-subscription-guid

baseline:
  identities: { users: 12, applications: 8, groups: 4, administrative_units: 2 }
  resources:  { key_vaults: 2, storage_accounts: 1, virtual_machines: 1, cosmos_dbs: 1 }
  assignments:
    group_memberships: 8
    entra_roles: 3
    azure_rbac: 5
    app_credentials: 3

attack_paths:

  # Identity: user owns an app with Global Admin
  ownership_abuse:
    privilege_escalation: ApplicationOwnershipAbuse
    method: AzureADRole
    entra_role: 62e90394-69f5-4237-9190-012177145e10

  # Identity: SP with App Admin targets Exchange
  admin_abuse:
    privilege_escalation: ApplicationAdministratorAbuse
    initial_access: service_principal
    method: APIPermission
    api_type: exchange
    app_role: dc890d15-9560-4a4c-9b7f-a736ec74ec40

  # Resource: VM -> Key Vault -> privileged app
  vm_to_keyvault:
    privilege_escalation: ManagedIdentityAbuse
    source_type: vm
    target_resource_type: key_vault
    method: APIPermission
    api_type: graph
    app_role: 06b708a9-e830-4db3-a914-8e69da51d44f

  # Resource: Key Vault access via group, random high-priv role
  keyvault_group:
    privilege_escalation: KeyVaultSecretTheft
    assignment_type: group_member
    method: AzureADRole
    entra_role: random

  # chained: explicit graph — user with Key Vault Contributor -> GA app
  explicit_kv_to_ga:
    objective:
      name: "Global Administrator via Key Vault"
      impact: critical
      capability: entra_role
      role: "Global Administrator"
    initial_access: { method: compromised_identity, principal_ref: dana }
    identities:
      users:        [{ ref: dana }]
      applications: [{ ref: reporting-app }]
    resources:
      key_vaults:   [{ ref: badzure-ref-kv-02 }]
    assignments:
      - { id: a1, type: azure_rbac, principal_ref: dana,
          role: "Key Vault Contributor", scope_ref: badzure-ref-kv-02 }
      - { id: a2, type: entra_role, principal_ref: reporting-app,
          role: "Global Administrator" }
    credentials:
      - { ref: app_secret, app_ref: reporting-app, type: password }
    data_injects:
      - { id: d1, material: app_secret, credential_ref: app_secret,
          location: key_vault_secret, location_ref: badzure-ref-kv-02,
          name: client-secret-reporting-app }
```
