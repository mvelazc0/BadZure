# Atomic Reference

An atomic path names one `privilege_escalation` technique plus an `initial_access` and an `objective`. BadZure picks the victim and target from the baseline and builds the chain. This page documents every option. For the chained form, see [Chained Reference](chained.md).

Set `enabled: false` to keep a path in the file without deploying it.

## initial_access

How the attacker first gains a foothold. The `vector` selects the entry method.

| Key | Values | Default | Description |
|---|---|---|---|
| `vector` | `compromised_credential`, `exposed_rdp`, `exposed_ssh`, `vulnerable_web_app` | `compromised_credential` | How the attacker lands |
| `principal_type` | `user`, `service_principal` | `user` | Required for `compromised_credential`: the identity type |
| `expose_to_internet` | `true`, `false` | `false` | Foothold vectors: `false` restricts to the operator IP, `true` opens to the public internet |
| `credential` | `known`, `weak` | `known` | Exposed-host (VM) footholds: `weak` sets a brute-forceable local admin password |
| `variant` | `rce` | `rce` | Vulnerable-web-app foothold: the vulnerability class deployed |

The resource-foothold vectors (`exposed_rdp`, `exposed_ssh`, `vulnerable_web_app`) apply to ManagedIdentityAbuse only: they land on a compute host and continue through its managed identity. `exposed_rdp`/`exposed_ssh` require `source_type: vm`; `vulnerable_web_app` requires `source_type: app_service`. See [Initial Access](../attack-paths/initial-access.md).

## privilege_escalation

| Key | Values | Description |
|---|---|---|
| `technique` | one of the seven techniques | The technique to build |
| `assignment_type` | `direct`, `group_member`, `group_owner` | How the escalation privilege is held |
| per technique | `scope`, `source_type`, `privilege_source`, `target_resource_type`, `credential_type` | See [Per-technique options](#per-technique-options) |

**assignment_type**: how the escalation privilege is held:

- `direct`: assigned directly to the identity (default).
- `group_member`: assigned to a security group; the identity is added as a member and inherits it.
- `group_owner`: the identity is added as an owner of a group that holds the privilege.

All techniques except ApplicationOwnershipAbuse support group-based assignment. Entra ID does not allow groups to own applications, so for ApplicationOwnershipAbuse the group options fall back to `direct`.

## objective

The access the terminal principal holds. Provide one or more typed keys; the principal holds all of them.

=== "Entra role"

    ```yaml
    objective:
      entra_role: 62e90394-69f5-4237-9190-012177145e10  # Global Administrator
      # or a list of GUIDs
    ```

=== "API permission"

    ```yaml
    objective:
      api_permission:
        graph: 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8     # RoleManagement.ReadWrite.Directory
        # exchange: dc890d15-9560-4a4c-9b7f-a736ec74ec40 # full_access_as_app
    ```

=== "Azure role"

    ```yaml
    objective:
      azure_role:
        - role: Owner            # role name or GUID
          scope: subscription    # or resource_group / resource (with scope_ref)
    ```

## Per-technique options

Each technique adds its own knobs under `privilege_escalation`.

### ApplicationOwnershipAbuse

**Required:** `technique` and an `objective`. **Optional:** `initial_access.principal_type`. Supports only `direct` assignment.

### ApplicationAdministratorAbuse

**Required:** `technique` and an `objective`. **Optional:** `initial_access`, `assignment_type`, `scope`.

**scope**: `directory` (the role applies to all applications, the default) or `application` (scoped to the target application via Entra ID's `directory_scope_id`, a more least-privilege posture).

### CloudAppAdministratorAbuse

Identical in configuration to ApplicationAdministratorAbuse, using the Cloud Application Administrator role (`158c047a-c907-4556-b7ef-446551a6b5f7`).

### ManagedIdentityAbuse

**Required:** `technique`, `source_type`, and an `objective`. The `stored_credential` flavor also requires `target_resource_type`. **Optional:** `initial_access`, `assignment_type`, `privilege_source`, `credential_type`.

**privilege_source**: the flavor:

- `stored_credential`: the managed identity reads an application credential from `target_resource_type`; the objective is the looted application's role or permission (default).
- `managed_identity`: the managed identity is itself over-privileged; there is no target resource and the objective is an `azure_role` on it.

**source_type**: the compute resource with the managed identity:

| Value | Resource | Required control role |
|---|---|---|
| `vm` | Virtual Machine | VM Contributor |
| `logic_app` | Logic App | Logic App Contributor |
| `automation_account` | Automation Account | Automation Contributor |
| `function_app` | Function App (Linux/Python) | Website Contributor |
| `app_service` | App Service (Linux/Python) | Website Contributor |

**target_resource_type**: the resource storing the credential:

| Value | Resource | Managed-identity access |
|---|---|---|
| `key_vault` | Key Vault | Key Vault Contributor: secrets or certificates |
| `storage_account` | Storage Account | Storage Blob Data Reader: certificates |
| `cosmos_db` | Cosmos DB | Cosmos DB Built-in Data Contributor: secrets |

**credential_type**: `secret` (client ID + secret, default) or `certificate` (X.509; Key Vault and Storage targets).

Ensure the baseline contains the source compute and target resource, or declare them on the path.

### KeyVaultSecretTheft

**Required:** `technique` and an `objective`. **Optional:** `initial_access`, `assignment_type`. Needs `key_vaults: 1` or more in the baseline. For managed-identity token theft against a vault, use ManagedIdentityAbuse with `target_resource_type: key_vault`.

### StorageCertificateTheft

**Required:** `technique` and an `objective`. **Optional:** `initial_access`, `assignment_type`. Needs `storage_accounts: 1` or more.

### CosmosDBSecretTheft

**Required:** `technique` and an `objective`. **Optional:** `initial_access`, `assignment_type`. Needs `cosmos_dbs: 1` or more; the secret document is planted in a post-apply data-plane step.
