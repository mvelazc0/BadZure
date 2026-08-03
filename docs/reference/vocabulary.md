# Vocabulary

The names and tokens a config may reference. These are the single source of truth in the code; the lists here are generated from it, so they cannot drift.

## Techniques

The seven atomic privilege-escalation techniques.

<!-- BADZURE:GEN techniques -->
`ApplicationOwnershipAbuse`, `ApplicationAdministratorAbuse`, `CloudAppAdministratorAbuse`, `ManagedIdentityAbuse`, `KeyVaultSecretTheft`, `StorageCertificateTheft`, `CosmosDBSecretTheft`
<!-- /BADZURE:GEN techniques -->

See the [technique catalog](../attack-paths/techniques/index.md).

## Initial-access vectors

How an attacker first lands.

<!-- BADZURE:GEN initial-access-vectors -->
`compromised_credential`, `exposed_rdp`, `exposed_ssh`, `vulnerable_web_app`
<!-- /BADZURE:GEN initial-access-vectors -->

`compromised_credential` takes a `principal_type` of `user` or `service_principal`. See [Initial Access](../attack-paths/initial-access.md).

## Assignment types

The primitives a chained path and an org design wire.

<!-- BADZURE:GEN assignment-types -->
`entra_role`, `azure_rbac`, `api_permission`, `group_membership`, `group_ownership`, `app_ownership`, `au_membership`
<!-- /BADZURE:GEN assignment-types -->

See [Chained Reference](chained.md).

## Resource kinds

The Azure resource types a baseline or path can declare.

<!-- BADZURE:GEN resource-kinds -->
`resource_groups`, `key_vaults`, `storage_accounts`, `virtual_machines`, `logic_apps`, `automation_accounts`, `function_apps`, `app_services`, `cosmos_dbs`
<!-- /BADZURE:GEN resource-kinds -->

## Azure RBAC roles

Common built-in roles a config may reference by name (Azure validates the full set at apply time).

<!-- BADZURE:GEN azure-rbac-roles -->
Owner, Contributor, Reader, Storage Blob Data Owner, Storage Blob Data Contributor, Storage Blob Data Reader, Storage Account Contributor, Storage Queue Data Contributor, Key Vault Administrator, Key Vault Secrets User, Key Vault Secrets Officer, Key Vault Reader, Key Vault Certificates Officer, Virtual Machine Contributor, Virtual Machine Administrator Login, Website Contributor, Web Plan Contributor, Cosmos DB Account Reader Role, DocumentDB Account Contributor, Network Contributor, Monitoring Reader, Monitoring Contributor, User Access Administrator
<!-- /BADZURE:GEN azure-rbac-roles -->

## Graph permissions

Common Graph app roles a service principal may hold.

<!-- BADZURE:GEN graph-permissions -->
User.Read.All, User.ReadWrite.All, Group.Read.All, GroupMember.Read.All, Directory.Read.All, Application.Read.All, Mail.Read, Mail.Send, Files.Read.All, Sites.Read.All, Calendars.Read, People.Read.All, AuditLog.Read.All, Reports.Read.All
<!-- /BADZURE:GEN graph-permissions -->

The full Entra role and permission catalogs are large; `baseline-spec` prints the exact low-privilege Entra role and Graph permission names an org design may use.
