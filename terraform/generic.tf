# =============================================================================
# generic.tf — Generic, registry-backed deployment primitives (Phase 1)
# =============================================================================
# This file introduces a small set of GENERIC, typed primitives that replace
# the per-technique attack_path_* variables. Each primitive is instantiated as
# two families that share an identical schema but are kept as separate variable
# interfaces:
#
#   random_<primitive>       -> organizational baseline ("the org": noise/decoys)
#   attack_path_<primitive>  -> deliberate edges that support a narrated step
#
# The two families are merged internally into one `for_each` per primitive with
# an `origin` tag, so resource logic is written once. Adding a new attack
# surface (Intune, Purview, K8s) means registering new types here + their
# emission, NOT editing a technique ladder.
#
# Primitives:
#   entra_role_assignment   -> azuread_directory_role_assignment
#   azure_rbac_assignment   -> azurerm_role_assignment (+ cosmos data-plane)
#   api_permission_assignment -> azuread_app_role_assignment
#   app_credential          -> azuread_application_password / _certificate
#   data_inject             -> azurerm_key_vault_secret / _certificate / storage_blob
#   group_membership        -> azuread_group_member
#   au_membership           -> azuread_administrative_unit_member
#   group_ownership         -> azuread_group.owners (set on the group; no standalone resource)
#   app_ownership           -> azuread_application_owner
#
# Phase 1 is ADDITIVE: all variables default to {} and the legacy per-technique
# blocks in main.tf are left untouched. Python is re-pointed onto this layer in
# Phase 2, at which point the legacy variables/blocks are removed.
# =============================================================================

# -----------------------------------------------------------------------------
# Variables — entra_role_assignment
# principal_ref + principal_type -> role_id, optionally scoped to one app.
# Replaces: user_role_assignments, app_role_assignments,
#           attack_path_user_role_assignments, attack_path_application_role_assignments
# -----------------------------------------------------------------------------
variable "random_entra_role_assignments" {
  description = "Baseline (org noise) Entra directory role assignments"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string                    # user | service_principal | group
    role           = string                    # Entra role_definition_id (GUID)
    scope_app_ref  = optional(string, null)    # if set, scope role to this app's object; else directory-wide
  }))
}

variable "attack_path_entra_role_assignments" {
  description = "Attack-path Entra directory role assignments"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string
    role           = string
    scope_app_ref  = optional(string, null)
  }))
}

# -----------------------------------------------------------------------------
# Variables — azure_rbac_assignment
# The universal substrate. principal (incl. managed_identity) -> role @ scope.
# Replaces: attack_path_kv_abuse, storage_abuse, cosmos_abuse, vm_contributor,
#           subscription_reader, and ALL managed-identity RBAC grants.
# -----------------------------------------------------------------------------
variable "random_azure_rbac_assignments" {
  description = "Baseline (org noise) Azure RBAC role assignments"
  default     = {}
  type = map(object({
    principal_ref       = string
    principal_type      = string                  # user | service_principal | group | managed_identity
    mi_source_type      = optional(string, null)  # managed_identity only: vm | logic_app | automation_account | function_app
    role                = string                  # role_definition_name (control plane) OR cosmos sql role GUID (data plane)
    scope_type          = string                  # subscription | resource_group | resource
    scope_ref           = optional(string, null)  # rg name, or resource key; ignored for subscription
    scope_resource_type = optional(string, null)  # key_vault|storage_account|cosmos_db|virtual_machine|logic_app|automation_account|function_app
    data_plane          = optional(string, null)  # null (control plane) | cosmos_sql (Cosmos data-plane role)
  }))
}

variable "attack_path_azure_rbac_assignments" {
  description = "Attack-path Azure RBAC role assignments"
  default     = {}
  type = map(object({
    principal_ref       = string
    principal_type      = string
    mi_source_type      = optional(string, null)
    role                = string
    scope_type          = string
    scope_ref           = optional(string, null)
    scope_resource_type = optional(string, null)
    data_plane          = optional(string, null)
  }))
}

# -----------------------------------------------------------------------------
# Variables — api_permission_assignment
# Grant a Graph/Exchange app role (application permission) to a service principal.
# Replaces: app_api_permission_assignments, attack_path_application_api_permission_assignments
# -----------------------------------------------------------------------------
variable "random_api_permission_assignments" {
  description = "Baseline (org noise) API permission grants"
  default     = {}
  type = map(object({
    principal_ref = string                     # the SP (app) receiving the permission
    permission_id = string                     # app role / permission GUID
    api_type      = optional(string, "graph")  # graph | exchange
  }))
}

variable "attack_path_api_permission_assignments" {
  description = "Attack-path API permission grants"
  default     = {}
  type = map(object({
    principal_ref = string
    permission_id = string
    api_type      = optional(string, "graph")
  }))
}

# -----------------------------------------------------------------------------
# Variables — app_credential
# Mint a REAL credential on an app so the next identity in a chain works.
# Decoupled from data_inject; a data_inject with material=app_secret references
# one of these by credential_ref. Replaces the 6 password + 3 certificate blocks.
# -----------------------------------------------------------------------------
variable "random_app_credentials" {
  description = "Baseline (org noise) application credentials"
  default     = {}
  type = map(object({
    app_ref          = string
    type             = string                            # password | certificate
    certificate_path = optional(string, null)            # required for type=certificate
    display_name     = optional(string, "BadZureCredential")
  }))
}

variable "attack_path_app_credentials" {
  description = "Attack-path application credentials"
  default     = {}
  type = map(object({
    app_ref          = string
    type             = string
    certificate_path = optional(string, null)
    display_name     = optional(string, "BadZureCredential")
  }))
}

# -----------------------------------------------------------------------------
# Variables — data_inject
# Plant material an attacker can reach. The join to app_credential is
# material=app_secret + credential_ref. Locations: key_vault_secret,
# key_vault_certificate (PFX import via file_path), storage_blob.
# -----------------------------------------------------------------------------
variable "random_data_injects" {
  description = "Baseline (org noise) data injects"
  default     = {}
  type = map(object({
    material       = string                    # app_secret | app_certificate | app_client_id | literal
    source_ref     = optional(string, null)    # app_ref for app_client_id / app_certificate materials
    credential_ref = optional(string, null)    # key into *_app_credentials for material=app_secret (origin-prefixed, e.g. "ap:kv_cred")
    literal_value  = optional(string, null)    # for material=literal
    location_type  = string                    # key_vault_secret | key_vault_certificate | storage_blob
    location_ref   = string                    # key_vault ref or storage_account ref
    name           = string                    # secret name, certificate name, or blob name
    file_path      = optional(string, null)    # PFX/PEM/key file for app_certificate (storage_blob) or key_vault_certificate import
    pfx_password   = optional(string, "")      # password protecting the PFX for key_vault_certificate import (default: none)
  }))
}

variable "attack_path_data_injects" {
  description = "Attack-path data injects"
  default     = {}
  type = map(object({
    material       = string
    source_ref     = optional(string, null)
    credential_ref = optional(string, null)
    literal_value  = optional(string, null)
    location_type  = string
    location_ref   = string
    name           = string
    file_path      = optional(string, null)
    pfx_password   = optional(string, "")
  }))
}

# -----------------------------------------------------------------------------
# Variables — group_membership
# Replaces: user_group_assignments, attack_path_group_memberships
# (named *_membership_assignments to stay additive alongside legacy vars).
# -----------------------------------------------------------------------------
variable "random_group_membership_assignments" {
  description = "Baseline (org noise) group memberships"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string   # user | service_principal | group
    group_ref      = string
  }))
}

variable "attack_path_group_membership_assignments" {
  description = "Attack-path group memberships"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string
    group_ref      = string
  }))
}

# -----------------------------------------------------------------------------
# Variables — au_membership
# Place a principal into an administrative unit (org-structure scoping).
# Replaces: user_au_assignments. AU members may be users or groups.
# -----------------------------------------------------------------------------
variable "random_au_membership_assignments" {
  description = "Baseline (org noise) administrative unit memberships"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string   # user | group
    au_ref         = string
  }))
}

variable "attack_path_au_membership_assignments" {
  description = "Attack-path administrative unit memberships"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string
    au_ref         = string
  }))
}

# -----------------------------------------------------------------------------
# Variables — group_ownership
# Make a principal an OWNER of a group (an attack edge: owning a role-assignable
# group lets a principal add itself as member and inherit the group's roles).
# The azuread provider has NO standalone group-owner resource, so these feed
# azuread_group.owners in main.tf — the one primitive whose wiring reaches into
# main.tf. Kept separate from the `groups` entity var so attack-path ownership is
# distinguishable from org-baseline ownership (provenance preserved upstream;
# the owners set merges them only at the final API call).
# -----------------------------------------------------------------------------
variable "random_group_ownership_assignments" {
  description = "Baseline (org noise) group ownership"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string   # user | service_principal
    group_ref      = string
  }))
}

variable "attack_path_group_ownership_assignments" {
  description = "Attack-path group ownership"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string
    group_ref      = string
  }))
}

# -----------------------------------------------------------------------------
# Variables — app_ownership
# Replaces: attack_path_application_owner_assignments (users/SPs only; AAD does
# not allow groups as app owners).
# -----------------------------------------------------------------------------
variable "random_app_ownership_assignments" {
  description = "Baseline (org noise) application ownership"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string   # user | service_principal
    app_ref        = string
  }))
}

variable "attack_path_app_ownership_assignments" {
  description = "Attack-path application ownership"
  default     = {}
  type = map(object({
    principal_ref  = string
    principal_type = string
    app_ref        = string
  }))
}

# =============================================================================
# Locals — merge the two families per primitive with an `origin` tag.
# Keys are origin-prefixed ("random:" / "ap:") to guarantee global uniqueness.
# =============================================================================
locals {
  g_entra_role = merge(
    { for k, v in var.random_entra_role_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_entra_role_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_azure_rbac = merge(
    { for k, v in var.random_azure_rbac_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_azure_rbac_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_api_permission = merge(
    { for k, v in var.random_api_permission_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_api_permission_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_app_credentials = merge(
    { for k, v in var.random_app_credentials : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_app_credentials : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_data_injects = merge(
    { for k, v in var.random_data_injects : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_data_injects : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_group_membership = merge(
    { for k, v in var.random_group_membership_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_group_membership_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_app_ownership = merge(
    { for k, v in var.random_app_ownership_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_app_ownership_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_au_membership = merge(
    { for k, v in var.random_au_membership_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_au_membership_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  g_group_ownership = merge(
    { for k, v in var.random_group_ownership_assignments : "random:${k}" => merge(v, { origin = "random" }) },
    { for k, v in var.attack_path_group_ownership_assignments : "ap:${k}" => merge(v, { origin = "attack_path" }) },
  )

  # Owner object_ids grouped by the group they own. Consumed by azuread_group.owners
  # in main.tf (no standalone group-owner resource exists). Every group key gets an
  # entry (possibly empty), so indexing by group key is always safe.
  g_group_owner_ids_by_group = {
    for grp in keys(var.groups) : grp => [
      for k, v in local.g_group_ownership :
      (v.principal_type == "user" ?
        azuread_user.users[v.principal_ref].object_id :
        azuread_service_principal.spns[v.principal_ref].object_id)
      if v.group_ref == grp
    ]
  }

  # ---- Shared principal selector for Azure RBAC (incl. managed identity) ----
  g_azure_rbac_principal_id = {
    for k, v in local.g_azure_rbac : k => (
      v.principal_type == "user" ? azuread_user.users[v.principal_ref].object_id :
      v.principal_type == "group" ? azuread_group.groups[v.principal_ref].object_id :
      v.principal_type == "service_principal" ? azuread_service_principal.spns[v.principal_ref].object_id :
      # managed_identity: resolve the source compute resource's system-assigned identity
      v.mi_source_type == "vm" ? (
        contains(keys(azurerm_linux_virtual_machine.linux_vms), v.principal_ref) ?
        azurerm_linux_virtual_machine.linux_vms[v.principal_ref].identity[0].principal_id :
        azurerm_windows_virtual_machine.windows_vms[v.principal_ref].identity[0].principal_id
      ) :
      v.mi_source_type == "logic_app" ? azurerm_logic_app_workflow.logic_apps[v.principal_ref].identity[0].principal_id :
      v.mi_source_type == "automation_account" ? azurerm_automation_account.automation_accounts[v.principal_ref].identity[0].principal_id :
      v.mi_source_type == "function_app" ? azurerm_function_app_flex_consumption.function_apps[v.principal_ref].identity[0].principal_id :
      null
    )
  }

  # ---- Shared scope resolver for Azure RBAC ----
  g_azure_rbac_scope = {
    for k, v in local.g_azure_rbac : k => (
      v.scope_type == "subscription" ? "/subscriptions/${var.subscription_id}" :
      v.scope_type == "resource_group" ? azurerm_resource_group.rgroups[v.scope_ref].id :
      # scope_type == "resource"
      v.scope_resource_type == "key_vault" ? azurerm_key_vault.kvaults[v.scope_ref].id :
      v.scope_resource_type == "storage_account" ? azurerm_storage_account.sas[v.scope_ref].id :
      v.scope_resource_type == "cosmos_db" ? azurerm_cosmosdb_account.cosmos_dbs[v.scope_ref].id :
      v.scope_resource_type == "logic_app" ? azurerm_logic_app_workflow.logic_apps[v.scope_ref].id :
      v.scope_resource_type == "automation_account" ? azurerm_automation_account.automation_accounts[v.scope_ref].id :
      v.scope_resource_type == "function_app" ? azurerm_function_app_flex_consumption.function_apps[v.scope_ref].id :
      v.scope_resource_type == "virtual_machine" ? (
        contains(keys(azurerm_linux_virtual_machine.linux_vms), v.scope_ref) ?
        azurerm_linux_virtual_machine.linux_vms[v.scope_ref].id :
        azurerm_windows_virtual_machine.windows_vms[v.scope_ref].id
      ) :
      null
    )
  }

  # ---- Resolved value for each data_inject (secret/literal/client_id) ----
  # app_certificate is materialized via file upload (source = file_path), not a value.
  g_inject_value = {
    for k, v in local.g_data_injects : k => (
      v.material == "literal" ? v.literal_value :
      v.material == "app_client_id" ? azuread_application_registration.spns[v.source_ref].client_id :
      v.material == "app_secret" ? azuread_application_password.generic_app_password[v.credential_ref].value :
      null
    )
  }
}

# =============================================================================
# Resources — generic emitters (one per primitive)
# =============================================================================

# ---- entra_role_assignment ----
resource "azuread_directory_role_assignment" "generic_entra_role" {
  for_each = local.g_entra_role

  principal_object_id = (
    each.value.principal_type == "user" ? azuread_user.users[each.value.principal_ref].object_id :
    each.value.principal_type == "group" ? azuread_group.groups[each.value.principal_ref].object_id :
    azuread_service_principal.spns[each.value.principal_ref].object_id
  )
  role_id = each.value.role
  directory_scope_id = (
    each.value.scope_app_ref != null ?
    "/${azuread_application_registration.spns[each.value.scope_app_ref].object_id}" :
    "/"
  )

  depends_on = [
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups,
    azuread_application_registration.spns,
  ]
}

# ---- azure_rbac_assignment (control plane) ----
resource "azurerm_role_assignment" "generic_azure_rbac" {
  for_each = { for k, v in local.g_azure_rbac : k => v if v.data_plane == null }

  scope                = local.g_azure_rbac_scope[each.key]
  role_definition_name = each.value.role
  principal_id         = local.g_azure_rbac_principal_id[each.key]

  depends_on = [
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups,
    azurerm_key_vault.kvaults,
    azurerm_storage_account.sas,
    azurerm_cosmosdb_account.cosmos_dbs,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps,
    azurerm_resource_group.rgroups,
  ]
}

# ---- azure_rbac_assignment (Cosmos DB SQL data-plane variant) ----
resource "azurerm_cosmosdb_sql_role_assignment" "generic_cosmos_rbac" {
  for_each = { for k, v in local.g_azure_rbac : k => v if v.data_plane == "cosmos_sql" }

  resource_group_name = azurerm_cosmosdb_account.cosmos_dbs[each.value.scope_ref].resource_group_name
  account_name        = azurerm_cosmosdb_account.cosmos_dbs[each.value.scope_ref].name
  role_definition_id  = "${azurerm_cosmosdb_account.cosmos_dbs[each.value.scope_ref].id}/sqlRoleDefinitions/${each.value.role}"
  scope               = azurerm_cosmosdb_account.cosmos_dbs[each.value.scope_ref].id
  principal_id        = local.g_azure_rbac_principal_id[each.key]

  depends_on = [
    azurerm_cosmosdb_account.cosmos_dbs,
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps,
  ]
}

# ---- api_permission_assignment ----
resource "azuread_app_role_assignment" "generic_api_permission" {
  for_each = local.g_api_permission

  app_role_id         = each.value.permission_id
  principal_object_id = azuread_service_principal.spns[each.value.principal_ref].object_id
  resource_object_id = (
    each.value.api_type == "exchange" ?
    data.azuread_service_principal.exchange_online.object_id :
    data.azuread_service_principal.microsoft_graph.object_id
  )

  depends_on = [azuread_service_principal.spns]
}

# ---- app_credential (password) ----
resource "azuread_application_password" "generic_app_password" {
  for_each = { for k, v in local.g_app_credentials : k => v if v.type == "password" }

  application_id    = azuread_application_registration.spns[each.value.app_ref].id
  display_name      = each.value.display_name
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]
}

# ---- app_credential (certificate) ----
resource "azuread_application_certificate" "generic_app_certificate" {
  for_each = { for k, v in local.g_app_credentials : k => v if v.type == "certificate" }

  application_id = azuread_application_registration.spns[each.value.app_ref].id
  type           = "AsymmetricX509Cert"
  value          = file(each.value.certificate_path)
  # end_date is extracted from the certificate itself.

  depends_on = [azuread_application_registration.spns]
}

# ---- data_inject (Key Vault secret) ----
resource "azurerm_key_vault_secret" "generic_inject_kv_secret" {
  for_each = { for k, v in local.g_data_injects : k => v if v.location_type == "key_vault_secret" }

  name         = each.value.name
  value        = local.g_inject_value[each.key]
  key_vault_id = azurerm_key_vault.kvaults[each.value.location_ref].id

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_password.generic_app_password,
    azurerm_role_assignment.terraform_kv_access,
  ]
}

# ---- data_inject (Key Vault certificate) ----
# Grant the Terraform-deploying identity certificate-import rights on every vault
# targeted by a key_vault_certificate inject (main.tf only grants Secrets Officer).
resource "azurerm_role_assignment" "generic_terraform_kv_certs_access" {
  for_each = toset([
    for k, v in local.g_data_injects : v.location_ref
    if v.location_type == "key_vault_certificate"
  ])

  scope                = azurerm_key_vault.kvaults[each.value].id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azurerm_client_config.current.object_id

  depends_on = [azurerm_key_vault.kvaults]
}

# Import a PFX into the vault's certificate store (file material, read from file_path).
resource "azurerm_key_vault_certificate" "generic_inject_kv_certificate" {
  for_each = { for k, v in local.g_data_injects : k => v if v.location_type == "key_vault_certificate" }

  name         = each.value.name
  key_vault_id = azurerm_key_vault.kvaults[each.value.location_ref].id

  certificate {
    contents = filebase64(each.value.file_path)
    password = each.value.pfx_password
  }

  depends_on = [
    azurerm_key_vault.kvaults,
    azurerm_role_assignment.generic_terraform_kv_certs_access,
    azurerm_role_assignment.terraform_kv_access,
  ]
}

# ---- data_inject (storage blob) — one private container per inject ----
resource "azurerm_storage_container" "generic_inject_container" {
  for_each = { for k, v in local.g_data_injects : k => v if v.location_type == "storage_blob" }

  # Container names: 3-63 chars, lowercase alphanumerics + single hyphens, no
  # leading/trailing hyphen. Build a readable prefix from the inject key (collapse
  # any invalid run to one hyphen, truncate, trim stray hyphens) then append a short
  # hash of the key so two injects whose prefixes truncate to the same value still
  # get distinct, valid names. (The meaningful name is on the blob inside.)
  name = format("inject-%s-%s",
    trim(substr(replace(lower(replace(replace(each.key, ":", "-"), "_", "-")), "/[^a-z0-9]+/", "-"), 0, 40), "-"),
    substr(sha1(each.key), 0, 8))
  storage_account_id    = azurerm_storage_account.sas[each.value.location_ref].id
  container_access_type = "private"

  depends_on = [azurerm_storage_account.sas]
}

resource "azurerm_storage_blob" "generic_inject_blob" {
  for_each = { for k, v in local.g_data_injects : k => v if v.location_type == "storage_blob" }

  name                   = each.value.name
  storage_account_name   = azurerm_storage_account.sas[each.value.location_ref].name
  storage_container_name = azurerm_storage_container.generic_inject_container[each.key].name
  type                   = "Block"
  # File material (certificate/key/pfx) uploads from file_path; everything else
  # writes its resolved value as blob content.
  source         = each.value.material == "app_certificate" ? each.value.file_path : null
  source_content = each.value.material == "app_certificate" ? null : local.g_inject_value[each.key]

  depends_on = [
    azurerm_storage_container.generic_inject_container,
    azuread_application_password.generic_app_password,
    time_sleep.wait_for_rbac,
  ]
}

# ---- group_membership ----
resource "azuread_group_member" "generic_group_membership" {
  for_each = local.g_group_membership

  group_object_id = azuread_group.groups[each.value.group_ref].object_id
  member_object_id = (
    each.value.principal_type == "user" ? azuread_user.users[each.value.principal_ref].object_id :
    each.value.principal_type == "group" ? azuread_group.groups[each.value.principal_ref].object_id :
    azuread_service_principal.spns[each.value.principal_ref].object_id
  )

  depends_on = [
    azuread_group.groups,
    azuread_user.users,
    azuread_service_principal.spns,
  ]
}

# ---- au_membership ----
resource "azuread_administrative_unit_member" "generic_au_membership" {
  for_each = local.g_au_membership

  administrative_unit_object_id = azuread_administrative_unit.aunits[each.value.au_ref].object_id
  member_object_id = (
    each.value.principal_type == "user" ?
    azuread_user.users[each.value.principal_ref].object_id :
    azuread_group.groups[each.value.principal_ref].object_id
  )

  depends_on = [
    azuread_administrative_unit.aunits,
    azuread_user.users,
    azuread_group.groups,
  ]
}

# ---- app_ownership ----
resource "azuread_application_owner" "generic_app_ownership" {
  for_each = local.g_app_ownership

  application_id = "/applications/${azuread_application_registration.spns[each.value.app_ref].object_id}"
  owner_object_id = (
    each.value.principal_type == "user" ?
    azuread_user.users[each.value.principal_ref].object_id :
    azuread_service_principal.spns[each.value.principal_ref].object_id
  )

  depends_on = [
    azuread_application_registration.spns,
    azuread_user.users,
    azuread_service_principal.spns,
  ]
}
