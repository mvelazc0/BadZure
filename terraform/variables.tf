variable "azure_config_dir" {
  description = "Path to the Azure CLI configuration directory"
  type        = string
}

variable "tenant_id" {
  description = "The tenant ID for Azure AD"
  type        = string
}

variable "domain" {
  description = "The domain for Azure AD users"
  type        = string
}

variable "public_ip" {
  description = "The public IP address of the machine running the tool"
  type        = string
}

variable "users" {
  type = map(object({
    user_principal_name = string
    display_name        = string
    mail_nickname       = string
    password            = string
  }))
}

variable "groups" {
  description = "A map of groups to create"
  type = map(object({
    display_name         = string
    is_attack_path_group = optional(bool, false)  # If true, group will be role-assignable for Entra ID roles
    owner_name           = optional(string, null)  # Optional owner for group_owner assignment type
    owner_type           = optional(string, null)  # "user" or "service_principal"
  }))
}

variable "applications" {
  description = "A map of applications to create"
  type = map(object({
    display_name = string
  }))
}

variable "administrative_units" {
  description = "A map of administrative units to create"
  type = map(object({
    display_name = string
  }))
}

variable "user_group_assignments" {
  description = "A map of user-to-group assignments"
  type = map(object({
    user_name = string
    group_name = string
  }))
}

variable "user_au_assignments" {
  description = "A map of user-to-administrative unit assignments"
  type = map(object({
    user_name = string
    administrative_unit_name = string
  }))
}

variable "user_role_assignments" {
  description = "A map of user-to-role assignments"
  type = map(object({
    user_name         = string
    role_definition_id = string
  }))
}

variable "app_role_assignments" {
  description = "A map of app-to-role assignments"
  type = map(object({
    app_name = string
    role_id  = string
  }))
}

variable "app_api_permission_assignments" {
  description = "A map of application to API permission assingments"
  default = {}
  type = map(object({
    app_name            = string
    api_permission_id   = string
  }))
}

variable "attack_path_user_role_assignments" {
  description = "A map of principal role assignments in an attack path (supports both users and service principals)"
  type = map(object({
    identity_type      = optional(string, "user")  # "user" or "service_principal"
    principal_name     = string  # user name or service principal name
    role_definition_id = string
    entry_point        = optional(string, "compromised_identity")
    scope_app_name     = optional(string, null)  # Application name to scope the role to (null = directory-wide)
  }))
}

variable "attack_path_application_role_assignments" {
  description = "A map of application role assignments used in an attack path"
  default = {}
  type = map(object({
    app_name = string
    role_ids = list(string)
  }))
}

variable "attack_path_application_api_permission_assignments" {
  description = "A map of application to API permission assingments in an attack path"
  default = {}
  type = map(object({
    app_name            = string
    api_permission_ids  = list(string)
    api_type            = optional(string, "graph")  # Optional field, defaults to "graph" for backward compatibility
  }))
}

variable "attack_path_application_owner_assignments" {
  description = "A map of application owner assignments used in an attack path (supports both users and service principals)"
  default = {}
  type = map(object({
    app_name       = string
    identity_type  = optional(string, "user")  # "user" or "service_principal"
    principal_name = string  # user name or service principal name
    entry_point    = optional(string, "compromised_identity")
  }))
}

variable "subscription_id" {
  description = "The subscription ID to use"
  type        = string
}

variable "resource_groups" {
  type = map(object({
    name     = string
    location = string
  }))
}


variable "key_vaults" {
  type = map(object({
    name     = string
    location = string
    resource_group_name = string
    sku_name = string
  }))
}

variable "storage_accounts" {
  type = map(object({
    name                  = string
    location              = string
    resource_group_name   = string
    account_tier          = string
    account_replication_type = string
  }))
}

variable "virtual_machines" {
  type = map(object({
    name                  = string
    location              = string
    resource_group_name   = string
    vm_size               = string
    admin_username        = string
    admin_password        = string
    os_type               = string # "Windows" or "Linux"
  }))
}

variable "logic_apps" {
  description = "A map of Logic Apps to create"
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
  }))
  default = {}
}

variable "automation_accounts" {
  description = "A map of Automation Accounts to create"
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
  }))
  default = {}
}

variable "function_apps" {
  description = "A map of Function Apps to create"
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
    os_type             = string  # "linux" or "windows"
  }))
  default = {}
}

variable "cosmos_dbs" {
  description = "A map of Cosmos DB accounts to create"
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
    offer_type          = string
    kind                = string
    database_name       = string
    container_name      = string
    partition_key_path  = string
  }))
  default = {}
}

variable "attack_path_kv_abuse_assignments" {
  type = map(object({
    key_vault              = string
    identity_type          = string  # Options: "user", "service_principal"
    principal_name         = string  # Name of the principal
    app_name               = string  # The application to which a secret will be added
    assignment_type        = optional(string, "direct")  # "direct", "group_member", or "group_owner"
    group_name             = optional(string, "")  # Group name for indirect assignment
    original_principal     = optional(string, "")  # Original principal for group assignment
    original_identity_type = optional(string, "")  # Original identity type for group assignment
  }))
}

variable "attack_path_storage_abuse_assignments" {
  type = map(object({
    app_name               = string
    certificate_path       = string
    private_key_path       = string
    storage_account        = string
    identity_type          = string  # Options: "user", "service_principal"
    principal_name         = string  # Name of the principal
    assignment_type        = optional(string, "direct")  # "direct", "group_member", or "group_owner"
    group_name             = optional(string, "")  # Group name for indirect assignment
    original_principal     = optional(string, "")  # Original principal for group assignment
    original_identity_type = optional(string, "")  # Original identity type for group assignment
    pfx_path               = optional(string, "")  # PFX file path for convenient authentication
  }))
}

variable "attack_path_cosmos_abuse_assignments" {
  description = "A map of Cosmos DB abuse assignments for CosmosDBSecretTheft attack paths"
  default = {}
  type = map(object({
    cosmos_db               = string  # Key into cosmos_dbs map
    identity_type           = string  # Options: "user", "service_principal"
    principal_name          = string  # Name of the principal
    app_name                = string  # The application to which a secret will be added
    assignment_type         = optional(string, "direct")  # "direct", "group_member", or "group_owner"
    group_name              = optional(string, "")  # Group name for indirect assignment
    original_principal      = optional(string, "")  # Original principal for group assignment
    original_identity_type  = optional(string, "")  # Original identity type for group assignment
  }))
}

variable "attack_path_managed_identity_theft_assignments" {
  description = "A map of managed identity theft assignments for attack paths"
  default = {}
  type = map(object({
    source_type              = string  # "vm", "logic_app", "automation_account", "function_app"
    source_name              = string  # Name of the source resource (VM name, etc.)
    target_resource_type     = string  # "key_vault" or "storage_account"
    target_name              = string  # Name of the target resource
    app_name                 = string  # The application to which credentials will be added
    entry_point              = string  # "compromised_identity" (future: "vulnerability")
    identity_type            = string  # "user" or "service_principal"
    initial_access_principal = string  # Name of user or service principal with access to source
    managed_identity_name    = string  # Name of the managed identity
    certificate_path         = optional(string, "")  # Required for storage_account targets or key_vault with certificate
    private_key_path         = optional(string, "")  # Required for storage_account targets or key_vault with certificate
    pfx_path                 = optional(string, "")  # PFX file path for convenient authentication
    credential_type          = optional(string, "secret")  # "secret" or "certificate" (only for key_vault targets)
    os_type                  = optional(string, "linux")  # OS type for function_app source type
    assignment_type          = optional(string, "direct")  # "direct", "group_member", or "group_owner" for indirect assignment
    group_name               = optional(string, "")  # Group name for indirect assignment
    original_principal       = optional(string, "")  # Original principal for group assignment
    original_identity_type   = optional(string, "")  # Original identity type for group assignment
  }))
}

variable "attack_path_vm_contributor_assignments" {
  description = "A map of user to VM Contributor role assignments for attack paths with managed identities"
  default = {}
  type = map(object({
    user_name        = string
    virtual_machine  = string
  }))
}

variable "attack_path_group_memberships" {
  description = "A map of group memberships for attack path groups (indirect assignment)"
  default = {}
  type = map(object({
    group_name     = string  # Name of the attack path group
    identity_type  = string  # "user" or "service_principal"
    principal_name = string  # Name of the user or service principal to add to the group
  }))
}

variable "attack_path_compromised_sp_credentials" {
  description = "Service principal credentials for compromised identity SPs in attack paths"
  default     = {}
  type = map(object({
    app_name = string
  }))
}
