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
  default = {}
  type = map(object({
    user_name = string
    group_name = string
  }))
}

variable "user_au_assignments" {
  description = "A map of user-to-administrative unit assignments"
  default = {}
  type = map(object({
    user_name = string
    administrative_unit_name = string
  }))
}

variable "user_role_assignments" {
  description = "A map of user-to-role assignments"
  default = {}
  type = map(object({
    user_name         = string
    role_definition_id = string
  }))
}

variable "app_role_assignments" {
  description = "A map of app-to-role assignments"
  default = {}
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