variable "tenant_id" {
  description = "The tenant ID for Azure AD"
  type        = string
}

variable "domain" {
  description = "The domain for Azure AD users"
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
    display_name = string
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

variable "attack_path_1_assignments" {
  description = "A map of application to role and owner assignments for attack path 1"
  type = map(object({
    app_name            = string
    role_id             = string
    user_principal_name = string
    display_name        = string
    password            = string
  }))
}

variable "azure_config_dir" {
  description = "Path to the Azure CLI configuration directory"
  type        = string
}