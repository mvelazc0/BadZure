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
    owner_name           = optional(string, null) # Optional owner for group_owner assignment type
    owner_type           = optional(string, null) # "user" or "service_principal"
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
    name                = string
    location            = string
    resource_group_name = string
    sku_name            = string
  }))
}

variable "storage_accounts" {
  type = map(object({
    name                     = string
    location                 = string
    resource_group_name      = string
    account_tier             = string
    account_replication_type = string
  }))
}

variable "virtual_machines" {
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
    vm_size             = string
    admin_username      = string
    admin_password      = string
    os_type             = string # "Windows" or "Linux"
    # Exposed-host initial-access foothold knob (projected by the builder from an
    # InitialAccessVector). false (default): RDP/SSH open to the operator IP only.
    # true: also add a 0.0.0.0/0 (Internet) allow rule so the host is reachable —
    # and brute-forceable — from the public internet.
    expose_to_internet = optional(bool, false)
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
    os_type             = string # "linux" or "windows"
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

# Cosmos accounts targeted by a cosmos_document data inject — the ONLY accounts
# whose master key the cosmos_db_connections output surfaces to the Python
# data-plane phase. Baseline Cosmos accounts with no inject are omitted, so their
# keys are never read back through `terraform output`.
variable "cosmos_dataplane_refs" {
  description = "Subset of cosmos_dbs keys whose connection info the data-plane phase needs"
  type        = list(string)
  default     = []
}

# VMs that are an exposed-host initial-access foothold — the ONLY VMs whose public
# IP + admin credentials the vm_foothold_access output surfaces to the operator.
# (The public IP is only known after apply, so it must come back through an output.)
variable "foothold_vm_refs" {
  description = "Subset of virtual_machines keys that are an exposed-host foothold"
  type        = list(string)
  default     = []
}