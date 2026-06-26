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
    # Whether to allocate a public IP for this VM. false (default): baseline VMs
    # are private (no public IP — saves cost and reduces attack surface). The
    # builder sets this true only for exposed-host foothold VMs (the ones whose
    # public IP + creds the operator needs to log in via RDP/SSH).
    assign_public_ip = optional(bool, false)
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

variable "app_services" {
  description = "A map of App Services (Linux web apps) to create"
  type = map(object({
    name                = string
    location            = string
    resource_group_name = string
    os_type             = string # "linux" (App Services are always Linux web apps here)
  }))
  default = {}
}

variable "app_service_sku" {
  description = <<-EOT
    SKU (App Service plan tier) for App Services. Default B1 (Basic).
    NOTE: every App Service plan tier counts against the subscription's per-region
    App Service quota, and the quota profile varies by BOTH subscription and region.
    Some SKUs are capped at 0 in some regions (e.g. West US on many subs) yet
    ungoverned/available in others (e.g. West US 2) — so App Services deploy to
    var.app_service_location (default West US 2), where Basic/Free are available. If
    apply fails 401 "Total VMs: Current Limit 0", either move app_service_location to
    a region where this SKU has quota, or override app_service_sku to a SKU that does.
    Override to "F1" for free hosting where available. Validate available SKUs with:
      az rest --method get --url "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Web/locations/<region>/providers/Microsoft.Quota/quotas?api-version=2023-02-01"
  EOT
  type        = string
  default     = "B1"
}

variable "app_service_location" {
  description = <<-EOT
    Azure region for App Service plans + web apps, independent of the rest of the
    lab's region. App Service quota is per-region and Free (F1) is blocked in some
    regions but free in others, so App Services default to West US 2 (where F1 is
    free on common subscriptions) even though other lab resources use West US.
  EOT
  type        = string
  default     = "West US 2"
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