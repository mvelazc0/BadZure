variable "subscription_id" {
  description = "The subscription the telemetry hub lives in"
  type        = string
}

variable "create_managed_workspace" {
  description = <<-EOT
    Whether to create (or keep) BadZure's own managed Log Analytics workspace
    and its resource group. True whenever this config is managed, and also
    true for a BYO config once a managed workspace already exists (see
    src/telemetry_hub.py's keep_managed_workspace): switching to BYO must not
    make Terraform plan to destroy an earlier managed workspace.
  EOT
  type        = bool
}

variable "workspace_name" {
  description = "Name for the managed Log Analytics workspace (ignored when create_managed_workspace is false)"
  type        = string
}

variable "location" {
  description = <<-EOT
    Azure region for the managed workspace and its resource group. Only applied
    when the workspace is first created: see the ignore_changes rule on
    azurerm_log_analytics_workspace.hub below.
  EOT
  type        = string
}

variable "retention_days" {
  description = "Retention (days) for the managed workspace. Only applied at creation, see ignore_changes."
  type        = number
}

variable "daily_cap_gb" {
  description = <<-EOT
    Daily ingestion cap (GB) for the managed workspace. -1 is the provider's
    value for no cap. Only applied at creation, see ignore_changes.
  EOT
  type        = number
}

variable "destination_workspace_id" {
  description = "Bring-your-own workspace resource ID, or empty to use the managed workspace"
  type        = string
  default     = ""
}

variable "activity_log_enabled" {
  description = "Whether to create BadZure's subscription Activity Log export to the destination workspace"
  type        = bool
}

variable "activity_log_categories" {
  description = "Activity Log category names to export. Fixed by Azure (ACTIVITY_LOG_CATEGORIES); passed in rather than hard-coded here."
  type        = list(string)
}

variable "setting_suffix" {
  description = "Deterministic suffix for this hub's diagnostic setting names (telemetry.setting_suffix(destination_workspace_id))"
  type        = string
}
