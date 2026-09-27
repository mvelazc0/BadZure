output "workspace_id" {
  description = "The destination Log Analytics workspace id (managed or BYO)"
  value       = local.destination
}

output "managed_workspace_id" {
  description = "The managed workspace's id, or empty when this hub run created none"
  value       = var.create_managed_workspace ? azurerm_log_analytics_workspace.hub[0].id : ""
}

output "workspace_name" {
  description = "The managed workspace's name, or empty when this hub run created none"
  value       = var.create_managed_workspace ? azurerm_log_analytics_workspace.hub[0].name : ""
}

output "workspace_location" {
  description = "The managed workspace's live location, or empty when this hub run created none"
  value       = var.create_managed_workspace ? azurerm_log_analytics_workspace.hub[0].location : ""
}

output "workspace_retention_days" {
  description = "The managed workspace's live retention (days), or null when this hub run created none"
  value       = var.create_managed_workspace ? azurerm_log_analytics_workspace.hub[0].retention_in_days : null
}

output "workspace_daily_cap_gb" {
  description = "The managed workspace's live daily cap (GB, -1 = no cap), or null when this hub run created none"
  value       = var.create_managed_workspace ? azurerm_log_analytics_workspace.hub[0].daily_quota_gb : null
}

output "activity_setting_name" {
  description = "The Activity Log export setting's name, or empty when activity_log_enabled is false"
  value       = var.activity_log_enabled ? azurerm_monitor_diagnostic_setting.activity[0].name : ""
}
