# Telemetry wiring (dev-docs/redesign/telemetry-implementation-plan.md, Phase 3).
#
# var.telemetry.diagnostic_targets carries each target as a SYMBOLIC ref
# ("<kind>:<entity_key>") plus a suffix, never a resource ID. A resource ID
# baked into the tfvars would hide the dependency from Terraform: a diagnostic
# setting could be created before its parent resource exists, or on destroy the
# parent could be deleted before its setting (and Azure can silently reattach an
# orphaned setting to a later resource that happens to get the same name). Reading
# the real IDs from the resources themselves (diag_parent_ids below) makes every
# diagnostic setting depend on its parent through Terraform's normal graph.
locals {
  # "kind:key" -> real resource ID, read from the resources themselves so every
  # diagnostic setting depends on its parent.
  diag_parent_ids = merge(
    { for k, v in azurerm_key_vault.kvaults : "key_vault:${k}" => v.id },
    { for k, v in azurerm_storage_account.sas : "storage_account:${k}" => v.id },
    { for k, v in azurerm_storage_account.function_storage : "function_storage:${k}" => v.id },
    { for k, v in azurerm_cosmosdb_account.cosmos_dbs : "cosmos_db:${k}" => v.id },
    { for k, v in azurerm_linux_web_app.app_services : "app_service:${k}" => v.id },
    { for k, v in azurerm_linux_function_app.function_apps : "function_app:${k}" => v.id },
    { for k, v in azurerm_logic_app_workflow.logic_apps : "logic_app:${k}" => v.id },
    { for k, v in azurerm_automation_account.automation_accounts : "automation_account:${k}" => v.id },
    { for k, v in azurerm_network_security_group.vm_nsg : "nsg:${k}" => v.id },
  )
  diag_target_ids = {
    for k, t in var.telemetry.diagnostic_targets :
    k => "${local.diag_parent_ids[t.parent]}${t.suffix}"
  }
}

# Only read for kinds whose log_mode is "discover" (none by default). The keys come
# from the variable, so for_each is known at plan time even though the IDs aren't.
data "azurerm_monitor_diagnostic_categories" "targets" {
  for_each    = { for k, id in local.diag_target_ids : k => id if var.telemetry.diagnostic_targets[k].log_mode == "discover" }
  resource_id = each.value
}

resource "azurerm_monitor_diagnostic_setting" "resources" {
  for_each                       = var.telemetry.diagnostic_targets
  name                           = "badzure-diag"
  target_resource_id             = local.diag_target_ids[each.key]
  log_analytics_workspace_id     = var.telemetry.workspace_id
  log_analytics_destination_type = each.value.destination_type

  # Every log the resource supports: the allLogs group, or for a kind without it,
  # each category Azure reports. Never a hand-written list.
  dynamic "enabled_log" {
    for_each = each.value.log_mode == "allLogs" ? ["allLogs"] : []
    content {
      category_group = enabled_log.value
    }
  }
  dynamic "enabled_log" {
    for_each = each.value.log_mode == "discover" ? data.azurerm_monitor_diagnostic_categories.targets[each.key].log_category_types : []
    content {
      category = enabled_log.value
    }
  }
}
