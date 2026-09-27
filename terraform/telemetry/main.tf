# The telemetry hub (dev-docs/redesign/telemetry-implementation-plan.md, Phase 4):
# a persistent Terraform root, separate from the lab root (terraform/), holding
# whatever BadZure's own managed Log Analytics workspace and subscription
# Activity Log export exist. This state survives `destroy`: only
# `destroy --telemetry` (src/telemetry_hub.py TelemetryHub.destroy) touches it.
#
# Every resource here is count-gated rather than unconditional, so a config that
# never turns telemetry on never needs this root run at all, and a BYO config
# creates nothing of its own besides the Activity Log export.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.57.0"
    }
  }
}

provider "azurerm" {
  features {
    log_analytics_workspace {
      # BadZure's managed workspace holds nothing an operator would want back
      # after destroy: a normal delete would leave it in Azure's 14-day soft
      # delete, still billable and still holding the collected telemetry.
      permanently_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "hub" {
  count    = var.create_managed_workspace ? 1 : 0
  name     = "badzure-telemetry"
  location = var.location

  lifecycle {
    # A later config's location never moves (and never destroys) an existing
    # hub resource group.
    ignore_changes = [location]
  }
}

resource "azurerm_log_analytics_workspace" "hub" {
  count               = var.create_managed_workspace ? 1 : 0
  name                = var.workspace_name
  resource_group_name = azurerm_resource_group.hub[0].name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_days
  daily_quota_gb      = var.daily_cap_gb

  lifecycle {
    # Workspace settings apply only when the workspace is created. Without this,
    # a later config with a different location would make Terraform REPLACE the
    # workspace, deleting all collected telemetry; retention/cap changes are
    # made in the Azure portal instead.
    ignore_changes = [location, retention_in_days, daily_quota_gb]
  }
}

# The managed workspace audits itself: every query against it is logged into
# itself, so "who read this data" is answerable from inside the workspace.
resource "azurerm_monitor_diagnostic_setting" "workspace_audit" {
  count                      = var.create_managed_workspace ? 1 : 0
  name                       = "badzure-diag"
  target_resource_id         = azurerm_log_analytics_workspace.hub[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.hub[0].id

  enabled_log {
    category_group = "allLogs"
  }
}

locals {
  # The workspace every lab and the Activity Log/Entra settings send to: BYO
  # when one was given, else the managed workspace this root just created.
  destination = var.destination_workspace_id != "" ? var.destination_workspace_id : azurerm_log_analytics_workspace.hub[0].id
}

# Subscription-level Activity Log export. Free to ingest (Azure does not bill
# Activity Log data), and subscription diagnostic settings take no category
# group: every category must be listed explicitly.
resource "azurerm_monitor_diagnostic_setting" "activity" {
  count                      = var.activity_log_enabled ? 1 : 0
  name                       = "badzure-activity-${var.setting_suffix}"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = local.destination

  dynamic "enabled_log" {
    for_each = var.activity_log_categories
    content {
      category = enabled_log.value
    }
  }
}
