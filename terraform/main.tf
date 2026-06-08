terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "3.8.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.57.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }

  subscription_id = var.subscription_id

  # Use Azure AD authentication for storage accounts (required when shared_access_key_enabled = false)
  storage_use_azuread = true
}

data "azuread_domains" "example" {
  only_initial = true
}

data "azuread_service_principal" "microsoft_graph" {
  display_name = "Microsoft Graph"
}

data "azuread_service_principal" "exchange_online" {
  display_name = "Office 365 Exchange Online"
}

resource "azuread_user" "users" {
  for_each = var.users

  user_principal_name = "${each.value.user_principal_name}@${var.domain}"
  display_name        = each.value.display_name
  mail_nickname       = each.value.mail_nickname
  password            = each.value.password
}

resource "azuread_group" "groups" {
  for_each = var.groups

  display_name     = each.value.display_name
  mail_enabled     = false
  security_enabled = true
  # Attack path groups need to be role-assignable to receive Entra ID directory roles
  assignable_to_role = lookup(each.value, "is_attack_path_group", false)

  # Set group owners. Union of three sources, with the deploying principal always
  # included to avoid "cannot remove last owner" errors:
  #   (a) Terraform's executing principal
  #   (b) legacy entity-level owner (owner_name/owner_type) — kept working until Phase 2
  #   (c) generic group_ownership primitive (local.g_group_owner_ids_by_group)
  # If no owner comes from (b) or (c), owners stays null (unmanaged), preserving
  # the original behavior for groups that have no ownership edge.
  owners = (
    length(local.g_group_owner_ids_by_group[each.key]) > 0 || lookup(each.value, "owner_name", null) != null ?
    toset(concat(
      [data.azurerm_client_config.current.object_id],
      local.g_group_owner_ids_by_group[each.key],
      lookup(each.value, "owner_name", null) != null ? [
        lookup(each.value, "owner_type", "user") == "user" ?
          azuread_user.users[each.value.owner_name].object_id :
          azuread_service_principal.spns[each.value.owner_name].object_id
      ] : []
    )) : null
  )

  depends_on = [
    azuread_user.users,
    azuread_service_principal.spns
  ]
}

resource "azuread_application_registration" "spns" {
  for_each = var.applications

  display_name = each.value.display_name
}

resource "azuread_service_principal" "spns" {
  for_each = var.applications

  client_id = azuread_application_registration.spns[each.key].client_id
}

resource "azuread_administrative_unit" "aunits" {
  for_each = var.administrative_units

  display_name = each.value.display_name
}

resource "azuread_group_member" "group_memberships" {
  for_each = var.user_group_assignments

  group_object_id  = azuread_group.groups[each.value.group_name].object_id
  member_object_id = azuread_user.users[each.value.user_name].object_id
}
resource "azuread_administrative_unit_member" "au_memberships" {
  for_each = var.user_au_assignments

  administrative_unit_object_id = azuread_administrative_unit.aunits[each.value.administrative_unit_name].object_id
  member_object_id              = azuread_user.users[each.value.user_name].object_id
}

resource "azuread_directory_role_assignment" "user_role_assignments" {
  for_each = var.user_role_assignments

  principal_object_id = azuread_user.users[each.value.user_name].object_id
  role_id             = each.value.role_definition_id
}

resource "azuread_directory_role_assignment" "app_role_assignments" {
  for_each = var.app_role_assignments

  principal_object_id = azuread_service_principal.spns[each.value.app_name].object_id
  role_id             = each.value.role_id
}

resource "azuread_app_role_assignment" "app_api_permission_assignments" {
  for_each = var.app_api_permission_assignments

  app_role_id         = each.value.api_permission_id
  principal_object_id = azuread_service_principal.spns[each.value.app_name].object_id
  resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
}
resource "azurerm_resource_group" "rgroups" {
  for_each = var.resource_groups

  name     = each.value.name
  location = each.value.location
}

resource "azurerm_key_vault" "kvaults" {
  for_each = var.key_vaults

  name                       = each.value.name
  location                   = each.value.location
  resource_group_name        = each.value.resource_group_name
  sku_name                   = each.value.sku_name
  tenant_id                  = var.tenant_id
  rbac_authorization_enabled = true

  depends_on = [azurerm_resource_group.rgroups]

}


# Grant Terraform's deploying identity Key Vault data plane access to write secrets
resource "azurerm_role_assignment" "terraform_kv_access" {
  for_each = var.key_vaults

  scope                = azurerm_key_vault.kvaults[each.key].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id

  depends_on = [azurerm_key_vault.kvaults]
}
resource "azurerm_storage_account" "sas" {
  for_each = var.storage_accounts

  name                     = each.value.name
  location                 = each.value.location
  resource_group_name      = each.value.resource_group_name
  account_tier             = each.value.account_tier
  account_replication_type = each.value.account_replication_type

  # Enable public network access to allow Terraform to connect, use Azure AD auth instead of keys
  public_network_access_enabled   = true
  shared_access_key_enabled       = true  # Needed to access SAS key in storage account for M003-V4
  allow_nested_items_to_be_public = false # CRITICAL: Prevents public access to blobs/containers

  depends_on = [azurerm_resource_group.rgroups]
}

# Get the current client (Terraform's service principal or user identity)
data "azurerm_client_config" "current" {}

# Grant Terraform's service principal access to storage accounts for blob uploads
resource "azurerm_role_assignment" "terraform_storage_access" {
  for_each = var.storage_accounts

  scope                = azurerm_storage_account.sas[each.key].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id

  depends_on = [azurerm_storage_account.sas]
}

# Add delay to allow role assignment to propagate
resource "time_sleep" "wait_for_rbac" {
  depends_on = [azurerm_role_assignment.terraform_storage_access]

  create_duration = "180s" # Increased from 120s to 180s for better RBAC propagation
}
resource "azurerm_linux_virtual_machine" "linux_vms" {
  for_each = { for k, v in var.virtual_machines : k => v if v.os_type == "Linux" }

  name                            = each.value.name
  location                        = each.value.location
  resource_group_name             = each.value.resource_group_name
  size                            = each.value.vm_size
  disable_password_authentication = false
  admin_username                  = each.value.admin_username
  admin_password                  = each.value.admin_password

  network_interface_ids = [azurerm_network_interface.vm_nics[each.key].id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  depends_on = [azurerm_network_interface.vm_nics]
}

resource "azurerm_windows_virtual_machine" "windows_vms" {
  for_each = { for k, v in var.virtual_machines : k => v if v.os_type == "Windows" }

  name                = each.value.name
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  size                = each.value.vm_size
  admin_username      = each.value.admin_username
  admin_password      = each.value.admin_password

  network_interface_ids = [azurerm_network_interface.vm_nics[each.key].id]

  identity {
    type = "SystemAssigned"
  }


  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }

  depends_on = [azurerm_network_interface.vm_nics]
}

resource "azurerm_public_ip" "vm_public_ips" {
  for_each = var.virtual_machines

  name                = "${each.key}-public-ip"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  allocation_method   = "Static"

  depends_on = [azurerm_resource_group.rgroups]
}


resource "azurerm_network_interface" "vm_nics" {
  for_each = var.virtual_machines

  name                = "${each.value.name}-nic"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm_subnets[each.key].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_public_ips[each.key].id

  }

  depends_on = [
    azurerm_subnet.vm_subnets,
    azurerm_public_ip.vm_public_ips
  ]
}

resource "azurerm_virtual_network" "vm_vnets" {
  for_each = { for k, v in var.virtual_machines : k => v }

  # Per-VM vnet name (was "<rg>-vnet", which collided when two VMs shared an RG).
  name                = "${each.value.name}-vnet"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  address_space       = ["10.0.0.0/16"]

  depends_on = [azurerm_resource_group.rgroups] # 

}

resource "azurerm_subnet" "vm_subnets" {
  for_each = var.virtual_machines

  name                 = "${each.value.name}-subnet"
  resource_group_name  = each.value.resource_group_name
  virtual_network_name = azurerm_virtual_network.vm_vnets[each.key].name
  # Use unique subnet range for each VM to prevent overlap when multiple VMs share a VNet
  address_prefixes = ["10.0.${index(keys(var.virtual_machines), each.key) + 1}.0/24"]

  depends_on = [azurerm_virtual_network.vm_vnets]
}

resource "azurerm_network_security_group" "vm_nsg" {
  for_each = var.virtual_machines

  name                = "${each.key}-nsg"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name

  security_rule {
    name                       = "Allow-RDP"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.public_ip
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.public_ip
    destination_address_prefix = "*"
  }

  depends_on = [azurerm_resource_group.rgroups]
}

resource "azurerm_network_interface_security_group_association" "vm_nic_nsg" {
  for_each = var.virtual_machines

  network_interface_id      = azurerm_network_interface.vm_nics[each.key].id
  network_security_group_id = azurerm_network_security_group.vm_nsg[each.key].id

  depends_on = [azurerm_network_interface.vm_nics]
}
# Logic App with system-assigned managed identity
resource "azurerm_logic_app_workflow" "logic_apps" {
  for_each = var.logic_apps

  name                = each.value.name
  location            = each.value.location
  resource_group_name = each.value.resource_group_name

  identity {
    type = "SystemAssigned"
  }

  depends_on = [azurerm_resource_group.rgroups]
}

# Automation Account with system-assigned managed identity
resource "azurerm_automation_account" "automation_accounts" {
  for_each = var.automation_accounts

  name                = each.value.name
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  depends_on = [azurerm_resource_group.rgroups]
}

# Storage Account for Function App (required dependency)
resource "azurerm_storage_account" "function_storage" {
  for_each = var.function_apps

  # Azure storage account names must be 3-24 characters, lowercase letters and numbers only
  # Transform: remove "func-" prefix, remove all hyphens, truncate to 24 chars
  name                     = substr(lower(replace(replace(each.value.name, "func-", "fc"), "-", "")), 0, 24)
  location                 = each.value.location
  resource_group_name      = each.value.resource_group_name
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Enable public network access for Function App connectivity with managed identity auth
  public_network_access_enabled   = true
  shared_access_key_enabled       = true
  allow_nested_items_to_be_public = false # CRITICAL: Prevents public access to blobs/containers

  depends_on = [azurerm_resource_group.rgroups]
}

# Storage Container for Function App (required for Flex Consumption)
resource "azurerm_storage_container" "function_container" {
  for_each = var.function_apps

  name                  = "app-package-${replace(each.value.name, "func-", "")}-${substr(md5(each.value.name), 0, 7)}"
  storage_account_id    = azurerm_storage_account.function_storage[each.key].id
  container_access_type = "private"

  depends_on = [azurerm_storage_account.function_storage]
}

# Service Plan for Flex Consumption Function Apps
resource "azurerm_service_plan" "function_plan" {
  for_each = var.function_apps

  name                = "${each.value.name}-plan"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  os_type             = each.value.os_type == "linux" ? "Linux" : "Windows"
  sku_name            = "FC1"

  depends_on = [azurerm_resource_group.rgroups]
}

# Application Insights for Function Apps
resource "azurerm_application_insights" "function_insights" {
  for_each = var.function_apps

  name                = "${each.value.name}-insights"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  application_type    = "web"

  depends_on = [azurerm_resource_group.rgroups]
}

# Function App with Flex Consumption (supports both Linux and Windows)
resource "azurerm_function_app_flex_consumption" "function_apps" {
  for_each = var.function_apps

  name                = each.value.name
  resource_group_name = each.value.resource_group_name
  location            = each.value.location
  service_plan_id     = azurerm_service_plan.function_plan[each.key].id

  # Storage configuration - Using connection string authentication
  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${azurerm_storage_account.function_storage[each.key].primary_blob_endpoint}${azurerm_storage_container.function_container[each.key].name}"
  storage_authentication_type = "StorageAccountConnectionString"
  storage_access_key          = azurerm_storage_account.function_storage[each.key].primary_access_key

  # Runtime configuration
  runtime_name    = each.value.os_type == "linux" ? "python" : "dotnet-isolated"
  runtime_version = each.value.os_type == "linux" ? "3.13" : "8.0"

  # Scale and concurrency settings (top-level arguments)
  maximum_instance_count = 100
  instance_memory_in_mb  = 2048

  # App settings for deployment storage connection string
  app_settings = {
    "DEPLOYMENT_STORAGE_CONNECTION_STRING"     = azurerm_storage_account.function_storage[each.key].primary_connection_string
    "APPLICATIONINSIGHTS_CONNECTION_STRING"    = azurerm_application_insights.function_insights[each.key].connection_string
    "ApplicationInsightsAgent_EXTENSION_VERSION" = "~3"
  }

  # Required site_config block
  site_config {
    application_insights_connection_string = azurerm_application_insights.function_insights[each.key].connection_string
    application_insights_key               = azurerm_application_insights.function_insights[each.key].instrumentation_key
  }

  # Keep System-Assigned Identity for attack path scenarios
  identity {
    type = "SystemAssigned"
  }

  depends_on = [
    azurerm_service_plan.function_plan,
    azurerm_storage_container.function_container,
    azurerm_application_insights.function_insights
  ]
}

# Cosmos DB Account (serverless capacity mode for cost efficiency)
resource "azurerm_cosmosdb_account" "cosmos_dbs" {
  for_each = var.cosmos_dbs

  name                = each.value.name
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  offer_type          = each.value.offer_type
  kind                = each.value.kind

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = each.value.location
    failover_priority = 0
    zone_redundant    = false
  }

  depends_on = [azurerm_resource_group.rgroups]
}

# Cosmos DB SQL Database
resource "azurerm_cosmosdb_sql_database" "cosmos_databases" {
  for_each = var.cosmos_dbs

  name                = each.value.database_name
  resource_group_name = each.value.resource_group_name
  account_name        = azurerm_cosmosdb_account.cosmos_dbs[each.key].name

  depends_on = [azurerm_cosmosdb_account.cosmos_dbs]
}

# Cosmos DB SQL Container
resource "azurerm_cosmosdb_sql_container" "cosmos_containers" {
  for_each = var.cosmos_dbs

  name                = each.value.container_name
  resource_group_name = each.value.resource_group_name
  account_name        = azurerm_cosmosdb_account.cosmos_dbs[each.key].name
  database_name       = azurerm_cosmosdb_sql_database.cosmos_databases[each.key].name
  partition_key_paths = [each.value.partition_key_path]

  depends_on = [azurerm_cosmosdb_sql_database.cosmos_databases]
}