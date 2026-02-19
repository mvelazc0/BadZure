terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.53.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.57.0"
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

  # Set group owners for group_owner assignment type
  # Include Terraform's executing principal to avoid "cannot remove last owner" errors
  owners = (
    lookup(each.value, "owner_name", null) != null ? toset(concat(
      [data.azurerm_client_config.current.object_id],
      [
        lookup(each.value, "owner_type", "user") == "user" ?
          azuread_user.users[each.value.owner_name].id :
          azuread_service_principal.spns[each.value.owner_name].id
      ]
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

  group_object_id  = azuread_group.groups[each.value.group_name].id
  member_object_id = azuread_user.users[each.value.user_name].id
}

# Attack path group memberships - supports both users and service principals
resource "azuread_group_member" "attack_path_group_memberships" {
  for_each = var.attack_path_group_memberships

  group_object_id = azuread_group.groups[each.value.group_name].id
  member_object_id = (
    each.value.identity_type == "user" ?
      azuread_user.users[each.value.principal_name].id :
      azuread_service_principal.spns[each.value.principal_name].id
  )

  depends_on = [
    azuread_group.groups,
    azuread_user.users,
    azuread_service_principal.spns
  ]
}

resource "azuread_administrative_unit_member" "au_memberships" {
  for_each = var.user_au_assignments

  administrative_unit_object_id = azuread_administrative_unit.aunits[each.value.administrative_unit_name].id
  member_object_id              = azuread_user.users[each.value.user_name].id
}

resource "azuread_directory_role_assignment" "user_role_assignments" {
  for_each = var.user_role_assignments

  principal_object_id = azuread_user.users[each.value.user_name].id
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
  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  resource_object_id  = data.azuread_service_principal.microsoft_graph.id
}

resource "azuread_directory_role_assignment" "attack_path_user_role_assignments" {
  for_each = var.attack_path_user_role_assignments

  # Support user, service_principal, and group identity types
  # Groups are used for indirect assignment (assignment_type: group_member or group_owner)
  principal_object_id = (
    lookup(each.value, "identity_type", "user") == "user" ?
      azuread_user.users[each.value.principal_name].id :
    lookup(each.value, "identity_type", "user") == "group" ?
      azuread_group.groups[each.value.principal_name].id :
      azuread_service_principal.spns[each.value.principal_name].id
  )
  role_id = each.value.role_definition_id

  # Scope the role to a specific application or directory-wide
  directory_scope_id = (
    lookup(each.value, "scope_app_name", null) != null
      ? "/${azuread_application_registration.spns[each.value.scope_app_name].object_id}"
      : "/"
  )

  depends_on = [
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups,
    azuread_application_registration.spns
  ]
}

resource "azuread_directory_role_assignment" "attack_path_application_role_assignments" {
  for_each = merge([
    for assignment_key, assignment in var.attack_path_application_role_assignments : {
      for idx, role_id in assignment.role_ids :
      "${assignment_key}-${idx}-${role_id}" => {
        app_name = assignment.app_name
        role_id  = role_id
      }
    }
  ]...)

  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  role_id             = each.value.role_id
}

resource "azuread_app_role_assignment" "attack_path_application_api_permission_assignments" {
  for_each = merge([
    for assignment_key, assignment in var.attack_path_application_api_permission_assignments : {
      for idx, permission_id in assignment.api_permission_ids :
      "${assignment_key}-${idx}-${permission_id}" => {
        app_name          = assignment.app_name
        api_permission_id = permission_id
        api_type          = lookup(assignment, "api_type", "graph") # Default to graph for backward compatibility
      }
    }
  ]...)

  app_role_id         = each.value.api_permission_id
  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  resource_object_id  = each.value.api_type == "exchange" ? data.azuread_service_principal.exchange_online.id : data.azuread_service_principal.microsoft_graph.id
}


resource "azuread_application_owner" "attack_path_application_owner_assignments" {
  for_each = var.attack_path_application_owner_assignments

  application_id  = "/applications/${azuread_application_registration.spns[each.value.app_name].object_id}"
  # Note: Azure AD does not support groups as application owners
  # Only users and service principals can own applications
  owner_object_id = (
    lookup(each.value, "identity_type", "user") == "user" ?
    azuread_user.users[each.value.principal_name].object_id :
    azuread_service_principal.spns[each.value.principal_name].object_id
  )
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

resource "azuread_application_password" "attack_path_kv_secrets" {
  for_each = var.attack_path_kv_abuse_assignments

  application_id    = azuread_application_registration.spns[each.value.app_name].id
  display_name      = "BadZureClientSecret"
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]

}

resource "azuread_application_password" "attack_path_compromised_sp" {
  for_each          = var.attack_path_compromised_sp_credentials
  application_id    = azuread_application_registration.spns[each.value.app_name].id
  display_name      = "BadZureCompromisedSPSecret"
  end_date_relative = "8760h"
  depends_on        = [azuread_application_registration.spns]
}

resource "azurerm_key_vault_secret" "attack_path_kv_secrets" {
  for_each = var.attack_path_kv_abuse_assignments

  name         = "client-secret-${each.value.app_name}"
  value        = azuread_application_password.attack_path_kv_secrets[each.key].value
  key_vault_id = azurerm_key_vault.kvaults[each.value.key_vault].id

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_password.attack_path_kv_secrets
  ]
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

resource "azuread_application_certificate" "attack_path_storage_certificates" {
  for_each = var.attack_path_storage_abuse_assignments

  application_id = azuread_application_registration.spns[each.value.app_name].id
  type           = "AsymmetricX509Cert"
  value          = file(each.value.certificate_path) # Read certificate file
  #end_date          = timeadd(timestamp(), "8760h")  # calculates 1 year from now in UTC
  #end_date          = "2025-12-01T01:02:03  
  # Don't specify end_date - let Azure AD extract it from the certificate itself

}

resource "azurerm_storage_container" "attack_path_storage_containers" {
  for_each = var.attack_path_storage_abuse_assignments

  name                  = "cert-container-${replace(each.key, "_", "-")}"
  storage_account_id    = azurerm_storage_account.sas[each.value.storage_account].id
  container_access_type = "private"

  depends_on = [azurerm_storage_account.sas]
}

# Upload the private key (.key)
resource "azurerm_storage_blob" "attack_path_storage_key_upload" {
  for_each = var.attack_path_storage_abuse_assignments

  name                   = "${each.value.app_name}-private-key.key"
  storage_account_name   = azurerm_storage_account.sas[each.value.storage_account].name
  storage_container_name = azurerm_storage_container.attack_path_storage_containers[each.key].name
  type                   = "Block"
  source                 = each.value.private_key_path # Uploads the .key file

  depends_on = [
    azurerm_storage_container.attack_path_storage_containers,
    azuread_application_certificate.attack_path_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Upload the certificate (.pem)
resource "azurerm_storage_blob" "attack_path_storage_pem_upload" {
  for_each = var.attack_path_storage_abuse_assignments

  name                   = "${each.value.app_name}-certificate.pem"
  storage_account_name   = azurerm_storage_account.sas[each.value.storage_account].name
  storage_container_name = azurerm_storage_container.attack_path_storage_containers[each.key].name
  type                   = "Block"
  source                 = each.value.certificate_path # Uploads the .pem file

  depends_on = [
    azurerm_storage_container.attack_path_storage_containers,
    azuread_application_certificate.attack_path_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Upload the PFX certificate (single file for easy download and authentication)
resource "azurerm_storage_blob" "attack_path_storage_pfx_upload" {
  for_each = {
    for k, v in var.attack_path_storage_abuse_assignments : k => v
    if lookup(v, "pfx_path", "") != ""
  }

  name                   = "${each.value.app_name}-certificate.pfx"
  storage_account_name   = azurerm_storage_account.sas[each.value.storage_account].name
  storage_container_name = azurerm_storage_container.attack_path_storage_containers[each.key].name
  type                   = "Block"
  source                 = each.value.pfx_path # Uploads the .pfx file

  depends_on = [
    azurerm_storage_container.attack_path_storage_containers,
    azuread_application_certificate.attack_path_storage_certificates,
    time_sleep.wait_for_rbac
  ]
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

  name                = "${each.value.resource_group_name}-vnet"
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

resource "azurerm_role_assignment" "attack_path_kv_access" {
  for_each = var.attack_path_kv_abuse_assignments

  scope                = azurerm_key_vault.kvaults[each.value.key_vault].id
  role_definition_name = "Key Vault Contributor"

  # Support group-based assignment (assignment_type: group_member or group_owner)
  # When assignment_type is "group_member" or "group_owner", assign the role to the group instead of the user/SP
  principal_id = (
    contains(["group_member", "group_owner"], lookup(each.value, "assignment_type", "direct")) ?
      azuread_group.groups[each.value.group_name].id :
    each.value.identity_type == "user" ?
    azuread_user.users[each.value.principal_name].id :
    azuread_service_principal.spns[each.value.principal_name].id
  )

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups
  ]
}

resource "azurerm_role_assignment" "attack_path_storage_access" {
  for_each = var.attack_path_storage_abuse_assignments

  scope                = azurerm_storage_account.sas[each.value.storage_account].id
  role_definition_name = "Storage Blob Data Reader"

  # Support group-based assignment (assignment_type: group_member or group_owner)
  # When assignment_type is "group_member" or "group_owner", assign the role to the group instead of the user/SP
  principal_id = (
    contains(["group_member", "group_owner"], lookup(each.value, "assignment_type", "direct")) ?
      azuread_group.groups[each.value.group_name].id :
    each.value.identity_type == "user" ?
    azuread_user.users[each.value.principal_name].id :
    azuread_service_principal.spns[each.value.principal_name].id
  )

  depends_on = [
    azurerm_storage_account.sas,
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups
  ]
}

resource "azurerm_role_assignment" "attack_path_vm_contributor_access" {
  for_each = var.attack_path_vm_contributor_assignments

  scope = (
    contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.virtual_machine) ?
    azurerm_linux_virtual_machine.linux_vms[each.value.virtual_machine].id :
    azurerm_windows_virtual_machine.windows_vms[each.value.virtual_machine].id
  )
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azuread_user.users[each.value.user_name].id

  depends_on = [
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azuread_user.users
  ]
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

# ============================================================================
# ManagedIdentityTheft Attack Path Resources
# ============================================================================

# Create application passwords for ManagedIdentityTheft targeting Key Vaults with secrets
resource "azuread_application_password" "attack_path_mi_theft_kv_secrets" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "secret"
  }

  application_id    = azuread_application_registration.spns[each.value.app_name].id
  display_name      = "BadZureMITheftSecret"
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]
}

# Store application passwords as secrets in Key Vault for ManagedIdentityTheft
resource "azurerm_key_vault_secret" "attack_path_mi_theft_kv_secrets" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "secret"
  }

  name         = "mi-client-secret-${each.value.app_name}"
  value        = azuread_application_password.attack_path_mi_theft_kv_secrets[each.key].value
  key_vault_id = azurerm_key_vault.kvaults[each.value.target_name].id

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_password.attack_path_mi_theft_kv_secrets,
    azurerm_role_assignment.attack_path_mi_theft_kv_access
  ]
}

# Store application client_id (app_id) as a separate secret in Key Vault for ManagedIdentityTheft (secrets)
resource "azurerm_key_vault_secret" "attack_path_mi_theft_kv_app_ids" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "secret"
  }

  name         = "mi-client-id-${each.value.app_name}"
  value        = azuread_application_registration.spns[each.value.app_name].client_id
  key_vault_id = azurerm_key_vault.kvaults[each.value.target_name].id

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_registration.spns,
    azurerm_role_assignment.attack_path_mi_theft_kv_access
  ]
}

# ============================================================================
# ManagedIdentityTheft - Key Vault Certificate Support
# ============================================================================

# Create application certificates for ManagedIdentityTheft targeting Key Vaults with certificates
resource "azuread_application_certificate" "attack_path_mi_theft_kv_certificates" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "certificate"
  }

  application_id = azuread_application_registration.spns[each.value.app_name].id
  type           = "AsymmetricX509Cert"
  value          = file(each.value.certificate_path)
}

# Import PFX certificate into Key Vault certificates section
resource "azurerm_key_vault_certificate" "attack_path_mi_theft_kv_cert_import" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "certificate" && v.pfx_path != ""
  }

  name         = "mi-certificate-${each.value.app_name}"
  key_vault_id = azurerm_key_vault.kvaults[each.value.target_name].id

  certificate {
    contents = filebase64(each.value.pfx_path)
    password = "" # Assuming no password on PFX, adjust if needed
  }

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_certificate.attack_path_mi_theft_kv_certificates,
    azurerm_role_assignment.attack_path_mi_theft_kv_access,
    azurerm_role_assignment.attack_path_mi_theft_kv_certificates_officer
  ]
}

# Store application client_id as a secret (needed for cert-based auth)
resource "azurerm_key_vault_secret" "attack_path_mi_theft_kv_cert_app_ids" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "certificate"
  }

  name         = "mi-client-id-${each.value.app_name}"
  value        = azuread_application_registration.spns[each.value.app_name].client_id
  key_vault_id = azurerm_key_vault.kvaults[each.value.target_name].id

  depends_on = [
    azurerm_key_vault.kvaults,
    azuread_application_registration.spns,
    azurerm_role_assignment.attack_path_mi_theft_kv_access
  ]
}

# ============================================================================
# ManagedIdentityTheft - Storage Account Secret Support
# ============================================================================

# Create application password/secret for ManagedIdentityTheft targeting Storage Accounts with secrets
resource "azuread_application_password" "attack_path_mi_theft_storage_secrets" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "secret"
  }

  application_id    = azuread_application_registration.spns[each.value.app_name].id
  display_name      = "BadZureMITheftSecret"
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]
}

# Create storage containers for ManagedIdentityTheft credentials (secrets)
resource "azurerm_storage_container" "attack_path_mi_theft_storage_secret_containers" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "secret"
  }

  name                  = "mi-credentials"
  storage_account_id    = azurerm_storage_account.sas[each.value.target_name].id
  container_access_type = "private"

  depends_on = [azurerm_storage_account.sas]
}

# Upload app ID for ManagedIdentityTheft (secrets)
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_secret_appid_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "secret"
  }

  name                   = "${each.value.app_name}-app-id.txt"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_secret_containers[each.key].name
  type                   = "Block"
  source_content         = azuread_application_registration.spns[each.value.app_name].client_id

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_secret_containers,
    azuread_application_password.attack_path_mi_theft_storage_secrets,
    time_sleep.wait_for_rbac
  ]
}

# Upload secret for ManagedIdentityTheft (secrets)
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_secret_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "secret"
  }

  name                   = "${each.value.app_name}-secret.txt"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_secret_containers[each.key].name
  type                   = "Block"
  source_content         = azuread_application_password.attack_path_mi_theft_storage_secrets[each.key].value

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_secret_containers,
    azuread_application_password.attack_path_mi_theft_storage_secrets,
    time_sleep.wait_for_rbac
  ]
}

# ============================================================================
# ManagedIdentityTheft - Storage Account Certificate Support
# ============================================================================

# Create application certificates for ManagedIdentityTheft targeting Storage Accounts with certificates
resource "azuread_application_certificate" "attack_path_mi_theft_storage_certificates" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate"
  }

  application_id = azuread_application_registration.spns[each.value.app_name].id
  type           = "AsymmetricX509Cert"
  value          = file(each.value.certificate_path)
}

# Create storage containers for ManagedIdentityTheft credentials (certificates)
resource "azurerm_storage_container" "attack_path_mi_theft_storage_cert_containers" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate"
  }

  name                  = "mi-credentials"
  storage_account_id    = azurerm_storage_account.sas[each.value.target_name].id
  container_access_type = "private"

  depends_on = [azurerm_storage_account.sas]
}

# Upload certificate (PEM) for ManagedIdentityTheft
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_cert_pem_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate"
  }

  name                   = "${each.value.app_name}-certificate.pem"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_cert_containers[each.key].name
  type                   = "Block"
  source                 = each.value.certificate_path

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_cert_containers,
    azuread_application_certificate.attack_path_mi_theft_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Upload private key for ManagedIdentityTheft
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_cert_key_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate"
  }

  name                   = "${each.value.app_name}-private-key.key"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_cert_containers[each.key].name
  type                   = "Block"
  source                 = each.value.private_key_path

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_cert_containers,
    azuread_application_certificate.attack_path_mi_theft_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Upload PFX certificate for ManagedIdentityTheft (single file for easy download)
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_cert_pfx_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate" && v.pfx_path != ""
  }

  name                   = "${each.value.app_name}-certificate.pfx"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_cert_containers[each.key].name
  type                   = "Block"
  source                 = each.value.pfx_path

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_cert_containers,
    azuread_application_certificate.attack_path_mi_theft_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Upload app ID for ManagedIdentityTheft (certificates) - needed for cert-based auth
resource "azurerm_storage_blob" "attack_path_mi_theft_storage_cert_appid_upload" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "storage_account" && lookup(v, "credential_type", "secret") == "certificate"
  }

  name                   = "${each.value.app_name}-app-id.txt"
  storage_account_name   = azurerm_storage_account.sas[each.value.target_name].name
  storage_container_name = azurerm_storage_container.attack_path_mi_theft_storage_cert_containers[each.key].name
  type                   = "Block"
  source_content         = azuread_application_registration.spns[each.value.app_name].client_id

  depends_on = [
    azurerm_storage_container.attack_path_mi_theft_storage_cert_containers,
    azuread_application_certificate.attack_path_mi_theft_storage_certificates,
    time_sleep.wait_for_rbac
  ]
}

# Grant VM managed identity access to Key Vault
resource "azurerm_role_assignment" "attack_path_mi_theft_kv_access" {
  for_each = { for k, v in var.attack_path_managed_identity_theft_assignments : k => v if v.target_resource_type == "key_vault" }

  scope                = azurerm_key_vault.kvaults[each.value.target_name].id
  role_definition_name = "Key Vault Contributor"

  principal_id = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
    null
  )


  depends_on = [
    azurerm_key_vault.kvaults,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant managed identity "Key Vault Secrets User" role on Key Vault
resource "azurerm_role_assignment" "attack_path_mi_theft_kv_secrets_user" {
  for_each = { for k, v in var.attack_path_managed_identity_theft_assignments : k => v if v.target_resource_type == "key_vault" }

  scope                = azurerm_key_vault.kvaults[each.value.target_name].id
  role_definition_name = "Key Vault Secrets User"

  principal_id = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
    null
  )

  depends_on = [
    azurerm_key_vault.kvaults,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant managed identity "Key Vault Reader" role on Key Vault
resource "azurerm_role_assignment" "attack_path_mi_theft_kv_reader" {
  for_each = { for k, v in var.attack_path_managed_identity_theft_assignments : k => v if v.target_resource_type == "key_vault" }

  scope                = azurerm_key_vault.kvaults[each.value.target_name].id
  role_definition_name = "Key Vault Reader"

  principal_id = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
    null
  )

  depends_on = [
    azurerm_key_vault.kvaults,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant managed identity "Key Vault Certificate User" role on Key Vault (for certificate scenarios)
resource "azurerm_role_assignment" "attack_path_mi_theft_kv_certificate_user" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "certificate"
  }

  scope                = azurerm_key_vault.kvaults[each.value.target_name].id
  role_definition_name = "Key Vault Certificate User"

  principal_id = (
    each.value.source_type == "vm" ?
      (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
        azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
        azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
      azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
      azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
      azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
      null
  )

  depends_on = [
    azurerm_key_vault.kvaults,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant Terraform service principal "Key Vault Administrator" role to import certificates
resource "azurerm_role_assignment" "attack_path_mi_theft_kv_certificates_officer" {
  for_each = {
    for k, v in var.attack_path_managed_identity_theft_assignments : k => v
    if v.target_resource_type == "key_vault" && lookup(v, "credential_type", "secret") == "certificate"
  }

  scope                = azurerm_key_vault.kvaults[each.value.target_name].id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id

  depends_on = [
    azurerm_key_vault.kvaults
  ]
}

# Grant VM managed identity access to Storage Account
resource "azurerm_role_assignment" "attack_path_mi_theft_storage_access" {
  for_each = { for k, v in var.attack_path_managed_identity_theft_assignments : k => v if v.target_resource_type == "storage_account" }

  scope                = azurerm_storage_account.sas[each.value.target_name].id
  role_definition_name = "Storage Blob Data Reader"

  principal_id = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
    null
  )

  depends_on = [
    azurerm_storage_account.sas,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant managed identity "Storage Account Contributor" role to enable key theft
resource "azurerm_role_assignment" "attack_path_mi_theft_storage_contributor" {
  for_each = { for k, v in var.attack_path_managed_identity_theft_assignments : k => v if v.target_resource_type == "storage_account" }

  scope                = azurerm_storage_account.sas[each.value.target_name].id
  role_definition_name = "Storage Account Contributor"

  principal_id = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].identity[0].principal_id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].identity[0].principal_id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].identity[0].principal_id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].identity[0].principal_id :
    null
  )

  depends_on = [
    azurerm_storage_account.sas,
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps
  ]
}

# Grant user, service principal, or group Contributor access for ManagedIdentityTheft
resource "azurerm_role_assignment" "attack_path_mi_theft_source_contributor_access" {
  for_each = var.attack_path_managed_identity_theft_assignments

  scope = (
    each.value.source_type == "vm" ?
    (contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.source_name) ?
      azurerm_linux_virtual_machine.linux_vms[each.value.source_name].id :
    azurerm_windows_virtual_machine.windows_vms[each.value.source_name].id) :
    each.value.source_type == "logic_app" ?
    azurerm_logic_app_workflow.logic_apps[each.value.source_name].id :
    each.value.source_type == "automation_account" ?
    azurerm_automation_account.automation_accounts[each.value.source_name].id :
    each.value.source_type == "function_app" ?
    azurerm_function_app_flex_consumption.function_apps[each.value.source_name].id :
    null
  )

  role_definition_name = (
    each.value.source_type == "vm" ? "Virtual Machine Contributor" :
    each.value.source_type == "logic_app" ? "Logic App Contributor" :
    each.value.source_type == "automation_account" ? "Automation Contributor" :
    each.value.source_type == "function_app" ? "Website Contributor" :
    null
  )
  
  # Support user, service_principal, and group identity types
  # When assignment_type is "group_member" or "group_owner", assign the role to the group instead of the user/SP
  principal_id = (
    contains(["group_member", "group_owner"], lookup(each.value, "assignment_type", "direct")) ?
      azuread_group.groups[each.value.group_name].id :
    each.value.identity_type == "user" ?
    azuread_user.users[each.value.initial_access_principal].id :
    azuread_service_principal.spns[each.value.initial_access_principal].id
  )

  depends_on = [
    azurerm_linux_virtual_machine.linux_vms,
    azurerm_windows_virtual_machine.windows_vms,
    azurerm_logic_app_workflow.logic_apps,
    azurerm_automation_account.automation_accounts,
    azurerm_function_app_flex_consumption.function_apps,
    azuread_user.users,
    azuread_service_principal.spns,
    azuread_group.groups
  ]
}
