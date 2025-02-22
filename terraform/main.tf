terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.50.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.18.0" 
    }    
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
}

data "azuread_domains" "example" {
  only_initial = true
}

data "azuread_service_principal" "microsoft_graph" {
  display_name = "Microsoft Graph"
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

  group_object_id = azuread_group.groups[each.value.group_name].id
  member_object_id = azuread_user.users[each.value.user_name].id
}

resource "azuread_administrative_unit_member" "au_memberships" {
  for_each = var.user_au_assignments

  administrative_unit_object_id = azuread_administrative_unit.aunits[each.value.administrative_unit_name].id
  member_object_id = azuread_user.users[each.value.user_name].id
}

resource "azuread_directory_role_assignment" "user_role_assignments" {
  for_each = var.user_role_assignments

  principal_object_id = azuread_user.users[each.value.user_name].id
  role_id  = each.value.role_definition_id
}

resource "azuread_directory_role_assignment"  "app_role_assignments" {
  for_each = var.app_role_assignments

  principal_object_id = azuread_service_principal.spns[each.value.app_name].object_id
  role_id             = each.value.role_id
}

resource "azuread_app_role_assignment" "app_api_permission_assignments" {
  for_each = var.app_api_permission_assignments

  app_role_id            = each.value.api_permission_id
  principal_object_id    = azuread_service_principal.spns[each.value.app_name].id
  resource_object_id     = data.azuread_service_principal.microsoft_graph.id
}

resource "azuread_directory_role_assignment" "attack_path_user_role_assignments" {
  for_each = var.attack_path_user_role_assignments

  principal_object_id = azuread_user.users[each.value.user_name].id
  role_id             = each.value.role_definition_id
}

resource "azuread_directory_role_assignment" "attack_path_application_role_assignments" {
  for_each = var.attack_path_application_role_assignments

  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  role_id             = each.value.role_id
}

resource "azuread_app_role_assignment" "attack_path_application_api_permission_assignments" {
  for_each = var.attack_path_application_api_permission_assignments

  app_role_id            = each.value.api_permission_id
  principal_object_id    = azuread_service_principal.spns[each.value.app_name].id
  resource_object_id     = data.azuread_service_principal.microsoft_graph.id
}

resource "azuread_application_owner" "attack_path_application_owner_assignments" {
  for_each = var.attack_path_application_owner_assignments

  application_id    = "/applications/${azuread_application_registration.spns[each.value.app_name].object_id}"
  owner_object_id   = azuread_user.users[replace(each.value.user_principal_name, "@${var.domain}", "")].object_id
}

resource "azurerm_resource_group" "rgroups" {
  for_each = var.resource_groups

  name     = each.value.name
  location = each.value.location
}

resource "azurerm_key_vault" "kvaults" {
  for_each = var.key_vaults

  name     = each.value.name
  location = each.value.location
  resource_group_name = each.value.resource_group_name
  sku_name = each.value.sku_name
  tenant_id = var.tenant_id
  enable_rbac_authorization = true

  depends_on = [azurerm_resource_group.rgroups]

}

resource "azuread_application_password" "attack_path_kv_secrets" {
  for_each        = var.attack_path_kv_abuse_assignments

  application_id  = azuread_application_registration.spns[each.value.app_name].id
  display_name    = "BadZureClientSecret"
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]

}

resource "azurerm_key_vault_secret" "attack_path_kv_secrets" {
  for_each     = var.attack_path_kv_abuse_assignments

  name         = "client-secret-${each.value.app_name}"
  value        = azuread_application_password.attack_path_kv_secrets[each.key].value
  key_vault_id = azurerm_key_vault.kvaults[each.value.key_vault].id

  depends_on   = [
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

  depends_on = [azurerm_resource_group.rgroups]
}

resource "azuread_application_certificate" "attack_path_storage_certificates" {
  for_each          = var.attack_path_storage_mi_abuse_assignments

  application_id    = azuread_application_registration.spns[each.value.app_name].id
  type              = "AsymmetricX509Cert"
  value             = file(each.value.certificate_path)  # Read certificate file
  #end_date          = timeadd(timestamp(), "8760h")  # calculates 1 year from now in UTC
  end_date          = "2025-05-01T01:02:03Z"

}

resource "azurerm_storage_container" "attack_path_storage_containers" {
  for_each            = var.attack_path_storage_mi_abuse_assignments

  name                = "cert-container"
  storage_account_name = azurerm_storage_account.sas[each.value.storage_account].name
  container_access_type = "private"

  depends_on = [azurerm_storage_account.sas]
}

# Upload the private key (.key)
resource "azurerm_storage_blob" "attack_path_storage_key_upload" {
  for_each               = var.attack_path_storage_mi_abuse_assignments

  name                   = "${each.value.app_name}-private-key.key"
  storage_account_name   = azurerm_storage_account.sas[each.value.storage_account].name
  storage_container_name = azurerm_storage_container.attack_path_storage_containers[each.key].name
  type                   = "Block"
  source                 = each.value.private_key_path  # Uploads the .key file

  depends_on = [
    azurerm_storage_container.attack_path_storage_containers,
    azuread_application_certificate.attack_path_storage_certificates
  ]
}

# Upload the certificate (.pem)
resource "azurerm_storage_blob" "attack_path_storage_pem_upload" {
  for_each               = var.attack_path_storage_mi_abuse_assignments

  name                   = "${each.value.app_name}-certificate.pem"
  storage_account_name   = azurerm_storage_account.sas[each.value.storage_account].name
  storage_container_name = azurerm_storage_container.attack_path_storage_containers[each.key].name
  type                   = "Block"
  source                 = each.value.certificate_path  # Uploads the .pem file

  depends_on = [
    azurerm_storage_container.attack_path_storage_containers,
    azuread_application_certificate.attack_path_storage_certificates
  ]
}

resource "azurerm_linux_virtual_machine" "linux_vms" {
  for_each            = { for k, v in var.virtual_machines : k => v if v.os_type == "Linux" }

  name                            = each.value.name
  location                        = each.value.location
  resource_group_name             = each.value.resource_group_name
  size                            = each.value.vm_size
  disable_password_authentication = false  
  admin_username                  = each.value.admin_username
  admin_password                  = each.value.admin_password
  
  network_interface_ids = [azurerm_network_interface.vm_nics[each.key].id]

  identity {
    type  = "SystemAssigned"
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
  for_each            = { for k, v in var.virtual_machines : k => v if v.os_type == "Windows" }

  name                = each.value.name
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  size                = each.value.vm_size
  admin_username      = each.value.admin_username
  admin_password      = each.value.admin_password

  network_interface_ids = [azurerm_network_interface.vm_nics[each.key].id]

  identity {
    type  = "SystemAssigned"
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
  for_each            = var.virtual_machines

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
  for_each            = { for k, v in var.virtual_machines : k => v }

  name                = "${each.value.resource_group_name}-vnet"
  location            = each.value.location
  resource_group_name = each.value.resource_group_name
  address_space       = ["10.0.0.0/16"]

  depends_on = [azurerm_resource_group.rgroups]  # 

}

resource "azurerm_subnet" "vm_subnets" {
  for_each            = var.virtual_machines

  name                 = "${each.value.name}-subnet"
  resource_group_name  = each.value.resource_group_name
  virtual_network_name = azurerm_virtual_network.vm_vnets[each.key].name
  address_prefixes     = ["10.0.1.0/24"]

  depends_on           = [azurerm_virtual_network.vm_vnets]
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

resource "azurerm_role_assignment" "attack_path_storage_mi_access" {
  for_each = var.attack_path_storage_mi_abuse_assignments

  scope                = azurerm_storage_account.sas[each.value.storage_account].id
  role_definition_name = "Storage Blob Data Reader"

  principal_id = (
    contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.virtual_machine) ? 
    azurerm_linux_virtual_machine.linux_vms[each.value.virtual_machine].identity[0].principal_id : 
    azurerm_windows_virtual_machine.windows_vms[each.value.virtual_machine].identity[0].principal_id
  )

  depends_on = [azurerm_storage_account.sas, azurerm_linux_virtual_machine.linux_vms, azurerm_windows_virtual_machine.windows_vms]
}

resource "azurerm_role_assignment" "attack_path_kv_access" {
  for_each = var.attack_path_kv_abuse_assignments

  scope                = azurerm_key_vault.kvaults[each.value.key_vault].id
  role_definition_name = "Key Vault Contributor"

  principal_id = (
    each.value.principal_type == "user" ? 
      azuread_user.users[each.value.principal_name].id :
    each.value.principal_type == "service_principal" ? 
      azuread_service_principal.spns[each.value.principal_name].id :
    contains(keys(azurerm_linux_virtual_machine.linux_vms), each.value.virtual_machine) ? 
      azurerm_linux_virtual_machine.linux_vms[each.value.virtual_machine].identity[0].principal_id :
      azurerm_windows_virtual_machine.windows_vms[each.value.virtual_machine].identity[0].principal_id
  )

  depends_on = [
    azurerm_key_vault.kvaults, 
    azurerm_linux_virtual_machine.linux_vms, 
    azurerm_windows_virtual_machine.windows_vms
  ]
}
