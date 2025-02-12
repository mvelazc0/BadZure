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

resource "azuread_application_password" "attack_path_secrets" {
  for_each        = var.attack_path_app_secret_assignments

  application_id  = azuread_application_registration.spns[each.value.app_name].id
  display_name    = "BadZureClientSecret"
  end_date_relative = "8760h" # 1 year

  depends_on = [azuread_application_registration.spns]

}

resource "azurerm_key_vault_secret" "attack_path_secrets" {
  for_each     = var.attack_path_app_secret_assignments

  name         = "client-secret-${each.value.app_name}"
  value        = azuread_application_password.attack_path_secrets[each.key].value
  key_vault_id = azurerm_key_vault.kvaults[each.value.key_vault].id

  depends_on   = [
    azurerm_key_vault.kvaults,
    azuread_application_password.attack_path_secrets
  ]  
}