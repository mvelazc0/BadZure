terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.15.0"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

data "azuread_domains" "example" {
  only_initial = true
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

resource "azuread_application" "spns" {
  for_each = var.applications

  display_name = each.value.display_name
}

resource "azuread_service_principal" "spns" {
  for_each = var.applications

  application_id = azuread_application.spns[each.key].application_id
}

resource "azuread_administrative_unit" "aunits" {
  for_each = var.administrative_units

  display_name = each.value.display_name
}

resource "azuread_group_member" "group_membership" {
  for_each = var.user_group_assignments

  group_object_id = azuread_group.groups[each.value.group_name].id
  member_object_id = azuread_user.users[each.value.user_name].id
}

resource "azuread_administrative_unit_member" "au_membership" {
  for_each = var.user_au_assignments

  administrative_unit_object_id = azuread_administrative_unit.aunits[each.value.administrative_unit_name].id
  member_object_id = azuread_user.users[each.value.user_name].id
}
