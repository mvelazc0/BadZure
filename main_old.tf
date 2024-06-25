provider "azuread" {
  version = "1.6.0"
}

resource "azuread_user" "example" {
  for_each = var.users

  user_principal_name = each.value.user_principal_name
  display_name        = each.value.display_name
  mail_nickname       = each.value.mail_nickname
  password            = each.value.password
}

resource "azuread_group" "example" {
  for_each = var.groups

  display_name     = each.value.display_name
  mail_nickname    = each.value.mail_nickname
  security_enabled = each.value.security_enabled
}

resource "azuread_application" "example" {
  for_each = var.applications

  display_name = each.value.display_name
}

resource "azuread_service_principal" "example" {
  for_each = azuread_application.example

  application_id = each.value.application_id
}

resource "azuread_app_role_assignment" "example" {
  for_each = var.role_assignments

  principal_object_id            = each.value.principal_object_id
  app_role_id                    = each.value.app_role_id
  resource_service_principal_id  = each.value.resource_service_principal_id
}
