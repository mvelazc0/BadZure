terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.50.0"
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

resource "azuread_directory_role_assignment" "attack_path_1_role_assignment" {
  for_each = var.attack_path_1_assignments

  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  role_id             = each.value.role_id
}

resource "azuread_application_owner" "attack_path_1_app_owner" {
  for_each = var.attack_path_1_assignments

  #application_id = azuread_application_registration.spns[each.value.app_name].object_id
  application_id = "/applications/${azuread_application_registration.spns[each.value.app_name].object_id}"
  owner_object_id       = azuread_user.users[replace(each.value.user_principal_name, "@${var.domain}", "")].object_id
}


#resource "azuread_user" "attack_path_1_user_password" {
#  for_each = var.attack_path_1_assignments

#  user_principal_name = each.value.user_principal_name
#  display_name        = each.value.display_name
#  password            = each.value.password
#  force_password_change = false
#}

resource "null_resource" "update_password" {
  for_each = var.attack_path_1_assignments

  provisioner "local-exec" {
    command = <<EOT
      echo "Updating password for ${each.value.user_principal_name}"
      az ad user update --id ${each.value.user_principal_name} --password "${each.value.password}" --force-change-password-next-sign-in false
    EOT

    environment = {
      AZURE_CONFIG_DIR = "${var.azure_config_dir}"
    }
  }
  depends_on = [azuread_user.users]
}

resource "azuread_app_role_assignment" "attack_path_2_api_permission" {
  for_each = var.attack_path_2_assignments

  app_role_id            = each.value.api_permission_id
  principal_object_id    = azuread_service_principal.spns[each.value.app_name].id
  resource_object_id     = data.azuread_service_principal.microsoft_graph.id
}

resource "azuread_application_owner" "attack_path_2_app_owner" {
  for_each = var.attack_path_2_assignments

  application_id    = "/applications/${azuread_application_registration.spns[each.value.app_name].object_id}"
  owner_object_id   = azuread_user.users[replace(each.value.user_principal_name, "@${var.domain}", "")].object_id
}

resource "null_resource" "update_password_2" {
  for_each = var.attack_path_2_assignments

  provisioner "local-exec" {
    command = <<EOT
      echo "Updating password for ${each.value.user_principal_name}"
      az ad user update --id ${each.value.user_principal_name} --password "${each.value.password}" --force-change-password-next-sign-in false
    EOT

    environment = {
      AZURE_CONFIG_DIR = "${var.azure_config_dir}"
    }
  }
  depends_on = [azuread_user.users]
}

data "azuread_service_principal" "microsoft_graph" {
  display_name = "Microsoft Graph"
}

resource "azuread_app_role_assignment" "attack_path_3_api_permission" {
  for_each = var.attack_path_3_assignments

  principal_object_id = azuread_service_principal.spns[each.value.app_name].id
  app_role_id         = each.value.api_permission_id
  resource_object_id         = data.azuread_service_principal.microsoft_graph.id

}

resource "azuread_application_owner" "attack_path_3_app_owner" {
  for_each = var.attack_path_3_assignments

  application_id    = "/applications/${azuread_application_registration.spns[each.value.app_name].object_id}"
  owner_object_id   = azuread_user.users[replace(each.value.owner_user_principal_name, "@${var.domain}", "")].object_id
}

resource "azuread_directory_role_assignment" "attack_path_3_role_assignment" {
  for_each = var.attack_path_3_assignments

  principal_object_id = azuread_user.users[replace(each.value.helpdesk_user_principal_name, "@${var.domain}", "")].object_id
  role_id             = each.value.role_id
}

resource "null_resource" "update_password_3" {
  for_each = var.attack_path_3_assignments

  provisioner "local-exec" {
    command = <<EOT
      echo "Updating password for ${each.value.helpdesk_user_principal_name}"
      az ad user update --id ${each.value.helpdesk_user_principal_name} --password "${each.value.password}" --force-change-password-next-sign-in false --debug
    EOT

    environment = {
      AZURE_CONFIG_DIR = "${var.azure_config_dir}"
    }
  }
  depends_on = [azuread_user.users]
}


