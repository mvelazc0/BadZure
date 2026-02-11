output "user_ids" {
  description = "The IDs of the created users"
  value       = [for user in azuread_user.users : user.id]
}

output "group_ids" {
  description = "The IDs of the created groups"
  value       = [for group in azuread_group.groups : group.id]
}

output "application_ids" {
  description = "The IDs of the created applications"
  value       = [for app in azuread_application_registration.spns : app.object_id]
}

output "service_principal_ids" {
  description = "The IDs of the created service principals"
  value       = [for sp in azuread_service_principal.spns : sp.id]
}

output "administrative_unit_ids" {
  description = "The IDs of the created administrative units"
  value       = [for au in azuread_administrative_unit.aunits : au.id]
}

output "compromised_sp_credentials" {
  description = "Credentials for compromised service principal identities"
  value = {
    for k, v in var.attack_path_compromised_sp_credentials : k => {
      app_name      = v.app_name
      client_id     = azuread_application_registration.spns[v.app_name].client_id
      client_secret = azuread_application_password.attack_path_compromised_sp[k].value
    }
  }
  sensitive = true
}
