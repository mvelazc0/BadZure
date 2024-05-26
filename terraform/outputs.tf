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
