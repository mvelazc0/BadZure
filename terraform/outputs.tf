output "user_ids" {
  value = [for user in azuread_user.example : user.id]
}
