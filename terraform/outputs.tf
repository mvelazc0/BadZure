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

# Generic layer: surface the value of any password app_credential by its
# (origin-prefixed) key, so initial-access / compromised identities minted via
# the generic primitives can be reported to the operator.
output "generic_app_credentials" {
  description = "Values of password app_credentials created via the generic layer"
  value = {
    for k, v in azuread_application_password.generic_app_password : k => {
      app_ref       = local.g_app_credentials[k].app_ref
      client_id     = azuread_application_registration.spns[local.g_app_credentials[k].app_ref].client_id
      client_secret = v.value
    }
  }
  sensitive = true
}

# Cosmos account connection info (endpoint + master key) so the Python post-apply
# data-plane phase can upsert cosmos_document data injects. Sensitive: the master
# key grants full data-plane access. Scoped to cosmos_dataplane_refs — only the
# accounts an inject targets — so baseline Cosmos accounts' keys are NOT surfaced
# here. (Note: tfstate still holds every account's primary_key as a resource
# attribute; this scopes the OUTPUT channel, not state.)
output "cosmos_db_connections" {
  description = "Endpoint + primary key for inject-targeted Cosmos accounts only"
  value = {
    for k in var.cosmos_dataplane_refs : k => {
      endpoint    = azurerm_cosmosdb_account.cosmos_dbs[k].endpoint
      primary_key = azurerm_cosmosdb_account.cosmos_dbs[k].primary_key
    }
  }
  sensitive = true
}

# Exposed-host foothold access — public IP + admin credentials for the VMs that are
# an InitialAccessVector entry point, so the operator can log in (RDP/SSH) and pivot
# to the host's managed identity. Scoped to foothold_vm_refs (only intentional
# footholds), and sensitive (carries the admin password). The public IP is only
# allocated at apply time, hence surfaced here rather than read from the tfvars.
output "vm_foothold_access" {
  description = "Public IP + admin credentials for exposed-host foothold VMs"
  value = {
    for k in var.foothold_vm_refs : k => {
      public_ip          = azurerm_public_ip.vm_public_ips[k].ip_address
      admin_username     = var.virtual_machines[k].admin_username
      admin_password     = var.virtual_machines[k].admin_password
      os_type            = var.virtual_machines[k].os_type
      expose_to_internet = var.virtual_machines[k].expose_to_internet
    }
  }
  sensitive = true
}

# Vulnerable-web-app foothold access — the public URL + the command-injectable
# endpoint for the App Services that are an InitialAccessVector entry point, so the
# operator knows where to start. Scoped to webapp_foothold_refs (only intentional
# footholds). Not sensitive: a URL only, no credentials (the app is internet-facing
# and has no host login — the attacker exploits the bug, not a password). The
# default_hostname is only known after apply, hence surfaced here.
output "app_service_foothold_access" {
  description = "Public URL + vuln endpoint for vulnerable-web-app foothold App Services"
  value = {
    for k in var.webapp_foothold_refs : k => {
      url       = "https://${azurerm_linux_web_app.app_services[k].default_hostname}"
      vuln_path = "/diag?host="
    }
  }
}

# app ref -> client_id, so the data-plane phase can resolve app_client_id-material
# injects (the client id is non-sensitive public metadata).
output "application_client_ids" {
  description = "Symbolic app ref -> application (client) id"
  value = {
    for k, v in azuread_application_registration.spns : k => v.client_id
  }
}

# The lab's own id (var.telemetry.lab_id, minted by the builder at build time),
# handed straight back out. This is how `show` and `destroy` (Phase 6) find this
# lab's entry in the telemetry hub's manifest: the lab id round-trips through
# tfvars -> state -> this output, since it is the only thing that survives
# between `build` and `destroy`. Empty string when telemetry is off.
output "telemetry_lab_id" {
  description = "This lab's telemetry lab id (empty when telemetry is off)"
  value       = var.telemetry.lab_id
}

# Every resource id this lab creates that the telemetry hub's manifest cares
# about: everything a diagnostic setting can target, plus the VMs and service
# plans (no diagnostic setting of their own, see TELEMETRY_EXCLUDED_TYPES and
# TELEMETRY_NO_LOG_TYPES, but still part of the lab's footprint the hub tracks). Read regardless of whether telemetry is on,
# since it costs nothing when it is off.
output "lab_resource_ids" {
  description = "Every lab resource id the telemetry hub's manifest tracks"
  value = concat(
    values(local.diag_parent_ids),
    [for v in azurerm_linux_virtual_machine.linux_vms : v.id],
    [for v in azurerm_windows_virtual_machine.windows_vms : v.id],
    [for v in azurerm_service_plan.app_service_plan : v.id],
    [for v in azurerm_service_plan.function_plan : v.id],
  )
}
