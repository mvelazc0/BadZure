
Function AssignAppRoles{
    
    $roles = ('Exchange Administrator', 'Security Operator', 'Network Administrator', 'Intune Administrator', 'Attack Simulation Administrator', 'Application Developer')
    $apps = Import-Csv -Path "Lib\apps.csv"
    $used_apps =@()
    foreach ($role in  $roles)
    {
        do
        {
            $random_app_dn = (Get-Random $apps).DisplayName
        }
        until ($used_apps -notcontains $random_app_dn)

        $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
        $appSpId = (Get-MgServicePrincipal -Filter "DisplayName eq '$random_app_dn'").Id
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $appSpId -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
        Write-Host [+] Assigned $role to application with displayName $random_app_dn
        $used_apps += $random_app_dn 
    }
    
}

Function AssignAppApiPermissions{

    $apps = Import-Csv -Path "Lib\apps.csv"
    $permissions = ('9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8')
    $used_apps =@()

    foreach ($permission in  $permissions)
    {
        do
        {
            $random_app_dn = (Get-Random $apps).DisplayName
        }
        until ($used_apps -notcontains $random_app_dn)

        $resourceId = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property "id,displayName,appId,appRoles").Id
        $appSpId = (Get-MgServicePrincipal -Filter "DisplayName eq '$random_app_dn'").Id

        $params = @{
            PrincipalId = $appSpId
            ResourceId = $resourceId 
            AppRoleId = $permission
        }
        New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $appSpId -BodyParameter $params | Out-Null
        Write-Host [+] Assigned API permissions $permission to application with displayName $random_app_dn
        $used_apps += $random_app_dn 
    }
}