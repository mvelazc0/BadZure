
Function AssignUserPerm{
    $users = Import-Csv -Path "Lib/users.csv"
    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)
    $user_ids = @()

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        $user_ids +=$user.Id
    }

    $used_users = @()
    $roles = ('Application Administrator')
    foreach ($role in  $roles)
    {
        do
        {
            $random_user = (Get-Random $user_ids)
        }
        until ($used_users -notcontains $random_user)

        $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $random_user -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
        Write-Host [+] Assigned $role to user with id $random_user
        $used_users += $random_user 
    }
}

