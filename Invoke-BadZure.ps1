

$banner = @"


____              _  _____                 
| __ )   __ _   __| ||__  /_   _  _ __  ___ 
|  _ \  / _` | / _` |  / /| | | || '__|/ _ \
| |_) || (_| || (_| | / /_| |_| || |  |  __/
|____/  \__,_| \__,_|/____|\__,_||_|   \___|
                                                                            

                By Mauricio Velazco
                            @mvelazco


"@


Function Invoke-BadZure {


    <#

    .DESCRIPTION

    BadZure is a PowerShell script that leverages the Microsft Graph SDK to automate the process of populating an Azure Active Directory environment with various entities such as users, groups, applications, and service principals. It then randomly assigns Azure AD Roles and API Graph permissions to users and service principals enabling the creation of simulated and unique attack paths within a controlled and vulnerable tenant.

    .PARAMETER Build

    Used to populate an Azure AD tenant

    .PARAMETER Destroy

    Used to delete entities created by BadZure on an Azure AD tenant.

    .PARAMETER NoAttackPaths

    Do not install attack paths.

    .PARAMETER Password

    Inital access password set on users.

    .EXAMPLE

    .LINK

    https://github.com/mvelazc0/BadZure/
   
#>

    [CmdletBinding()]

    param
    (
    [Parameter(Mandatory = $false,
        HelpMessage = 'Used to populate an Azure AD tenant.')]
        [switch]$Build,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Used to delete all entities from an Azure AD tenant.')]
        [switch]$Destroy,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Do not install attack paths.')]
        [switch]$NoAttackPaths,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Inital access password set on users.')]
        [String]$Password

    )


    Write-Host $banner

    if($Build -eq $true){

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" | Out-Null

        # create principals
        CreateUsers
        CreateGroups
        CreateApps

        # assign random groups and permissions
        AssignGroups
        AssignUserPerm
        AssignAppRoles
        AssignAppApiPermissions

        # create attack paths
        if($NoAttackPaths -eq $false){

            CreateAttackPath1 $Password
            CreateAttackPath2 $Password
        }
    }
    elseif($Destroy-eq $true){

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" | Out-Null

        DeleteUsers
        DeleteGroups
        DeleteApps
    }
    else{

        Get-Help Invoke-BadZure

    }

}


Function AssignAppRoles (){

    Write-Host [!] Assigning random Azure Ad roles to applications
    $roles = ('Exchange Administrator', 'Security Operator', 'Network Administrator', 'Intune Administrator', 'Attack Simulation Administrator', 'Application Developer', 'Privileged Role Administrator')
    $apps = Import-Csv -Path "Csv\apps.csv"
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
        $appId = (Get-MgApplication -Filter "DisplayName eq '$random_app_dn'").Id
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $appSpId -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
        Write-Host `t[+] Assigned $role to application with displayName $random_app_dn
        $used_apps += $random_app_dn 

    }
    
}

Function AssignAppApiPermissions{


    Write-Host [!] Assigning random Graph API permissions to applications
    $apps = Import-Csv -Path "Csv\apps.csv"
    # RoleManagement.ReadWrite.Directory
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
        $appId = (Get-MgApplication -Filter "DisplayName eq '$random_app_dn'").Id

        $params = @{
            PrincipalId = $appSpId
            ResourceId = $resourceId 
            AppRoleId = $permission
        }
        New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $appSpId -BodyParameter $params | Out-Null
        Write-Host `t[+] Assigned API permissions $permission to application with displayName $random_app_dn
        $used_apps += $random_app_dn 

    }
}


Function AssignUserPerm([string]$Password) {


    Write-Host [!] Assigning random Azure Ad roles to users
    $users = Import-Csv -Path "Csv/users.csv"
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
    $roles = ('Reports Reader', 'Reports Reader', 'Helpdesk Administrator', 'Authentication Administrator', 'Directory Readers', 'Guest Inviter', 'Message Center Reader', 'Groups Administrator')
    foreach ($role in  $roles)
    {
        do
        {
            $random_user = (Get-Random $user_ids)
        }
        until ($used_users -notcontains $random_user)

        $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $random_user -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
        Write-Host `t[+] Assigned $role to user with id $random_user
        $used_users += $random_user 
    }
}

Function UpdatePassword ([String]$userId, [String]$Password) {

    if([string]::IsNullOrEmpty($Password)){

        $randomString = -join ((33..47) + (48..57) + (65..90) + (97..122) + (123..126) | Get-Random -Count 15 | % { [char]$_ })
        $NewPassword = @{}
        $NewPassword["Password"]= $randomString
        $NewPassword["ForceChangePasswordNextSignIn"] = $False
        Update-Mguser -UserId $userId.Trim() -PasswordProfile $NewPassword
        Write-Host `t[+] Updated password for user with id $userId with a random password $randomString.
    }
    else{

        $NewPassword = @{}
        $NewPassword["Password"]= $Password
        $NewPassword["ForceChangePasswordNextSignIn"] = $False
        Update-Mguser -UserId $userId.Trim() -PasswordProfile $NewPassword
        Write-Host `t[+] Updated password for user with id $userId with a cli parameter.
    }

}

Function CreateApps{

    Write-Host [!] Creating application registrations and service principals
    $apps = Import-Csv -Path "Csv\apps.csv"
    foreach ($app in $apps) {

        $new_app= New-MgApplication -DisplayName $app.DisplayName 
        $new_sp= New-MgServicePrincipal -AppId $new_app.Appid
        Write-Host `t[+] Created application with displayname $app.DisplayName and Service Principal $new_sp.Id

    }
}

Function CreateGroups{

    Write-Host [!] Creating Groups
    $groups = Import-Csv -Path "Csv\groups.csv"
    foreach ($group in $groups) {

        $nickName= $group.DisplayName -replace (' ','')
        #$new_group = New-MgGroup -DisplayName $group.DisplayName -MailEnabled:$False -MailNickName $nickName -SecurityEnabled -IsAssignableToRole
        $new_group = New-MgGroup -DisplayName $group.DisplayName -MailEnabled:$False -MailNickName $nickName -SecurityEnabled
        Write-Host `t[+] Created group with displayname $new_group.DisplayName and Id $new_group.Id
    }
}

Function AssignGroups{

    Write-Host [!] Assigning random users to random groups
    $users = Import-Csv -Path "Csv/users.csv"
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

    $groups = Import-Csv -Path "Csv\groups.csv"
    foreach ($group in $groups) {

        $displayName = $group.DisplayName
        $group_id = (Get-MgGroup -Filter "DisplayName eq '$displayName'").Id
        $used_users = @()
        foreach($i in 1..3){
            do
            {
                $random_user = (Get-Random $user_ids)
            }
            until ($used_users -notcontains $random_user)
            New-MgGroupMember -GroupId $group_id -DirectoryObjectId $random_user
            Write-Host `t[+] Added user with Id $random_user to group with id $group_id

            $used_users += $random_user 
        }

    }


}

Function DeleteGroups{

    Write-Host [!] Removing groups
    $groups = Import-Csv -Path "Csv\groups.csv"
    foreach ($group in $groups) {

        $displayName = $group.DisplayName
        $delgroup = Get-MgGroup -Filter "DisplayName eq '$displayName'"
        Remove-MgGroup -GroupId $delgroup.Id
        Write-Host `t[+] Deleted group with displayname $delgroup.DisplayName and Id $delgroup.Id
    }
}

Function CreateUsers{

    Write-Host [!] Creating Users
    $PasswordProfile = @{
        Password = "bmNEe%PA@hw91vIvg7V%"
    }
    
    $users = Import-Csv -Path "Csv\users.csv"
    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)


    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        New-MgUser -DisplayName $displayName -PasswordProfile $PasswordProfile -AccountEnabled -MailNickName $displayName -UserPrincipalName $upn | Out-Null
        Write-Host `t[+] Created User $upn
    }
}

Function DeleteApps{

    Write-Host [!] Removing application registrations

    $apps = Import-Csv -Path "Csv\apps.csv"
    foreach ($app in $apps) {

	    $DisplayName = $app.DisplayName
        $app_id= (Get-MgApplication -Filter "DisplayName eq '$DisplayName'").Id
        Remove-MgApplication -ApplicationId $app_id | Out-Null
        Write-Host `t[+] Deleted application with Id $app_id
    }
}


Function DeleteUsers{

    Write-Host [!] Removing users

    $users = Import-Csv -Path "Csv\users.csv"
    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        Remove-MgUser -UserId $user.Id
        Write-Host `t[+] Deleted user with ObjectId $user.Id
    }
}

Function CreateAttackPath1 ([String]$Password){

    # We have to use the Graph beta based on https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/880
    Write-Host [!] Creating attack path 1

    Select-MgProfile beta
    $directoryRole='Privileged Role Administrator'
    $directoryRoleId= (Get-MgDirectoryRole -Filter "DisplayName eq '$directoryRole'").Id
    $service_principal_id=""
    $service_principals= Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRoleId | where { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.servicePrincipal"}
    Select-MgProfile v1.0

    if ($service_principals -is [Array]){

        $service_principal_id=$service_principals[0].Id
    }

    else {
        $service_principal_id=$service_principals.Id
    }
    

    $displayName= (Get-MgServicePrincipal -Filter "Id eq '$service_principal_id'").DisplayName
    $appId = (Get-MgApplication -Filter "DisplayName eq '$displayName'").Id

    $random_user_id= GetRandomUser
    $NewOwner = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$random_user_id}"
        }
        
    New-MgApplicationOwnerByRef -ApplicationId $appId -BodyParameter $NewOwner
    Write-Host `t[+] Created application owner for $appId 
    UpdatePassword $random_user_id  $Password

}

Function CreateAttackPath2([String]$Password){

    Write-Host [!] Creating attack path 2
    $directoryRole='Helpdesk Administrator'
    $directoryRoleId= (Get-MgDirectoryRole -Filter "DisplayName eq '$directoryRole'").Id
    $user_id=""
    $users = Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRoleId 

    if ($users -is [Array]){

        $user_id=$users[0].Id
    }

    else {
        $user_id=$users.Id
    }
    $NewOwner = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$user_id}"
     }

     $applications = Import-Csv -Path "Csv\apps.csv"
     $service_principal_ids= @()
     foreach ($app in $applications) {
 
         $DisplayName = $app.DisplayName
         $service_principal_ids+=(Get-MgServicePrincipal -Filter "DisplayName eq '$DisplayName'").Id
     }
     
     foreach ($service_principal_id in $service_principal_ids){
        $appRoleId = (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $service_principal_id).AppRoleId
        if ($appRoleId -eq '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8')
        {
            $DisplayName = (Get-MgServicePrincipal -ServicePrincipalId $service_principal_id).DisplayName
            $appId= (Get-MgApplication -Filter "DisplayName eq '$DisplayName'").Id
            New-MgApplicationOwnerByRef -ApplicationId $appId -BodyParameter $NewOwner
            Write-Host `t[+] Created application owner for $appId 
            UpdatePassword $user_id $Password
        }
     }

}


Function GetRandomUser{

    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)
    $users = Import-Csv -Path "Csv/users.csv"
    $user_ids = @()

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        $user_ids +=$user.Id
    }
    $random_userid = (Get-Random $user_ids)
    return $random_userid

}

