

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

    BadZure is a PowerShell script that leverages the Microsoft Graph SDK to orchestrate the setup of Azure Active Directory environments, populating them with diverse entities while also introducing common security misconfigurations to create vulnerable Azure AD tenants with multiple attack paths.
    
    .PARAMETER Build

    Used to populate and configure an Azure AD tenant

    .PARAMETER Destroy

    Used to delete entities created by BadZure on an Azure AD tenant.

    .PARAMETER TenantId

    Used to specify the Tenant ID for the initial authentication with Azure AD

    .PARAMETER NoAttackPaths

    If set, no attack paths are configured.

    .PARAMETER RandomAttackPath

    If set, only one random attack path is configured.

    .PARAMETER Password

    If set, Passwords will be leveraged for initial access simulation. Can be either random or user defined.

    .PARAMETER Token

    If set, Tokens will be leveraged for initial access simulation.


    .EXAMPLE

    .LINK

    https://github.com/mvelazc0/BadZure/

   
#>

    [CmdletBinding()]

    param
    (
    [Parameter(Mandatory = $false)]
        [switch]$Build,
    [Parameter(Mandatory = $false)]
        [switch]$Destroy,
    [Parameter(Mandatory = $false)]
        [switch]$NoAttackPaths,
    [Parameter(Mandatory = $false)]
        [String]$Password,
    [Parameter(Mandatory = $false)]
        [Switch]$Token,
    [Parameter(Mandatory = $false)]
        [Switch]$RandomAttackPath,
    [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [string]$TenantId

    )
    $Verbose = $false
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent){$Verbose = $true}
    
    Write-Host $banner

    if($Build -eq $true){

        

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" -TenantId $TenantId | Out-Null #Added the -TenantId parameter here

        CheckDomain
        # create principals
        CreateUsers 
        CreateGroups
        CreateApps 
        CreateAdministrativeUnits 

        # assign random groups and permissions
        AssignGroups 
        AssignUserRoles 
        AssignAppRoles 
        AssignAppApiPermissions

        # create attack paths
        if($NoAttackPaths -eq $false){

            # choose a random attack path
            if ($RandomAttackPath -eq $true)
            {
                $path = Get-Random (1,3)
                Switch ($path){
                    1 {CreateAttackPath1 $Password $Token}
                    2 {CreateAttackPath2 $Password $Token}
                    3 {CreateAttackPath3 $Password $Token}

                }
            }
            else
            {
                CreateAttackPath1 $Password $Token
                CreateAttackPath2 $Password $Token
                CreateAttackPath3 $Password $Token
                $global:attackpath_apps =@()
            }    
        }
    }
    elseif($Destroy-eq $true){

        

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" -TenantId $TenantId | Out-Null #Added the -TenantId parameter here 

        CheckDomain
        # remove principals
        DeleteUsers
        DeleteGroups 
        DeleteApps 
        DeleteeAdministrativeUnits 
    }
    else{

        Get-Help Invoke-BadZure

    }

}

## Global var

$global:attackpath_apps = @()
$global:tenantDomain = ""

## Create functions

Function CheckDomain([Boolean]$Verbose) {


    $account = (Get-MgContext | Select-Object Account).Account
    if ([string]::IsNullorEmpty($account) -eq $false){ 
        $pos=$account.IndexOf('@')
        $global:tenantDomain = $account.Substring($pos+1) 
    }
    else {
        $global:tenantDomain = Read-Host -Prompt "Enter your tenant's domain name. Example badzure.com" 
    }

}


Function CreateUsers([Boolean]$Verbose) {

    Write-Host [!] Creating Users
    # set a random password for each user
    $randomString = -join ((33..47) + (48..57) + (65..90) + (97..122) + (123..126) | Get-Random -Count 15 | % { [char]$_ })
    $PasswordProfile = @{
        Password = $randomString
    }
    
    $users = Import-Csv -Path "Csv\users.csv"
    <#
    $checkdomain = (Get-MgContext | Select-Object Account).Account
    #if $checkdomain has a value, use it as part of the newly created users' email addresses
    if ([string]::IsNullorEmpty($checkdomain) -eq $false){ 
        $checkdomain = $account
    }
    #if get-mgcontext does not have the .account, ask them to enter their domain in the form of an email. code flow proceeds. 
    else{ 
        $account = Read-Host -Prompt "Enter a verified email domain in the format hello@emaildomain"
    }
     
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1) 
    #>
    $upns=@()


    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        #$upn = -join($displayName,'@',$domain)
        $upn = -join($displayName,'@',$global:tenantDomain)
        $upns+=$upn
        New-MgUser -DisplayName $displayName -PasswordProfile $PasswordProfile -AccountEnabled -MailNickName $displayName -UserPrincipalName $upn | Out-Null
        Write-Verbose "`t[+] Created User $upn"
    }
    $upns | Out-File -FilePath users.txt
}

Function CreateApps([Boolean]$Verbose){

    Write-Host [!] Creating application registrations and service principals
    $apps = Import-Csv -Path "Csv\apps.csv"
    foreach ($app in $apps) {

        $new_app= New-MgApplication -DisplayName $app.DisplayName 
        $new_sp= New-MgServicePrincipal -AppId $new_app.Appid
        Write-Verbose "`t[+] Created application with displayname $($app.DisplayName) and Service Principal $($new_sp.Id)"

    }
}

Function CreateGroups([Boolean]$Verbose){

    Write-Host [!] Creating Groups
    $groups = Import-Csv -Path "Csv\groups.csv"
    foreach ($group in $groups) {

        $nickName= $group.DisplayName -replace (' ','')
        #$new_group = New-MgGroup -DisplayName $group.DisplayName -MailEnabled:$False -MailNickName $nickName -SecurityEnabled -IsAssignableToRole
        $new_group = New-MgGroup -DisplayName $group.DisplayName -MailEnabled:$False -MailNickName $nickName -SecurityEnabled
        Write-Verbose "`t[+] Created group with displayname $($new_group.DisplayName) and Id $($new_group.Id)"

    }
}

Function CreateAdministrativeUnits([Boolean]$Verbose){

    Write-Host [!] Creating administrative units
    $a_units = Import-Csv -Path "Csv\a_units.csv"
    foreach ($a_unit in $a_units) {

        $params = @{
            displayName = $a_unit.DisplayName
        }
        $new_adunit = New-MgDirectoryAdministrativeUnit -BodyParameter $params
        Write-Verbose "`t[+] Created administrative unit with displayname $($new_adunit.DisplayName) and Id $($new_adunit.Id)"
    }

}


## Delete functions


Function DeleteGroups([Boolean]$Verbose){

    Write-Host [!] Removing groups
    $groups = Import-Csv -Path "Csv\groups.csv"
    foreach ($group in $groups) {

        $displayName = $group.DisplayName
        $groups = Get-MgGroup -Filter "DisplayName eq '$displayName'"

        # in case groups were created more than once
        if ($groups -is [Array]) {
            foreach ($group in $groups){
                
                Remove-MgGroup -GroupId $group.Id
                Write-Verbose "`t[+] Deleted group with displayname $($group.DisplayName) and Id $($group.Id)"

            }
        }
        else {
            Remove-MgGroup -GroupId $($groups.Id)
            Write-Verbose "`t[+] Deleted group with displayname $($groups.DisplayName) and Id $($groups.Id)"
        }

    }
}



Function DeleteApps([Boolean]$Verbose){

    Write-Host [!] Removing application registrations

    $apps = Import-Csv -Path "Csv\apps.csv"
    foreach ($app in $apps) {

	    $DisplayName = $app.DisplayName
        $app_ids= (Get-MgApplication -Filter "DisplayName eq '$DisplayName'").Id

        # in case apps were created more than once
        if ($app_ids -is [Array]) {
            foreach ($app_id in $app_ids){
                Remove-MgApplication -ApplicationId $app_id | Out-Null
                Write-Verbose "`t[+] Deleted application with Id $app_id"

            }
        }
        else {
            Remove-MgApplication -ApplicationId $app_ids | Out-Null
            Write-Verbose "`t[+] Deleted application with Id $app_ids"
        }

    }
}


Function DeleteUsers([Boolean]$Verbose){

    Write-Host [!] Removing users

    $users = Import-Csv -Path "Csv\users.csv"
    <#
    $checkdomain = (Get-MgContext | Select-Object Account).Account
    #if $checkdomain has a value, use it as part of the newly created users' email addresses
    if ([string]::IsNullorEmpty($checkdomain) -eq $false){ 
        $checkdomain = $account
    }
    #if get-mgcontext does not have the .account, ask them to enter their domain in the form of an email. code flow proceeds. 
    else{ 
        $account = Read-Host -Prompt "Enter a verified email domain in the format hello@emaildomain"
    }
     
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1) 
    #>

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)

        #$upn = -join($displayName,'@',$domain)
        $upn = -join($displayName,'@',$global:tenantDomain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        Remove-MgUser -UserId $user.Id
        Write-Verbose "`t[+] Deleted user with ObjectId $($user.Id)"
    }
}


Function DeleteeAdministrativeUnits([Boolean]$Verbose){

    Write-Host [!] Removing administrative units
    $a_units = Import-Csv -Path "Csv\a_units.csv"
    foreach ($a_unit in $a_units) {

        $DisplayName = $a_unit.DisplayName
        $admunit_ids= (Get-MgDirectoryAdministrativeUnit -Filter "DisplayName eq '$DisplayName'").Id

        # in case adm units were created more than once
        if ($admunit_ids -is [Array]) {
            foreach ($admunit_id in $admunit_ids){
                
                Remove-MgDirectoryAdministrativeUnit -AdministrativeUnitId $admunit_id | Out-Null
                Write-Verbose "`t[+] Deleted administrative unit with Id $admunit_id"

            }
        }
        else {
            Remove-MgDirectoryAdministrativeUnit -AdministrativeUnitId $admunit_ids| Out-Null
            Write-Verbose "`t[+] Deleted administrative unit with Id $admunit_ids"
        }
    }
}


## Assign functions

Function AssignGroups([Boolean]$Verbose){

    Write-Host [!] Assigning random users to random groups
    $users = Import-Csv -Path "Csv/users.csv"
    <#
    $checkdomain = (Get-MgContext | Select-Object Account).Account
    #if $checkdomain has a value, use it as part of the newly created users' email addresses
    if ([string]::IsNullorEmpty($checkdomain) -eq $false){ 
        $checkdomain = $account
    }
    #if get-mgcontext does not have the .account, ask them to enter their domain in the form of an email. code flow proceeds. 
    else{ 
        $account = Read-Host -Prompt "Enter a verified email domain in the format hello@emaildomain"
    }
     
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1) 
    #>

    $user_ids = @()

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        #$upn = -join($displayName,'@',$domain)
        $upn = -join($displayName,'@',$global:tenantDomain)
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
            Write-Verbose "`t[+] Added user with Id $random_user to group with id $group_id"

            $used_users += $random_user 
        }

    }

}


Function AssignAppRoles([Boolean]$Verbose){

    Write-Host [!] Assigning random Azure Ad roles to applications
    $roles = ('Exchange Administrator', 'Security Operator', 'Network Administrator', 'Intune Administrator', 'Attack Simulation Administrator', 'Application Developer')
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
        Write-Verbose "`t[+] Assigned $role to application with displayName $random_app_dn"
        $used_apps += $random_app_dn 

    }
    
}

Function AssignAppApiPermissions([Boolean]$Verbose){


    Write-Host [!] Assigning random Graph API permissions to applications
    $apps = Import-Csv -Path "Csv\apps.csv"

    $permissions = ('d07a8cc0-3d51-4b77-b3b0-32704d1f69fa', '134fd756-38ce-4afd-ba33-e9623dbe66c2', '93283d0a-6322-4fa8-966b-8c121624760d', '798ee544-9d2d-430c-a058-570e29e34338', '6b7d71aa-70aa-4810-a8d9-5d9fb2830017', '7e05723c-0bb0-42da-be95-ae9f08a6e53c' ,'4f5ac95f-62fd-472c-b60f-125d24ca0bc5' , 'eedb7fdd-7539-4345-a38b-4839e4a84cbd')
    # 06da0dbc-49e2-44d2-8312-53f166ab848a
    # eda39fa6-f8cf-4c3c-a909-432c683e4c9b
    # eda39fa6-f8cf-4c3c-a909-432c683e4c9b
    # 6323133e-1f6e-46d4-9372-ac33a0870636


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
        Write-Verbose "`t[+] Assigned API permissions $permission to application with displayName $random_app_dn"
        $used_apps += $random_app_dn 

    }
}


Function AssignUserRoles([string]$Password, [Boolean]$Verbose) {


    Write-Host [!] Assigning random Azure Ad roles to users
    $users = Import-Csv -Path "Csv/users.csv"
    <#
    $checkdomain = (Get-MgContext | Select-Object Account).Account
    #if $checkdomain has a value, use it as part of the newly created users' email addresses
    if ([string]::IsNullorEmpty($checkdomain) -eq $false){ 
        $checkdomain = $account
    }
    #if get-mgcontext does not have the .account, ask them to enter their domain in the form of an email. code flow proceeds. 
    else{ 
        $account = Read-Host -Prompt "Enter a verified email domain in the format hello@emaildomain"
    }
     
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1) 
    #>

    $user_ids = @()

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        #$upn = -join($displayName,'@',$domain)
        $upn = -join($displayName,'@',$global:tenantDomain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        $user_ids +=$user.Id
    }

    $used_users = @()
    $roles = ('Reports Reader', 'Reports Reader', 'Authentication Administrator', 'Directory Readers', 'Guest Inviter', 'Message Center Reader', 'Groups Administrator', 'Guest Inviter', 'Network Administrator')
    foreach ($role in  $roles)
    {
        do
        {
            $random_user = (Get-Random $user_ids)
        }
        until ($used_users -notcontains $random_user)

        $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $random_user -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
        Write-Verbose "`t[+] Assigned $role to user with id $random_user"
        $used_users += $random_user 
    }
}




## Attack path functions

Function CreateAttackPath1 ([String]$Password, [Boolean]$Token){

    Write-Host [!] Creating attack path 1

    <#
    We have to use the Graph beta based on https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/880
    Select-MgProfile beta -Verbose:$false
    $directoryRole='Privileged Role Administrator'
    $directoryRoleId= (Get-MgDirectoryRole -Filter "DisplayName eq '$directoryRole'").Id
    $service_principal_id=""
    $service_principals= Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRoleId | where { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.servicePrincipal"}
    Select-MgProfile v1.0 -Verbose:$false
    #>

    $role = "Privileged Role Administrator"
    $apps = Import-Csv -Path "Csv\apps.csv"

    Do 
    {
        $random_app_dn = (Get-Random $apps).DisplayName
        $appSpId = (Get-MgServicePrincipal -Filter "DisplayName eq '$random_app_dn'").Id
        $appId = (Get-MgApplication -Filter "DisplayName eq '$random_app_dn'").Id
    }
    While ($global:attackpath_apps -contains $appId )

    $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $appSpId -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
    Write-Verbose "`t[+] Assigned $role to application with displayName $random_app_dn"
    $random_user_id= GetRandomUser
    $NewOwner = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$random_user_id}"
        }
        
    New-MgApplicationOwnerByRef -ApplicationId $appId -BodyParameter $NewOwner
    Write-Verbose "`t[+] Created application owner for $appId"
    $global:attackpath_apps+=$appId
    UpdatePassword $random_user_id $Password $Token

    

}

Function CreateAttackPath2([String]$Password, [Boolean]$Token){

    Write-Host [!] Creating attack path 2
    
    $random_user_id = GetRandomUser
    $role= 'Helpdesk Administrator'
    $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $random_user_id -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
    Write-Verbose "`t[+] Assigned $role to user with id $random_user_id"
    
    $NewOwner = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/$random_user_id"
     }


     <#
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
            UpdatePassword $user_id $Password $Token

        }
     #>

    # RoleManagement.ReadWrite.Directory
    $permission = ('9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8')
    $apps = Import-Csv -Path "Csv\apps.csv"

    Do 
    {
        $random_app_dn = (Get-Random $apps).DisplayName
        $appSpId = (Get-MgServicePrincipal -Filter "DisplayName eq '$random_app_dn'").Id
        $appId = (Get-MgApplication -Filter "DisplayName eq '$random_app_dn'").Id
    }
    While ($global:attackpath_apps -contains $appId )

    $resourceId = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property "id,displayName,appId,appRoles").Id

    $params = @{
        PrincipalId = $appSpId
        ResourceId = $resourceId 
        AppRoleId = $permission
    }
    
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $appSpId -BodyParameter $params | Out-Null
    Write-Verbose "[+] Assigned API permissions $permission to application with displayName $random_app_dn"
    New-MgApplicationOwnerByRef -ApplicationId $appId -BodyParameter $NewOwner
    Write-Verbose "[+] Created application owner for $appId"
    $global:attackpath_apps+=$appId
    UpdatePassword $random_user_id $Password $Token

}

Function CreateAttackPath3([String]$Password, [Boolean]$Token){

    Write-Host [!] Creating attack path3
    
    $random_user_id = GetRandomUser
    $role= 'User Administrator'
    $roleDefinitionId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $random_user_id -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/" | Out-Null
    Write-Verbose "`t[+] Assigned $role to user with id $random_user_id"
     

    <#
    $directoryRole='User Administrator'
    $directoryRoleId= (Get-MgDirectoryRole -Filter "DisplayName eq '$directoryRole'").Id
    $user_id=""
    $users = Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRoleId 

    if ($users -is [Array]){

        $user_id=$users[0].Id
    }

    else {
        $user_id=$users.Id
    }
    #>

    $NewOwner = @{
        "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/$random_user_id"
     }


    # AppRoleAssignment.ReadWrite.All
    $permission = ('06b708a9-e830-4db3-a914-8e69da51d44f')
    $apps = Import-Csv -Path "Csv\apps.csv"

    Do 
    {
        $random_app_dn = (Get-Random $apps).DisplayName
        $appSpId = (Get-MgServicePrincipal -Filter "DisplayName eq '$random_app_dn'").Id
        $appId = (Get-MgApplication -Filter "DisplayName eq '$random_app_dn'").Id
    }
    While ($global:attackpath_apps -contains $appId )

    $resourceId = (Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property "id,displayName,appId,appRoles").Id

    $params = @{
        PrincipalId = $appSpId
        ResourceId = $resourceId 
        AppRoleId = $permission
    }
    
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $appSpId -BodyParameter $params | Out-Null
    Write-Verbose "`t[+] Assigned API permissions $permission to application with displayName $random_app_dn"
    New-MgApplicationOwnerByRef -ApplicationId $appId -BodyParameter $NewOwner
    Write-Verbose "`t[+] Created application owner for $appId"
    $global:attackpath_apps+=$appId
    UpdatePassword $random_user_id $Password $Token

}


## Util functions

Function GetRandomUser{

    <#
    $checkdomain = (Get-MgContext | Select-Object Account).Account
    #if $checkdomain has a value, use it as part of the newly created users' email addresses
    if ([string]::IsNullorEmpty($checkdomain) -eq $false){ 
        $checkdomain = $account
    }
    #if get-mgcontext does not have the .account, ask them to enter their domain in the form of an email. code flow proceeds. 
    else{ 
        $account = Read-Host -Prompt "Enter a verified email domain in the format hello@emaildomain"
    }
     
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1) 
    #>

    $users = Import-Csv -Path "Csv/users.csv"
    $user_ids = @()

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        #$upn = -join($displayName,'@',$domain)
        $upn = -join($displayName,'@',$global:tenantDomain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        $user_ids +=$user.Id
    }
    $random_userid = (Get-Random $user_ids)
    return $random_userid

}


Function UpdatePassword ([String]$userId, [String]$Password, [Boolean]$Token) {

    if([string]::IsNullOrEmpty($Password)){

        $randomString = -join ((33..47) + (48..57) + (65..90) + (97..122) + (123..126) | Get-Random -Count 15 | % { [char]$_ })
        $NewPassword = @{}
        $NewPassword["Password"]= $randomString
        $NewPassword["ForceChangePasswordNextSignIn"] = $False
        Update-Mguser -UserId $userId.Trim() -PasswordProfile $NewPassword
        $username = (Get-MgUser -Filter "Id eq '$userId'").UserPrincipalName

        if ($Token -eq $false)
        {
            Write-Host `t[+] `"$randomString`" assigned as password to random user.
            Write-Verbose  "t[+] $username"

        }
        else{
            GetAccessToken2 $userId $randomString
        }
        
    }
    else{

        $NewPassword = @{}
        $NewPassword["Password"]= $Password
        $NewPassword["ForceChangePasswordNextSignIn"] = $False
        Update-Mguser -UserId $userId.Trim() -PasswordProfile $NewPassword
        $username = (Get-MgUser -Filter "Id eq '$userId'").UserPrincipalName
        if ($Token -eq $false)
        {
            Write-Host `t[+] `"$Password`" assigned as password to random user.
            Write-Verbose "`t[+] $username"
        }
        else{
            GetAccessToken2 $userId $Password
        }

    }

}

Function GetAccessToken ([String]$userId, [String]$Password) {

    Write-Host `t`[!] Obtaining user access token
    $username = (Get-MgUser -Filter "Id eq '$userId'").UserPrincipalName
    $SecurePassword = ConvertTo-SecureString “$Password” -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential($username, $SecurePassword)
    Connect-AzAccount -Credential $credentials | Out-Null
    Write-Host `t`[+] Access token for $username :
    Write-Host `t` (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

}

Function GetAccessToken2 ([String]$userId, [String]$Password) {

    Write-Host `t`[!] Obtaining access and refresh tokens for $username
    $username = (Get-MgUser -Filter "Id eq '$userId'").UserPrincipalName
    $tenantId = (Get-MgContext).TenantId
    $tokens = Get-CKAccessToken -ClientId 1950a258-227b-4e31-a9cf-717495945fc2 -Resource 'https://graph.microsoft.com/' -TenantId $tenantId  -GrantType password -Username $username -Password $Password -Verbose:$false
    $access_token = $tokens.access_token 
    $refresh_token = $tokens.refresh_token 
    Write-Host `t`[+] access_token:$access_token
    Write-Host `t`[+] refresh_token:$refresh_token

}


## External Functions

## credtis to Roberto Rodriguez for this function https://github.com/Azure/Cloud-Katana/blob/main/CloudKatanaAbilities/AzureAD/Authentication/Get-CKAccessToken.ps1
function Get-CKAccessToken {
    <#
    .SYNOPSIS
    A PowerShell script to get a MS graph access token with a specific grant type and Azure AD application.
    
    Author: Roberto Rodriguez (@Cyb3rWard0g)
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    Get-CKAccessToken is a simple PowerShell wrapper around the Microsoft Graph API to get an access token. 

    .PARAMETER ClientId
    The Application (client) ID assigned to the Azure AD application.

    .PARAMETER TenantId
    Tenant ID. Can be /common, /consumers, or /organizations. It can also be the directory tenant that you want to request permission from in GUID or friendly name format.

    .PARAMETER ResourceUrl
    Resource url for what you're requesting token. This could be one of the Azure services that support Azure AD authentication or any other resource URI. Example: https://graph.microsoft.com/

    .PARAMETER GrantType
    The type of token request.

    .PARAMETER Username
    Username used for Password grant type.

    .PARAMETER Password
    Password used for Password grant type.

    .PARAMETER SamlToken
    SAML token used for SAML token grant type.

    .PARAMETER DeviceCode
    The device_code returned in the device authorization request.

    .PARAMETER AppSecret
    if the application requires a client secret, then use this parameter.

    .LINK
    https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-overview

    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String] $ClientId,

        [Parameter(Mandatory = $false)]
        [string] $TenantId,

        [Parameter(Mandatory = $false)]
        [string] $Resource = 'https://graph.microsoft.com/',

        [Parameter(Mandatory=$true)]
        [ValidateSet("client_credentials","password","saml_token","device_code","refresh_token")]
        [string] $GrantType,

        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string] $AppSecret
    )
    DynamicParam {
        if ($GrantType) {
            # Adding Dynamic parameters
            if ($GrantType -eq 'password') {
                $ParamOptions = @(
                    @{
                    'Name' = 'Username';
                    'Mandatory' = $true
                    },
                    @{
                    'Name' = 'Password';
                    'Mandatory' = $true
                    }
                )
            }
            elseif ($GrantType -eq 'saml_token') {
                $ParamOptions = @(
                    @{
                    'Name' = 'SamlToken';
                    'Mandatory' = $true
                    }
                )  
            }
            elseif ($GrantType -eq 'device_code') {
                $ParamOptions = @(
                    @{
                    'Name' = 'DeviceCode';
                    'Mandatory' = $true
                    }
                )  
            }
            elseif ($GrantType -eq 'refresh_token') {
                $ParamOptions = @(
                    @{
                    'Name' = 'RefreshToken';
                    'Mandatory' = $true
                    }
                )  
            }

            # Adding Dynamic parameter
            $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            foreach ($Param in $ParamOptions) {
                $RuntimeParam = New-DynamicParam @Param
                $RuntimeParamDic.Add($Param.Name, $RuntimeParam)
            }
            return $RuntimeParamDic
        }
    }
    begin {
        # Force TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Process Tenant ID
        if (!$TenantId) {
            $TenantId = 'common'
        }

        # Process Dynamic parameters
        $PsBoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue'}
    }
    process {
        # Initialize Headers dictionary
        $headers = @{}
        $headers.Add('Content-Type','application/x-www-form-urlencoded')

        # Initialize Body
        $body = @{}
        $body.Add('resource',$Resource)
        $body.Add('client_id',$ClientId)

        if ($GrantType -eq 'client_credentials') {
            $body.Add('grant_type','client_credentials')
        }
        elseif ($GrantType -eq 'password') {
            $body.Add('username',$Username)
            $body.Add('password',$Password)
            $body.Add('grant_type','password')
        }
        elseif ($GrantType -eq 'saml_token') {
            $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SamlToken))
            $body.Add('assertion',$encodedSamlToken)
            $body.Add('grant_type','urn:ietf:params:oauth:grant-type:saml1_1-bearer')
            $body.Add('scope','openid')
        }
        elseif ($GrantType -eq 'device_code') {
            $body.Add('grant_type','urn:ietf:params:oauth:grant-type:device_code')
            $body.Add('code',$DeviceCode)
        }
        elseif ($GrantType -eq 'refresh_token') {
            $body.Add('refresh_token',$RefreshToken)
            $body.Add('grant_type','refresh_token')
            $body.Add('scope','openid')
        }

        if ($AppSecret)
        {
            $body.Add('client_secret',$AppSecret)
        }

        $Params = @{
            Headers = $headers
            uri     = "https://login.microsoftonline.com/$TenantId/oauth2/token?api-version=1.0"
            Body    = $body
            method  = 'Post'
        }
        $request  = Invoke-RestMethod @Params
    
        # Process authentication request
        if($null -eq $request) {
            throw "Token never received from AAD"
        }
        else {
            $request
        }
    }
}

function New-DynamicParam {
    [CmdletBinding()]
    [OutputType('System.Management.Automation.RuntimeDefinedParameter')]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [array]$ValidateSetOptions,
        [Parameter()]
        [switch]$Mandatory = $false,
        [Parameter()]
        [switch]$ValueFromPipeline = $false,
        [Parameter()]
        [switch]$ValueFromPipelineByPropertyName = $false
    )

    $Attrib = New-Object System.Management.Automation.ParameterAttribute
    $Attrib.Mandatory = $Mandatory.IsPresent
    $Attrib.ValueFromPipeline = $ValueFromPipeline.IsPresent
    $Attrib.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName.IsPresent

    # Create AttributeCollection object for the attribute
    $Collection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
    # Add our custom attribute
    $Collection.Add($Attrib)
    # Add Validate Set
    if ($ValidateSetOptions)
    {
        $ValidateSet= new-object System.Management.Automation.ValidateSetAttribute($Param.ValidateSetOptions)
        $Collection.Add($ValidateSet)
    }

    # Create Runtime Parameter
    $DynParam = New-Object System.Management.Automation.RuntimeDefinedParameter($Param.Name, [string], $Collection)
    $DynParam
}
