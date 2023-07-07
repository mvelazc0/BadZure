

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
        [String]$Password,
    [Parameter(Mandatory = $false,
    HelpMessage = 'Print access tokens for initial access simulation')]
    [Switch]$Token

    )


    Write-Host $banner

    if($Build -eq $true){

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" | Out-Null

        # create principals
        CreateUsers
        CreateGroups
        CreateApps
        CreateAdministrativeUnits

        # assign random groups and permissions
        AssignGroups
        AssignUserPerm
        AssignAppRoles
        AssignAppApiPermissions

        # create attack paths
        if($NoAttackPaths -eq $false){

            CreateAttackPath1 $Password $Token
            CreateAttackPath2 $Password $Token
        }
    }
    elseif($Destroy-eq $true){

        Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory","Group.Read.All" | Out-Null

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

## Create functions

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

Function CreateAdministrativeUnits{

    Write-Host [!] Creating administrative units
    $a_units = Import-Csv -Path "Csv\a_units.csv"
    foreach ($a_unit in $a_units) {

        $params = @{
            displayName = $a_unit.DisplayName
        }
        $new_adunit = New-MgDirectoryAdministrativeUnit -BodyParameter $params
        Write-Host `t[+] Created administrative unit with displayname $new_adunit.DisplayName and Id $new_adunit.Id
    }

}


## Delete functions


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


Function DeleteeAdministrativeUnits{

    Write-Host [!] Removing administrative units
    $a_units = Import-Csv -Path "Csv\a_units.csv"
    foreach ($a_unit in $a_units) {

        $DisplayName = $a_unit.DisplayName
        $admunit_id= (Get-MgDirectoryAdministrativeUnit -Filter "DisplayName eq '$DisplayName'").Id
        Remove-MgDirectoryAdministrativeUnit -AdministrativeUnitId $admunit_id | Out-Null
        Write-Host `t[+] Deleted administrative unit with Id $admunit_id
    }

}


## Assign functions

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




## Attack path functions

Function CreateAttackPath1 ([String]$Password, [Boolean]$Token){

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
    UpdatePassword $random_user_id $Password $Token

    

}

Function CreateAttackPath2([String]$Password, [Boolean]$Token){

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
            UpdatePassword $user_id $Password $Token

        }
     }

}

## Util functions

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
            Write-Host `t[+] Updated password for user $username with random password `"$randomString`"
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
            Write-Host `t[+] Updated password for user $username with password `"$Password`".
        }
        else{
            GetAccessToken $userId $Password
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
    $tokens = Get-CKAccessToken -ClientId 1950a258-227b-4e31-a9cf-717495945fc2 -Resource 'https://graph.microsoft.com/' -TenantId $tenantId  -GrantType password -Username $username -Password $Password
    $access_token = $tokens.access_token 
    $refresh_token = $tokens.refresh_token 
    Write-Host `t`[+] access_token:$access_token
    Write-Host `t`[+] refresh_token:$refresh_token

}


## External Functions

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