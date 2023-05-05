<#
    .Synopsis

    .DESCRIPTION

    .EXAMPLE

    .OUTPUTS
    
    .NOTES

    .FUNCTIONALITY

    .LINK
   
#>

[CmdletBinding()]

param
(
   [Parameter(Mandatory = $false,
      Position = 1,
      HelpMessage = 'Build')]
   [switch]$Build,
   [Parameter(Mandatory = $false,
   Position = 1,
   HelpMessage = 'Destroy')]
   [switch]$Destroy
)

if($Build -eq $true){

    . Lib/CreateUsers.ps1
    . Lib/CreateApps.ps1
    . Lib/AssignAppPerm.ps1
    . Lib/AssignUserPerm.ps1
    
    Connect-Graph -Scopes "Application.ReadWrite.All", "Directory.AccessAsUser.All","EntitlementManagement.ReadWrite.All","RoleManagement.ReadWrite.Directory"

    Write-Host I will build !
    CreateUsers
    CreateApps
    AssignAppPermissions
    AssignUserPerm



}

elseif($Destroy-eq $true){

    Write-Host I will destroy !
    . Lib/DeleteApps.ps1
    . Lib/DeleteUsers.ps1


    DeleteUsers
    DeleteApps

}



