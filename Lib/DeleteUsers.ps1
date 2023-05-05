
Function DeleteUsers{

    $users = Import-Csv -Path "Lib\users.csv"
    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)

    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        $user = Get-MgUser -Filter "UserPrincipalName eq '$upn'"
        Remove-MgUser -UserId $user.Id
        Write-Host [+] Deleted user with ObjectId $user.Id
    }
}

