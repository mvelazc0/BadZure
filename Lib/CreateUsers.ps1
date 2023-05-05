$PasswordProfile = @{
    Password = "bmNEe%PA@hw91vIvg7V%"
}
$users = Import-Csv -Path "Lib\users.csv"

Function CreateUsers{

    $account=(Get-MgContext | Select-Object Account).Account
    $pos=$account.IndexOf('@')
    $domain=$account.Substring($pos+1)


    foreach ($user in $users) {
        $displayName = -join($user.FirstName,'.',$user.LastName)
        $upn = -join($displayName,'@',$domain)
        New-MgUser -DisplayName $displayName -PasswordProfile $PasswordProfile -AccountEnabled -MailNickName $displayName -UserPrincipalName $upn | Out-Null
        Write-Host Created User $upn
    }
}

