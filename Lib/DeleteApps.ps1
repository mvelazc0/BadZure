Connect-Graph -Scopes "Application.ReadWrite.All"

$apps = Import-Csv -Path "Lib\apps.csv"
Function DeleteApps{

    foreach ($app in $apps) {

	    $DisplayName = $app.DisplayName
        $app_id= (Get-MgApplication -Filter "DisplayName eq '$DisplayName'").Id
        Remove-MgApplication -ApplicationId $app_id | Out-Null
        Write-Host Deleted application with Id $app_id

    }
}