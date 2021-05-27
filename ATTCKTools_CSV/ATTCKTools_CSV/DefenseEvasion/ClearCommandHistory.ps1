Function Get-ClearCommandHistory{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Clear-History*"){
            $log
        }
    }
}
$sdir = $args[0]
Get-ClearCommandHistory "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1070_ClearCommandHistory.csv"
