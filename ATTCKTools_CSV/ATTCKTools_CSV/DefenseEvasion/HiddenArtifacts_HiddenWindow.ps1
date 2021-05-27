Function Get-HiddenCommand{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*-windowstyle hidden*"){
            $log
        }
    }
}
$sdir = $args[0]

Get-HiddenCommand "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1564_HiddenWindow.csv"