Function Get-ImpairHistoryCommand{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Set-PSReadLineOption -HistorySavePath*"){
            $log
        }
    }
}
$sdir = $args[0]
Get-ImpairHistoryCommand "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1562_ImpairCommandHistoryLogging.csv"
