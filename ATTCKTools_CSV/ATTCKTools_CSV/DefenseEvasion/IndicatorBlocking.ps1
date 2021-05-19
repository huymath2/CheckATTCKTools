Function Get-ImpairIndicatorBlocking{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Set-EtwTraceProvider*"){
            $log
        }
    }
}
$sdir = args[0]
Get-ImpairHisCommand "$sdir\T1059_PowerShell.csv"
