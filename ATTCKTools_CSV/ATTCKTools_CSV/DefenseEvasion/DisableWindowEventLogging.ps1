Function Get-EventDisableWEL{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$SecurityLogPath
    )
    Import-Csv -Path $SecurityLogPath | ForEach-Object{
        if($_.Id -eq "1100"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $report
        }
    }
    
}
$sdir = $args[0]
Get-EventDisableWEL "$sdir\Security_Log.csv" | Export-Csv "$sdir\T1562_DisableWindowsEventLogging.csv"