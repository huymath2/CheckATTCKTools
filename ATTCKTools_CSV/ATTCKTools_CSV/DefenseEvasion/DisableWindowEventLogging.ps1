Function Get-EventDisableWEL{
    Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "1100"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $report
        }
    }
    
}

Get-EventDisableWEL | Export-Csv "C:\EventId1100.csv"