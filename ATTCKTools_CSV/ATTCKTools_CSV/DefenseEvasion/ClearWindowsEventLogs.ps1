Function Get-ClearEventLog{
    Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "1102"){
            $report = "" | Select-Object Id, CreationTime, Event, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
    
}

Get-ClearEventLog