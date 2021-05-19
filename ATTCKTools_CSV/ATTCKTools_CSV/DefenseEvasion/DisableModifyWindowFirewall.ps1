Function Get-EventDisableModifyFirewall{
    Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "4950" -or $_.Id -eq "4946" -or $_.Id -eq "4947" -or $_.Id -eq "4948" -or $_.Id -eq "4954" -or $_.Id -eq "4956" -or $_.Id -eq "5025" -or $_.Id -eq "5034"){
            $report = "" | Select-Object Id, CreationTime, Event, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
    
}

#4946	A change has been made to Windows Firewall exception list. A rule was added
#4947	A change has been made to Windows Firewall exception list. A rule was modified
#4948	A change has been made to Windows Firewall exception list. A rule was deleted
#4950	A Windows Firewall setting has changed
#4954	Windows Firewall Group Policy settings has changed. The new settings have been applied
#4956	Windows Firewall has changed the active profile
#5025	The Windows Firewall Service has been stopped
#5034	The Windows Firewall Driver has been stopped

Get-EventDisableModifyFirewall