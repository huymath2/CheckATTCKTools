Function Get-LogonFailEvent{
    Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "4625"){
            $report = "" | Select-Object Id, CreationTime, Event, "Account Name", "Account Domain", "Source Network Address", "Source Port", "Failure Reason", Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
			$lines = $_.Message.Split("`n")
			foreach($line in $lines){
				if($line -like "*Account Name*"){
					$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
				}
				if($line -like "*Account Domain*"){
					$report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
				}
				if($line -like "*Source Network Address*"){
					$report."Source Network Address" = $line.TrimStart("`tSource Network Address").TrimStart(":`t")
				}
				if($line -like "*Source Port*"){
					$report."Source Port" = $line.TrimStart("`tSource Port").TrimStart(":`t")
				}
				if($line -like "*Failure Reason*"){
					$report."Failure Reason" = $line.TrimStart("`tFailure Reason").TrimStart(":`t")
				}
			}
            $report
        }
    }
    
}

Function Get-LogonExplicitCredentialsEvent{
	Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
		if($_.Id -eq "4648"){
			$report = "" | Select-Object Id, CreationTime, Event, "Account Name", "Account Domain", "Target Server Name", "Process Name", "Network Address", Port, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
			$lines = $_.Message.Split("`n")
			foreach($line in $lines){
				if($line -like "*Account Name*"){
					$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
				}
				if($line -like "*Account Domain*"){
					$report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
				}
				if($line -like "*Target Server Name*"){
					$report."Target Server Name" = $line.TrimStart("`tTarget Server Name").TrimStart(":`t")
				}
				if($line -like "*Process Name*"){
					$report."Process Name" = $line.TrimStart("`tProcess Name").TrimStart(":`t")
				}
				if($line -like "*Network Address*"){
					$report."Network Address" = $line.TrimStart("`tNetwork Address").TrimStart(":`t")
				}
				if($line -like "*Port*"){
					$report."Port" = $line.TrimStart("`tPort").TrimStart(":`t")
				}
			}
			$report
		}
	
	}
}

Function Get-KerberosPreauthenticationFail{
	Get-WinEvent -LogName "Security" | Select-Object Id, TimeCreated, Message | ForEach-Object{
		if($_.Id -eq "4771"){
			$report = "" | Select-Object Id, CreationTime, Event, "Account Name", "Client Address", "Client Port", Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
			$lines = $_.Message.Split("`n")
			foreach($line in $lines){
				if($line -like "*Account Name*"){
					$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
				}
				if($line -like "*Client Address*"){
					$report."Client Address" = $line.TrimStart("`tClient Address").TrimStart(":`t")
				}
				if($line -like "*Client Port*"){
					$report."Client Port" = $line.TrimStart("`tClient Port").TrimStart(":`t")
				}
			}
			$report
		}
	
	}

}

Get-LogonFailEvent | Export-Csv "C:\EventId4625.csv"
Get-LogonExplicitCredentialsEvent | Export-Csv "C:\EventId4648.csv"
Get-KerberosPreauthenticationFail | Export-Csv "C:\EventId4771.csv"