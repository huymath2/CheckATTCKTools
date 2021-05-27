Function Get-ClearEventLog{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$SecurityLogPath
    )
    Import-Csv -Path $SecurityLogPath | ForEach-Object{
        if($_.Id -eq "1102"){
            $report = "" | Select-Object Id, CreationTime, Event, "Account Name", "Domain Name", Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
            $lines = $_.Message.Split("`n")
			foreach($line in $lines){
				if($line -like "*Account Name*"){
					$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
				}
				if($line -like "*Domain Name*"){
					$report."Domain Name" = $line.TrimStart("`tDomain Name").TrimStart(":`t")
				}
			}
            $report
        } 
    }
    
}

$sdir = $args[0]
Get-ClearEventLog "$sdir\Security_Log.csv" | Export-Csv "$sdir\T1070_ClearWindowsEventLogs.csv"