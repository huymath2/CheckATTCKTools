Function Get-WindowDefendLog{
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "5001" -or $_.Id -eq "5010" -or $_.Id -eq "5012"){
            $report = "" | Select-Object Id, CreationTime, Event, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
}
$sdir = $args[0]
Get-WindowDefendLog | Export-Csv "$sdir\T1562_DisableorModifyTools.csv"