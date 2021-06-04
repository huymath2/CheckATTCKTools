$ErrorActionPreference = 'silentlycontinue'

Function Get-RDPEvent{
    Get-WinEvent -Path "D:\abcd\RDPHijack.evtx" | Select-Object Id, TimeCreated, Message | ForEach-Object{
    #Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "24" -or $_.Id -eq "25"){
            $report = "" | Select-Object CreationTime, EventId, User, "Source Network Address"       
            $report.EventId = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $lines = $_.Message.Split("`n")
	        foreach($line in $lines){
	            if($line -like "*User*"){
			        $report."User" = $line.TrimStart("User").TrimStart(":")
		        }
		        if($line -like "*Source Network Address*"){
			        $report."Source Network Address" = $line.TrimStart("Source Network Address").TrimStart(":")
		        }
	        }
            $report
        }

    }
    Get-WinEvent -Path "D:\abcd\remoteconnectionmanager.evtx" | Select-Object Id, TimeCreated, Message | ForEach-Object{
    #Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "1149"){
            $report = "" | Select-Object CreationTime, EventId, User, "Source Network Address"       
            $report.EventId = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $lines = $_.Message.Split("`n")
	        foreach($line in $lines){
	            if($line -like "*User*"){
			        $report."User" = $line.TrimStart("User").TrimStart(":")
		        }
		        if($line -like "*Source Network Address*"){
			        $report."Source Network Address" = $line.TrimStart("Source Network Address").TrimStart(":")
		        }
	        }
            $report
        }

    }

}






#$sdir = "D:\abcd"
$sdir = $args[0]

Get-RDPEvent | Export-Csv "$sdir\RDPHijack_Event.csv"
#Get-RDPEvent | FT -Wrap