$ErrorActionPreference = 'silentlycontinue'

#--------------------------Result Array----------------------#

#---Defense Evasion---#
$EventID_1100 = @()

$EventID_1102 = @()

$EventID_4768 = @()
$EventID_4769 = @()
$EventID_4770 = @()

$EventID_4928 = @()
$EventID_4929 = @()
$EventID_4765 = @()
$EventID_4766 = @()

#---------------------#

#--Credential Access--#
$EventID_4625 = @()
$EventID_4648 = @()
$EventID_4771 = @()
$EventID_4624 = @()
$EventID_4634 = @()
$EventID_4672 = @()


#---------------------#

#------------------------------------------------------------#


Function Collect-SecurityLog{
    Get-WinEvent -Path "D:\test\x.evtx" | Select-Object TimeCreated, Id, Message, MachineName | ForEach-Object{
    #Get-WinEvent -LogName "Security" | Select-Object TimeCreated, Id, Message, MachineName | ForEach-Object{
        if($_.Id -eq "1100"){
            $report = "" | Select-Object EventId, CreationTime, Message, MachineName       
            $report.EventId = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $report.MachinName = $_.MachineName
            
            $Global:EventID_1100 += $report
        }

        if($_.Id -eq "1102"){
            $report = "" | Select-Object CreationTime, EventID, "Account Name", "Domain Name", MachineName     
            $report.EventID = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.MachineName = $_.MachineName
            $lines = $_.Message.Split("`n")
	        foreach($line in $lines){
	            if($line -like "*Account Name*"){
			        $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		        }
		        if($line -like "*Domain Name*"){
			        $report."Domain Name" = $line.TrimStart("`tDomain Name").TrimStart(":`t")
		        }
	        }
            $Global:EventID_1102 += $report

        }

        if($_.Id -eq "4768"){
            $report = "" | Select-Object CreationTime, EventID, "Account Name", MachineName     
            $report.EventID = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.MachineName = $_.MachineName
            $lines = $_.Message.Split("`n")
	        foreach($line in $lines){
	            if($line -like "*Account Name:*"){
			        $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		        }
                if($line -like "*Supplied Realm Name*"){
			        $s = $line.TrimStart("`tSupplied Realm Name").TrimStart(":`t")
                    $report."Account Name" += "@$s"
                    Write-Output $report."Account Name"
		        }
	        }
            $Global:EventID_4768 += $report
        }
    }
}



$sdir = $args[0]
#$sdir = "D:\test"

Measure-Command -Expression {

Collect-SecurityLog 

}

<#Measure-Command -Expression{
Collect-SecurityLog | Export-Csv "$sdir\Security_Log.csv"
}#>


#TotalMinutes      : 1.76836639166667
