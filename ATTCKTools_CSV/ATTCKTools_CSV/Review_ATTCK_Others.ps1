$ErrorActionPreference= 'silentlycontinue'

function Pause ($Message = "Press any key to continue . . . ") {
    if ((Test-Path variable:psISE) -and $psISE) {
        $Shell = New-Object -ComObject "WScript.Shell"
        $Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)
    }
    else {     
        Write-Host -NoNewline $Message
        [void][System.Console]::ReadKey($true)
        Write-Host
    }
}


Function CheckExist{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    return
    while (1){
        if(!(Test-Path -Path $FilePath -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead($FilePath).Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }

}

#$sdir = $args[0]
$sdir = "D:\ThreatHuntingToolBuilding\CheckATTCK\CheckATTCKTools\SetupLab\SampleCSV"

#Functions follow PS logs
Function Review_T1070_ClearCommandHistory{
    CheckExist("$sdir\T1070_ClearCommandHistory.csv")
    $report = Import-Csv -Path "$sdir\T1070_ClearCommandHistory.csv"
    $report
}

Function Review_T1562_IndicatorBlocking{
    CheckExist("$sdir\T1562_IndicatorBlocking.csv")
    $report = Import-Csv -Path "$sdir\T1562_IndicatorBlocking.csv"
    $report

}

Function Review_T1562_ImpairCommandHistoryLogging{
    CheckExist("$sdir\T1562_ImpairCommandHistoryLogging.csv")
    $report = Import-Csv -Path "$sdir\T1562_ImpairCommandHistoryLogging.csv"
    $report

}

Function Review_T1564_HiddenWindow{
    CheckExist("$sdir\T1564_HiddenWindow.csv")
    $report = Import-Csv -Path "$sdir\T1564_HiddenWindow.csv"
    $report

}

Function Review_TA0007_Discovery{
    CheckExist("$sdir\TA0007_Discovery.csv")
    $report = Import-Csv -Path "$sdir\TA0007_Discovery.csv"
    $report

}


#Funtions not follow logs
Function Review_T1562_DisableorModifyTools{
    CheckExist("$sdir\T1562_DisableorModifyTools.csv")
    $report = Import-Csv -Path "$sdir\T1562_DisableorModifyTools.csv"
    $report

}

Function Review_T1564_HiddenFilesandDirectories{
    CheckExist("$sdir\T1564_HiddenFilesandDirectories.csv")
    $reports = Import-Csv -Path "$sdir\T1564_HiddenFilesandDirectories.csv"
    foreach($report in $reports){
        if($report.Owner -ne "NT SERVICE\TrustedInstaller"){
            $report | Select-Object LastWriteTime, Attributes, Owner, FullName ,Sign
        }
    }
}

Function Review_T1036_RighttoLeftOverride{
    CheckExist("$sdir\T1036_RighttoLeftOverride.csv")
    $reports = Import-Csv -Path "$sdir\T1036_RighttoLeftOverride.csv"
    foreach($report in $reports){
        if($report.Owner -ne "NT SERVICE\TrustedInstaller"){
            $report | Select-Object LastWriteTime, Attributes, Owner, FullName ,Sign
        }
    }

}



#Functions follow Security logs
Function CheckSecurityEvent{
    CheckExist("$sdir\EventID_1102.csv")
    CheckExist("$sdir\T1562_DisableorModifySystemFirewall.csv")
    CheckExist("$sdir\EventID_1100.csv")
    CheckExist("$sdir\EventID_4768.csv")
    CheckExist("$sdir\EventID_4769.csv")
    CheckExist("$sdir\EventID_4928.csv")
    CheckExist("$sdir\EventID_4929.csv")
    CheckExist("$sdir\EventID_4765.csv")
    CheckExist("$sdir\EventID_4766.csv")
    CheckExist("$sdir\EventID_4625.csv")
    CheckExist("$sdir\EventID_4648.csv")
    CheckExist("$sdir\EventID_4771.csv")
    CheckExist("$sdir\EventID_4624.csv")
    CheckExist("$sdir\EventID_4634.csv")
    CheckExist("$sdir\EventID_4672.csv")

}



Function Review_T1134_SID-HistoryInjection{
#pending - output not ready
    $report = Import-Csv -Path "$sdir\T1036_RighttoLeftOverride.csv"

}



Function Review_T1562_DisableWindowsEventLogging{
    Import-Csv -Path "$sdir\EventID_1102.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Domain Name"     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
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


Function Review_T1070_ClearWindowsEventLogs{
    $report = Import-Csv -Path "$sdir\EventID_1100.csv"
    $report

}

Function Review_T1562_DisableorModifySystemFirewall{
    $report = Import-Csv -Path "$sdir\T1562_DisableorModifySystemFirewall.csv"
    $report

}

Function Review_T1207_RogueDomainController{
    $report = Import-Csv -Path "$sdir\EventID_4928.csv"
    $report

    $report = Import-Csv -Path "$sdir\EventID_4929.csv"
    $report

}

Function Review_T1553_CodeSigningPolicyModification{
    $report = Import-Csv -Path "$sdir\T1553_CodeSigningPolicyModification.csv"
    if($report -ne $null){
        Write-Host "HKCU\Software\Policies\Microsoft\Windows NT\Driver Signing"
    }
    $report
}

Function Review_Event4769{
    Import-Csv -Path "$sdir\EventID_4769.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain", "Client Address", "Client Port"     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
		    if($line -like "*Account Domain:*"){
			    $report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
		    }
            if($line -like "*Client Address:*"){
			    $report."Client Address" = $line.TrimStart("`tClient Address").TrimStart(":`t")
		    }
            if($line -like "*Client Port:*"){
			    $report."Client Port" = $line.TrimStart("`tClient Port").TrimStart(":`t")
		    }
	    }
        $report
    }

}

Function Review_Event4768{
    Import-Csv -Path "$sdir\EventID_4768.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Client Address", "Client Port"     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
            if($line -like "*Client Address:*"){
			    $report."Client Address" = $line.TrimStart("`tClient Address").TrimStart(":`t")
		    }
            if($line -like "*Client Port:*"){
			    $report."Client Port" = $line.TrimStart("`tClient Port").TrimStart(":`t")
		    }
	    }
        $report
    }

}

Function Review_Event4625{
    Import-Csv -Path "$sdir\EventID_4625.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain", "Source Network Address", "Source Port", "Failure Reason"     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
				$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
			}
			if($line -like "*Account Domain:*"){
				$report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
			}
			if($line -like "*Source Network Address:*"){
				$report."Source Network Address" = $line.TrimStart("`tSource Network Address").TrimStart(":`t")
			}
			if($line -like "*Source Port:*"){
				$report."Source Port" = $line.TrimStart("`tSource Port").TrimStart(":`t")
			}
			if($line -like "*Failure Reason:*"){
				$report."Failure Reason" = $line.TrimStart("`tFailure Reason").TrimStart(":`t")
			}
	    }
        $report
    }

}

Function Review_Event4648{
    Import-Csv -Path "$sdir\EventID_4648.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain", "Target Server Name", "Process Name", "Network Address", Port     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
				$report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
			}
			if($line -like "*Account Domain:*"){
				$report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
			}
			if($line -like "*Target Server Name:*"){
				$report."Target Server Name" = $line.TrimStart("`tTarget Server Name").TrimStart(":`t")
			}
			if($line -like "*Process Name:*"){
				$report."Process Name" = $line.TrimStart("`tProcess Name").TrimStart(":`t")
			}
			if($line -like "*Network Address:*"){
				$report."Network Address" = $line.TrimStart("`tNetwork Address").TrimStart(":`t")
			}
			if($line -like "*Port:*"){
				$report."Port" = $line.TrimStart("`tPort").TrimStart(":`t")
			}
	    }
        $report
    }

}

Function Review_Event4771{
    Import-Csv -Path "$sdir\EventID_4771.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Client Address", "Client Port"     
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
            if($line -like "*Client Address:*"){
			    $report."Client Address" = $line.TrimStart("`tClient Address").TrimStart(":`t")
		    }
            if($line -like "*Client Port:*"){
			    $report."Client Port" = $line.TrimStart("`tClient Port").TrimStart(":`t")
		    }
	    }
        $report
    }

}

Function Review_Event4624{
    Import-Csv -Path "$sdir\EventID_4624.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain"    
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
		    if($line -like "*Account Domain:*"){
			    $report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
		    }
	    }
        $report
    }

}

Function Review_Event4634{
    Import-Csv -Path "$sdir\EventID_4634.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain"    
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
		    if($line -like "*Account Domain:*"){
			    $report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
		    }
	    }
        $report
    }

}

Function Review_Event4672{
    Import-Csv -Path "$sdir\EventID_4672.csv" | ForEach-Object{
        $report = "" | Select-Object CreationTime, EventID, "Account Name", "Account Domain"    
        $report.EventID = $_.Id
        $report.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $lines = $_.Message.Split("`n")
	    foreach($line in $lines){
	        if($line -like "*Account Name:*"){
			    $report."Account Name" = $line.TrimStart("`tAccount Name").TrimStart(":`t")
		    }
		    if($line -like "*Account Domain:*"){
			    $report."Account Domain" = $line.TrimStart("`tAccount Domain").TrimStart(":`t")
		    }
	    }
        $report
    }

}


#-----------------------PowerShell Log---------------------------------#
#CreationTime, EventId, Description, ProviderName, HostName, HostApplication
Write-Host "[+] Ra soat Clear Command History..."
Review_T1070_ClearCommandHistory | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostApplication"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Indicator Blocking..."
Review_T1070_ClearCommandHistory | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostApplication"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Impair Command History Logging..."
Review_T1562_ImpairCommandHistoryLogging | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostApplication"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Hidden Window..."
Review_T1564_HiddenWindow | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostApplication"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Discovery..."
Review_TA0007_Discovery | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostApplication"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

#----------------------------------------------------------------------#

#------------------------not in PowerShell Log-------------------------#
Write-Host "[+] Ra soat Disable or Modify Tools..."
Review_T1562_DisableorModifyTools | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

#Attributes
Write-Host "[+] Ra soat Hidden Files and Directories..."
Review_T1564_HiddenFilesandDirectories | Sort-Object -Property Attributes, LastWriteTime | Format-Table -Property @{e = "LastWriteTime"; width = 20}, @{e = "Attributes"; width = 10}, @{e = "Owner"; width = 20},  @{e = "FullName"; width = 40},  @{e = "Sign"; width = 20} -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Right to Left Override..."
Review_T1036_RighttoLeftOverride |  Sort-Object -Property LastWriteTime | Format-Table -Property @{e = "LastWriteTime"; width = 20}, @{e = "Owner"; width = 20},  @{e = "FullName"; width = 40},  @{e = "Sign"; width = 20} -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Code Signing Policy Modification..."
Review_T1553_CodeSigningPolicyModification | Format-Table -Wrap | Out-String -Width 2048 | more
Pause
#----------------------------------------------------------------------#


#-------------------------Security Log---------------------------------#
Write-Host "[+] Wait for all security logs..."
CheckSecurityEvent

Write-Host "[+] Ra soat Disable or Modify Tools..."
Review_T1562_DisableorModifyTools | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Disable Windows Event Logging..."
Review_T1562_DisableWindowsEventLogging | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Account Name"; width = 30}, @{e = "Domain Name"; width = 30} -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Clear Windows Event Logs..."
Review_T1070_ClearWindowsEventLogs | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Disable or Modify System Firewall..."
Review_T1562_DisableorModifySystemFirewall | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Rogue Domain Controller..."
Review_T1207_RogueDomainController | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Use Alternate Authentication Material; Steal or Forge Kerberos Tickets: Kerberoasting, AS-REP Roasting..."
Review_Event4768 | Format-Table -Wrap | Out-String -Width 2048 | more
Review_Event4769 | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

Write-Host "[+] Ra soat Brute Force..."
Review_Event4625 | Format-Table -Wrap | Out-String -Width 2048 | more
Review_Event4648 | Format-Table -Wrap | Out-String -Width 2048 | more
Review_Event4771 | Format-Table -Wrap | Out-String -Width 2048 | more
Pause

<# Pending: Check all event have blank field or are anomalous 
Write-Host "[+] Ra soat Steal or Forge Kerberos Tickets: Golden Ticket, Silver Ticket..."
Review_Event4624 | Format-Table -Wrap | Out-String -Width 2048 | more
Review_Event4634 | Format-Table -Wrap | Out-String -Width 2048 | more
Review_Event4672 | Format-Table -Wrap | Out-String -Width 2048 | more
Pause#>



#---------------------------------------------------------------------#>