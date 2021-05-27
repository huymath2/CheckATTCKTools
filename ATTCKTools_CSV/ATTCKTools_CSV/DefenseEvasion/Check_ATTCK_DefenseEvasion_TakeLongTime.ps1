$ErrorActionPreference= 'silentlycontinue'


Function Get-ClearCommandHistory{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Clear-History*"){
            $log
        }
    }
}


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

Function Get-EventDisableModifyFirewall{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$SecurityLogPath
    )
    Import-Csv -Path $SecurityLogPath | ForEach-Object{
        if($_.Id -eq "4950" -or $_.Id -eq "4946" -or $_.Id -eq "4947" -or $_.Id -eq "4948" -or $_.Id -eq "4954" -or $_.Id -eq "4956" -or $_.Id -eq "5025" -or $_.Id -eq "5034"){
            $report = "" | Select-Object Id, CreationTime, Event, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			#$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
    
}

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

Function Get-ImpairIndicatorBlocking{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Set-EtwTraceProvider*"){
            $log
        }
    }
}

Function Get-ImpairHistoryCommand{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Set-PSReadLineOption -HistorySavePath*"){
            $log
        }
    }
}


Function Get-HiddenFileAndDir{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse -Hidden | Select-Object CreationTime, Attributes, FullName
    $items
}


Function Get-HiddenCommand{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*-windowstyle hidden*"){
            $log
        }
    }
}



Function Get-RighttoLeftOverride{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse | where { $_ -cmatch '[\u0080-\uffff]'}   | Select-Object CreationTime, Attributes, FullName
    $items
}




$sdir = "D:\abcd"
#$sdir = $args[0]
Measure-Command -Expression {
Get-ClearCommandHistory "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1070_ClearCommandHistory.csv"
Get-ClearEventLog "$sdir\Security_Log.csv" | Export-Csv "$sdir\T1070_ClearWindowsEventLogs.csv"
Get-EventDisableModifyFirewall "$sdir\Security_Log.csv" | Export-Csv "$sdir\T1562_DisableorModifySystemFirewall.csv"
Get-EventDisableWEL "$sdir\Security_Log.csv" | Export-Csv "$sdir\T1562_DisableWindowsEventLogging.csv"
Get-WindowDefendLog | Export-Csv "$sdir\T1562_DisableorModifyTools.csv"
Get-ImpairIndicatorBlocking "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1562_IndicatorBlocking.csv"
Get-ImpairHistoryCommand "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1562_ImpairCommandHistoryLogging.csv"
Get-HiddenFileAndDir | Export-Csv "$sdir\T1564_HiddenFilesandDirectories.csv"
Get-HiddenCommand "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\T1564_HiddenWindow.csv"
Get-RighttoLeftOverride | Export-Csv "$sdir\T1036_RighttoLeftOverride.csv"
#call syscheck.bat -nobanner -tuv > "%sdir%\T1553_InstallRootCertificate.txt"

}


