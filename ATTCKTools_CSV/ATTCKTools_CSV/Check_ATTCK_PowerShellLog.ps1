$ErrorActionPreference= 'silentlycontinue'
#Call via other process

#--------------------------Result Array----------------------#

#---Defense Evasion---#
$T1070_ClearCommandHistory = @()
$T1562_IndicatorBlocking = @()
$T1562_ImpairCommandHistoryLogging = @()
$T1564_HiddenWindow = @()



#---------------------#

#-----Discovery------#
$TA0007_Discovery = @()



#--------------------#




#------------------------------------------------------------#


Function Get-ATTCKPowerShellLog{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )

    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        #Defense Evasion
        if($log.HostApplication -like "*Clear-History*"){
            $global:T1070_ClearCommandHistory += $log
        }
        if($log.HostApplication -like "*Set-EtwTraceProvider*"){
            $global:T1562_IndicatorBlocking += $log
        }
        if($log.HostApplication -like "*Set-PSReadLineOption -HistorySavePath*"){
            $global:T1562_ImpairCommandHistoryLogging += $log
        }
        if($log.HostApplication -like "*-windowstyle hidden*"){
            $global:T1564_HiddenWindow += $log
        }

        #Discovery

        if($log.HostApplication -like "*Get-LocalGroup*" -or $log.HostApplication -like "*Get-LocalUser*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Local Account" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-ADUser*" -or $log.HostApplication -like "*Get-ADDomain*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Domain Account" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-GlobalAddressList*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Email Account" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-Process | Where-Object {$_.MainWindowTitle -ne `"`"}*"){
            $log | Add-Member NoteProperty Category "Application Window Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-Content `"C:\Users\*\Bookmarks`"*"){
            $log | Add-Member NoteProperty Category "Browser Bookmark Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-ADTrust*"){
            $log | Add-Member NoteProperty Category "Domain Trust Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "* Dir *"){
            $log | Add-Member NoteProperty Category "File and Directory Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*net view \remotesystem*" -or $log.HostApplication -like "*net share*"){
            $log | Add-Member NoteProperty Category "Network Share Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-ADDefaultDomainPasswordPolicy*"){
            $log | Add-Member NoteProperty Category "Password Policy Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-PnpDevice*"){
            $log | Add-Member NoteProperty Category "Peripheral Device Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-LocalGroup*" -or $log.HostApplication -like "*Get-ADGroup*"){
            $log | Add-Member NoteProperty Category "Permission Groups Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-Process*"){
            $log | Add-Member NoteProperty Category "Process Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-ItemProperty HK*"){
            $log | Add-Member NoteProperty Category "Query Registry " -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-ComputerInfo*"){
            $log | Add-Member NoteProperty Category "System Information Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*ipconfig *"){
            $log | Add-Member NoteProperty Category "System Network Configuration Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*net session*" -or $log.HostApplication -like "*net use*"){
            $log | Add-Member NoteProperty Category "System Network Connections Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*whoami*"){
            $log | Add-Member NoteProperty Category "System Owner/User Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-Service*"){
            $log | Add-Member NoteProperty Category "System Service Discovery" -Force
            $global:TA0007_Discovery += $log
        }
        if($log.HostApplication -like "*Get-Date*" -or $log.HostApplication -like "*Get-TimeZone*"){
            $log | Add-Member NoteProperty Category "System Time Discovery" -Force
            $global:TA0007_Discovery += $log
        }
    }


}



#$sdir = "D:\abcd"
$sdir = $args[0]
Get-ATTCKPowerShellLog "$sdir\PowerShell_Log.csv"


#---------------Export CSV-----------------------#
$T1070_ClearCommandHistory | Export-Csv "$sdir\T1070_ClearCommandHistory.csv"
$T1562_IndicatorBlocking | Export-Csv "$sdir\T1562_IndicatorBlocking.csv" 
$T1562_ImpairCommandHistoryLogging | Export-Csv "$sdir\T1562_ImpairCommandHistoryLogging.csv"
$T1564_HiddenWindow | Export-Csv "$sdir\T1564_HiddenWindow.csv"

$TA0007_Discovery | Export-Csv "$sdir\TA0007_Discovery.csv"
#------------------------------------------------#>


<#---------------Write on Console-----------------#
$T1070_ClearCommandHistory | FT -Property @{e = '*'; width = 30} -Wrap
$T1562_IndicatorBlocking | FT -Property @{e = '*'; width = 30} -Wrap
$T1562_ImpairCommandHistoryLogging | FT -Property @{e = '*'; width = 30} -Wrap
$T1564_HiddenWindow | FT -Wrap

$TA0007_Discovery | FT -Property @{e = '*'; width = 30} -Wrap


#------------------------------------------------#>
