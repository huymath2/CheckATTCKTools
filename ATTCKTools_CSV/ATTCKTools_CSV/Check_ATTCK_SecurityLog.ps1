$ErrorActionPreference= 'silentlycontinue'


#--------------------------Result Array----------------------#

#---Defense Evasion---#
$T1070_ClearWindowsEventLogs = @()
$T1562_DisableorModifySystemFirewall = @()
$T1562_DisableWindowsEventLogging = @()


#---------------------#





#------------------------------------------------------------#

Function Get-ATTCKSecurityLog{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$SecurityLogPath
    )
    Import-Csv -Path $SecurityLogPath| Select-Object * | ForEach-Object{
        #Defense Evasion
        if($_.Id -eq "1102"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:T1070_ClearWindowsEventLogs += $report
        }
        if($_.Id -eq "4950" -or $_.Id -eq "4946" -or $_.Id -eq "4947" -or $_.Id -eq "4948" -or $_.Id -eq "4954" -or $_.Id -eq "4956" -or $_.Id -eq "5025" -or $_.Id -eq "5034"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:T1562_DisableorModifySystemFirewall += $report
        }
        if($_.Id -eq "1100"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:T1562_DisableWindowsEventLogging += $report
        }

        #Credential Access
        if($_.Id -eq "4625"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:T1562_DisableWindowsEventLogging += $report
        }
         
    }
}


$sdir = "D:\abcd"
#$sdir = $args[0]
Get-ATTCKSecurityLog "$sdir\Security_Log0.csv"



#---------------Export CSV-----------------------#
$T1070_ClearWindowsEventLogs | Export-Csv "$sdir\T1070_ClearWindowsEventLogs.csv"
$T1562_DisableorModifySystemFirewall | Export-Csv "$sdir\T1562_DisableorModifySystemFirewall.csv"
$T1562_DisableWindowsEventLogging | Export-Csv "$sdir\T1562_DisableWindowsEventLogging.csv"

#------------------------------------------------#


<#---------------Write on Console-----------------#
$T1070_ClearWindowsEventLogs | FT -Property @{e = '*'; width = 30} -Wrap
$T1562_DisableorModifySystemFirewall | FT -Property @{e = '*'; width = 30} -Wrap
$T1562_DisableWindowsEventLogging | FT -Property @{e = '*'; width = 30} -Wrap

#------------------------------------------------#>