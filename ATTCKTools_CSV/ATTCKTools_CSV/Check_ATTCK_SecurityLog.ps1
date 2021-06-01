$ErrorActionPreference= 'silentlycontinue'


#--------------------------Result Array----------------------#

#---Defense Evasion---#
$EventID_1102 = @()
$T1562_DisableorModifySystemFirewall = @()
$EventID_1100 = @()
$EventID_4768 = @()
$EventID_4769 = @()
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
            $global:EventID_1102 += $report
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
            $global:EventID_1100 += $report
        }

        if($_.Id -eq "4768"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4768 += $report
        }

        if($_.Id -eq "4769"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4769 += $report
        }

        if($_.Id -eq "4928"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4928 += $report
        }

        if($_.Id -eq "4929"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4929 += $report
        }

        if($_.Id -eq "4765"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4765 += $report
        }

        if($_.Id -eq "4766"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4766 += $report
        }

        #Credential Access
        if($_.Id -eq "4625"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4625 += $report
        }

        if($_.Id -eq "4648"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4648 += $report
        }

        if($_.Id -eq "4771"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4771 += $report
        }

        if($_.Id -eq "4624"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4624 += $report
        }

        if($_.Id -eq "4634"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4634 += $report
        }

        if($_.Id -eq "4672"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
            $global:EventID_4672 += $report
        }
         
    }
}


$sdir = "D:\abcd"
#$sdir = $args[0]
Get-ATTCKSecurityLog "$sdir\Security_Log0.csv"



<#---------------Export CSV-----------------------#
$EventID_1102 | Export-Csv "$sdir\EventID_1102.csv"
$T1562_DisableorModifySystemFirewall | Export-Csv "$sdir\T1562_DisableorModifySystemFirewall.csv"
$EventID_1100 | Export-Csv "$sdir\EventID_1100.csv"
$EventID_4768 | Export-Csv "$sdir\EventID_4768.csv"
$EventID_4769 | Export-Csv "$sdir\EventID_4769.csv"
$EventID_4928 | Export-Csv "$sdir\EventID_4928.csv"
$EventID_4929 | Export-Csv "$sdir\EventID_4929.csv"
$EventID_4765 | Export-Csv "$sdir\EventID_4765.csv"
$EventID_4766 | Export-Csv "$sdir\EventID_4766.csv"

$EventID_4625 | Export-Csv "$sdir\EventID_4625.csv"
$EventID_4648 | Export-Csv "$sdir\EventID_4648.csv"
$EventID_4771 | Export-Csv "$sdir\EventID_4771.csv"
$EventID_4624 | Export-Csv "$sdir\EventID_4624.csv"
$EventID_4634 | Export-Csv "$sdir\EventID_4634.csv"
$EventID_4672 | Export-Csv "$sdir\EventID_4672.csv"
#------------------------------------------------#>


#---------------Write on Console-----------------#
$EventID_1102 | FT -Property @{e = '*'; width = 30} -Wrap
$T1562_DisableorModifySystemFirewall | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_1100 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4768 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4769 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4928 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4929 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4765 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4766 | FT -Property @{e = '*'; width = 30} -Wrap

$EventID_4625 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4648 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4771 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4624 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4634 | FT -Property @{e = '*'; width = 30} -Wrap
$EventID_4672 | FT -Property @{e = '*'; width = 30} -Wrap

#------------------------------------------------#>