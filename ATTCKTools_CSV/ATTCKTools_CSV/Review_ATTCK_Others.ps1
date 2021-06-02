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

$sdir = $args[0]


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
    $report = Import-Csv -Path "$sdir\T1564_HiddenFilesandDirectories.csv"
    $report

}

Function Review_T1036_RighttoLeftOverride{
    CheckExist("$sdir\T1036_RighttoLeftOverride.csv")
    $report = Import-Csv -Path "$sdir\T1036_RighttoLeftOverride.csv"
    $report

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
    $report = Import-Csv -Path "$sdir\T1036_RighttoLeftOverride.csv"

}




#-----------------------PowerShell Log---------------------------------#
#CreationTime, EventId, Description, ProviderName, HostName, HostApplication
Write-Host "[+] Ra soat Clear Command History..."
Review_T1070_ClearCommandHistory | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostName"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Indicator Blocking..."
Review_T1070_ClearCommandHistory | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostName"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Impair Command History Logging..."
Review_T1562_ImpairCommandHistoryLogging | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostName"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Hidden Window..."
Review_T1564_HiddenWindow | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostName"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Discovery..."
Review_TA0007_Discovery | Format-Table -Property @{e = "CreationTime"; width = 20}, @{e = "EventId"; width = 10}, @{e = "Description"; width = 30},  @{e = "ProviderName"; width = 20}, @{e = "HostName"; width = 10}, @{e = "HostName"; width = 20} -Wrap | Out-String -Width 2048 | more

Pause

#----------------------------------------------------------------------#

#------------------------not in PowerShell Log-------------------------#
Write-Host "[+] Ra soat Disable or Modify Tools..."
Review_T1562_DisableorModifyTools | Format-Table -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Hidden Files and Directories..."
Review_T1564_HiddenFilesandDirectories | Format-Table -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Right to Left Override..."
Review_T1036_RighttoLeftOverride | Format-Table -Wrap | Out-String -Width 2048 | more


#----------------------------------------------------------------------#


#-------------------------Security Log---------------------------------#
Write-Host "[+] Wait for all security logs..."
CheckSecurityEvent

Write-Host "[+] Ra soat Disable or Modify Tools..."
Review_T1562_DisableorModifyTools | Format-Table -Wrap | Out-String -Width 2048 | more

Pause







#---------------------------------------------------------------------#