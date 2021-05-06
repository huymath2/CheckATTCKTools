

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


$sdir = $args[0]

function Review_BITSJobs{
    $report = Import-Csv -Path "$sdir\T1197_BITSJob.csv"
    $report
}


function Review_COR_PROFILER{
    $report = Import-Csv -Path "$sdir\T1574_COR_PROFILER.csv"
    $report
}

function Review_NetshHelperDLL{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv"
    $report
}

function Review_TimeProviders{
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"
    $report
}

function Review_PrintProcessors{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv"
    $report
}

function Review_PowerShellProfile{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"
    $report
}

function Review_ShortcutModification{
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv"
    $report
} 

function Review_PATHHijacking{
    $report = Import-Csv -Path "$sdir\T_1574_PathHijacking.csv"
    $report
}

function Review_ChangeDefaultFileAssociation{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"
    $report
}


Write-Host "[+] Ra soat BITSJobs..."
Review_BITSJobs | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat COR_PROFILER"
Review_COR_PROFILER | Select-Object KeyName, Owner, Path, Sign | Sort-Object -Property Sign, Path | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Netsh Helper DLL..."
Review_NetshHelperDLL | Select-Object KeyName, Owner, Path, Sign | Sort-Object -Property Sign, Path | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Time Provider..."
Review_TimeProviders | Select-Object KeyName, Owner, Path, Sign | Sort-Object -Property Sign, Path | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Print Processors..."
Review_PrintProcessors | Select-Object KeyName, Owner, Path, Sign | Sort-Object -Property Sign, Path | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Powershell Profile..."
Review_PowerShellProfile | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Shortcut Modification..."
Review_ShortcutModification | Select-Object Owner, Entry, Path, Sign, CMDLine | Sort-Object -Property Sign, Path | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Path Hijacking..."
Review_PATHHijacking | Select-Object Owner, FullName, Sign | Format-Table -Wrap | Out-String -width 2048

Pause

Write-Host "[+] Ra soat Change Default File Association..."
Review_ChangeDefaultFileAssociation | Format-Table -Wrap | Out-String -width 2048


